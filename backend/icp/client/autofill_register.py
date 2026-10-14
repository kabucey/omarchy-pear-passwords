"""pear-passwords-autofill: opt in to browser autofill, one browser at a time.

Pear Passwords ships no browser extension and writes no native-messaging manifest on install.
Autofill stays off until you run, as yourself:

    pear-passwords-autofill register --browser zen --extension-id <id>
    pear-passwords-autofill unregister --browser zen
    pear-passwords-autofill unregister --all
    pear-passwords-autofill status

`register` writes io.github.dragosol.pearpasswords.json into that browser's user manifest
directory, allowing only the extension id you name, and records the file's sha256 in a receipt
under $XDG_STATE_HOME/pear-passwords/autofill-receipts. It refuses to replace a file it did not
write. `unregister` removes a manifest only while its sha256 still matches the receipt; a file
you edited is left alone and reported.

The manifest directories are computed from the browser table below, never read from the
receipt, so an edited receipt cannot point this command at any other file.

This runs as the user (no set-gid, no daemon connection) from the root-owned venv via
/usr/local/bin/pear-passwords-autofill. It must not be run as root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import stat
import sys
from dataclasses import dataclass

from ..daemon import paths

# The manifest every registration writes. system/native-messaging/<host>.json.in is the same
# text, kept in the repository for review; test_autofill_register checks the two are equal.
MANIFEST_TEMPLATE = """\
{
  "name": "@NAME@",
  "description": "Pear Passwords autofill host. Every fill asks you first.",
  "path": "@HOST_PATH@",
  "type": "stdio",
  "@ALLOWED_KEY@": @ALLOWED@
}
"""

HOST_PATH = paths.AUTOFILL_HOST
RECEIPT_FORMAT = 1

_MOZ_ID_RE = re.compile(
    r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"
    r"|[A-Za-z0-9._-]{1,80}@[A-Za-z0-9._-]{1,170}")
_CHROMIUM_ID_RE = re.compile(r"[a-p]{32}")


@dataclass(frozen=True)
class Browser:
    name: str
    kind: str                     # "mozilla" (allowed_extensions) or "chromium" (allowed_origins)
    title: str


BROWSERS = {b.name: b for b in (
    Browser("firefox", "mozilla", "Firefox"),
    Browser("zen", "mozilla", "Zen"),
    Browser("librewolf", "mozilla", "LibreWolf"),
    Browser("chromium", "chromium", "Chromium"),
    Browser("chrome", "chromium", "Google Chrome"),
    Browser("brave", "chromium", "Brave"),
    Browser("vivaldi", "chromium", "Vivaldi"),
    Browser("edge", "chromium", "Microsoft Edge"),
)}

_CHROMIUM_DIRS = {
    "chromium": "chromium",
    "chrome": "google-chrome",
    "brave": "BraveSoftware/Brave-Browser",
    "vivaldi": "vivaldi",
    "edge": "microsoft-edge",
}


class RegisterError(Exception):
    """Refused; the message says why and what to do."""


@dataclass(frozen=True)
class Env:
    home: str
    config: str                   # $XDG_CONFIG_HOME
    state: str                    # $XDG_STATE_HOME

    @classmethod
    def current(cls) -> "Env":
        home = os.environ.get("HOME", "")
        if not os.path.isabs(home):
            home = pwd.getpwuid(os.getuid()).pw_dir

        def xdg(var, default):
            v = os.environ.get(var, "")
            return v if os.path.isabs(v) else os.path.join(home, default)
        return cls(home, xdg("XDG_CONFIG_HOME", ".config"), xdg("XDG_STATE_HOME", ".local/state"))

    @property
    def receipt(self) -> str:
        return os.path.join(self.state, "pear-passwords", "autofill-receipts")


# --- where each browser looks ------------------------------------------------------------------

def _mozilla_dir(env: Env) -> str:
    """Firefox's user manifest directory: ~/.mozilla while it exists (it always has, and Zen,
    being Firefox, reads the same one), else the XDG location newer Firefox uses."""
    legacy = os.path.join(env.home, ".mozilla")
    if os.path.isdir(legacy) or not os.path.isdir(os.path.join(env.config, "mozilla")):
        return os.path.join(legacy, "native-messaging-hosts")
    return os.path.join(env.config, "mozilla", "native-messaging-hosts")


def candidate_dirs(browser: str, env: Env) -> list[str]:
    """Every directory `browser` might read, whether or not it exists. unregister only ever
    touches files in these."""
    b = BROWSERS[browser]
    if b.kind == "chromium":
        return [os.path.join(env.config, _CHROMIUM_DIRS[browser], "NativeMessagingHosts")]
    moz = [os.path.join(env.home, ".mozilla", "native-messaging-hosts"),
           os.path.join(env.config, "mozilla", "native-messaging-hosts")]
    if browser == "zen":
        return moz + [os.path.join(env.home, ".zen", "native-messaging-hosts"),
                      os.path.join(env.config, "zen", "native-messaging-hosts")]
    if browser == "librewolf":
        return [os.path.join(env.home, ".librewolf", "native-messaging-hosts"),
                os.path.join(env.config, "librewolf", "native-messaging-hosts")]
    return moz


def target_dirs(browser: str, env: Env) -> list[str]:
    """Where register writes for `browser`: the directories it reads, limited to a browser
    that has been run as this user (its profile directory exists)."""
    b = BROWSERS[browser]
    home, cfg = env.home, env.config
    if b.kind == "chromium":
        base = os.path.join(cfg, _CHROMIUM_DIRS[browser])
        out = [os.path.join(base, "NativeMessagingHosts")] if os.path.isdir(base) else []
    elif browser == "firefox":
        seen = os.path.isdir(os.path.join(home, ".mozilla")) or os.path.isdir(
            os.path.join(cfg, "mozilla"))
        out = [_mozilla_dir(env)] if seen else []
    elif browser == "zen":
        # Zen reads Firefox's directory; some Zen builds also read their own profile root.
        zen_dirs = [d for d in (os.path.join(home, ".zen"), os.path.join(cfg, "zen"))
                    if os.path.isdir(d)]
        out = [_mozilla_dir(env)] + [os.path.join(d, "native-messaging-hosts")
                                     for d in zen_dirs] if zen_dirs else []
    else:                                    # librewolf
        out = [os.path.join(d, "native-messaging-hosts")
               for d in (os.path.join(home, ".librewolf"), os.path.join(cfg, "librewolf"))
               if os.path.isdir(d)][:1]
    # ~/.config/zen is often a symlink to ~/.zen: one file, one receipt line.
    unique, real = [], set()
    for d in out:
        r = os.path.realpath(d)
        if r not in real:
            real.add(r)
            unique.append(d)
    return unique


def manifest_path(directory: str) -> str:
    return os.path.join(directory, paths.NATIVE_HOST_MANIFEST)


# --- manifest text ----------------------------------------------------------------------------

def valid_extension_id(kind: str, ext_id: str) -> bool:
    if not isinstance(ext_id, str) or len(ext_id) > 255:
        return False
    rx = _MOZ_ID_RE if kind == "mozilla" else _CHROMIUM_ID_RE
    return bool(rx.fullmatch(ext_id))


def render(kind: str, ext_ids: list[str]) -> bytes:
    ids = sorted(set(ext_ids))
    if not ids or not all(valid_extension_id(kind, i) for i in ids):
        raise ValueError("bad extension ids")
    if kind == "mozilla":
        key, allowed = "allowed_extensions", ids
    else:
        key, allowed = "allowed_origins", [f"chrome-extension://{i}/" for i in ids]
    text = (MANIFEST_TEMPLATE
            .replace("@NAME@", paths.NATIVE_HOST_NAME)
            .replace("@HOST_PATH@", HOST_PATH)
            .replace("@ALLOWED_KEY@", key)
            .replace("@ALLOWED@", json.dumps(allowed)))
    json.loads(text)                         # the template must stay valid JSON
    return text.encode("utf-8")


def _is_our_rendering(kind: str, data: bytes) -> bool:
    """True if `data` is exactly what render() produces for some set of valid ids. Lets a
    lost receipt be rebuilt for a file that is provably ours, without trusting anything else."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(doc, dict) or doc.get("name") != paths.NATIVE_HOST_NAME:
        return False
    if kind == "mozilla":
        ids = doc.get("allowed_extensions")
    else:
        origins = doc.get("allowed_origins")
        if not isinstance(origins, list):
            return False
        ids = [o[len("chrome-extension://"):-1] for o in origins
               if isinstance(o, str) and o.startswith("chrome-extension://")
               and o.endswith("/")]
        if len(ids) != len(origins):
            return False
    if not isinstance(ids, list) or not ids:
        return False
    try:
        return render(kind, ids) == data
    except ValueError:
        return False


def _ids_in(kind: str, data: bytes) -> list[str]:
    doc = json.loads(data.decode("utf-8"))
    if kind == "mozilla":
        return list(doc["allowed_extensions"])
    return [o[len("chrome-extension://"):-1] for o in doc["allowed_origins"]]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- files ------------------------------------------------------------------------------------

def _read_regular(path: str) -> bytes | None:
    """The file's bytes, None if it does not exist. Refuses symlinks and non-regular files."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOCTTY | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        if os.path.islink(path):
            raise RegisterError(f"{path} is a symlink; leaving it alone") from None
        raise RegisterError(f"cannot read {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RegisterError(f"{path} is not a regular file; leaving it alone")
        if st.st_size > 64 * 1024:
            raise RegisterError(f"{path} is unexpectedly large; leaving it alone")
        chunks = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_atomic(path: str, data: bytes, mode: int) -> None:
    d = os.path.dirname(path)
    tmp = os.path.join(d, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    os.rename(tmp, path)
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def load_receipt(env: Env) -> dict:
    """{abs manifest path: {"sha256", "kind", "registrations": [{"browser", "extension_id"}]}}"""
    data = _read_regular(env.receipt)
    if data is None:
        return {}
    try:
        doc = json.loads(data.decode("utf-8"))
        manifests = doc["manifests"]
        if doc.get("format") != RECEIPT_FORMAT or not isinstance(manifests, dict):
            raise ValueError
        for path, rec in manifests.items():
            if (not os.path.isabs(path) or not isinstance(rec.get("sha256"), str)
                    or rec.get("kind") not in ("mozilla", "chromium")
                    or not isinstance(rec.get("registrations"), list)):
                raise ValueError
        return manifests
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError):
        raise RegisterError(f"{env.receipt} is not readable; move it aside and register "
                            "again (manifests it does not list will be refused)") from None


def save_receipt(env: Env, manifests: dict) -> None:
    if not manifests:
        try:
            os.unlink(env.receipt)
        except FileNotFoundError:
            pass
        return
    os.makedirs(os.path.dirname(env.receipt), mode=0o700, exist_ok=True)
    data = json.dumps({"format": RECEIPT_FORMAT, "manifests": manifests}, indent=2,
                      sort_keys=True).encode("utf-8") + b"\n"
    _write_atomic(env.receipt, data, 0o600)


def _ours(path: str, kind: str, data: bytes, receipt: dict) -> bool:
    rec = receipt.get(path)
    if rec is not None and rec.get("sha256") == sha256(data) and rec.get("kind") == kind:
        return True
    return _is_our_rendering(kind, data)


def _registrations(path: str, kind: str, data: bytes | None, receipt: dict) -> list[dict]:
    """Who the existing, verified-ours file at `path` currently allows."""
    if data is None:
        return []
    rec = receipt.get(path)
    if rec is not None and rec.get("sha256") == sha256(data):
        regs = [r for r in rec["registrations"]
                if isinstance(r, dict) and r.get("browser") in BROWSERS
                and valid_extension_id(kind, r.get("extension_id", ""))]
        if regs:
            return regs
    # A rebuilt receipt: the file is ours but nobody recorded which browser asked for which
    # id. Keep each id, attributed to no browser in particular.
    return [{"browser": "", "extension_id": i} for i in _ids_in(kind, data)]


# --- commands ---------------------------------------------------------------------------------

def register(browser: str, ext_id: str, env: Env | None = None, out=print) -> list[str]:
    env = env or Env.current()
    if browser not in BROWSERS:
        raise RegisterError(f"unknown browser {browser!r}; one of: {', '.join(BROWSERS)}")
    kind = BROWSERS[browser].kind
    if not valid_extension_id(kind, ext_id):
        what = ("an add-on id like name@example.org or {xxxxxxxx-xxxx-...}" if kind == "mozilla"
                else "a 32-letter extension id (a-p)")
        raise RegisterError(f"{ext_id!r} is not a valid {BROWSERS[browser].title} extension "
                            f"id; expected {what}")
    if not os.path.isfile(HOST_PATH):
        raise RegisterError(f"the Pear Passwords system part is not installed ({HOST_PATH} "
                            "is missing); run the root install step first")
    dirs = target_dirs(browser, env)
    if not dirs:
        raise RegisterError(f"no {BROWSERS[browser].title} profile for this user; start the "
                            "browser once, then register again")
    receipt = load_receipt(env)

    # Check every target before writing any, so a refusal leaves nothing half done.
    plan = []
    for d in dirs:
        path = manifest_path(d)
        data = _read_regular(path)
        if data is not None and not _ours(path, kind, data, receipt):
            raise RegisterError(f"{path} exists and was not written by pear-passwords-autofill;"
                                " move it away first if you want Pear to replace it")
        # One extension id per browser: registering again replaces this browser's id. Other
        # browsers sharing the file (Firefox and Zen both read ~/.mozilla) keep theirs.
        regs = [r for r in _registrations(path, kind, data, receipt) if r["browser"] != browser]
        regs.append({"browser": browser, "extension_id": ext_id})
        regs.sort(key=lambda r: (r["browser"], r["extension_id"]))
        plan.append((d, path, regs))

    written = []
    for d, path, regs in plan:
        new = render(kind, [r["extension_id"] for r in regs])
        os.makedirs(d, mode=0o755, exist_ok=True)
        _write_atomic(path, new, 0o644)
        receipt[path] = {"sha256": sha256(new), "kind": kind, "registrations": regs}
        save_receipt(env, receipt)
        written.append(path)
        out(f"registered {ext_id} for {BROWSERS[browser].title}: {path}")
    out("Restart the browser if it was running. Then turn autofill on in the Pear window "
        "(Settings, Browser autofill): until then the daemon refuses every autofill host. "
        "Every fill still asks you in a Pear dialog.")
    return written


def unregister(browser: str | None, env: Env | None = None, out=print,
               err=None) -> tuple[list[str], list[str]]:
    """Remove `browser`'s registration (all browsers when None). Returns (removed or
    rewritten paths, kept paths)."""
    env = env or Env.current()
    err = err or (lambda m: print(m, file=sys.stderr))
    if browser is not None and browser not in BROWSERS:
        raise RegisterError(f"unknown browser {browser!r}; one of: {', '.join(BROWSERS)}")
    receipt = load_receipt(env)
    names = list(BROWSERS) if browser is None else [browser]
    allowed = {}
    for name in names:
        for d in candidate_dirs(name, env):
            allowed.setdefault(manifest_path(d), BROWSERS[name].kind)

    done, kept = [], []
    for path in sorted(receipt):
        if path not in allowed:
            continue                         # not a place this browser reads: never touched
        rec, kind = receipt[path], allowed[path]
        if rec.get("kind") != kind:
            continue
        try:
            data = _read_regular(path)
        except RegisterError as e:
            err(str(e))
            del receipt[path]
            kept.append(path)
            continue
        if data is None:
            del receipt[path]
            continue
        if sha256(data) != rec["sha256"]:
            err(f"{path} changed since it was registered; left in place")
            del receipt[path]
            kept.append(path)
            continue
        regs = [r for r in rec["registrations"]
                if browser is not None and r.get("browser") != browser]
        if regs:
            new = render(kind, [r["extension_id"] for r in regs])
            _write_atomic(path, new, 0o644)
            receipt[path] = {"sha256": sha256(new), "kind": kind, "registrations": regs}
            out(f"updated {path} (still used by "
                f"{', '.join(sorted({r['browser'] or 'another browser' for r in regs}))})")
        else:
            os.unlink(path)
            del receipt[path]
            out(f"removed {path}")
        done.append(path)
    save_receipt(env, receipt)
    if not done and not kept:
        out("nothing registered" + (f" for {BROWSERS[browser].title}" if browser else ""))
    return done, kept


def status(env: Env | None = None, out=print) -> int:
    env = env or Env.current()
    receipt = load_receipt(env)
    if not receipt:
        out("Autofill is not registered for any browser.")
    for path in sorted(receipt):
        rec = receipt[path]
        try:
            data = _read_regular(path)
        except RegisterError:
            data = b""
        state = ("missing" if data is None else
                 "ok" if sha256(data) == rec["sha256"] else "changed by someone else")
        who = ", ".join(f"{r.get('browser') or '?'}={r.get('extension_id')}"
                        for r in rec["registrations"])
        out(f"{path}: {state} ({who})")
    if not os.path.isfile(HOST_PATH):
        out(f"note: {HOST_PATH} is missing; the system part is not installed")
    out(f"Browsers: {', '.join(BROWSERS)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pear-passwords-autofill",
        description="Let one browser extension ask Pear Passwords to fill a login. Off until "
                    "you register; every fill still asks you in a Pear dialog.",
        epilog="Browsers: " + ", ".join(BROWSERS) + ".")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("register", help="allow an extension in one browser")
    r.add_argument("--browser", required=True, choices=list(BROWSERS))
    r.add_argument("--extension-id", required=True)
    u = sub.add_parser("unregister", help="remove what register wrote")
    g = u.add_mutually_exclusive_group(required=True)
    g.add_argument("--browser", choices=list(BROWSERS))
    g.add_argument("--all", action="store_true")
    sub.add_parser("status", help="show what is registered")
    args = ap.parse_args(argv)

    if os.getuid() == 0:
        print("pear-passwords-autofill: run this as yourself, not as root", file=sys.stderr)
        return 1
    try:
        if args.cmd == "register":
            register(args.browser, args.extension_id)
            return 0
        if args.cmd == "unregister":
            _, kept = unregister(None if args.all else args.browser)
            return 1 if kept else 0
        return status()
    except RegisterError as e:
        print(f"pear-passwords-autofill: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"pear-passwords-autofill: {e.filename or ''}: {e.strerror}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
