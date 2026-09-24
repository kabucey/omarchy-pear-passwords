"""JSON surface for the Passwords app.

The Quickshell front end is a view; every decision that matters happens here.

Two rules shape the whole file:

* A password is never handed to the UI unless a person asked to see it. Listing returns
  metadata; **copying never returns it at all** - the value goes straight to the clipboard from
  this process, so it never crosses into QML, never lands in a JS string, and never sits in the
  UI's heap waiting to be swapped out.
* One fingerprint opens the app and starts two clocks, not a grant per entry. For
  `FULL_TTL` seconds everything works; after that the app still shows what is in it but
  revealing, copying and editing ask for another scan (which restarts both clocks, for the
  whole app, not one entry). After `SESSION_TTL` the app locks completely and the backend
  stops sending names at all. Prompting per entry trained people to approve prompts without
  reading them; one scan that clearly buys two minutes does not.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import sys
import time

from .. import paths
from ..vault import history as hist, nicknames as nick
from ..vault.store import load_vault

# Two clocks, both restarted by a scan. FULL_TTL is how long the answer to "is this you?"
# is treated as still true; SESSION_TTL is how long the window may keep showing anything.
FULL_TTL = 120.0
SESSION_TTL = 300.0
_UUIDISH = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-")


# ------------------------------------------------------------------ the session
#
# Opening the app needs a fingerprint (or the system password - whichever PAM offers). Until
# then the backend withholds every name, domain and username rather than handing them to the UI
# to blur: obfuscating data that has already been sent is decoration, while data that was never
# sent cannot be read, searched, or scraped out of the window.
#
# The session is bound to the app instance - the PID of the process that runs these commands -
# so quitting and relaunching asks again. Honest scope: this is against someone at the keyboard
# or looking at the screen. Code running as this user can read the encrypted files, and while
# passphrase mode is unlocked can request the key from the private runtime agent.


def _runtime_dir() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    d = os.path.join(base, "icp")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _clipboard_owner_path() -> str:
    """The non-secret state for the one clipboard source Pear currently owns."""
    return os.path.join(_runtime_dir(), "clipboard-owner.json")


def _clipboard_owner_lock_path() -> str:
    return os.path.join(_runtime_dir(), "clipboard-owner.lock")


def _acquire_clipboard_owner_lock() -> int | None:
    """Serialize marker replacement with ownership checks and removal."""
    fd = None
    try:
        path = _clipboard_owner_lock_path()
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        os.chmod(path, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except OSError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        return None


def _release_clipboard_owner_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _process_start_time(pid: int) -> str | None:
    """Return Linux's per-process start cookie, or None if the process is gone."""
    try:
        # /proc/<pid>/stat has a parenthesised comm field, so split from its final ')'.
        with open(f"/proc/{pid}/stat") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        return fields[19]
    except (OSError, ValueError, IndexError):
        return None


def _process_name(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            command = fh.read().split(b"\0", 1)[0]
        return os.path.basename(os.fsdecode(command)) if command else None
    except OSError:
        return None


def _clipboard_owner_is_alive(state: dict) -> bool:
    """Only claim a PID if it is still the exact wl-copy process we started."""
    try:
        pid = int(state["pid"])
    except (KeyError, TypeError, ValueError):
        return False
    return (_process_start_time(pid) == str(state.get("start_time"))
            and _process_name(pid) == state.get("tool"))


def _write_clipboard_owner(token: str, pid: int, tool: str) -> bool:
    path = _clipboard_owner_path()
    tmp = f"{path}.{os.getpid()}.tmp"
    lock_fd = _acquire_clipboard_owner_lock()
    if lock_fd is None:
        return False
    try:
        start_time = _process_start_time(pid)
        if start_time is None:
            return False
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"token": token, "pid": pid, "start_time": start_time,
                       "tool": os.path.basename(tool)}, fh)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    finally:
        _release_clipboard_owner_lock(lock_fd)


def _remove_clipboard_owner_marker(path: str) -> bool:
    """Remove a marker while the caller holds the owner lock."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def _clear_clipboard_owner(token: str | None = None) -> bool:
    """Release Pear's source only; never issue wl-copy --clear against another owner.

    A timer for an older copy supplies its token, so it cannot clear a newer Pear copy. The
    expiry action omits the token and releases whichever *current* source is still verifiably
    the wl-copy process Pear launched. If another application replaced it, wl-copy is gone (or
    the PID/start cookie no longer matches) and this is a safe no-op.
    """
    path = _clipboard_owner_path()
    lock_fd = _acquire_clipboard_owner_lock()
    if lock_fd is None:
        return False
    try:
        try:
            with open(path) as fh:
                state = json.load(fh)
        except FileNotFoundError:
            return True
        except (OSError, ValueError):
            # A malformed state file cannot prove ownership. Leave it in place: a concurrent copy
            # may already have replaced it, and report failure so the UI does not silently claim
            # the cleanup succeeded.
            return False
        if not isinstance(state, dict):
            return False
        if token is not None and state.get("token") != token:
            return True
        if _clipboard_owner_is_alive(state):
            import signal
            try:
                os.kill(int(state["pid"]), signal.SIGTERM)
            except ProcessLookupError:
                pass
            except (OSError, KeyError, TypeError, ValueError):
                return False
        return _remove_clipboard_owner_marker(path)
    finally:
        _release_clipboard_owner_lock(lock_fd)


def _app_session_path() -> str:
    return os.path.join(_runtime_dir(), "app-session.json")


def _read_session() -> dict | None:
    try:
        with open(_app_session_path()) as fh:
            s = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(s, dict) or s.get("pid") != os.getppid():
        return None
    return s if s.get("expires", 0) > time.time() else None


def _write_session() -> dict:
    """Start (or restart) both clocks. Returns what the window needs to count down."""
    now = time.time()
    s = {"pid": os.getppid(), "expires": now + SESSION_TTL, "full_until": now + FULL_TTL}
    fd = os.open(_app_session_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(s, fh)
    return s


def _app_session_ok() -> bool:
    return _read_session() is not None


def _full_access() -> bool:
    """Inside the window where the last scan still counts."""
    s = _read_session()
    return bool(s and s.get("full_until", 0) > time.time())


def _session_state(s: dict | None = None) -> dict:
    s = s if s is not None else _read_session()
    if not s:
        return {"unlocked": False, "full": False, "full_until": 0, "expires": 0}
    return {"unlocked": True, "full": s.get("full_until", 0) > time.time(),
            "full_until": s.get("full_until", 0), "expires": s.get("expires", 0)}


def _locked_reply() -> int:
    json.dump({"ok": False, "locked": True, "error": "Pear Passwords is locked"}, sys.stdout)
    return 1


def _authenticate(timeout: int = 120) -> tuple[str, str]:
    """Return the authentication verdict and the mechanism that produced it.

    A refusal is a real answer and must never be routed around.  Only an unavailable or broken
    custom gate is eligible for the weaker pkexec fallback.  Keeping that distinction here
    makes opening the app and every later privileged operation obey the same rule.
    """
    from ..ui import reauth

    status = reauth.challenge_status(timeout=timeout)
    if status == "error":
        return reauth.pkexec_challenge(), "pkexec"
    return status, "polkit"


def cmd_app_auth(args) -> int:
    """Authenticate to open the app.

    polkit first (fingerprint or password, ALWAYS_CHECK). If the gate *breaks* - not if the
    person says no - fall back to pkexec so a broken gate can't lock someone out of their own
    passwords. A cancel is a normal answer, not an error, so the window can offer a retry.
    """
    import signal
    from ..ui import reauth

    # The window retries a stuck unlock by killing this process. Take the prompt down with it,
    # or the old dialog stays up beside the new one.
    def _on_term(*_):
        reauth.kill_current()
        os._exit(143)
    signal.signal(signal.SIGTERM, _on_term)

    if _app_session_ok():
        json.dump({"ok": True, "authed": True, "via": "session"}, sys.stdout)
        return 0

    status, via = _authenticate(timeout=60)
    if status != "authed":
        json.dump({"ok": True, "authed": False, "via": via, "reason": status}, sys.stdout)
        return 0

    json.dump({"ok": True, "authed": True, "via": via, **_session_state(_write_session())},
              sys.stdout)
    return 0


def cmd_app_lock_app(args) -> int:
    try:
        os.unlink(_app_session_path())
    except OSError:
        pass
    json.dump({"ok": True}, sys.stdout)
    return 0


def _elevate() -> bool:
    """True when the last scan still counts, or a fresh one is given now.

    A scan restarts both clocks for the whole app: the next action within the window does not
    ask again, whichever entry it is on."""
    if _full_access():
        return True
    status, _ = _authenticate()
    if status != "authed":
        return False
    _write_session()
    return True


# --------------------------------------------------------------------------- shaping

def _entry_id(c) -> str:
    return f"{c.domain}\x1f{c.username}"


def _display(c) -> dict:
    """Split what the row should actually show.

    The keychain's title is `domain (username)` for 81% of entries, and the row prints the
    username underneath anyway - so the parenthetical is pure duplication, and it is what
    pushes titles past the column width. Strip it. When the domain is a UUID (an entry saved
    with no website) the domain is noise, so lead with the account instead.
    """
    title = (c.title or "").strip()
    user = (c.username or "").strip()
    domain = (c.domain or "").strip()
    if user and title.endswith(f"({user})"):
        title = title[: -len(f"({user})")].strip()
    if not title or _UUIDISH.match(title):
        return {"primary": user or domain or "(untitled)", "secondary": "",
                "no_site": True}
    return {"primary": title, "secondary": user, "no_site": False}


def _public(c, names=None) -> dict:
    d = _display(c)
    eid = _entry_id(c)
    local = (names or {}).get(eid, "")
    apple = (c.apple_title or "").strip()
    # Precedence: a local nickname (this machine only, for entries Apple cannot name), then
    # the name from Apple's Passwords app, then the derived display title.
    nickname = local or apple
    # A named entry with no website of its own still has an account to show underneath -
    # _display only left the second line empty because the username was the headline.
    if d["no_site"] and nickname and c.username and not d["secondary"]:
        d["secondary"] = c.username
    return {"id": eid, "domain": c.domain, "username": c.username,
            # `primary` is what the row shows; `real_title` is what it would have shown, kept
            # so a renamed entry can still be found by its original name and shown alongside.
            "primary": nickname or d["primary"], "real_title": d["primary"],
            "nickname": nickname, "apple_title": apple,
            "synced_name": bool(apple and not local),
            "secondary": d["secondary"], "no_site": d["no_site"],
            "mdat": c.mdat, "has_totp": bool(c.totp), "aliases": list(c.aliases or ()),
            # Extra websites are shown like the primary one; notes only say they exist until
            # the entry is unlocked (app-details), since people keep recovery answers there.
            "sites": list(getattr(c, "sites", ()) or ()), "has_notes": bool(c.notes),
            # Wi-Fi passwords sync as items whose "site" is AirPort and whose account is the
            # network name. They are not websites and carry no codes or notes.
            "is_wifi": (c.domain or "") == "AirPort"}


def _find(store, entry_id: str):
    for c in store.all():
        if _entry_id(c) == entry_id:
            return c
    return None


def _is_internal(e: dict) -> bool:
    """Keychain items that exist for Apple's own services, not for a person to log in with."""
    user, domain = e["username"] or "", e["domain"] or ""
    title = e.get("real_title") or ""
    if len(user) > 60 or user.startswith("PCSBoundaryKey") or user.startswith("com.apple."):
        return True
    if re.fullmatch(r"[0-9]{6,}", user) or re.fullmatch(r"[0-9]{6,}", title):
        return True
    # HomeKit/Matter commissioning keys and the Personal Hotspot's own record: they share the
    # keychain with logins but nobody signs in with them.
    if "CHIPPlugin" in user or "CHIPPlugin" in title:
        return True
    if user.startswith("_Apple") or title.startswith("_Apple"):
        return True
    return not domain and not (e["primary"] or "")


# --------------------------------------------------------------------------- commands

def cmd_app_list(args) -> int:
    if not _app_session_ok():
        # Not even a count: the locked window draws placeholder rows of its own. Whether a
        # session exists is the one fact it gets - with none, the first screen is sign-in.
        from .. import paths
        json.dump({"ok": True, "locked": True, "entries": [],
                   "signed_in": paths.session_file().exists()}, sys.stdout)
        return 0
    names = nick.load()
    entries = [_public(c, names) for c in load_vault().all()]
    if not getattr(args, "all", False):
        entries = [e for e in entries if not _is_internal(e)]
    # Sort on what the row actually shows, not on the raw title - otherwise the UUID-named
    # entries sort into the hex range instead of next to their account name.
    entries.sort(key=lambda e: (e["primary"].lower(), e["secondary"].lower()))
    # Rows that are identical on screen get their date shown so they can be told apart.
    seen = {}
    for e in entries:
        k = (e["primary"], e["secondary"])
        seen[k] = seen.get(k, 0) + 1
    for e in entries:
        e["ambiguous"] = seen[(e["primary"], e["secondary"])] > 1
    # So the app can show a sign-in banner instead of silently serving a stale vault.
    from .. import paths
    json.dump({"ok": True, "count": len(entries), "entries": entries,
               "needs_login": paths.needs_login_file().exists(),
               "signed_in": paths.session_file().exists(), **_session_state()}, sys.stdout)
    return 0


def cmd_app_unlock(args) -> int:
    """Take one fingerprint and give the whole app full access again for FULL_TTL seconds."""
    if not _app_session_ok():
        return _locked_reply()
    if _full_access():
        json.dump({"ok": True, **_session_state()}, sys.stdout)
        return 0
    status, _ = _authenticate()
    if status != "authed":
        error = "authentication cancelled" if status == "denied" else "authentication unavailable"
        json.dump({"ok": False, "error": error}, sys.stdout)
        return 1
    json.dump({"ok": True, **_session_state(_write_session())}, sys.stdout)
    return 0


def cmd_app_lock(args) -> int:
    """End full access now, but keep the app open: the list stays readable, and the next
    reveal/copy/edit asks for a scan."""
    s = _read_session()
    if s:
        s["full_until"] = 0
        fd = os.open(_app_session_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(s, fh)
    json.dump({"ok": True, **_session_state()}, sys.stdout)
    return 0


def cmd_app_reveal(args) -> int:
    if not _app_session_ok():
        return _locked_reply()
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    json.dump({"ok": True, "id": args.id, "password": c.password, **_session_state()}, sys.stdout)
    return 0


def cmd_app_copy(args) -> int:
    """Put the password on the clipboard without ever returning it.

    The UI asks for a copy and gets back only a confirmation, so the secret never enters the
    front end at all. A foreground wl-copy child owns the selection. We retain only its PID,
    start cookie and a random token, so expiry and the detached timer can release that exact
    source without clobbering a clipboard that another application has since claimed.
    """
    if not _app_session_ok():
        return _locked_reply()
    import shutil
    import subprocess
    field = getattr(args, "field", "password")
    # Only the password is gated. Making someone scan a finger to copy their own email
    # address teaches them the prompt is noise, which is how real prompts stop being read.
    if field == "password" and not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    tool = shutil.which("wl-copy")
    if not tool:
        json.dump({"ok": False, "error": "wl-clipboard is not installed"}, sys.stdout)
        return 1
    value = {"password": c.password, "username": c.username, "domain": c.domain}.get(field)
    if not value:
        json.dump({"ok": False, "error": f"no {field} on this entry"}, sys.stdout)
        return 1
    seconds = getattr(args, "seconds", 30) if field == "password" else 0
    # Replace an earlier Pear source before starting the new one. This only signals the
    # verifiably-owned wl-copy process recorded in our runtime state.
    _clear_clipboard_owner()
    token = secrets.token_hex(16)
    try:
        owner = subprocess.Popen(
            [tool, "--foreground"], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        owner.stdin.write(value.encode())
        owner.stdin.close()
    except (OSError, BrokenPipeError):
        try:
            owner.terminate()
        except (UnboundLocalError, OSError):
            pass
        json.dump({"ok": False, "error": "could not copy to the clipboard"}, sys.stdout)
        return 1
    if owner.poll() is not None or not _write_clipboard_owner(token, owner.pid, tool):
        try:
            owner.terminate()
        except OSError:
            pass
        json.dump({"ok": False, "error": "could not keep clipboard ownership"}, sys.stdout)
        return 1
    if seconds:
        try:
            subprocess.Popen(
                [sys.executable, "-m", "icp", "app-clipboard-clear", "--token", token,
                 "--delay", str(int(seconds))],
                start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            _clear_clipboard_owner(token)
            json.dump({"ok": False, "error": "could not schedule clipboard cleanup"}, sys.stdout)
            return 1
    json.dump({"ok": True, "id": args.id, "field": field, "clears_in": seconds}, sys.stdout)
    return 0


def cmd_app_clipboard_clear(args) -> int:
    """Release the current Pear clipboard owner after an optional detached delay."""
    delay = max(0, int(getattr(args, "delay", 0) or 0))
    if delay:
        time.sleep(delay)
    return 0 if _clear_clipboard_owner(getattr(args, "token", None)) else 1


def _stdout_to_stderr():
    """Keep the JSON channel exclusively JSON while doing work that may print.

    push_* end with a sync, and sync announces "Synced N credential(s)" on stdout - so the app
    received that line followed by its JSON reply, failed to parse it, and never ran the
    completion handler: the change landed in iCloud while the window still showed the old
    value. Anything a command prints before its result goes to stderr instead.
    """
    import contextlib
    return contextlib.redirect_stdout(sys.stderr)


def _read_payload() -> str:
    """One line from stdin.

    Not `sys.stdin.read()`: that waits for EOF, and the app writes the value into a pipe it
    keeps open - so the process sat in read() forever and the rename never ran. It is also
    the right protocol shape anyway, matching jsonui's line-per-message framing. A password
    or a name has no business containing a newline.
    """
    return sys.stdin.readline().rstrip("\r\n")


def cmd_app_signin(args) -> int:
    """Run sign-in (or an interactive sync) with a GUI driving every prompt.

    This deliberately calls the same cmd_login/cmd_sync the terminal uses. Re-implementing the
    flow for the app would mean two versions of Apple's sign-in dance, and the GUI one would
    be the one that silently rots when a step changes.
    """
    from . import jsonui, ui
    frontend = jsonui.JsonFrontend()
    ui.set_frontend(frontend)
    try:
        from . import app as cli_app
        mode = getattr(args, "mode", "login")
        # A real namespace, with every default the subcommand declares.
        ns = cli_app.build_parser().parse_args([mode])
        ns.anisette = getattr(args, "anisette", None)
        if mode == "login" and getattr(args, "username", None):
            ns.username = args.username
        if mode == "sync":
            code = cli_app.cmd_sync(ns)
        else:
            code = cli_app.cmd_login(ns)
    except KeyboardInterrupt:
        frontend._send({"event": "done", "ok": False, "code": 130, "cancelled": True})
        return 130
    except Exception as e:
        frontend._send({"event": "err", "text": str(e)})
        frontend._send({"event": "done", "ok": False, "code": 1})
        return 1
    finally:
        ui.set_frontend(None)
    frontend._send({"event": "done", "ok": code == 0, "code": code})
    return code


@paths.mutation_lock
def cmd_app_set_nickname(args) -> int:
    """Rename one entry. Gated like any other edit: the name is the thing a shoulder-surfer
    reads off the list, so changing it is not a cosmetic act."""
    if not _app_session_ok():
        return _locked_reply()
    name = _read_payload()
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    cleaned = nick.clean(name)
    # Prefer Apple: a name written to the metadata record reaches every device. Only entries
    # with no metadata record (most of them) fall back to a nickname that lives here alone.
    synced = False
    try:
        from .push import push_nickname
        with _stdout_to_stderr():
            synced = push_nickname(c.domain, c.username, cleaned,
                                   anisette=getattr(args, "anisette", None))
    except Exception as e:
        json.dump({"ok": False, "error": f"could not rename in iCloud: {e}"}, sys.stdout)
        return 1
    if synced:
        # The name now comes back from Apple on every sync, so a local override would only
        # shadow it and drift.
        nick.set_for(args.id, "")
    else:
        nick.set_for(args.id, cleaned)
    json.dump({"ok": True, "id": args.id, "nickname": cleaned, "synced": synced},
              sys.stdout)
    return 0


def cmd_app_generate(args) -> int:
    """A new password in Apple's shape. Not gated: nothing in the vault is read, and a
    generated string only becomes a secret once the user decides to keep it."""
    from ..vault import generate as gen
    json.dump({"ok": True, "password": gen.generate(),
               "entropy_bits": round(gen.entropy_bits(), 1)}, sys.stdout)
    return 0


def cmd_app_totp(args) -> int:
    if not _app_session_ok():
        return _locked_reply()
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None or not c.totp:
        json.dump({"ok": False, "error": "no verification code for this entry"}, sys.stdout)
        return 1
    code, seconds = c.totp_code()
    json.dump({"ok": True, "id": args.id, "code": code, "seconds": seconds, **_session_state()}, sys.stdout)
    return 0


def cmd_app_history(args) -> int:
    if not _app_session_ok():
        return _locked_reply()
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    entries = hist.for_account(hist.load(), c.domain, c.username)
    merged = hist.merge_apple_history(entries, list(c.apple_history or ()))
    json.dump({"ok": True, "id": args.id, "current": c.password, "history": merged},
              sys.stdout)
    return 0


@paths.mutation_lock
def cmd_app_set_password(args) -> int:
    """Change one password. The new value arrives on stdin so it never lands in argv, where
    any process on the machine could read it out of /proc."""
    if not _app_session_ok():
        return _locked_reply()
    new = _read_payload()
    if not new:
        json.dump({"ok": False, "error": "no password on stdin"}, sys.stdout)
        return 1
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    old = c.password
    from .push import push_password
    try:
        with _stdout_to_stderr():
            touched = push_password(c.domain, c.username, new,
                                    anisette=getattr(args, "anisette", None))
    except Exception as e:
        json.dump({"ok": False, "error": str(e)}, sys.stdout)
        return 1
    accounts = hist.load()
    hist.record(accounts, c.domain, c.username, old=old, new=new,
                source=hist.SOURCE_LOCAL, when=time.time(), title=c.title)
    hist.save(accounts)
    json.dump({"ok": True, "id": args.id, "records_written": touched}, sys.stdout)
    return 0


# --------------------------------------------------------------------------- details

def _payload_json() -> dict:
    raw = _read_payload()
    try:
        d = json.loads(raw) if raw else {}
    except ValueError:
        d = None
    return d if isinstance(d, dict) else {}


def cmd_app_details(args) -> int:
    """The unlocked view of an entry's extras: its notes."""
    if not _app_session_ok():
        return _locked_reply()
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    json.dump({"ok": True, "id": args.id, "notes": c.notes, "sites": list(c.sites), **_session_state()}, sys.stdout)
    return 0


@paths.mutation_lock
def cmd_app_set_details(args) -> int:
    """Change one entry's extra websites and/or notes: stdin {"sites": [...], "notes": "..."}.
    Fields left out are not touched."""
    if not _app_session_ok():
        return _locked_reply()
    d = _payload_json()
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    from ..keychain import update as up
    from .push import push_details
    kw = {}
    if isinstance(d.get("sites"), list):
        kw["sites"] = [str(s) for s in d["sites"]]
    if isinstance(d.get("notes"), str):
        kw["notes"] = d["notes"]
    if not kw:
        json.dump({"ok": False, "error": "nothing to change"}, sys.stdout)
        return 1
    try:
        with _stdout_to_stderr():
            push_details(c.domain, c.username, anisette=getattr(args, "anisette", None), **kw)
    except Exception as e:
        json.dump({"ok": False, "error": str(e)}, sys.stdout)
        return 1
    json.dump({"ok": True, "id": args.id}, sys.stdout)
    return 0


def cmd_app_totp_preview(args) -> int:
    """What a pasted/scanned setup would produce, before anything is saved: stdin is the
    setup key or otpauth:// link. Reads nothing from the vault."""
    if not _app_session_ok():
        return _locked_reply()
    from .. import totp
    try:
        cfg = totp.parse_setup(_read_payload())
    except totp.SetupError as e:
        json.dump({"ok": False, "error": str(e)}, sys.stdout)
        return 1
    json.dump({"ok": True, "code": totp.code(cfg["secret"], digits=cfg["digits"],
                                             period=cfg["period"], algorithm=cfg["algorithm"]),
               "seconds": totp.seconds_remaining(cfg["period"]),
               "issuer": cfg.get("issuer", ""), "account": cfg.get("accountName", "")},
              sys.stdout)
    return 0


@paths.mutation_lock
def cmd_app_set_totp(args) -> int:
    """Pair (stdin {"setup": key-or-link}) or remove (stdin {"remove": true}) the
    verification code of one entry."""
    if not _app_session_ok():
        return _locked_reply()
    d = _payload_json()
    from .. import totp
    cfg = None
    if not d.get("remove"):
        try:
            cfg = totp.parse_setup(str(d.get("setup") or ""))
        except totp.SetupError as e:
            json.dump({"ok": False, "error": str(e)}, sys.stdout)
            return 1
    if not _elevate():
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    c = _find(load_vault(), args.id)
    if c is None:
        json.dump({"ok": False, "error": "no such entry"}, sys.stdout)
        return 1
    from .push import push_details
    try:
        with _stdout_to_stderr():
            push_details(c.domain, c.username, totp=cfg, anisette=getattr(args, "anisette", None))
    except Exception as e:
        json.dump({"ok": False, "error": str(e)}, sys.stdout)
        return 1
    json.dump({"ok": True, "id": args.id, "paired": bool(cfg)}, sys.stdout)
    return 0


def cmd_app_scan_qr(args) -> int:
    """Read a QR code off the screen: you drag a box around it (slurp), the region is grabbed
    (grim) and decoded (zbarimg). Nothing is saved; the text goes back to the window only."""
    if not _app_session_ok():
        return _locked_reply()
    import shutil
    import subprocess
    missing = [t for t in ("slurp", "grim", "zbarimg") if not shutil.which(t)]
    if missing:
        json.dump({"ok": False, "error": "needs " + ", ".join(missing)}, sys.stdout)
        return 1
    sel = subprocess.run(["slurp"], capture_output=True, text=True)
    if sel.returncode != 0 or not sel.stdout.strip():
        json.dump({"ok": False, "cancelled": True}, sys.stdout)
        return 0
    grab = subprocess.run(["grim", "-g", sel.stdout.strip(), "-"], capture_output=True)
    if grab.returncode != 0:
        json.dump({"ok": False, "error": "could not capture the screen"}, sys.stdout)
        return 1
    dec = subprocess.run(["zbarimg", "--raw", "-q", "-"], input=grab.stdout, capture_output=True)
    text = dec.stdout.decode("utf-8", "replace").strip().splitlines()
    found = next((l for l in text if l.lower().startswith("otpauth://")), text[0] if text else "")
    if not found:
        json.dump({"ok": False, "error": "no QR code found in that area"}, sys.stdout)
        return 1
    json.dump({"ok": True, "text": found}, sys.stdout)
    return 0


@paths.mutation_lock
def cmd_app_create(args) -> int:
    """Add a new entry. stdin: {"site","username","password","title","notes","sites","setup"}.
    Asks for a fresh fingerprint or password every time - there is no entry yet to hold a grant."""
    if not _app_session_ok():
        return _locked_reply()
    d = _payload_json()
    from .. import totp
    cfg = None
    if str(d.get("setup") or "").strip():
        try:
            cfg = totp.parse_setup(str(d["setup"]))
        except totp.SetupError as e:
            json.dump({"ok": False, "error": str(e)}, sys.stdout)
            return 1
    if not str(d.get("password") or ""):
        json.dump({"ok": False, "error": "a password is needed"}, sys.stdout)
        return 1
    status, _ = _authenticate()
    if status != "authed":
        json.dump({"ok": False, "error": "not authorised"}, sys.stdout)
        return 1
    from .push import create_entry
    try:
        with _stdout_to_stderr():
            create_entry(str(d.get("site") or ""), str(d.get("username") or ""),
                         str(d["password"]), title=str(d.get("title") or ""),
                         notes=str(d.get("notes") or ""),
                         sites=[str(s) for s in d.get("sites") or []], totp=cfg,
                         anisette=getattr(args, "anisette", None))
    except Exception as e:
        json.dump({"ok": False, "error": str(e)}, sys.stdout)
        return 1
    new = next((x for x in load_vault().all()
                if x.username == str(d.get("username") or "") and x.password == str(d["password"])), None)
    _write_session()                       # the scan just given also restarts the clocks
    json.dump({"ok": True, "id": _entry_id(new) if new else ""}, sys.stdout)
    return 0
