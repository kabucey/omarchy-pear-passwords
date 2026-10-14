"""pear-migrate: the one-time move of a 1.x vault into the daemon, and the later purge of the
old copy. Spec section 10 steps 4, 5 and 7; docs/protocol.md sections 8 and 10.2.

Started by the Pear window as `pear-exec migrate`, with the ticket on stdin and the window
reading this process's stdout (one JSON object per line). The ticket's purpose, given back by
the daemon at hello, decides what happens:

import
  1. Read ~/.config/icp safely (O_NOFOLLOW everywhere, owned by you, regular files under
     4 MiB) and stream the eight v1 files to the daemon, which converts them.
  2. Get the old key, with no prompt of Pear's own:
     - a passphrase vault (kdf.json + check.enc): PEEK the 1.3.2 agent, which answers only
       inside the grace window of a recent unlock and never prompts (never GET: that is the
       command that can put a legacy dialog on screen);
     - then, for either kind, the key 1.x kept in your login keyring: the Secret Service items
       {application: icp, type: master-key | lockbox-key}, read over D-Bus from an unlocked
       collection. 1.x's default vault (no passphrase) is keyed by exactly that item. The
       daemon checks every candidate against check.enc, or against vault.enc itself when
       there is no check.enc;
     - a keyring vault whose keyring is locked: the window says the keyring is locked and to
       unlock it the way the user usually does, and offers "Check again", which only reads
       again. Pear never asks the keyring to unlock (no Service.Unlock, no Prompt): that
       would be a second password dialog, and the one-time old passphrase in the window is
       the only password Pear asks for besides polkit;
     - a passphrase vault with neither: the window asks for the old passphrase, once (the one
       in-window exception); it goes to the daemon in memory, which runs Argon2id itself.
  3. import-commit. Only after the daemon has verified the converted store against counts and
     a digest does anything here change a file: the old agent is told to LOCK and QUIT, stray
     key copies are deleted, the legacy user units are stopped (over D-Bus; any that could not
     be are reported with the command to run), consented browser manifests are moved, the 1.x
     launcher and backend are removed when they are byte-for-byte what 1.x installed, and
     ~/.config/icp is renamed to ~/.config/icp.v1-backup-YYYYMMDD.
  It never registers the new autofill host; the window shows the command for that instead.

purge
  Delete the files the daemon recorded at import, from the backup directory it recorded, and
  only those whose sha256 still matches. Anything else is kept and listed.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import pwd
import re
import socket
import stat
import struct
import sys

from ..daemon import paths, protocol
from ..dbus_safe import call_blocking
from .channel import Channel, ChannelError, runtime_dir, stdin_line

TICKET_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
BACKUP_RE = re.compile(r"^icp\.v1-backup-[0-9]{8}(-[0-9]{1,3})?$")

# The 1.x units that could run the old code (and pop zenity) once the vault has moved. Always
# stopped and disabled, no opt-out (spec section 9).
LEGACY_UNITS = ("icp-host.service", "icp-sync.timer", "icp-sync.service",
                "pear-passwords-sync.timer", "pear-passwords-sync.service")

# Stray copies of the old key that 1.x versions could leave beside the vault.
LEGACY_KEY_FILES = ("vault.key", "master.key")
SECRET_SERVICE_ITEMS = ({"application": "icp", "type": "master-key"},
                        {"application": "icp", "type": "lockbox-key"})

# The old native-messaging host. A manifest is moved only if it is exactly this (any
# description); anything else is listed and left alone. ~/icp itself is never touched.
LEGACY_MANIFEST_DIRS = (("firefox", ".mozilla/native-messaging-hosts"),
                        ("zen", ".zen/native-messaging-hosts"),
                        ("zen-config", ".config/zen/native-messaging-hosts"))
LEGACY_EXTENSION_ID = "{5ad01040-3351-492c-9a42-1d56b881da78}"
MANIFESTS_SUBDIR = "legacy-browser-manifests"

# The 1.x launcher, retired once the vault has moved: it would start 1.3.2's first-run
# sign-in (its own passphrase prompts) against a ~/.config/icp that is no longer there. Removed
# only when it is byte-for-byte a released copy, with the user's data directory written as
# @DATA@ (system/lib/user-files.sh holds the same list; a test keeps them equal).
LAUNCHER_1X = ".local/share/applications/pear-passwords.desktop"
DATA_1X = ".local/share/pear-passwords"
RELEASED_LAUNCHER_SHA256 = frozenset({
    "720986736414f5ffc6ae8119650ce72bb85ebdba0c0814ed07514d92952cac53",
    "500f1ad818d777801e2d7929dc8aa90d454fd1faf835ebee5788b36c3554ac70",
    "9fea786026bfbfa8c9cc3146bd93d8ddb31fcc9e73b88e26c3865fd4442d9c1a",
    "282145fd9d9d173f38c2e5a68b2e17bcfc22907d8cc5105cc1b25769a9803065",
})
DATA_1X_PARTS = ("venv", "app", "app.new", "app.old")


class MigrateError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class Out:
    """The stdout half of the pipe to the window. Never carries a key, passphrase or value."""

    def __init__(self, stream):
        self.stream = stream

    def __call__(self, **obj) -> None:
        self.stream.write(json.dumps(obj, separators=(",", ":")) + "\n")
        self.stream.flush()


# --- reading the v1 directory safely -----------------------------------------------------

def _open_own_dir(path: str) -> int:
    """O_DIRECTORY|O_NOFOLLOW: a symlink in the last component fails, and the directory must
    be ours. Raises MigrateError."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise MigrateError("no-v1", "no ~/.config/icp") from None
    except OSError as e:
        raise MigrateError("unsafe-file", f"{os.path.basename(path)}: {e.strerror}") from None
    st = os.fstat(fd)
    if st.st_uid != os.getuid():
        os.close(fd)
        raise MigrateError("unsafe-file", f"{os.path.basename(path)} is not yours")
    return fd


def _read_own_file(dfd: int, name: str, limit: int = protocol.IMPORT_FILE_MAX) -> bytes | None:
    """A regular file of ours, at most `limit` bytes, opened without following a symlink and
    without blocking on a FIFO. None if it does not exist."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOCTTY | os.O_NONBLOCK
                     | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise MigrateError("unsafe-file", f"{name}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise MigrateError("unsafe-file", f"{name} is not a regular file")
        if st.st_uid != os.getuid():
            raise MigrateError("unsafe-file", f"{name} is not yours")
        if st.st_size > limit:
            raise MigrateError("unsafe-file", f"{name} is larger than {limit} bytes")
        chunks, total = [], 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            total += len(b)
            if total > limit:
                raise MigrateError("unsafe-file", f"{name} grew while being read")
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def is_passphrase_vault(files: dict) -> bool:
    """1.x with a passphrase set wrote kdf.json and check.enc; its default mode, the key in
    the login keyring, wrote neither."""
    return "kdf.json" in files and "check.enc" in files


def read_v1(config_dir: str) -> dict[str, bytes]:
    dfd = _open_own_dir(config_dir)
    try:
        files = {}
        for name in protocol.IMPORT_FILES:
            data = _read_own_file(dfd, name)
            if data is not None:
                files[name] = data
    finally:
        os.close(dfd)
    missing = [n for n in protocol.IMPORT_REQUIRED if n not in files]
    if missing:
        raise MigrateError("no-v1", "missing " + ", ".join(missing))
    return files


# --- the 1.3.2 agent ------------------------------------------------------------------------

def _agent_socket(runtime: str) -> str | None:
    d = os.path.join(runtime, "icp")
    sock = os.path.join(d, "agent.sock")
    try:
        dst, sst = os.lstat(d), os.lstat(sock)
    except OSError:
        return None
    uid = os.getuid()
    if (not stat.S_ISDIR(dst.st_mode) or dst.st_uid != uid
            or not stat.S_ISSOCK(sst.st_mode) or sst.st_uid != uid):
        return None
    return sock


def agent_command(runtime: str, command: str, timeout: float = 5.0) -> bytes | None:
    """One line to the old agent, one line back. Never starts an agent. The only commands
    sent are PEEK (before the import) and LOCK and QUIT (after it); never GET."""
    assert command in ("PEEK", "LOCK", "QUIT")
    path = _agent_socket(runtime)
    if path is None:
        return None
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    s.settimeout(timeout)
    try:
        s.connect(path)
        creds = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        if struct.unpack("3i", creds)[1] != os.getuid():
            return None
        s.sendall(command.encode() + b"\n")
        buf = bytearray()
        while not buf.endswith(b"\n") and len(buf) < 4096:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return bytes(buf).rstrip(b"\n")
    except OSError:
        return None
    finally:
        s.close()


def peek_key(runtime: str) -> bytearray | None:
    """The v1 key if the 1.3.2 agent holds it inside its grace window, else None."""
    reply = agent_command(runtime, "PEEK")
    if not reply or not reply.startswith(b"OK "):
        return None
    try:
        key = bytearray(bytes.fromhex(reply[3:].decode("ascii")))
    except (ValueError, UnicodeDecodeError):
        return None
    return key if len(key) == 32 else None


# --- the 1.x key in the login keyring (Secret Service) ---------------------------------------

SECRETS_BUS = "org.freedesktop.secrets"
_KEY_BYTES = 32


def decode_v1_key(stored) -> bytearray | None:
    """1.x stored the key base64 (or, in its first releases, raw). None for anything else."""
    raw = bytes(stored or b"")
    if len(raw) == _KEY_BYTES:
        return bytearray(raw)
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (ValueError, TypeError):
        return None
    return bytearray(key) if len(key) == _KEY_BYTES else None


class SecretServiceKeyring:
    """Reads the 1.x key items from the Secret Service over the session bus (jeepney, which
    reads DBUS_SESSION_BUS_ADDRESS itself; pear-exec has checked it is the user's own bus).

    keys() never unlocks anything and never shows a prompt: it reads only unlocked items, and
    reports whether locked ones exist. There is deliberately no unlock: Service.Unlock would
    put up the keyring's own password dialog, a password prompt outside the window that Pear
    started (requirement 2 allows only polkit and the one-time old passphrase). The service
    is never started by us: if it is not running there is simply no key."""

    def __init__(self, open_bus=None):
        self._open_bus = open_bus

    def _connect(self):
        if self._open_bus is not None:
            return self._open_bus()
        from jeepney.io.blocking import open_dbus_connection
        return open_dbus_connection(bus="SESSION")

    @staticmethod
    def _call(conn, path, iface, method, sig=None, body=(), timeout=10.0):
        from jeepney import DBusAddress, HeaderFields, MessageType, new_method_call
        bus = "org.freedesktop.DBus" if iface == "org.freedesktop.DBus" else SECRETS_BUS
        addr = DBusAddress(path, bus_name=bus, interface=iface)
        reply = call_blocking(conn, new_method_call(addr, method, sig, body),
                                        timeout=timeout)
        if reply.header.message_type == MessageType.error:
            raise RuntimeError(str(reply.header.fields.get(HeaderFields.error_name, "error")))
        return reply.body

    def _running(self, conn) -> bool:
        body = self._call(conn, "/org/freedesktop/DBus", "org.freedesktop.DBus",
                          "NameHasOwner", "s", (SECRETS_BUS,))
        return bool(body and body[0])

    def _search(self, conn) -> tuple[list[str], list[str]]:
        unlocked, locked = [], []
        for attrs in SECRET_SERVICE_ITEMS:
            body = self._call(conn, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service",
                              "SearchItems", "a{ss}", (attrs,))
            if len(body) == 2:
                unlocked += [p for p in body[0] if p not in unlocked]
                locked += [p for p in body[1] if p not in locked]
        return unlocked, locked

    def keys(self) -> tuple[list[bytearray], bool]:
        """(candidate keys from unlocked items, whether a locked item exists)."""
        try:
            conn = self._connect()
        except Exception:
            return [], False
        keys: list[bytearray] = []
        try:
            if not self._running(conn):
                return [], False
            unlocked, locked = self._search(conn)
            if unlocked:
                _, session = self._call(conn, "/org/freedesktop/secrets",
                                        "org.freedesktop.Secret.Service", "OpenSession", "sv",
                                        ("plain", ("s", "")))
                try:
                    body = self._call(conn, "/org/freedesktop/secrets",
                                      "org.freedesktop.Secret.Service", "GetSecrets", "aoo",
                                      (unlocked, session))
                    secrets_ = body[0] if body else {}
                    for path in unlocked:
                        value = secrets_.get(path)
                        key = decode_v1_key(value[2]) if value and len(value) >= 3 else None
                        if key is not None:
                            keys.append(key)
                    secrets_ = None
                finally:
                    try:
                        self._call(conn, session, "org.freedesktop.Secret.Session", "Close")
                    except Exception:
                        pass
            return keys, bool(locked)
        except Exception:
            return keys, False
        finally:
            try:
                conn.close()
            except Exception:
                pass


def _try_keyring(daemon: "Channel", keyring) -> tuple[bool, bool]:
    """Send every candidate key from the keyring; (accepted, locked items exist)."""
    keys, locked = keyring.keys()
    accepted = False
    try:
        for key in keys:
            if not accepted and _send_key(daemon,
                                          key_b64=base64.b64encode(bytes(key)).decode("ascii")):
                accepted = True
    finally:
        for key in keys:
            key[:] = bytes(len(key))
    return accepted, locked


# --- cleanup after a verified import --------------------------------------------------------

def _unlink_own(dfd: int | None, path: str) -> bool:
    try:
        st = os.lstat(path, dir_fd=dfd)
    except OSError:
        return False
    if st.st_uid != os.getuid() or stat.S_ISDIR(st.st_mode):
        return False
    try:
        os.unlink(path, dir_fd=dfd)
        return True
    except OSError:
        return False


def retire_agent(runtime: str) -> None:
    agent_command(runtime, "LOCK")
    agent_command(runtime, "QUIT")
    for name in ("app-session.json", "agent.sock"):
        _unlink_own(None, os.path.join(runtime, "icp", name))


def purge_secret_service() -> int:
    """Delete the 1.x master-key and lockbox-key items from the Secret Service, if it is
    running and its collection is unlocked. Never unlocks anything and never completes a
    prompt, so nothing can appear on screen. Returns how many items went."""
    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return 0
    removed = 0
    try:
        conn = open_dbus_connection(bus="SESSION")
    except Exception:
        return 0
    try:
        bus = DBusAddress("/org/freedesktop/DBus", bus_name="org.freedesktop.DBus",
                          interface="org.freedesktop.DBus")
        has = call_blocking(conn, new_method_call(bus, "NameHasOwner", "s",
                                                      ("org.freedesktop.secrets",)), timeout=5)
        if not has.body or not has.body[0]:
            return 0                       # not running; do not activate it
        service = DBusAddress("/org/freedesktop/secrets", bus_name="org.freedesktop.secrets",
                              interface="org.freedesktop.Secret.Service")
        for attrs in SECRET_SERVICE_ITEMS:
            reply = call_blocking(conn, new_method_call(service, "SearchItems", "a{ss}",
                                                            (attrs,)), timeout=5)
            if len(reply.body) != 2:
                continue
            unlocked = reply.body[0]
            for path in unlocked:
                item = DBusAddress(path, bus_name="org.freedesktop.secrets",
                                   interface="org.freedesktop.Secret.Item")
                r = call_blocking(conn, new_method_call(item, "Delete"), timeout=5)
                # A returned prompt path other than "/" means the keyring wants to ask; we
                # never complete it, so that item simply stays.
                if r.body and r.body[0] == "/":
                    removed += 1
    except Exception:
        pass
    finally:
        conn.close()
    return removed


def stop_legacy_units(open_bus=None) -> tuple[list[str], list[str]]:
    """Disable and stop each legacy unit through the systemd user manager over D-Bus.

    Not `systemctl --user`: this process runs set-gid (AT_SECURE), and libsystemd reads
    DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR with secure_getenv, so systemctl cannot find
    the user bus here at all. Python reads its environment directly; pear-exec has already
    checked the bus address is unix:path=$XDG_RUNTIME_DIR/bus.

    Returns (stopped, not_stopped): a unit with no unit file is neither; one that exists and
    could not be disabled or stopped is not_stopped, and the window shows the command for it."""
    try:
        from jeepney import DBusAddress, HeaderFields, MessageType, new_method_call
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return [], list(LEGACY_UNITS)
    mgr = DBusAddress("/org/freedesktop/systemd1", bus_name="org.freedesktop.systemd1",
                      interface="org.freedesktop.systemd1.Manager")

    def call(conn, method, sig=None, body=()):
        reply = call_blocking(conn, new_method_call(mgr, method, sig, body), timeout=30)
        if reply.header.message_type == MessageType.error:
            raise RuntimeError(str(reply.header.fields.get(HeaderFields.error_name, "error")))
        return reply.body
    try:
        conn = (open_bus or (lambda: open_dbus_connection(bus="SESSION")))()
    except Exception:
        return [], list(LEGACY_UNITS)
    stopped, failed = [], []
    try:
        present = []
        for unit in LEGACY_UNITS:
            try:
                call(conn, "GetUnitFileState", "s", (unit,))
            except RuntimeError as e:
                if any(k in str(e) for k in ("NoSuchUnit", "FileNotFound", "NoSuchFile")):
                    continue                      # no such unit file: nothing to stop
                failed.append(unit)
                continue
            except Exception:
                failed.append(unit)
                continue
            present.append(unit)
        if present:
            try:
                call(conn, "DisableUnitFiles", "asb", (present, False))
            except Exception:
                failed.extend(present)
                present = []
        for unit in present:
            try:
                call(conn, "StopUnit", "ss", (unit, "replace"))
                stopped.append(unit)
            except RuntimeError as e:
                if "NoSuchUnit" in str(e):         # disabled and not loaded: nothing ran
                    stopped.append(unit)
                else:
                    failed.append(unit)
            except Exception:
                failed.append(unit)
        try:
            call(conn, "Reload")
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return stopped, failed


def launcher_sha(data: bytes, home: str) -> str:
    return hashlib.sha256(data.replace(os.path.join(home, DATA_1X).encode(), b"@DATA@")).hexdigest()


def retire_1x_app(home: str, desktop_file: str = paths.DESKTOP_FILE) -> list[str]:
    """After a verified import, with the 2.0 launcher installed: remove the 1.x launcher if it
    is a released copy, and 1.x's backend and window copy. Returns what was removed."""
    removed = []
    if not os.path.exists(desktop_file):
        return removed
    path = os.path.join(home, LAUNCHER_1X)
    try:
        dfd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                      | os.O_CLOEXEC)
    except OSError:
        dfd = None
    if dfd is not None:
        try:
            data = _read_own_file(dfd, os.path.basename(path), 64 * 1024)
            if data is not None and launcher_sha(data, home) in RELEASED_LAUNCHER_SHA256 \
                    and _unlink_own(dfd, os.path.basename(path)):
                removed.append(path)
        except MigrateError:
            pass
        finally:
            os.close(dfd)
    data_dir = os.path.join(home, DATA_1X)
    try:
        st = os.lstat(data_dir)
    except OSError:
        return removed
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        return removed
    import shutil
    for part in DATA_1X_PARTS:
        p = os.path.join(data_dir, part)
        try:
            pst = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISDIR(pst.st_mode) and pst.st_uid == os.getuid():
            shutil.rmtree(p, ignore_errors=True)
            if not os.path.lexists(p):
                removed.append(p)
    try:
        os.rmdir(data_dir)
    except OSError:
        pass
    return removed


def legacy_manifest_matches(data: bytes, home: str) -> bool:
    try:
        m = json.loads(data)
    except ValueError:
        return False
    if not isinstance(m, dict) or not set(m) <= {"name", "description", "path", "type",
                                                  "allowed_extensions"}:
        return False
    return (m.get("name") == "org.icp.native"
            and m.get("path") == os.path.join(home, "icp/host/icp-host.sh")
            and m.get("type") == "stdio"
            and m.get("allowed_extensions") == [LEGACY_EXTENSION_ID])


def move_legacy_manifests(home: str, backup_dir: str | None,
                          consent: bool) -> tuple[list[str], bool]:
    """Move content-matched org.icp.native.json files into the backup, with consent. Returns
    the manifests left in place (all of them without consent), as paths, and whether any of
    them was the 1.x extension's (so the window can show the register command with its id).
    Nothing is registered for the new host either way."""
    kept = []
    seen_legacy = False
    for label, rel in LEGACY_MANIFEST_DIRS:
        d = os.path.join(home, rel)
        path = os.path.join(d, paths.LEGACY_NATIVE_HOST_MANIFEST)
        try:
            dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            try:
                data = _read_own_file(dfd, paths.LEGACY_NATIVE_HOST_MANIFEST, 64 * 1024)
            except MigrateError:
                kept.append(path)
                continue
            if data is None:
                continue
            matches = legacy_manifest_matches(data, home)
            seen_legacy = seen_legacy or matches
            if not consent or backup_dir is None or not matches:
                kept.append(path)
                continue
            dest_dir = os.path.join(backup_dir, MANIFESTS_SUBDIR)
            try:
                os.makedirs(dest_dir, mode=0o700, exist_ok=True)
                dest = os.path.join(dest_dir, f"{label}-{paths.LEGACY_NATIVE_HOST_MANIFEST}")
                if os.path.lexists(dest):
                    kept.append(path)
                    continue
                os.rename(paths.LEGACY_NATIVE_HOST_MANIFEST, dest, src_dir_fd=dfd)
            except OSError:
                kept.append(path)
        finally:
            os.close(dfd)
    return kept, seen_legacy


def choose_backup_dir(home: str, today: datetime.date | None = None) -> str:
    base = os.path.join(home, ".config",
                        "icp.v1-backup-" + (today or datetime.date.today()).strftime("%Y%m%d"))
    if not os.path.lexists(base):
        return base
    for n in range(2, 1000):
        cand = f"{base}-{n}"
        if not os.path.lexists(cand):
            return cand
    raise MigrateError("daemon", "no free backup directory name")


# --- the two jobs ----------------------------------------------------------------------------

def _send_file(daemon: Channel, name: str, data: bytes) -> None:
    want = hashlib.sha256(data).hexdigest()
    step = protocol.IMPORT_CHUNK_MAX
    chunks = [data[i:i + step] for i in range(0, len(data), step)] or [b""]
    for seq, chunk in enumerate(chunks):
        eof = seq == len(chunks) - 1
        reply = daemon.request("import-file", name=name, seq=seq, eof=eof,
                               b64=base64.b64encode(chunk).decode("ascii"))
        if "error" in reply:
            raise MigrateError("daemon", f"{name}: {reply['error']}")
        if eof and reply.get("sha256") != want:
            raise MigrateError("daemon", f"{name} arrived damaged")


def _send_key(daemon: Channel, **field) -> bool:
    """True if the daemon accepted the key; False for wrong-passphrase."""
    reply = daemon.request("import-key", timeout=120, **field)
    if reply.get("error") == "wrong-passphrase":
        return False
    if "error" in reply:
        raise MigrateError("daemon", f"import-key: {reply['error']}")
    return True


def do_import(daemon: Channel, stdin, out: Out, home: str, runtime: str,
              stop_units=None, secret_service=None, retire_app=None, keyring=None) -> int:
    try:
        opts = json.loads(stdin_line(stdin) or "{}")
    except ValueError:
        opts = {}
    consent = isinstance(opts, dict) and opts.get("move_manifests") is True
    config_dir = os.path.join(home, ".config", "icp")

    out(stage="reading")
    files = read_v1(config_dir)
    passphrase_vault = is_passphrase_vault(files)
    for name in protocol.IMPORT_FILES:
        if name in files:
            _send_file(daemon, name, files[name])
    files.clear()

    accepted = False
    if passphrase_vault:
        out(stage="peek")
        key = peek_key(runtime)
        if key is not None:
            try:
                accepted = _send_key(daemon,
                                     key_b64=base64.b64encode(bytes(key)).decode("ascii"))
            finally:
                for i in range(len(key)):
                    key[i] = 0
    keyring = keyring or SecretServiceKeyring()
    locked = False
    if not accepted:
        out(stage="keyring")
        accepted, locked = _try_keyring(daemon, keyring)
    asked = False
    while not accepted and not passphrase_vault:
        # 1.x's default vault: its key is only in the login keyring. No passphrase exists.
        if not locked:
            raise MigrateError("no-key", "the 1.x vault's key is not in your login keyring")
        # Locked: the user unlocks it the way they usually do, outside Pear, and clicks
        # "Check again". Nothing here asks the keyring to unlock or shows a prompt.
        out(need="keyring-locked", retry=asked)
        try:
            line = stdin_line(stdin)
            msg = json.loads(line) if line is not None else {"cancel": True}
        except ValueError:
            msg = {"cancel": True}
        if not isinstance(msg, dict) or msg.get("check_keyring") is not True:
            return 4                      # the window cancelled; nothing has changed
        asked = True
        accepted, locked = _try_keyring(daemon, keyring)
    retry = False
    while not accepted:
        out(need="passphrase", retry=retry)
        try:
            line = stdin_line(stdin)
            msg = json.loads(line) if line is not None else {"cancel": True}
        except ValueError:
            msg = {"cancel": True}
        if not isinstance(msg, dict) or msg.get("cancel") or not isinstance(
                msg.get("passphrase"), str):
            return 4                      # the window cancelled; nothing has changed
        accepted = _send_key(daemon, passphrase=msg.pop("passphrase"))
        del msg
        retry = True

    out(stage="converting")
    backup_dir = choose_backup_dir(home)
    reply = daemon.request("import-commit", timeout=600, backup_dir=backup_dir)
    if reply.get("error") in ("mismatch", "incomplete"):
        raise MigrateError("mismatch" if reply["error"] == "mismatch" else "daemon",
                           reply["error"])
    if "error" in reply:
        raise MigrateError("daemon", f"import-commit: {reply['error']}")
    counts, digest = reply.get("counts", {}), reply.get("digest", "")

    # Verified. Only now does anything of the old install change.
    out(stage="cleanup")
    retire_agent(runtime)
    try:
        dfd = _open_own_dir(config_dir)
        try:
            for name in LEGACY_KEY_FILES:
                _unlink_own(dfd, name)
        finally:
            os.close(dfd)
    except MigrateError:
        pass
    (secret_service or purge_secret_service)()
    units_stopped, units_not_stopped = (stop_units or stop_legacy_units)()
    renamed = None
    try:
        os.rename(config_dir, backup_dir)
        os.chmod(backup_dir, 0o700)
        renamed = backup_dir
    except OSError as e:
        out(error="daemon", detail=f"imported, but ~/.config/icp could not be renamed "
                                   f"({e.strerror})")
    kept, seen_legacy = move_legacy_manifests(home, renamed, consent)
    retired = (retire_app or retire_1x_app)(home) if renamed else []
    extra = {"extension_id": LEGACY_EXTENSION_ID} if seen_legacy else {}
    out(done=True, counts=counts, digest=digest, backup_dir=renamed or config_dir,
        kept_manifests=kept, units_stopped=units_stopped,
        units_not_stopped=units_not_stopped, retired_1x=retired, **extra)
    return 0


def _purge_dir_ok(home: str, d: str) -> bool:
    if not isinstance(d, str) or not d.startswith("/"):
        return False
    parent, base = os.path.split(os.path.normpath(d))
    return parent == os.path.join(home, ".config") and bool(BACKUP_RE.match(base))


def do_purge(daemon: Channel, hello: dict, out: Out, home: str) -> int:
    out(stage="purging")
    d = hello.get("dir")
    files = hello.get("files")
    if not _purge_dir_ok(home, d) or not isinstance(files, list):
        raise MigrateError("unsafe-file", "the recorded backup directory is not one Pear made")
    removed, kept = [], []
    try:
        dfd = _open_own_dir(d)
    except MigrateError as e:
        if e.code == "no-v1":            # already gone entirely
            removed = [f.get("name") for f in files if isinstance(f, dict)]
            daemon.request("purge-result", removed=removed, kept=[])
            out(done=True, removed=removed, kept=[])
            return 0
        raise
    try:
        for f in files:
            name = f.get("name") if isinstance(f, dict) else None
            want = f.get("sha256") if isinstance(f, dict) else None
            if name not in protocol.IMPORT_FILES or not isinstance(want, str):
                continue
            try:
                data = _read_own_file(dfd, name)
            except MigrateError:
                kept.append(name)
                continue
            if data is None:
                removed.append(name)
                continue
            if hashlib.sha256(data).hexdigest() != want.lower():
                kept.append(name)
                continue
            try:
                os.unlink(name, dir_fd=dfd)
                removed.append(name)
            except OSError:
                kept.append(name)
    finally:
        os.close(dfd)
    try:
        os.rmdir(d)                       # only succeeds if nothing else was in it
    except OSError:
        pass
    daemon.request("purge-result", removed=removed, kept=kept)
    out(done=True, removed=removed, kept=kept)
    return 0


def run(stdin, stdout, socket_path: str, home: str, runtime: str,
        stop_units=None, secret_service=None, retire_app=None, keyring=None) -> int:
    out = Out(stdout)
    try:
        ticket = stdin_line(stdin, 256)
    except ValueError:
        ticket = None
    if not ticket or not TICKET_RE.match(ticket):
        out(error="daemon", detail="no ticket")
        return 2
    try:
        daemon = Channel.connect(socket_path)
        hello = daemon.hello("migrate", ticket)
    except ChannelError as e:
        out(error="daemon", detail=str(e))
        return 3
    try:
        if hello.get("purpose") == "import":
            return do_import(daemon, stdin, out, home, runtime, stop_units, secret_service,
                             retire_app, keyring)
        if hello.get("purpose") == "purge":
            return do_purge(daemon, hello, out, home)
        out(error="daemon", detail="unknown purpose")
        return 1
    except MigrateError as e:
        out(error=e.code, detail=e.detail)
        return 1
    except ChannelError as e:
        out(error="daemon", detail=str(e))
        return 1
    finally:
        daemon.close()


def main() -> int:
    home = pwd.getpwuid(os.getuid()).pw_dir
    return run(sys.stdin, sys.stdout, paths.SOCKET_PATH, home, runtime_dir())


if __name__ == "__main__":
    raise SystemExit(main())
