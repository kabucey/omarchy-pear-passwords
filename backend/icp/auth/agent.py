"""Key agent: holds the derived master key in memory and forgets it after an idle timeout.

Lives on a unix socket under $XDG_RUNTIME_DIR, which is already 0700, so only your own user can
reach it. That is also the honest limit of this design: while unlocked, anything running as you
can ask for the key, exactly as anything running as you can scrape an unlocked Bitwarden. The
timeout is what bounds the window. Only used once a passphrase is set.

Auto-spawns on first use; no systemd unit to install.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

from . import lockbox
from ..errors import AppleError

DEFAULT_TIMEOUT = 900  # seconds of idleness before the key is dropped


class AgentError(AppleError):
    pass


def _timeout() -> int:
    try:
        return max(0, int(os.environ.get("ICP_LOCK_TIMEOUT", DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def socket_path() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    d = os.path.join(base, "icp")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    return os.path.join(d, "agent.sock")


# --------------------------------------------------------------------------- server


def _serve() -> int:
    path = socket_path()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(8)
    srv.settimeout(60)

    key = None          # bytearray so it can be wiped; bytes are immutable
    expires = 0.0

    def wipe():
        nonlocal key, expires
        if key is not None:
            for i in range(len(key)):
                key[i] = 0
        key, expires = None, 0.0

    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            if key is not None and time.monotonic() >= expires:
                wipe()
            continue
        with conn:
            conn.settimeout(30)
            try:
                line = conn.makefile("rb").readline().decode("utf-8", "replace").rstrip("\n")
            except OSError:
                continue
            cmd, _, arg = line.partition(" ")

            if key is not None and time.monotonic() >= expires:
                wipe()

            if cmd == "GET":
                if key is None:
                    conn.sendall(b"LOCKED\n")
                else:
                    expires = time.monotonic() + _timeout()  # idle timeout, so refresh on use
                    conn.sendall(b"OK " + bytes(key).hex().encode() + b"\n")
            elif cmd == "UNLOCK":
                try:
                    key = bytearray(lockbox.unlock(arg))
                    expires = time.monotonic() + _timeout()
                    conn.sendall(b"OK\n")
                except lockbox.WrongPassphrase:
                    conn.sendall(b"ERR wrong passphrase\n")
                except AppleError as e:
                    conn.sendall(b"ERR " + str(e).replace("\n", " ").encode() + b"\n")
            elif cmd == "UNLOCK_KEY":
                # Pass a freshly derived key from the migration process without publishing
                # the staged KDF files first.  The socket is 0600 inside a 0700 runtime
                # directory; the key is never written to disk and is held only by the agent.
                try:
                    candidate = bytes.fromhex(arg)
                    if len(candidate) != lockbox._KEY_SIZE:
                        raise ValueError("invalid key length")
                    key = bytearray(candidate)
                    expires = time.monotonic() + _timeout()
                    conn.sendall(b"OK\n")
                except (ValueError, TypeError):
                    conn.sendall(b"ERR invalid derived key\n")
            elif cmd == "LOCK":
                wipe()
                conn.sendall(b"OK\n")
            elif cmd == "STATUS":
                if key is None:
                    conn.sendall(b"locked\n")
                else:
                    conn.sendall(f"unlocked {int(expires - time.monotonic())}\n".encode())
            elif cmd == "QUIT":
                conn.sendall(b"OK\n")
                wipe()
                return 0
            else:
                conn.sendall(b"ERR unknown command\n")


# --------------------------------------------------------------------------- client


def _request(line: str, autostart: bool = True) -> str:
    path = socket_path()
    try:
        return _send(path, line)
    except (FileNotFoundError, ConnectionRefusedError):
        if not autostart:
            raise AgentError("agent not running")
        _spawn()
        return _send(path, line)


def _send(path: str, line: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path)
        s.sendall(line.encode("utf-8") + b"\n")
        return s.makefile("rb").readline().decode("utf-8", "replace").rstrip("\n")


def _spawn() -> None:
    subprocess.Popen(
        [sys.executable, "-m", "icp.auth.agent", "--serve"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    path = socket_path()
    for _ in range(100):  # up to ~5s for the socket to appear
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise AgentError("key agent did not start")


def get_key() -> bytes | None:
    """The cached key, or None if the agent is locked."""
    resp = _request("GET")
    if resp.startswith("OK "):
        return bytes.fromhex(resp[3:])
    return None


def unlock(passphrase: str) -> None:
    resp = _request("UNLOCK " + passphrase)
    if resp != "OK":
        raise AgentError(resp.removeprefix("ERR ") or "unlock failed")


def unlock_key(key: bytes) -> None:
    """Install an already-derived key for an atomic passphrase migration.

    The migration stages the new KDF parameters until all ciphertext is ready, so the normal
    passphrase command cannot derive through the still-active old parameters.  This transport
    is local-only and transient: the key is sent over the private agent socket and retained only
    in the agent's memory.
    """
    raw = bytes(key)
    if len(raw) != lockbox._KEY_SIZE:
        raise AgentError("invalid derived key")
    resp = _request("UNLOCK_KEY " + raw.hex())
    if resp != "OK":
        raise AgentError(resp.removeprefix("ERR ") or "unlock failed")


def lock() -> None:
    try:
        _request("LOCK", autostart=False)
    except (AgentError, OSError):
        pass  # not running == already locked


def lock_strict() -> None:
    """Invalidate the runtime key, surfacing failures instead of swallowing them.

    Rollback code must not restore old ciphertext while a newly derived key is still reachable
    from this process's agent.  A missing agent is already inaccessible and is therefore safe;
    every other failure is fatal to rollback.
    """
    try:
        resp = _request("LOCK", autostart=False)
    except AgentError as e:
        if str(e) == "agent not running":
            return
        raise
    except OSError as e:
        raise AgentError("could not invalidate the key agent") from e
    if resp != "OK":
        raise AgentError(resp.removeprefix("ERR ") or "could not invalidate the key agent")


def status() -> str:
    try:
        return _request("STATUS", autostart=False)
    except (AgentError, OSError):
        return "locked"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--serve" in argv:
        return _serve()
    print(status())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
