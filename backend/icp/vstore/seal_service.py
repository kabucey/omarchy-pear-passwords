"""The gate G1 fallback: root's side of `seal.SealServiceBackend`.

Only used when the VM test shows that `systemd-creds --user` cannot work for uid
pear-passwords inside the hardened unit. Then the release ships pear-passwordsd.service with
`Environment=PEAR_SEAL_BACKEND=seal-service`, and install-root.sh enables
`pear-passwords-seal.socket` (Accept=yes): each connection starts one
`pear-passwords-seal@.service` instance as root with the connection on stdin and stdout,
which runs this module once and exits. Without that line the socket is installed but never
enabled, and nothing here runs.

One request per connection, one JSON line each way:

    {"op":"encrypt"|"decrypt","name":"pear.list.u1000","b64":"..."}
    {"b64":"..."}  |  {"error":"refused"|"bad-request"|"internal","detail":"..."}

An encrypt may carry "with": "host" | "host+tpm2" (default "host"). It serves exactly one
peer: SO_PEERCRED uid `pear-passwords` (anyone else is disconnected without a reply), and
only names `pear.(list|secret).u<digits>`. It runs system-scope systemd-creds locally, where
the flags take effect: an explicit `--with-key=host` or `--with-key=host+tpm2` (never auto,
never a *-with-public-key type), no PCRs (`--tpm2-pcrs=`) and an empty `--tpm2-public-key=`
so no signed PCR policy is ever picked up. The secret travels on a pipe; it keeps nothing
between requests and logs no payload. "refused" is only ever a decrypt the tool rejected (the daemon
classifies it into tpm-missing, tpm-cleared or damaged); everything else is "internal", which
the daemon treats as transient.
"""

from __future__ import annotations

import base64
import binascii
import json
import pwd
import re
import socket
import struct
import subprocess
import sys
from typing import Callable

from ..daemon import paths as system_paths
from .seal import (SYSTEM_ALLOWED, SYSTEMD_CREDS, TIMEOUT_S, _CHILD_ENV, SealRefused,
                   _why, allowed_key_type)

NAME_RE = re.compile(r"pear\.(list|secret)\.u[0-9]{1,10}")
MAX_REQUEST = 256 * 1024            # a sealed 32-byte key is well under 4 KiB; this is slack

# (argv, stdin bytes) -> (returncode, stdout, stderr)
Runner = Callable[[list, bytes], "tuple[int, bytes, bytes]"]


WITH_KEYS = ("host", "host+tpm2")


def encrypt_argv(name: str, with_key: str = "host") -> list[str]:
    if with_key not in WITH_KEYS:
        raise ValueError(f"bad key type {with_key!r}")
    return [SYSTEMD_CREDS, "encrypt", f"--with-key={with_key}", "--tpm2-pcrs=",
            "--tpm2-public-key=", f"--name={name}", "-", "-"]


def decrypt_argv(name: str) -> list[str]:
    return [SYSTEMD_CREDS, "decrypt", f"--name={name}", "-", "-"]


def _run(argv: list, data: bytes) -> tuple[int, bytes, bytes]:
    r = subprocess.run(argv, input=bytes(data), env=_CHILD_ENV, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=TIMEOUT_S, check=False)
    return r.returncode, r.stdout, r.stderr


def handle(line: bytes, run: Runner = _run) -> dict:
    """One request line to one reply object."""
    try:
        req = json.loads(line)
    except ValueError:
        return {"error": "bad-request", "detail": "not JSON"}
    if not isinstance(req, dict) or not {"op", "name", "b64"} <= set(req) \
            or set(req) - {"op", "name", "b64", "with"}:
        return {"error": "bad-request", "detail": "expected op, name and b64"}
    op, name, b64 = req["op"], req["name"], req["b64"]
    with_key = req.get("with", "host")
    if op not in ("encrypt", "decrypt"):
        return {"error": "bad-request", "detail": "op"}
    if with_key not in WITH_KEYS or (op == "decrypt" and "with" in req):
        return {"error": "bad-request", "detail": "with"}
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        return {"error": "bad-request", "detail": "name"}
    try:
        data = bytearray(base64.b64decode(b64, validate=True)) if isinstance(b64, str) else None
    except (binascii.Error, ValueError):
        data = None
    if not data:
        return {"error": "bad-request", "detail": "b64"}
    try:
        argv = encrypt_argv(name, with_key) if op == "encrypt" else decrypt_argv(name)
        try:
            rc, out, err = run(argv, bytes(data))
        except FileNotFoundError:
            return {"error": "internal", "detail": "systemd-creds is not installed"}
        except subprocess.TimeoutExpired:
            return {"error": "internal", "detail": "systemd-creds timed out"}
        except OSError as e:
            return {"error": "internal", "detail": f"systemd-creds could not run ({e.strerror})"}
    finally:
        data[:] = bytes(len(data))
    if rc < 0:
        return {"error": "internal", "detail": f"systemd-creds killed by signal {-rc}"}
    if rc != 0 or not out:
        if op == "decrypt" and rc != 0:
            return {"error": "refused", "detail": _why(err)}
        return {"error": "internal", "detail": f"systemd-creds {op} failed ({_why(err)})"}
    if op == "encrypt":
        # The same allowlist as the daemon's: exactly the key type asked for, from the types
        # confirmed on a real TPM. Anything else is never handed out.
        try:
            got = allowed_key_type(out, SYSTEM_ALLOWED)
        except SealRefused as e:
            return {"error": "internal", "detail": str(e)[:200]}
        if got != with_key:
            return {"error": "internal",
                    "detail": f"sealed as {got}, not the {with_key} that was asked for"}
    return {"b64": base64.b64encode(out).decode()}


def peer_uid(sock: socket.socket) -> int:
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def serve(sock: socket.socket, expected_uid: int, run: Runner = _run) -> bool:
    """Answer one request on `sock`. Returns False when the peer was refused."""
    if peer_uid(sock) != expected_uid:
        return False
    sock.settimeout(TIMEOUT_S)
    buf = bytearray()
    try:
        while b"\n" not in buf and len(buf) <= MAX_REQUEST:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        if len(buf) > MAX_REQUEST:
            # Read what is left (bounded) so the reply is not lost to a reset on close.
            left = 4 * MAX_REQUEST
            while left > 0 and (chunk := sock.recv(65536)):
                left -= len(chunk)
            reply = {"error": "bad-request", "detail": "too large"}
        else:
            reply = handle(bytes(buf).split(b"\n", 1)[0], run)
        sock.sendall(json.dumps(reply).encode() + b"\n")
    finally:
        buf[:] = bytes(len(buf))
    return True


def main() -> int:
    if len(sys.argv) != 1:
        return 64
    try:
        uid = pwd.getpwnam(system_paths.SERVICE_USER).pw_uid
    except KeyError:
        return 1
    sock = socket.socket(fileno=0)            # StandardInput=socket, Accept=yes
    try:
        return 0 if serve(sock, uid) else 1
    finally:
        sock.detach()


if __name__ == "__main__":
    sys.exit(main())
