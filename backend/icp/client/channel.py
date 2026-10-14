"""One JSON-lines connection to pear-passwordsd, for the clip and migrate clients.

docs/protocol.md section 1: one object per line, requests carry a client-chosen `rid`, replies
echo it, events carry none. Lines this process sends are capped at MAX_REQUEST_LINE (the daemon
closes the connection on a longer one); lines it reads may be up to MAX_REPLY_LINE.

Deliberately small and blocking-or-select: the clip writer multiplexes this socket with the
Wayland one in a select loop, the importer just asks and waits. Nothing here logs a line, since
replies can carry a password (redeem) or a passphrase is in a request (import-key).
"""

from __future__ import annotations

import json
import os
import select
import socket
import time
from collections import deque

from ..daemon import paths, protocol


class ChannelError(Exception):
    """The daemon went away, sent something that is not protocol, or refused the hello.

    `code` is the protocol error code when the daemon sent one, else "daemon"."""

    def __init__(self, message: str, code: str = "daemon"):
        super().__init__(message)
        self.code = code


class Channel:
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = bytearray()
        self._pending: deque[dict] = deque()     # messages read but not yet handed out
        self._rid = 0
        self.closed = False

    # --- setup ----------------------------------------------------------------------------
    @classmethod
    def connect(cls, path: str = paths.SOCKET_PATH, timeout: float = 5.0) -> "Channel":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        s.settimeout(timeout)
        try:
            s.connect(path)
        except OSError as e:
            s.close()
            raise ChannelError(f"cannot reach the Pear Passwords service ({e.strerror})") from e
        s.settimeout(None)
        return cls(s)

    def hello(self, role: str, ticket: str | None = None, timeout: float = 10.0) -> dict:
        req = {"role": role, "proto": protocol.PROTO}
        if ticket is not None:
            req["ticket"] = ticket
        reply = self.request("hello", timeout=timeout, **req)
        if "error" in reply:
            raise ChannelError(f"hello refused: {reply['error']}", reply["error"])
        return reply

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    # --- writing ---------------------------------------------------------------------------
    def send(self, op: str, **fields) -> int:
        """Send one request and return its rid. Never waits for the reply."""
        rid = self._rid
        self._rid += 1
        line = json.dumps({"op": op, "rid": rid, **fields}, separators=(",", ":")).encode()
        if len(line) + 1 > protocol.MAX_REQUEST_LINE:
            raise ChannelError(f"{op} request too large")
        try:
            self._sock.sendall(line + b"\n")
        except OSError as e:
            self.close()
            raise ChannelError("the Pear Passwords service closed the connection") from e
        return rid

    def request(self, op: str, timeout: float = 60.0, **fields) -> dict:
        """Send a request and wait for its reply. Events that arrive meanwhile are kept and
        returned by later read_messages() calls, in order."""
        rid = self.send(op, **fields)
        deadline = time.monotonic() + timeout
        while True:
            for i, msg in enumerate(self._pending):
                if msg.get("rid") == rid and "event" not in msg:
                    del self._pending[i]
                    return msg
            left = deadline - time.monotonic()
            if left <= 0:
                raise ChannelError(f"no reply to {op}")
            self._fill(left)

    # --- reading ---------------------------------------------------------------------------
    def read_messages(self, timeout: float | None = 0.0) -> list[dict]:
        """Everything available now (waiting up to `timeout` for the first byte if nothing is
        buffered). Raises ChannelError on EOF."""
        if not self._pending:
            self._fill(timeout)
        out = list(self._pending)
        self._pending.clear()
        return out

    def has_pending(self) -> bool:
        """Messages already read off the socket (select() will not report them again)."""
        return bool(self._pending)

    def _fill(self, timeout: float | None) -> None:
        if self.closed:
            raise ChannelError("the Pear Passwords service closed the connection")
        if timeout is not None:
            ready, _, _ = select.select([self._sock], [], [], max(0.0, timeout))
            if not ready:
                return
        try:
            chunk = self._sock.recv(65536)
        except BlockingIOError:
            return
        except OSError as e:
            self.close()
            raise ChannelError("the Pear Passwords service closed the connection") from e
        if not chunk:
            self.close()
            raise ChannelError("the Pear Passwords service closed the connection")
        self._buf += chunk
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                if len(self._buf) > protocol.MAX_REPLY_LINE:
                    self.close()
                    raise ChannelError("reply line too long")
                return
            line = bytes(self._buf[:nl])
            del self._buf[:nl + 1]
            try:
                msg = json.loads(line)
            except ValueError:
                self.close()
                raise ChannelError("malformed reply") from None
            if not isinstance(msg, dict):
                self.close()
                raise ChannelError("malformed reply")
            self._pending.append(msg)

    def wipe(self) -> None:
        """Zero the receive buffer (it may have held a redeemed value)."""
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf.clear()


def stdin_line(stream, limit: int = 64 * 1024) -> str | None:
    """One line from the parent UI's pipe, without the newline; None at EOF. Bounded, so a
    confused parent cannot make the child buffer without limit."""
    line = stream.readline(limit + 1)
    if not line:
        return None
    if len(line) > limit:
        raise ValueError("line too long")
    return line.rstrip("\r\n")


def runtime_dir() -> str:
    """$XDG_RUNTIME_DIR as pear-exec checked it (/run/user/<uid>, 0700, ours)."""
    return os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
