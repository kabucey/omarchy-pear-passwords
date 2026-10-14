"""The browser autofill host: what `pear-exec autofill` runs for a native-messaging browser.

A browser starts $P/libexec/pear-autofill-host when an extension calls the native host
io.github.dragosol.pearpasswords; the wrapper drops the browser's arguments and runs
`pear-exec autofill`, which scrubs the environment and execs this module with egid
pear-client. Only then can it connect to the daemon.

This process is a translator and nothing else. It holds no key, no list and no state beyond
the daemon's last locked/unlocked word, and it trusts the extension with nothing: every
request is rebuilt from scratch with the two fields the daemon needs (origin, id), so an
extension cannot reach a daemon op other than autofill-query, -names and -fill or smuggle
extra fields into them. Whether a fill happens is decided by the daemon and the polkit dialog
it raises for every fill; whether the origin is well-formed is decided by the daemon too, so
there is one parser, not two that could disagree.

The browser-facing format (4-byte native-endian length, then UTF-8 JSON) and every message are
in docs/autofill-protocol.md. Nothing here ever writes a username or password anywhere but
stdout, and diagnostics on stderr (the browser console) carry codes only.
"""

from __future__ import annotations

import json
import os
import select
import socket
import struct
import sys
import time

from ..daemon import paths, protocol

# A request from the extension is an origin and an id: a few hundred bytes. Anything near this
# is not one, and since the length prefix cannot be trusted after it, the host stops.
NATIVE_IN_MAX = 64 * 1024
# Firefox and Chromium both refuse a host-to-extension message over 1 MiB.
NATIVE_OUT_MAX = 1024 * 1024
MAX_PENDING = 8                      # requests awaiting the daemon, per host process
ORIGIN_MAX = 2048
ID_MAX = 128
RECONNECT_GAP_S = 1.0
VERSION = "2.0.3"

EXT_OPS = {"status": None, "query": "autofill-query", "names": "autofill-names",
           "fill": "autofill-fill"}
# Errors the host itself answers with; everything else is the daemon's code passed through.
HOST_ERRORS = ("bad-request", "unknown-op", "too-large", "too-many", "no-daemon", "disabled")

_LEN = struct.Struct("=I")           # native byte order, as both browsers send it
_BAD = object()                      # a frame that was not a JSON object


class FrameError(Exception):
    """The byte stream can no longer be trusted (oversized frame or line)."""


def encode_message(obj: dict) -> bytes:
    """One native-messaging frame. Raises FrameError if it would exceed NATIVE_OUT_MAX."""
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(data) > NATIVE_OUT_MAX:
        raise FrameError("too-large")
    return _LEN.pack(len(data)) + data


class NativeReader:
    """Splits the browser's stdin stream into messages: a dict each, or _BAD for a frame that
    is not a JSON object. A declared length over the limit raises FrameError."""

    def __init__(self, limit: int = NATIVE_IN_MAX):
        self.limit = limit
        self.buf = bytearray()

    def feed(self, data: bytes) -> list:
        self.buf += data
        out = []
        while len(self.buf) >= _LEN.size:
            (n,) = _LEN.unpack_from(self.buf)
            if n > self.limit:
                raise FrameError("too-large")
            if len(self.buf) < _LEN.size + n:
                break
            raw = bytes(self.buf[_LEN.size:_LEN.size + n])
            del self.buf[:_LEN.size + n]
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                msg = _BAD
            out.append(msg if isinstance(msg, dict) else _BAD)
        return out


class LineReader:
    """Splits the daemon's stream into JSON objects, one per line (docs/protocol.md 1)."""

    def __init__(self, limit: int = protocol.MAX_REPLY_LINE):
        self.limit = limit
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[dict]:
        self.buf += data
        out = []
        while True:
            i = self.buf.find(b"\n")
            if i < 0:
                if len(self.buf) > self.limit:
                    raise FrameError("too-large")
                return out
            line = bytes(self.buf[:i])
            del self.buf[:i + 1]
            if len(line) + 1 > self.limit:
                raise FrameError("too-large")
            try:
                obj = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise FrameError("bad-line") from None
            if isinstance(obj, dict):
                out.append(obj)


class DaemonUnavailable(Exception):
    """Could not connect, or the daemon refused the hello (code in args[0])."""


def connect_daemon(path: str = paths.SOCKET_PATH) -> tuple[socket.socket, dict]:
    """Connect, say hello as role autofill, and return (socket, hello reply)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        s.settimeout(protocol.HELLO_TIMEOUT_S)
        s.connect(path)
        s.sendall(_line({"op": "hello", "rid": 0, "role": "autofill",
                         "proto": protocol.PROTO}))
        reader = LineReader()
        while True:
            data = s.recv(65536)
            if not data:
                raise DaemonUnavailable("closed")
            for obj in reader.feed(data):
                if obj.get("rid") == 0:
                    if "error" in obj:
                        raise DaemonUnavailable(str(obj.get("error")))
                    s.settimeout(None)
                    return s, obj
    except (OSError, FrameError) as e:
        s.close()
        raise DaemonUnavailable("connect") from e
    except DaemonUnavailable:
        s.close()
        raise


def _line(obj: dict) -> bytes:
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    if len(data) > protocol.MAX_REQUEST_LINE:
        raise FrameError("too-large")
    return data


def _log(code: str) -> None:
    # The browser shows stderr in its console. Codes only, never a value.
    try:
        sys.stderr.write(f"pear-autofill-host: {code}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


class Host:
    """One native-messaging session: the browser on fd_in/fd_out, the daemon on a socket."""

    def __init__(self, fd_in: int = 0, fd_out: int = 1, connect=connect_daemon,
                 clock=time.monotonic):
        self.fd_in, self.fd_out = fd_in, fd_out
        self.connect, self.clock = connect, clock
        self.native = NativeReader()
        self.lines = LineReader()
        self.sock: socket.socket | None = None
        self.state: str | None = None        # the daemon's last word: locked/unlocked/unavailable
        self.refused: str | None = None      # last hello refusal, e.g. too-many
        self.last_attempt = -RECONNECT_GAP_S
        self.pending: dict[int, int] = {}    # daemon rid -> extension rid
        self.next_rid = 1

    # --- output ----------------------------------------------------------------------------
    def send(self, obj: dict) -> None:
        try:
            frame = encode_message(obj)
        except FrameError:
            frame = encode_message({"rid": obj.get("rid"), "error": "too-large"})
        view = memoryview(frame)
        while view:
            n = os.write(self.fd_out, view)
            view = view[n:]

    def _set_state(self, state: str) -> None:
        if state != self.state:
            self.state = state
            self.send({"event": "state", "state": state})

    # --- daemon connection -----------------------------------------------------------------
    def ensure_daemon(self) -> bool:
        if self.sock is not None:
            return True
        now = self.clock()
        if now - self.last_attempt < RECONNECT_GAP_S:
            return False
        self.last_attempt = now
        try:
            self.sock, hello = self.connect()
        except DaemonUnavailable as e:
            self.refused = e.args[0] if e.args else "connect"
            _log(f"daemon {self.refused}")
            return False
        self.refused = None
        self.lines = LineReader()
        state = hello.get("state")
        self._set_state(state if state in protocol.AUTOFILL_STATES else "unavailable")
        return True

    def daemon_gone(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        for ext_rid in self.pending.values():
            self.send({"rid": ext_rid, "error": "no-daemon"})
        self.pending.clear()
        if self.state is not None:
            self._set_state("unavailable")

    def _unreachable(self, rid) -> dict:
        # The daemon's own refusal (too-many autofill connections, or autofill switched off
        # in the window) is more useful than a generic one.
        if self.refused == "too-many":
            return {"rid": rid, "error": "too-many"}
        if self.refused == "forbidden":
            return {"rid": rid, "error": "disabled"}
        return {"rid": rid, "error": "no-daemon"}

    # --- extension -> daemon ---------------------------------------------------------------
    def from_extension(self, msg) -> None:
        if msg is _BAD:
            self.send({"rid": None, "error": "bad-request"})
            return
        rid = msg.get("rid")
        if isinstance(rid, bool) or not isinstance(rid, int) or not 0 <= rid <= protocol.MAX_RID:
            self.send({"rid": None, "error": "bad-request", "field": "rid"})
            return
        op = msg.get("op")
        if op not in EXT_OPS:
            self.send({"rid": rid, "error": "unknown-op"})
            return
        if op == "status":
            if not self.ensure_daemon():
                self.send(self._unreachable(rid))
                return
            self.send({"rid": rid, "state": self.state, "version": VERSION})
            return

        origin = msg.get("origin")
        if not isinstance(origin, str) or not origin or len(origin) > ORIGIN_MAX:
            self.send({"rid": rid, "error": "bad-request", "field": "origin"})
            return
        req = {"op": EXT_OPS[op], "origin": origin}
        if op == "fill":
            entry_id = msg.get("id")
            if not isinstance(entry_id, str) or not entry_id or len(entry_id) > ID_MAX:
                self.send({"rid": rid, "error": "bad-request", "field": "id"})
                return
            req["id"] = entry_id
        if len(self.pending) >= MAX_PENDING:
            self.send({"rid": rid, "error": "too-many"})
            return
        if not self.ensure_daemon():
            self.send(self._unreachable(rid))
            return
        drid = self.next_rid
        self.next_rid = self.next_rid + 1 if self.next_rid < protocol.MAX_RID else 1
        req["rid"] = drid
        self.pending[drid] = rid
        try:
            self.sock.sendall(_line(req))
        except OSError:
            self.daemon_gone()

    # --- daemon -> extension ---------------------------------------------------------------
    def from_daemon(self, obj: dict) -> None:
        if "rid" not in obj:
            if obj.get("event") == "state" and obj.get("state") in protocol.AUTOFILL_STATES:
                self._set_state(obj["state"])
            return                           # no other event is meant for the browser
        drid = obj.get("rid")
        if drid not in self.pending:
            return
        reply = dict(obj)
        reply["rid"] = self.pending.pop(drid)
        if reply.get("error") == "forbidden":
            reply["error"] = "disabled"       # autofill was switched off in the window
        self.send(reply)

    # --- loop ------------------------------------------------------------------------------
    def run(self) -> int:
        try:
            while True:
                fds = [self.fd_in] + ([self.sock] if self.sock is not None else [])
                ready, _, _ = select.select(fds, [], [])
                if self.fd_in in ready:
                    data = os.read(self.fd_in, 65536)
                    if not data:
                        return 0             # the extension closed the port
                    try:
                        msgs = self.native.feed(data)
                    except FrameError:
                        _log("oversized message from the browser")
                        self.send({"rid": None, "error": "too-large"})
                        return 2
                    for msg in msgs:
                        self.from_extension(msg)
                if self.sock is not None and self.sock in ready:
                    try:
                        data = self.sock.recv(65536)
                    except OSError:
                        data = b""
                    if not data:
                        self.daemon_gone()
                        continue
                    try:
                        objs = self.lines.feed(data)
                    except FrameError:
                        _log("bad line from the daemon")
                        self.daemon_gone()
                        continue
                    for obj in objs:
                        self.from_daemon(obj)
        except BrokenPipeError:
            return 0                         # the browser went away mid-write
        finally:
            if self.sock is not None:
                self.sock.close()
                self.sock = None


def main(argv: list[str] | None = None) -> int:
    # pear-exec passes no arguments; the browser's own are dropped by the wrapper.
    try:
        return Host().run()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
