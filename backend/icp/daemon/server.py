"""The client socket: peer checks, framing, hello, dispatch, and per-connection limits.

One asyncio task per connection reads lines; each request runs in its own task so a dialog
waiting on a person never blocks the next line (docs/protocol.md 1). The order of the checks
on a request line is fixed:

  size (> MAX_REQUEST_LINE: too-large, close) -> UTF-8 JSON object with an integer rid
  (bad-request) -> op known (unknown-op) -> op allowed for the role (forbidden) ->
  MAX_INFLIGHT (too-many) -> handler

Writes never block the loop: replies and events go into the transport's buffer, and a client
that lets more than SEND_BUFFER_MAX pile up is disconnected rather than allowed to hold daemon
memory hostage. A reply over MAX_REPLY_LINE is replaced by `internal`.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import sys
import time
from typing import Callable

from . import handlers as _handlers
from . import protocol
from .peer import PeerError, PeerInfo
from .protocol import OpError
from .sessions import Request, reset_request, set_request

logger = logging.getLogger(__name__)

SEND_BUFFER_MAX = 16 * 1024 * 1024
_TOO_LARGE = object()


class BadLine(Exception):
    def __init__(self, rid=None):
        super().__init__("bad-request")
        self.rid = rid


def _reject_constant(name):
    raise ValueError(f"{name} is not JSON")


def parse_line(line: bytes) -> dict:
    """One request line as a dict with a valid integer rid and a string op, or BadLine."""
    try:
        obj = json.loads(line.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BadLine() from None
    if not isinstance(obj, dict):
        raise BadLine()
    rid = obj.get("rid")
    if isinstance(rid, bool) or not isinstance(rid, int) or not 0 <= rid <= protocol.MAX_RID:
        raise BadLine()
    if not isinstance(obj.get("op"), str):
        raise BadLine(rid)
    return obj


class Conn:
    """A verified connection (protocol.Connection)."""

    def __init__(self, peer: PeerInfo, writer, conn_id: int = 0):
        self.id = conn_id
        self.uid = peer.uid
        self.pid = peer.pid
        self.pidfd = peer.pidfd
        self.start_time = peer.start_time
        self.ppid = peer.ppid
        self.role: str | None = None
        self.closed = False
        self.ticket = None
        self.data: dict = {}
        self.tasks: set[asyncio.Task] = set()
        self._writer = writer
        self._pidfd_closed = False

    def __repr__(self):
        return f"<Conn {self.id} uid={self.uid} pid={self.pid} role={self.role}>"

    def send_event(self, event: dict) -> None:
        self.send(event)

    def send(self, obj: dict) -> None:
        if self.closed:
            return
        try:
            line = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
        except (TypeError, ValueError):
            logger.error("unserializable %s for %r", "reply" if "rid" in obj else "event", self)
            if "rid" not in obj:
                return
            line = json.dumps({"rid": obj["rid"], "error": "internal"}).encode() + b"\n"
        if len(line) > protocol.MAX_REPLY_LINE:
            logger.error("reply over MAX_REPLY_LINE for %r", self)
            if "rid" not in obj:
                return
            line = json.dumps({"rid": obj["rid"], "error": "internal"}).encode() + b"\n"
        try:
            self._writer.write(line)
            transport = self._writer.transport
            if transport is not None and transport.get_write_buffer_size() > SEND_BUFFER_MAX:
                logger.warning("%r stopped reading; disconnecting", self)
                self.close(abort=True)
        except (ConnectionError, RuntimeError, OSError):
            self.close(abort=True)

    def close(self, abort: bool = False) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            if abort and self._writer.transport is not None:
                self._writer.transport.abort()
            else:
                self._writer.close()
        except Exception:
            pass

    def release_pidfd(self) -> None:
        """Close the pidfd once no request of this connection can still hand it to polkit.
        Closing it under a running check could let the fd number be reused for another file
        and sent in its place."""
        def maybe_close(_task=None):
            if self.tasks or self._pidfd_closed:
                return
            self._pidfd_closed = True
            try:
                os.close(self.pidfd)
            except OSError:
                pass
        for t in list(self.tasks):
            t.add_done_callback(maybe_close)
        maybe_close()


class Server:
    def __init__(self, registry, *, verify_peer: Callable[[object], PeerInfo],
                 handlers: dict | None = None, hello_timeout: float = protocol.HELLO_TIMEOUT_S):
        self.reg = registry
        self.verify_peer = verify_peer
        self.handlers = dict(_handlers.HANDLERS if handlers is None else handlers)
        self.hello_timeout = hello_timeout

    async def start(self, sock):
        # The stream limit makes readuntil() refuse a line longer than MAX_REQUEST_LINE before
        # buffering much more than that; _read_line checks the exact boundary.
        # cleanup_socket=False: the socket file is systemd's (socket activation, in a root-owned
        # /run/pear-passwords). Python 3.13+ would otherwise unlink it when the server closes,
        # which fails with EACCES there and would break activation if it ever succeeded.
        kw = {"cleanup_socket": False} if sys.version_info >= (3, 13) else {}
        return await asyncio.start_unix_server(self.handle_client, sock=sock,
                                               limit=protocol.MAX_REQUEST_LINE, **kw)

    async def handle_client(self, reader, writer) -> None:
        sock = writer.get_extra_info("socket")
        try:
            peer = self.verify_peer(sock)
        except PeerError as e:
            logger.warning("connection refused: %s", e)
            try:
                writer.write(b'{"rid":null,"error":"peer"}\n')
                writer.close()
            except Exception:
                pass
            return
        conn = Conn(peer, writer, self.reg.new_conn_id())
        try:
            await self._serve(conn, reader)
        except (ConnectionError, OSError):
            pass
        except Exception:
            logger.exception("connection %r failed", conn)
        finally:
            conn.close()
            self.reg.detach(conn)
            conn.release_pidfd()

    async def _read_line(self, reader):
        try:
            line = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError:
            return None
        except asyncio.LimitOverrunError:
            return _TOO_LARGE
        except (ConnectionError, OSError):
            return None
        if len(line) > protocol.MAX_REQUEST_LINE:
            return _TOO_LARGE
        return line

    async def _serve(self, conn: Conn, reader) -> None:
        try:
            line = await asyncio.wait_for(self._read_line(reader), self.hello_timeout)
        except asyncio.TimeoutError:
            conn.send({"rid": None, "error": "hello-required"})
            return
        if line is None:
            return
        if line is _TOO_LARGE:
            conn.send({"rid": None, "error": "too-large"})
            return
        try:
            req = parse_line(line)
        except BadLine:
            conn.send({"rid": None, "error": "hello-required"})
            return
        rid = req["rid"]
        if req["op"] != "hello":
            conn.send({"rid": None, "error": "hello-required"})
            return
        proto = req.get("proto")
        if isinstance(proto, bool) or proto != protocol.PROTO:
            conn.send({"rid": rid, "error": "proto", "proto": protocol.PROTO})
            return
        role = req.get("role")
        if role not in protocol.ROLES:
            return                                  # unknown role: close without a reply
        conn.role = role
        request = Request(conn, rid)
        token = set_request(request)
        try:
            reply = await _handlers.hello(self.reg, conn, req)
        except OpError as e:
            conn.send(e.reply(rid))
            return
        except Exception:
            logger.exception("hello failed for %r", conn)
            conn.send({"rid": rid, "error": "internal"})
            return
        finally:
            reset_request(token)
        self.reg.attach(conn)
        conn.send({"rid": rid, **_without_rid(reply)})
        _run_after(request)
        logger.info("%r connected", conn)
        await self._loop(conn, reader)

    async def _loop(self, conn: Conn, reader) -> None:
        loop = asyncio.get_running_loop()
        allowed = protocol.ROLE_OPS[conn.role]
        while not conn.closed:
            line = await self._read_line(reader)
            if line is None:
                return
            if line is _TOO_LARGE:
                conn.send({"rid": None, "error": "too-large"})
                return
            try:
                req = parse_line(line)
            except BadLine as e:
                conn.send({"rid": e.rid, "error": "bad-request"})
                continue
            rid, op = req["rid"], req["op"]
            if op not in protocol.ALL_OPS:
                conn.send({"rid": rid, "error": "unknown-op"})
                continue
            if op not in allowed:
                conn.send({"rid": rid, "error": "forbidden"})
                continue
            if len(conn.tasks) >= protocol.MAX_INFLIGHT:
                conn.send({"rid": rid, "error": "too-many"})
                continue
            self.reg.touch(conn)
            task = loop.create_task(self._run(conn, req, rid, op),
                                    context=contextvars.Context())
            conn.tasks.add(task)
            task.add_done_callback(conn.tasks.discard)

    async def _run(self, conn: Conn, req: dict, rid: int, op: str) -> None:
        request = Request(conn, rid)
        set_request(request)
        started = time.monotonic()
        try:
            payload = await self.handlers[op](self.reg, conn, req)
            out = {"rid": rid, **_without_rid(payload or {})}
            if op in LOGGED_OPS:
                log_outcome(op, "ok", started)
        except OpError as e:
            out = e.reply(rid)
            field = e.extra.get("field")
            log_outcome(op, e.code + (f" ({field})" if isinstance(field, str) else ""), started)
        except asyncio.CancelledError:
            if op in LOGGED_OPS:
                log_outcome(op, "cancelled (the window went away)", started)
            raise
        except Exception:
            logger.exception("op %s failed for %r", op, conn)
            out = {"rid": rid, "error": "internal"}
        conn.send(out)
        _run_after(request)


# Ops whose outcome and duration always go to the journal: the ones that reach Apple or change
# the vault, where a failure the window showed for a moment is otherwise gone. Any op that ends
# in an error is logged too. Only the op, the error code and the field name are written - never
# a value, and never an error's `detail` (Apple's text can name the account).
LOGGED_OPS = frozenset({"create", "set", "delete", "sync", "signin", "migrate-begin", "reset",
                        "tpm-move"})


def log_outcome(op: str, outcome: str, started: float) -> None:
    logger.info("op %s: %s in %.1fs", op, outcome, time.monotonic() - started)


def _without_rid(d: dict) -> dict:
    return {k: v for k, v in d.items() if k != "rid"}


def _run_after(request: Request) -> None:
    for fn in request.after:
        try:
            fn()
        except Exception:
            logger.exception("post-reply action failed")
    request.after.clear()
