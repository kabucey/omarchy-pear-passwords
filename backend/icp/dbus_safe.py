"""D-Bus replies that another client on the bus cannot forge.

jeepney 0.9 matches a reply to the call waiting for it by REPLY_SERIAL alone - its threading
ReplyMatcher and the blocking connection's send_and_get_reply both do - whatever the message
type and whoever sent it. Any client on the bus may send this connection a directed SIGNAL that
carries a REPLY_SERIAL header (bus policy lets signals through where it stops unrequested
replies), and serials simply count up from 1, so a guessed one is handed to the waiting call as
its answer. In Pear's polkit check that was a forged "authorized" (HANCORE-linux,
omacom/omarchy-plugin-marketplace#10755).

Here a message answers a call only if all three hold:
  - it is a METHOD_RETURN or an ERROR (never a signal or a method call);
  - its REPLY_SERIAL is the call's;
  - its SENDER is the unique name that owned the call's destination when the call was sent.
    The bus daemon stamps SENDER itself; no client can set it. The bus driver's own replies
    come from "org.freedesktop.DBus", and the owner of a well-known name is asked of the driver
    first, under the same rule.
Anything else is dropped and the call keeps waiting for its real reply. Signals still reach
filters; callers that act on them compare the sender themselves (logind.py).

A message that cannot be parsed is dropped too, and the connection carries on (_TolerantParser).
In jeepney it ends the connection, and any client can send one (see _TolerantParser).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from concurrent.futures import Future

from jeepney import HeaderFields, MessageType
from jeepney.bus_messages import message_bus
from jeepney.low_level import Message, Parser, calc_msg_size
from jeepney.wrappers import unwrap_msg

logger = logging.getLogger(__name__)

DRIVER = "org.freedesktop.DBus"
_REPLY_TYPES = (MessageType.method_return, MessageType.error)


class RouterClosed(Exception):
    pass


class _TolerantParser(Parser):
    """jeepney's Parser, except that a message it cannot parse is dropped and the stream goes on.

    Any client may send a signal to any connection, and dbus-broker passes on header fields that
    jeepney 0.9 does not know: the spec says to ignore them, but jeepney raises ValueError. That
    exception used to end the receiving thread, so one signal from any local user stopped the
    daemon hearing logind (screen lock, sleep). jeepney's Parser also takes the message's bytes
    before parsing them and keeps its size if parsing fails, so even a caller that caught the
    error would cut every later message at the wrong place. Here the size is cleared first, and
    the bad message's file descriptors are closed. With fd passing on, jeepney reads one message
    at a time, so every buffered fd belongs to the bad message. The fixed 16-byte header that
    gives the size is checked by the bus before it routes anything, so it is still trusted."""

    def get_next_message(self):
        while True:
            if self.next_msg_size is None:
                if self.buf.bytes_buffered < 16:
                    return None
                self.next_msg_size = calc_msg_size(self.buf.peek(16))
            size = self.next_msg_size
            if self.buf.bytes_buffered < size:
                return None
            raw = self.buf.read(size)
            self.next_msg_size = None
            try:
                msg = Message.from_buffer(raw, fds=self.fds)
            except Exception as e:
                for fd in self.fds:
                    try:
                        fd.close()
                    except Exception:
                        pass
                self.fds = []
                logger.warning("dropped a D-Bus message that could not be parsed (%s)",
                               type(e).__name__)
                continue
            self.fds = self.fds[msg.header.fields.get(HeaderFields.unix_fds, 0):]
            return msg


def tolerant(conn):
    """Give a jeepney connection a _TolerantParser that carries on from whatever its own parser
    has already buffered. Safe to call more than once."""
    old = getattr(conn, "parser", None)
    if isinstance(old, Parser) and not isinstance(old, _TolerantParser):
        new = _TolerantParser()
        new.buf, new.fds, new.next_msg_size = old.buf, old.fds, old.next_msg_size
        conn.parser = new
    return conn


def is_reply(msg, serial: int, sender: str) -> bool:
    """True only for a method return or error to `serial` sent by `sender`."""
    fields = msg.header.fields
    return (msg.header.message_type in _REPLY_TYPES
            and fields.get(HeaderFields.reply_serial) == serial
            and fields.get(HeaderFields.sender) == sender)


def _destination(msg) -> str:
    dest = msg.header.fields.get(HeaderFields.destination)
    if not dest:
        raise ValueError("a method call needs a destination")
    return dest


class Router:
    """A replacement for jeepney.io.threading.DBusRouter (call, filter, close) that accepts only
    replies from the right sender. Wraps a jeepney.io.threading.DBusConnection."""

    def __init__(self, conn):
        self.conn = tolerant(conn)
        self._lock = threading.Lock()
        self._pending: dict[int, tuple[str, Future]] = {}
        self._filters: list = []
        self._thread = threading.Thread(target=self._receiver, name="pear-dbus", daemon=True)
        self._thread.start()

    @property
    def unique_name(self):
        return self.conn.unique_name

    def owner(self, name: str, timeout: float | None = None) -> str:
        """The unique name that owns `name` now, asked of the bus driver."""
        if name == DRIVER or name.startswith(":"):
            return name
        return unwrap_msg(self._call(message_bus.GetNameOwner(name), DRIVER, timeout))[0]

    def call(self, msg, timeout: float | None = None):
        """Send a method call; return its reply (an error reply included) from the owner of its
        destination. Raises TimeoutError, or RouterClosed if the connection went away."""
        dest = _destination(msg)
        return self._call(msg, self.owner(dest, timeout), timeout)

    # jeepney's name, for callers written against DBusRouter
    def send_and_get_reply(self, msg, *, timeout: float | None = None):
        return self.call(msg, timeout)

    def _call(self, msg, sender: str, timeout: float | None):
        if not self._thread.is_alive():
            raise RouterClosed("the D-Bus connection is closed")
        serial = next(self.conn.outgoing_serial)
        fut: Future = Future()
        with self._lock:
            self._pending[serial] = (sender, fut)
        try:
            self.conn.send(msg, serial=serial)
            return fut.result(timeout=timeout)
        finally:
            with self._lock:
                self._pending.pop(serial, None)

    def filter(self, rule, *, queue: "queue.Queue"):
        """Signals matching `rule` go to `queue` (dropped when it is full)."""
        with self._lock:
            self._filters.append((rule, queue))
        return queue

    def _dispatch(self, msg) -> None:
        mtype = msg.header.message_type
        fields = msg.header.fields
        if mtype in _REPLY_TYPES:
            serial = fields.get(HeaderFields.reply_serial)
            with self._lock:
                entry = self._pending.get(serial)
            if entry is None:
                return
            sender, fut = entry
            if fields.get(HeaderFields.sender) != sender:
                logger.warning("ignored a D-Bus reply to %s from %s (expected %s)", serial,
                               fields.get(HeaderFields.sender), sender)
                return
            if not fut.done():
                fut.set_result(msg)
            return
        if mtype == MessageType.signal:
            if fields.get(HeaderFields.reply_serial) is not None:
                logger.warning("ignored a signal carrying a reply serial from %s",
                               fields.get(HeaderFields.sender))
            with self._lock:
                filters = list(self._filters)
            for rule, q in filters:
                if rule.matches(msg):
                    try:
                        q.put_nowait(msg)
                    except queue.Full:
                        pass

    def _receiver(self) -> None:
        from jeepney.io.threading import ReceiveStopped
        try:
            while True:
                msg = self.conn.receive()
                try:
                    self._dispatch(msg)
                except Exception:
                    # One odd message must not stop the thread every call and filter relies on.
                    logger.exception("D-Bus message handling failed")
        except ReceiveStopped:
            pass
        except Exception as e:
            logger.warning("D-Bus connection lost (%s)", type(e).__name__)
        finally:
            with self._lock:
                pending, self._pending = list(self._pending.values()), {}
            for _sender, fut in pending:
                if not fut.done():
                    fut.set_exception(RouterClosed("the D-Bus connection closed"))

    def close(self) -> None:
        self.conn.interrupt()
        self._thread.join(timeout=10)
        self.conn.reset_interrupt()


def call_blocking(conn, msg, timeout: float | None = None):
    """The same rule for a jeepney.io.blocking.DBusConnection with no other traffic: send `msg`
    and return the first message that is its reply from its destination's owner; anything else
    that arrives meanwhile is dropped, and so is anything that cannot be parsed."""
    tolerant(conn)
    dest = _destination(msg)
    deadline = None if timeout is None else time.monotonic() + timeout
    sender = dest
    if dest != DRIVER and not dest.startswith(":"):
        sender = unwrap_msg(_blocking_once(conn, message_bus.GetNameOwner(dest), DRIVER,
                                           deadline))[0]
    return _blocking_once(conn, msg, sender, deadline)


def _blocking_once(conn, msg, sender: str, deadline: float | None):
    serial = next(conn.outgoing_serial)
    conn.send(msg, serial=serial)
    while True:
        left = None if deadline is None else deadline - time.monotonic()
        if left is not None and left <= 0:
            raise TimeoutError("no D-Bus reply in time")
        reply = conn.receive(timeout=left)
        if is_reply(reply, serial, sender):
            return reply
        if reply.header.message_type == MessageType.signal \
                and reply.header.fields.get(HeaderFields.reply_serial) is not None:
            logger.warning("ignored a signal carrying a reply serial from %s",
                           reply.header.fields.get(HeaderFields.sender))
