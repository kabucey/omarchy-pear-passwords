"""Asking polkit, from the daemon, about the process on the other end of a connection.

The daemon - not the client - calls org.freedesktop.PolicyKit1.Authority.CheckAuthorization on
the system bus, with the connection's pidfd as a `unix-process` subject. polkit lets a non-root
caller do this for another user's process only because each action carries the owner
annotation `unix-user:pear-passwords` (polkit/io.github.dragosol.pearpasswords.policy).

Gate G2 decides the subject form. The primary path is {pidfd, uid}: a pidfd cannot be recycled.
The fallback, for a polkit that refuses pidfd subjects, is the classic {pid, start-time, uid};
it is selected only by PEAR_POLKIT_SUBJECT=pid-start-time in the unit's environment, never
automatically, so a misbehaving polkit cannot silently downgrade the subject.

Gate G7 decides how "no agent" looks. polkitd answers a check it could not show to anyone as
not authorized, a challenge, and without `polkit.dismissed`, and it does so at once. A person
cannot answer a dialog in under NO_AGENT_FAST_FAIL_S, so a failure that fast is classified as
the agent being unavailable: `no-agent` when nothing was dismissed, `busy` when the agent
refused straight away (it reports that as a dismissal). Neither counts against the rate limit.

Only this module sets AllowUserInteraction. The scheduler and the Apple pipeline never import
it, and tests walk their AST to keep it that way.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Callable

from . import protocol

logger = logging.getLogger(__name__)

AUTHORITY_PATH = "/org/freedesktop/PolicyKit1/Authority"
AUTHORITY_BUS_NAME = "org.freedesktop.PolicyKit1"
AUTHORITY_IFACE = "org.freedesktop.PolicyKit1.Authority"
CHECK_SIGNATURE = "(sa{sv})sa{ss}us"

ALLOW_USER_INTERACTION = 0x1           # CheckAuthorizationFlags.AllowUserInteraction

SUBJECT_PIDFD = "pidfd"
SUBJECT_PID_START_TIME = "pid-start-time"
SUBJECT_ENV = "PEAR_POLKIT_SUBJECT"

# Outcomes, named as the protocol's error codes so the registry can raise them as they are.
AUTHORIZED = "authorized"
DISMISSED = "dismissed"
DENIED = "denied"
NO_AGENT = "no-agent"
BUSY = "busy"
CANCELLED = "cancelled"
INTERNAL = "internal"                  # polkitd refused the call itself: a bug, never "no agent"
# "Not authorized" without a challenge: polkit decided with no dialog answered (a policy "no",
# or an agent that died mid-dialog). Reported as denied, never counted against the limit.
DENIED_UNANSWERED = "denied-unanswered"
# Only answers that said no count: an approval never holds up the next account's dialog.
COUNTED = frozenset({DISMISSED, DENIED})

# D-Bus errors that mean polkitd or the bus could not be reached (transient, like no agent).
_TRANSPORT_ERRORS = ("transport", "org.freedesktop.DBus.Error.ServiceUnknown",
                     "org.freedesktop.DBus.Error.NameHasNoOwner",
                     "org.freedesktop.DBus.Error.NoReply", "org.freedesktop.DBus.Error.Timeout",
                     "org.freedesktop.DBus.Error.TimedOut",
                     "org.freedesktop.DBus.Error.Disconnected",
                     "org.freedesktop.DBus.Error.NoServer",
                     "org.freedesktop.DBus.Error.Spawn.ChildExited")
# What _unwrap calls a message that is neither a method return nor an error: an INTERNAL fault.
NOT_A_REPLY = "io.github.dragosol.pearpasswords.Error.NotAReply"

# Characters a details value may not carry into the dialog: controls, format characters (which
# include every bidi override and zero-width joiner), surrogates, private use, unassigned, and
# line/paragraph separators. Other whitespace becomes a plain space.
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def sanitize(value) -> str:
    """A details value as the dialog may show it: printable characters only, whitespace runs
    collapsed to one space, at most DETAIL_MAX_CHARS characters."""
    out = []
    for ch in str(value):
        cat = unicodedata.category(ch)
        if cat in _STRIP_CATEGORIES:
            if ch in "\t\n\r\v\f  \x85":
                out.append(" ")
            continue
        out.append(" " if cat == "Zs" else ch)
    text = " ".join("".join(out).split())
    if len(text) > protocol.DETAIL_MAX_CHARS:
        text = text[: protocol.DETAIL_MAX_CHARS - 1].rstrip() + "…"
    return text


@dataclass
class Subject:
    pid: int
    pidfd: int
    uid: int
    start_time: int


def subject_mode() -> str:
    mode = os.environ.get(SUBJECT_ENV, SUBJECT_PIDFD)
    return mode if mode in (SUBJECT_PIDFD, SUBJECT_PID_START_TIME) else SUBJECT_PIDFD


def subject_struct(subject: Subject, mode: str = SUBJECT_PIDFD) -> tuple:
    """The (sa{sv}) polkit subject. jeepney variants are (signature, value) pairs."""
    if mode == SUBJECT_PID_START_TIME:
        return ("unix-process", {"pid": ("u", subject.pid),
                                 "start-time": ("t", subject.start_time),
                                 "uid": ("i", subject.uid)})
    return ("unix-process", {"pidfd": ("h", subject.pidfd), "uid": ("i", subject.uid)})


def classify(result: tuple | None, *, error: str | None, elapsed: float,
             cancelled: bool) -> str:
    """Map a CheckAuthorization reply (or a D-Bus error name) to an outcome."""
    if cancelled:
        return CANCELLED
    if error is not None:
        if error.endswith(".Cancelled"):
            return BUSY
        if error in _TRANSPORT_ERRORS:
            # polkitd or the bus is not there right now; the UI says to retry.
            return NO_AGENT
        # polkitd refused the call itself (NotAuthorized: the owner annotation is missing;
        # a refused subject; InvalidArgs): a real fault, never shown as "shell restarting".
        logger.error("polkit refused the check: %s", error)
        return INTERNAL
    is_authorized, is_challenge, details = result
    if is_authorized:
        return AUTHORIZED
    dismissed = str((details or {}).get("polkit.dismissed", "")).lower() in ("true", "1")
    fast = elapsed < protocol.NO_AGENT_FAST_FAIL_S
    if fast and is_challenge:
        return BUSY if dismissed else NO_AGENT
    if dismissed:
        return DISMISSED
    return DENIED if is_challenge else DENIED_UNANSWERED


class SystemBus:
    """A lazily opened system-bus connection with fd passing, shared by every check so a
    cancel comes from the same bus name as the check it cancels (polkit requires that).
    Replies go through dbus_safe.Router: only a method return or error from polkitd's own
    connection answers a check - jeepney's router took a directed signal with a matching
    serial from any client as the reply, which forged "authorized" (#10755)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._router = None
        self._conn = None

    def _router_or_open(self):
        with self._lock:
            if self._router is None:
                from jeepney.io.threading import open_dbus_connection
                from ..dbus_safe import Router
                self._conn = open_dbus_connection("SYSTEM", enable_fds=True)
                self._router = Router(self._conn)
            return self._router

    def call(self, msg, timeout: float | None = None):
        """Send a method call and return the reply Message (error replies included)."""
        router = self._router_or_open()
        try:
            return router.call(msg, timeout=timeout)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        with self._lock:
            router, conn, self._router, self._conn = self._router, self._conn, None, None
        for obj in (router, conn):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass


class Authority:
    """CheckAuthorization / CancelCheckAuthorization. Both methods block; the registry runs
    them in a worker pool."""

    def __init__(self, bus=None, clock: Callable[[], float] = time.monotonic,
                 mode: str | None = None):
        self._bus = bus if bus is not None else SystemBus()
        self._clock = clock
        self._mode = mode or subject_mode()
        self._cancelled: set[str] = set()
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        return self._mode

    def _address(self):
        from jeepney import DBusAddress
        return DBusAddress(AUTHORITY_PATH, bus_name=AUTHORITY_BUS_NAME,
                           interface=AUTHORITY_IFACE)

    def check_message(self, subject: Subject, action: str, details: dict,
                      cancellation_id: str):
        from jeepney import new_method_call
        clean = {str(k): sanitize(v) for k, v in details.items()}
        return new_method_call(self._address(), "CheckAuthorization", CHECK_SIGNATURE,
                               (subject_struct(subject, self._mode), action, clean,
                                ALLOW_USER_INTERACTION, cancellation_id))

    def check(self, subject: Subject, action: str, details: dict,
              cancellation_id: str) -> str:
        """Raise the dialog and wait for it. Returns one of the outcome constants."""
        if action not in _ACTIONS:
            raise ValueError(f"not a Pear Passwords action: {action!r}")
        msg = self.check_message(subject, action, details, cancellation_id)
        start = self._clock()
        result, error = None, None
        try:
            reply = self._bus.call(msg)
            error, body = _unwrap(reply)
            if error is None:
                result = body[0]
        except Exception as e:                       # no system bus, polkitd gone, ...
            logger.warning("polkit check failed: %s", type(e).__name__)
            error = "transport"
        elapsed = self._clock() - start
        with self._lock:
            cancelled = cancellation_id in self._cancelled
            self._cancelled.discard(cancellation_id)
        outcome = classify(result, error=error, elapsed=elapsed, cancelled=cancelled)
        logger.info("polkit %s: %s (%.1fs)", action.rsplit(".", 1)[-1], outcome, elapsed)
        return outcome

    def close(self) -> None:
        """Drop the bus connection; checks still waiting return (as no-agent) at once."""
        close = getattr(self._bus, "close", None)
        if close is not None:
            close()

    def cancel(self, cancellation_id: str) -> None:
        from jeepney import new_method_call
        with self._lock:
            self._cancelled.add(cancellation_id)
        try:
            reply = self._bus.call(new_method_call(
                self._address(), "CancelCheckAuthorization", "s", (cancellation_id,)),
                timeout=5)
            err, _ = _unwrap(reply)
            if err:
                logger.debug("cancel %s: %s", cancellation_id, err)
        except Exception as e:
            logger.debug("cancel failed: %s", type(e).__name__)


_ACTIONS = frozenset(protocol.PROMPT_ACTION.values())


def _unwrap(reply) -> tuple[str | None, tuple]:
    """(error name or None, body) of a reply Message. Only a METHOD_RETURN is an answer: a
    signal or anything else that reached here is NOT_A_REPLY, never a success (#10755)."""
    from jeepney import HeaderFields, MessageType
    if reply.header.message_type == MessageType.error:
        return str(reply.header.fields.get(HeaderFields.error_name, "error")), reply.body
    if reply.header.message_type != MessageType.method_return:
        return NOT_A_REPLY, ()
    return None, reply.body
