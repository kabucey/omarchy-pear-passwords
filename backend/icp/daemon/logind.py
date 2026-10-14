"""Lock triggers from systemd-logind: screen lock, sleep, and the end of a user's sessions.

On the system bus the daemon listens for:

- org.freedesktop.login1.Session.Lock on any session, and PropertiesChanged with
  LockedHint=true: that session's uid is locked with reason `screen-locked`;
- Manager.PrepareForSleep(true): every uid is locked with reason `sleep` while a `delay`
  inhibitor holds the suspend back (SLEEP_WAIT_S at the most), and only then is the
  inhibitor released, so no key is in RAM or in a hibernation image - unless a store call is
  still running then (docs/security.md, "Sleep while a store call runs").
  PrepareForSleep(false) takes a new inhibitor;
- Manager.SessionRemoved: when a uid's last session ends it is locked (`session-ended`).

Signals are accepted only from logind's own bus name. A forged one could at worst cause a
lock, which is harmless (gate G6). If the bus or logind is unavailable the daemon still runs,
and closing the window (EOF) and the Lock button still lock. The spec's G6 fallback - the
window forwarding Hyprland's own lock event as a `lock` op - is not built: which event
Hyprland 0.56 emits for a session lock is for the G6 test to establish first.

The D-Bus I/O runs in a thread of its own (jeepney's threading router, which can receive the
inhibitor fd). Every action on daemon state is handed to the event loop and waited for.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable

logger = logging.getLogger(__name__)

LOGIN1 = "org.freedesktop.login1"
MANAGER_PATH = "/org/freedesktop/login1"
MANAGER_IFACE = "org.freedesktop.login1.Manager"
SESSION_IFACE = "org.freedesktop.login1.Session"
PROPS_IFACE = "org.freedesktop.DBus.Properties"

# How long PrepareForSleep may hold the suspend back: the lock never waits, and a store call
# still running gets this long to return before the machine sleeps anyway.
SLEEP_WAIT_S = 1.0

INHIBIT_WHO = "Pear Passwords"
INHIBIT_WHY = "Wipe password keys before the computer sleeps"


def _variant_value(v):
    """jeepney gives variants as (signature, value)."""
    if isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str):
        return v[1]
    return v


class LogindWatcher:
    def __init__(self, *, on_lock: Callable[[int, str], None], on_sleep: Callable[[], None],
                 call_in_loop: Callable[[Callable[[], None]], None],
                 lookup_uid: Callable[[str], int | None] | None = None,
                 take_inhibitor: Callable[[], object] | None = None,
                 pending: Callable[[], bool] | None = None):
        self._on_lock = on_lock
        self._pending = pending or (lambda: False)
        self._on_sleep = on_sleep
        self._call_in_loop = call_in_loop
        self._lookup_uid = lookup_uid or self._bus_lookup_uid
        self._take_inhibitor_fn = take_inhibitor or self._bus_take_inhibitor
        self._sessions: dict[str, int] = {}
        self._owner: str | None = None
        self._inhibitor = None
        self._router = None
        self._conn = None
        self._queue: queue.Queue = queue.Queue(maxsize=256)
        self._thread: threading.Thread | None = None

    # --- the decisions (no I/O beyond the injected callables) -------------------------------
    def set_owner(self, owner: str | None) -> None:
        self._owner = owner

    def set_sessions(self, rows) -> None:
        """ListSessions rows: (id, uid, user, seat, path)."""
        self._sessions = {str(r[4]): int(r[1]) for r in rows}

    def sessions(self) -> dict[str, int]:
        return dict(self._sessions)

    def handle(self, msg) -> None:
        from jeepney import HeaderFields
        f = msg.header.fields
        sender = f.get(HeaderFields.sender)
        if self._owner is not None and sender != self._owner:
            # logind may have restarted under a new unique name; ask the bus once.
            self._refresh_owner()
            if sender != self._owner:
                return
        iface, member = f.get(HeaderFields.interface), f.get(HeaderFields.member)
        path = f.get(HeaderFields.path)
        body = msg.body
        if iface == SESSION_IFACE and member == "Lock":
            self._lock_session(path)
        elif iface == PROPS_IFACE and member == "PropertiesChanged":
            if body and body[0] == SESSION_IFACE and isinstance(body[1], dict):
                if "LockedHint" in body[1] and _variant_value(body[1]["LockedHint"]) is True:
                    self._lock_session(path)
        elif iface == MANAGER_IFACE and member == "PrepareForSleep":
            if body and body[0] is True:
                self.before_sleep()
            else:
                self.take_inhibitor()
        elif iface == MANAGER_IFACE and member == "SessionNew":
            spath = str(body[1])
            uid = self._lookup_uid(spath)
            if uid is not None:
                self._sessions[spath] = uid
        elif iface == MANAGER_IFACE and member == "SessionRemoved":
            spath = str(body[1])
            uid = self._sessions.pop(spath, None)
            if uid is not None and uid not in self._sessions.values():
                self._call_in_loop(lambda: self._on_lock(uid, "session-ended"))

    def _lock_session(self, path) -> None:
        uid = self._sessions.get(str(path))
        if uid is None:
            uid = self._lookup_uid(str(path))
            if uid is not None:
                self._sessions[str(path)] = uid
        if uid is not None:
            self._call_in_loop(lambda: self._on_lock(uid, "screen-locked"))

    def before_sleep(self) -> None:
        """Wipe every uid, then let the machine sleep - after SLEEP_WAIT_S at the most.

        The wipe itself never waits (Registry.lock). A uid whose store is inside a call (a
        systemd-creds unseal on a slow TPM, a sync) is wiped the moment that call returns; we
        give that up to SLEEP_WAIT_S and then release the inhibitor anyway. The residual risk
        is documented in docs/security.md: a call still running then keeps its keys in RAM
        across the suspend until it returns after resume."""
        deadline = time.monotonic() + SLEEP_WAIT_S
        try:
            self._call_in_loop(self._on_sleep, timeout=SLEEP_WAIT_S)
            while self._pending() and time.monotonic() < deadline:
                time.sleep(0.02)
            if self._pending():
                logger.warning("sleeping with a store call still running; its keys are "
                               "wiped when it returns")
        finally:
            self.release_inhibitor()

    def take_inhibitor(self) -> None:
        if self._inhibitor is not None:
            return
        try:
            self._inhibitor = self._take_inhibitor_fn()
        except Exception as e:
            logger.warning("no sleep inhibitor (%s); keys are still wiped on sleep, but "
                           "the machine may suspend before that finishes", type(e).__name__)

    def release_inhibitor(self) -> None:
        inh, self._inhibitor = self._inhibitor, None
        if inh is not None:
            try:
                inh.close()
            except Exception:
                pass

    # --- the bus ------------------------------------------------------------------------------
    def start(self) -> bool:
        """Connect, subscribe, read the current sessions, take the inhibitor and start the
        pump thread. Returns False (and logs) if logind cannot be reached."""
        try:
            from jeepney import DBusAddress, MatchRule, new_method_call
            from jeepney.bus_messages import message_bus
            from jeepney.io.threading import open_dbus_connection
            from ..dbus_safe import Router
            self._conn = open_dbus_connection("SYSTEM", enable_fds=True)
            # Replies only from the sender that owns the destination (dbus_safe): logind's own
            # identity, which handle() checks signals against, comes from such a reply.
            self._router = Router(self._conn)
            owner = self._call(message_bus.GetNameOwner(LOGIN1))[0]
            self.set_owner(owner)
            rules = [
                MatchRule(type="signal", interface=SESSION_IFACE, member="Lock"),
                MatchRule(type="signal", interface=PROPS_IFACE, member="PropertiesChanged"),
                MatchRule(type="signal", interface=MANAGER_IFACE, member="PrepareForSleep"),
                MatchRule(type="signal", interface=MANAGER_IFACE, member="SessionNew"),
                MatchRule(type="signal", interface=MANAGER_IFACE, member="SessionRemoved"),
            ]
            for rule in rules:
                # The bus filters by logind's well-known name; locally the sender is its
                # unique name, which handle() compares.
                bus_rule = MatchRule(type="signal", sender=LOGIN1,
                                     interface=rule.header_fields["interface"],
                                     member=rule.header_fields["member"])
                if rule.header_fields["member"] == "PropertiesChanged":
                    bus_rule.add_arg_condition(0, SESSION_IFACE)
                self._call(message_bus.AddMatch(bus_rule))
                self._router.filter(rule, queue=self._queue)
            mgr = DBusAddress(MANAGER_PATH, bus_name=LOGIN1, interface=MANAGER_IFACE)
            self.set_sessions(self._call(new_method_call(mgr, "ListSessions"))[0])
        except Exception as e:
            logger.warning("logind unavailable (%s): screen-lock and sleep wipes depend on "
                           "the window's own lock", type(e).__name__)
            self.stop()
            return False
        self.take_inhibitor()
        self._thread = threading.Thread(target=self._pump, name="pear-logind", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self.release_inhibitor()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        for obj in (self._router, self._conn):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass
        self._router = self._conn = None

    def _pump(self) -> None:
        while True:
            msg = self._queue.get()
            if msg is None:
                return
            try:
                self.handle(msg)
            except Exception:
                logger.exception("logind signal handling failed")

    def _refresh_owner(self) -> None:
        if self._router is None:
            return
        try:
            from jeepney.bus_messages import message_bus
            self._owner = self._call(message_bus.GetNameOwner(LOGIN1), timeout=5)[0]
        except Exception:
            logger.debug("GetNameOwner failed", exc_info=True)

    def _call(self, msg, timeout: float = 10):
        from jeepney.wrappers import unwrap_msg
        return unwrap_msg(self._router.send_and_get_reply(msg, timeout=timeout))

    def _bus_lookup_uid(self, path: str) -> int | None:
        if self._router is None:
            return None
        try:
            from jeepney import DBusAddress
            from jeepney.wrappers import Properties
            props = Properties(DBusAddress(path, bus_name=LOGIN1, interface=SESSION_IFACE))
            user = _variant_value(self._call(props.get("User"))[0])
            return int(user[0])
        except Exception:
            return None

    def _bus_take_inhibitor(self):
        from jeepney import DBusAddress, new_method_call
        mgr = DBusAddress(MANAGER_PATH, bus_name=LOGIN1, interface=MANAGER_IFACE)
        return self._call(new_method_call(mgr, "Inhibit", "ssss",
                                          ("sleep", INHIBIT_WHO, INHIBIT_WHY, "delay")))[0]
