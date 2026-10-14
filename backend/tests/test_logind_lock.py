"""Lock triggers (docs/protocol.md 4.2): logind signals, sleep, session end, window EOF, and
what a lock wipes."""

import asyncio
import unittest

from daemon_fakes import UID, Harness
from jeepney import DBusAddress, HeaderFields, new_signal

from icp.daemon import logind

LOGIND = ":1.7"
S1 = "/org/freedesktop/login1/session/_31"
S2 = "/org/freedesktop/login1/session/_32"


def signal(path, iface, member, sig=None, body=(), sender=LOGIND):
    msg = new_signal(DBusAddress(path, interface=iface), member, sig, body)
    msg.header.fields[HeaderFields.sender] = sender
    return msg


class Inhibitor:
    def __init__(self, log):
        self.log = log

    def close(self):
        self.log.append("inhibitor released")


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.log = []
        self.w = logind.LogindWatcher(
            on_lock=lambda uid, reason: self.log.append(("lock", uid, reason)),
            on_sleep=lambda: self.log.append("wipe all"),
            call_in_loop=lambda fn, **kw: fn(),
            lookup_uid=lambda path: {S2: 2000}.get(path),
            take_inhibitor=lambda: (self.log.append("inhibitor taken"), Inhibitor(self.log))[1])
        self.w.set_owner(LOGIND)
        self.w.set_sessions([("31", 1000, "me", "seat0", S1), ("c2", 1000, "me", "", "/x")])

    def test_lock_signal(self):
        self.w.handle(signal(S1, logind.SESSION_IFACE, "Lock"))
        self.assertEqual(self.log, [("lock", 1000, "screen-locked")])

    def test_locked_hint(self):
        self.w.handle(signal(S1, logind.PROPS_IFACE, "PropertiesChanged", "sa{sv}as",
                             (logind.SESSION_IFACE, {"LockedHint": ("b", False)}, [])))
        self.assertEqual(self.log, [])
        self.w.handle(signal(S1, logind.PROPS_IFACE, "PropertiesChanged", "sa{sv}as",
                             (logind.SESSION_IFACE, {"LockedHint": ("b", True)}, [])))
        self.assertEqual(self.log, [("lock", 1000, "screen-locked")])

    def test_other_interfaces_properties_ignored(self):
        self.w.handle(signal(S1, logind.PROPS_IFACE, "PropertiesChanged", "sa{sv}as",
                             ("org.example.Other", {"LockedHint": ("b", True)}, [])))
        self.assertEqual(self.log, [])

    def test_forged_sender_is_ignored(self):
        self.w.handle(signal(S1, logind.SESSION_IFACE, "Lock", sender=":1.666"))
        self.assertEqual(self.log, [])

    def test_unknown_session_is_looked_up(self):
        self.w.handle(signal(S2, logind.SESSION_IFACE, "Lock"))
        self.assertEqual(self.log, [("lock", 2000, "screen-locked")])
        self.assertEqual(self.w.sessions()[S2], 2000)

    def test_sleep_wipes_before_releasing_the_inhibitor(self):
        self.w.take_inhibitor()
        self.w.handle(signal(logind.MANAGER_PATH, logind.MANAGER_IFACE, "PrepareForSleep", "b",
                             (True,)))
        self.assertEqual(self.log, ["inhibitor taken", "wipe all", "inhibitor released"])
        self.w.handle(signal(logind.MANAGER_PATH, logind.MANAGER_IFACE, "PrepareForSleep", "b",
                             (False,)))
        self.assertEqual(self.log[-1], "inhibitor taken")

    def test_sleep_releases_even_if_the_wipe_fails(self):
        def broken():
            raise RuntimeError("loop gone")
        self.w._on_sleep = broken
        self.w.take_inhibitor()
        with self.assertRaises(RuntimeError):
            self.w.before_sleep()
        self.assertEqual(self.log[-1], "inhibitor released")

    def test_session_end_locks_only_after_the_last_session(self):
        self.w.handle(signal(logind.MANAGER_PATH, logind.MANAGER_IFACE, "SessionRemoved", "so",
                             ("31", S1)))
        self.assertEqual(self.log, [])                    # /x is still a session of 1000
        self.w.handle(signal(logind.MANAGER_PATH, logind.MANAGER_IFACE, "SessionRemoved", "so",
                             ("c2", "/x")))
        self.assertEqual(self.log, [("lock", 1000, "session-ended")])

    def test_session_new_is_tracked(self):
        self.w.handle(signal(logind.MANAGER_PATH, logind.MANAGER_IFACE, "SessionNew", "so",
                             ("32", S2)))
        self.w.handle(signal(logind.MANAGER_PATH, logind.MANAGER_IFACE, "SessionRemoved", "so",
                             ("32", S2)))
        self.assertEqual(self.log, [("lock", 2000, "session-ended")])

    def test_no_bus_is_not_fatal(self):
        w = logind.LogindWatcher(on_lock=lambda *a: None, on_sleep=lambda: None,
                                 call_in_loop=lambda fn, **kw: fn())
        w._take_inhibitor_fn = lambda: (_ for _ in ()).throw(OSError("no bus"))
        with self.assertLogs("icp.daemon.logind", "WARNING"):
            w.take_inhibitor()


class LockEffectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.h = await Harness().start()
        self.st = self.h.seed()
        self.ui, self.peer = await self.h.ui()
        await self.ui.call("unlock")
        await self.h.enable_autofill()
        self.af, hello = await self.h.hello("autofill")
        self.assertEqual(hello["state"], "unlocked")

    async def asyncTearDown(self):
        await self.h.stop()

    async def _clip(self):
        r = await self.ui.call("copy", id="e.1", field="username")
        c, _ = await self.h.hello("clip", peer=self.h.peer(ppid=self.peer.pid),
                                  ticket=r["ticket"])
        return c

    async def test_screen_lock_wipes_everything(self):
        await self.ui.call("grant", id="e.0")
        g = self.h.reg.grants.current(UID)
        clip = await self._clip()
        r = await self.ui.call("copy", id="e.1", field="domain")    # an unredeemed ticket
        clip = await self._clip()
        self.h.reg.lock(UID, "screen-locked")
        self.assertFalse(self.st.keys)
        self.assertIsNone(g.secrets)
        self.assertEqual(self.h.reg.tickets.pending(UID), 0)
        self.assertEqual((await clip.event("withdraw"))["event"], "withdraw")
        await asyncio.wait_for(clip.closed.wait(), 5)
        self.assertEqual((await self.ui.event("locked"))["reason"], "screen-locked")
        self.assertEqual(await self.af.event("state"), {"event": "state", "state": "locked",
                                                        "_seen": True})
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "locked")
        del r

    async def test_lock_op(self):
        r = await self.ui.call("lock")
        self.assertEqual(r, {"rid": self.ui.rid, "locked": True})
        ev = await self.ui.event("locked")
        self.assertEqual(ev["reason"], "user")
        self.assertLess(self.ui.raw.index(r), self.ui.raw.index(ev))   # reply first
        self.assertFalse(self.st.keys)

    async def test_window_eof_locks(self):
        clip = await self._clip()
        self.ui.close()
        await asyncio.wait_for(clip.closed.wait(), 5)
        self.assertFalse(self.st.keys)
        self.assertEqual((await self.af.event("state"))["state"], "locked")
        ui2, _ = await self.h.ui()
        self.assertEqual(ui2.hello["state"], "locked")
        self.assertEqual((await ui2.call("grant", id="e.0"))["error"], "locked")

    async def test_sleep_locks_every_uid(self):
        self.h.reg.lock_all("sleep")
        self.assertFalse(self.st.keys)
        self.assertEqual((await self.ui.event("locked"))["reason"], "sleep")

    async def test_lock_landing_during_unlock_wipes_the_keys(self):
        await self.ui.call("lock")
        self.h.authority.block = True
        self.h.authority.started.clear()
        pending = self.ui.send("unlock")
        await asyncio.to_thread(self.h.authority.started.wait, 5)
        self.h.reg.lock(UID, "screen-locked")
        r = await asyncio.wait_for(pending, 5)
        self.assertEqual(r["error"], "cancelled")
        self.assertFalse(self.st.keys)

    async def test_lock_after_approval_before_unseal(self):
        await self.ui.call("lock")
        real_unlock = self.st.unlock

        def unlock_then_lock():
            real_unlock()
            asyncio.run_coroutine_threadsafe(self._lock_now(), self.loop).result(5)
        self.loop = asyncio.get_running_loop()
        self.st.unlock = unlock_then_lock
        r = await self.ui.call("unlock")
        self.assertEqual(r["error"], "cancelled")
        self.assertFalse(self.st.keys)
        self.assertFalse(self.h.reg.get(UID).unlocked())

    async def _lock_now(self):
        self.h.reg.lock(UID, "screen-locked")


if __name__ == "__main__":
    unittest.main()
