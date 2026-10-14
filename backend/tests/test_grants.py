"""Per-entry grants (docs/protocol.md 6.3-6.5): one dialog opens one account, for grant_s."""

import unittest

from daemon_fakes import FakeClock, Harness, secrets

from icp.daemon import paths, protocol
from icp.daemon.grants import GrantTable
from icp.daemon.protocol import OpError

U = 4242


class GrantTableTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.wall = FakeClock(1_800_000_000.0)
        self.t = GrantTable(self.clock, self.wall)

    def code(self, uid, id):
        with self.assertRaises(OpError) as cm:
            self.t.check(uid, id)
        return cm.exception.code

    def test_grant_is_for_that_entry_only(self):
        self.t.put(U, "A", secrets(), 120)
        self.assertEqual(self.t.check(U, "A").id, "A")
        self.assertEqual(self.code(U, "B"), "no-grant")
        self.assertEqual(self.code(U + 1, "A"), "no-grant")

    def test_expiry(self):
        g = self.t.put(U, "A", secrets(), 120)
        self.assertEqual(g.expires_wall, 1_800_000_120.0)
        self.clock.advance(119.9)
        self.t.check(U, "A")
        self.clock.advance(0.1)
        self.assertEqual(self.code(U, "A"), "grant-expired")
        self.assertIsNone(g.secrets)                    # the buffer is gone
        self.assertEqual(self.code(U, "A"), "grant-expired")

    def test_new_grant_replaces_and_wipes(self):
        g = self.t.put(U, "A", secrets(password="x"), 120)
        self.t.put(U, "B", secrets(), 120)
        self.assertIsNone(g.secrets)
        self.assertEqual(self.code(U, "A"), "no-grant")

    def test_single_use(self):
        self.t.put(U, "A", secrets(), 0)
        g, ended = self.t.use(U, "A")
        self.assertTrue(ended and g.single_use and g.expires_wall is None)
        self.assertEqual(self.code(U, "A"), "no-grant")      # spent, not yet ended
        self.t.end(U)
        self.assertEqual(self.code(U, "A"), "grant-expired")

    def test_drop_forgets(self):
        self.t.put(U, "A", secrets(), 120)
        self.t.drop(U)
        self.assertEqual(self.code(U, "A"), "no-grant")

    def test_wipe_zeroes_bytearray_seed(self):
        seed = bytearray(b"seedseedseed")
        self.t.put(U, "A", secrets(seed=seed), 120)
        self.t.drop(U)
        self.assertEqual(seed, bytearray(len(seed)))

    def test_due(self):
        self.t.put(U, "A", secrets(), 10)
        self.assertEqual(self.t.due(), [])
        self.clock.advance(10)
        self.assertEqual(self.t.due(), [(U, "A")])


class GrantFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = FakeClock()
        self.h = await Harness(clock=self.clock).start()
        self.st = self.h.seed()
        self.ui, _ = await self.h.ui()
        await self.ui.call("unlock")

    async def asyncTearDown(self):
        await self.h.stop()

    async def test_grant_raises_reveal_dialog_naming_the_account(self):
        r = await self.ui.call("grant", id="e.0")
        self.assertEqual(r["fields"], ["password", "notes", "code", "history"])
        self.assertEqual((r["grant_s"], r["single_use"]), (120, False))
        _, action, details, _ = self.h.authority.calls[-1]
        self.assertEqual(action, paths.ACTION_REVEAL)
        self.assertEqual(details, {"account": "Site 0 — user0"})
        self.assertEqual(self.st.unseal_count, 1)
        reveal = await self.ui.call("reveal", id="e.0", field="password")
        self.assertEqual((reveal["value"], reveal["hide_after"]), ("pw-0-fake", 20))
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="notes"))["value"], "note")
        self.assertEqual(self.st.unseal_count, 1)          # served from the grant buffer

    async def test_grant_for_a_does_not_open_b(self):
        await self.ui.call("grant", id="e.0")
        for op, extra in (("reveal", {"field": "password"}), ("totp", {}), ("history", {}),
                          ("copy", {"field": "password"}), ("set", {"fields": {"notes": "x"}})):
            r = await self.ui.call(op, id="e.1", **extra)
            self.assertEqual(r["error"], "no-grant", op)

    async def test_expiry_is_enforced_by_the_clock(self):
        await self.ui.call("grant", id="e.0")
        self.clock.advance(protocol.GRANT_S_DEFAULT)
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "grant-expired")
        ev = await self.ui.event("grant-expired")
        self.assertEqual(ev["id"], "e.0")
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "grant-expired")

    async def test_release_and_new_grant_end_the_old_one(self):
        await self.ui.call("grant", id="e.0")
        await self.ui.call("grant", id="e.1")
        self.assertEqual((await self.ui.event("grant-expired"))["id"], "e.0")
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "no-grant")
        self.assertEqual(await self.ui.call("release"), {"rid": self.ui.rid, "released": True})
        self.assertEqual((await self.ui.event("grant-expired"))["id"], "e.1")
        self.assertEqual((await self.ui.call("reveal", id="e.1", field="password"))["error"],
                         "no-grant")

    async def test_single_use_grant(self):
        await self.ui.call("settings", set={"grant_s": 0})
        r = await self.ui.call("grant", id="e.0")
        self.assertEqual((r["expires"], r["single_use"]), (None, True))
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["value"],
                         "pw-0-fake")
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "grant-expired")

    async def test_totp_and_history(self):
        await self.ui.call("grant", id="e.0")
        t = await self.ui.call("totp", id="e.0")
        self.assertRegex(t["code"], r"^\d{6}$")
        self.assertNotIn("seed", str(t))
        hist = await self.ui.call("history", id="e.0")
        self.assertEqual([(i["value"], i["source"]) for i in hist["items"]],
                         [("old-apple", "apple"), ("old-local", "local")])
        await self.ui.call("grant", id="e.1")
        self.assertEqual((await self.ui.call("totp", id="e.1"))["error"], "invalid")

    async def test_history_read_after_a_release_returns_nothing(self):
        # clipboard_ui-4: op_history awaits the store in a worker; a release (selecting
        # another account) that lands meanwhile must keep A's history from coming back.
        import asyncio
        import threading
        await self.ui.call("grant", id="e.0")
        started, proceed = threading.Event(), threading.Event()
        real = self.st.history

        def slow(id):
            started.set()
            proceed.wait(5)
            return real(id)
        self.st.history = slow
        pending = self.ui.send("history", id="e.0")
        await asyncio.to_thread(started.wait, 5)
        self.assertEqual((await self.ui.call("release"))["released"], True)
        proceed.set()
        r = await asyncio.wait_for(pending, 5)
        self.assertEqual(r.get("error"), "no-grant")
        self.assertNotIn("items", r)

    async def test_single_use_history_is_still_answered(self):
        await self.ui.call("settings", set={"grant_s": 0})
        await self.ui.call("grant", id="e.0")
        hist = await self.ui.call("history", id="e.0")
        self.assertEqual(len(hist["items"]), 2)

    async def test_dismissed_grant_opens_nothing(self):
        self.h.authority.outcome = "dismissed"
        self.assertEqual((await self.ui.call("grant", id="e.0"))["error"], "dismissed")
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "no-grant")
        self.assertEqual(self.st.unseal_count, 0)

    async def test_grant_needs_tier1(self):
        await self.ui.call("lock")
        self.assertEqual((await self.ui.call("grant", id="e.0"))["error"], "locked")
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "locked")

    async def test_unknown_or_malformed_id(self):
        self.assertEqual((await self.ui.call("grant", id="nope"))["error"], "not-found")
        self.assertEqual((await self.ui.call("grant", id="../../x"))["error"], "not-found")
        self.assertEqual((await self.ui.call("grant", id=5))["error"], "bad-request")
        self.assertEqual(len(self.h.authority.calls), 1)       # only the unlock

    async def test_lock_wipes_the_grant(self):
        await self.ui.call("grant", id="e.0")
        g = self.h.reg.grants.current(4242)
        await self.ui.call("lock")
        self.assertIsNone(g.secrets)
        await self.ui.call("unlock")
        self.assertEqual((await self.ui.call("reveal", id="e.0", field="password"))["error"],
                         "no-grant")


if __name__ == "__main__":
    unittest.main()
