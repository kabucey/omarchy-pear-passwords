"""The browser's own unlock, on the real server and registry (daemon_fakes.Harness).

With the Pear window closed or locked, autofill-names asks one `.autofill-names` dialog and
that approval also unlocks the store, for that autofill connection only: the browser needs no
window. It ends AUTOFILL_OPEN_S after that connection's last request, when the connection
closes, or on any lock; another connection sees "locked" throughout; every fill still asks.
"""

import asyncio
import unittest
from unittest import mock

from daemon_fakes import Harness

from icp.daemon import paths, protocol

ORIGIN = "https://site0.example"


class BrowserUnlockTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.h = await Harness().start()
        self.h.seed()
        await self.h.enable_autofill()
        self.store = self.h.store()

    async def asyncTearDown(self):
        await self.h.stop()

    async def browser(self):
        c, reply = await self.h.hello("autofill")
        self.assertEqual(reply["state"], "locked")
        return c

    async def test_one_dialog_unlocks_for_this_browser_only(self):
        c = await self.browser()
        r = await c.call("autofill-query", origin=ORIGIN)
        self.assertEqual({k: v for k, v in r.items() if k != "rid"}, {"state": "locked"})
        self.assertEqual(self.h.authority.actions(), [])
        r = await c.call("autofill-names", origin=ORIGIN)
        self.assertEqual(self.h.authority.actions(), [paths.ACTION_AUTOFILL_NAMES])
        self.assertEqual(self.h.authority.calls[0][2], {"origin": "site0.example"})
        self.assertEqual(r["state"], "unlocked")
        self.assertEqual([(a["username"], a["label"]) for a in r["accounts"]],
                         [("user0", "Site 0 — user0")])
        self.assertTrue(self.store.keys)
        self.assertNotIn("pw-0-fake", repr(r))
        # another program's connection learns nothing from it
        other = await self.browser()
        self.assertEqual((await other.call("autofill-query", origin=ORIGIN))["state"], "locked")
        # the fill is a second dialog, and works without any window
        f = await c.call("autofill-fill", origin=ORIGIN, id=r["accounts"][0]["id"])
        self.assertEqual((f["username"], f["password"]), ("user0", "pw-0-fake"))
        self.assertEqual(self.h.authority.actions(),
                         [paths.ACTION_AUTOFILL_NAMES, paths.ACTION_AUTOFILL])

    async def test_it_ends_when_the_browser_disconnects(self):
        c = await self.browser()
        await c.call("autofill-names", origin=ORIGIN)
        self.assertTrue(self.store.keys)
        c.close()
        for _ in range(100):
            if not self.store.keys:
                break
            await asyncio.sleep(0.02)
        self.assertFalse(self.store.keys)
        c2 = await self.browser()
        self.assertEqual((await c2.call("autofill-query", origin=ORIGIN))["state"], "locked")

    async def test_it_ends_after_the_browser_goes_quiet_and_requests_keep_it_open(self):
        with mock.patch.object(protocol, "AUTOFILL_OPEN_S", 0.4):
            c = await self.browser()
            await c.call("autofill-names", origin=ORIGIN)
            for _ in range(3):                         # 0.75 s of requests, 0.25 s apart
                await asyncio.sleep(0.25)
                self.assertEqual((await c.call("autofill-query", origin=ORIGIN))["state"],
                                 "unlocked")
            await asyncio.sleep(0.7)
            self.assertFalse(self.store.keys)
            self.assertEqual((await c.call("autofill-query", origin=ORIGIN))["state"],
                             "locked")

    async def test_a_refused_dialog_unlocks_nothing(self):
        from icp.daemon import polkit
        self.h.authority.outcome = polkit.DENIED
        c = await self.browser()
        r = await c.call("autofill-names", origin=ORIGIN)
        self.assertEqual(r.get("error"), "denied")
        self.assertFalse(self.store.keys)
        self.assertNotIn("unlock", self.store.calls)

    async def test_the_window_closing_or_a_lock_ends_it_too(self):
        c = await self.browser()
        await c.call("autofill-names", origin=ORIGIN)
        self.h.reg.lock_all("sleep")
        self.assertFalse(self.store.keys)
        self.assertEqual((await c.call("autofill-query", origin=ORIGIN))["state"], "locked")
        # and the next request for names is a fresh dialog and a fresh unlock
        r = await c.call("autofill-names", origin=ORIGIN)
        self.assertEqual(r["state"], "unlocked")
        self.assertTrue(self.store.keys)
        self.assertEqual(self.h.authority.actions(), [paths.ACTION_AUTOFILL_NAMES] * 2)

    async def test_an_empty_store_never_asks(self):
        self.store.exists = False
        c, reply = await self.h.hello("autofill")
        self.assertEqual(reply["state"], "unavailable")
        r = await c.call("autofill-names", origin=ORIGIN)
        self.assertEqual({k: v for k, v in r.items() if k != "rid"}, {"state": "unavailable"})
        self.assertEqual(self.h.authority.actions(), [])


if __name__ == "__main__":
    unittest.main()
