"""A Wi-Fi network's tags are read-only (VM gap: Wi-Fi had no Tags row).

Apple keeps a network in the WiFi zone as one genp item (service AirPort) with no details
record, so there are no notes Apple syncs for it: nowhere for tags, notes, websites or a code to
go. The window shows a network's tags without an edit; `set` refuses those fields before the
grant is used or anything is pushed. The network's password and name still go through.
"""

import unittest

from daemon_fakes import Harness, meta, secrets


class WifiSetTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.h = await Harness().start()
        self.st = self.h.seed()
        self.st.metas["e.wf"] = meta("e.wf", title="Home", domain="AirPort", username="Home",
                                     tags=["home"])
        self.st.secrets["e.wf"] = secrets(password="wifi-pw-fake", notes="Tags: #home")
        self.ui, _ = await self.h.ui()
        await self.h.unlock(self.ui)

    async def asyncTearDown(self):
        await self.h.stop()

    async def test_details_are_refused_before_any_push(self):
        await self.ui.call("grant", id="e.wf")
        for fields in ({"tags": ["home", "family"]}, {"tags": []}, {"notes": "x"},
                       {"sites": ["example.com"]}, {"password": "new-pw-fake", "tags": ["a"]}):
            r = await self.ui.call("set", id="e.wf", fields=fields)
            want = "tags" if "tags" in fields else next(iter(fields))
            self.assertEqual((r.get("error"), r.get("field")), ("invalid", want), fields)
        self.assertNotIn("push_set", str(self.h.apple.calls))
        # Refused before the grant is used: it still reveals.
        self.assertIn("value", await self.ui.call("reveal", id="e.wf", field="password"))

    async def test_the_password_still_changes(self):
        await self.ui.call("grant", id="e.wf")
        r = await self.ui.call("set", id="e.wf", fields={"password": "new-pw-fake"})
        self.assertNotIn("error", r)
        self.assertIn(("push_set", "e.wf", ["password"]), self.h.apple.calls)

    async def test_a_login_still_takes_tags(self):
        await self.ui.call("grant", id="e.0")
        r = await self.ui.call("set", id="e.0", fields={"tags": ["work"]})
        self.assertNotIn("error", r)
        self.assertIn(("push_set", "e.0", ["tags"]), self.h.apple.calls)


if __name__ == "__main__":
    unittest.main()
