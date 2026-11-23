"""One account on several websites is one listing (vstore/groups.py, daemon/wire.py).

Apple keeps one keychain item per website with the same account and password and no field that
points from one to the other, so the daemon groups by username plus pwmac: nothing is opened,
and no password or MAC reaches the window.
"""

import dataclasses

from test_pwmac_sync_diff import _SyncCase
from test_store_v2 import item

from icp.daemon import wire


def _titled(it, apple_title):
    return dataclasses.replace(it, meta=dataclasses.replace(it.meta, apple_title=apple_title))


class GroupingTests(_SyncCase):
    def test_same_account_and_password_is_one_group(self):
        a, b, c = (item("a.example.test", "me", "pw"), item("b.example.test", "me", "pw"),
                   item("c.example.test", "me", "pw"))
        self.s.apply_sync([a, b, c], set())
        metas = self.s.list_meta()
        self.assertEqual(len({m.group for m in metas}), 1)
        self.assertTrue(all(m.group for m in metas))
        self.assertEqual(self.s.group_members(b.id)[0], b.id)
        self.assertEqual(sorted(self.s.group_members(b.id)), sorted([a.id, b.id, c.id]))
        self.assertNoUnseal()

    def test_different_password_or_user_stays_apart(self):
        self.s.apply_sync([item("a.example.test", "me", "pw"),
                           item("b.example.test", "me", "other"),
                           item("c.example.test", "you", "pw")], set())
        self.assertEqual({m.group for m in self.s.list_meta()}, {""})

    def test_different_names_stay_apart(self):
        self.s.apply_sync([_titled(item("a.example.test", "me", "pw"), "Work"),
                           _titled(item("b.example.test", "me", "pw"), "Home"),
                           item("c.example.test", "me", "pw")], set())
        groups = {m.domain: m.group for m in self.s.list_meta()}
        self.assertEqual(groups["a.example.test"], groups["c.example.test"])
        self.assertNotEqual(groups["a.example.test"], "")
        self.assertEqual(groups["b.example.test"], "")

    def test_deleted_member_leaves_the_group(self):
        a, b = item("a.example.test", "me", "pw"), item("b.example.test", "me", "pw")
        self.s.apply_sync([a, b], set())
        self.s.apply_sync([], {b.id})
        self.assertEqual(self.s.list_meta()[0].group, "")
        self.assertEqual(self.s.group_members(a.id), [a.id])

    def test_password_change_splits_the_group(self):
        a, b = item("a.example.test", "me", "pw"), item("b.example.test", "me", "pw")
        self.s.apply_sync([a, b], set())
        self.s.apply_sync([item("a.example.test", "me", "new")], set())
        self.assertEqual({m.group for m in self.s.list_meta()}, {""})


class WireTests(_SyncCase):
    def test_one_row_with_every_website(self):
        a, b, c = (item("a.example.test", "me", "pw"), item("b.example.test", "me", "pw"),
                   item("c.example.test", "me", "pw"))
        lone = item("z.example.test", "me", "different")
        self.s.apply_sync([a, b, c, lone], set())
        rows = wire.entries(self.s.list_meta(), features={})
        self.assertEqual(len(rows), 2)
        row = next(r for r in rows if len(r["members"]) > 1)
        self.assertCountEqual(row["members"], [a.id, b.id, c.id])
        self.assertEqual(row["id"], row["members"][0])
        self.assertCountEqual([row["domain"]] + row["sites"],
                              ["a.example.test", "b.example.test", "c.example.test"])
        self.assertEqual(row["own_sites"], [])
        self.assertNotIn("group", row)
        self.assertNotIn("pwmac", repr(rows))
        lone_row = next(r for r in rows if r["id"] == lone.id)
        self.assertEqual(lone_row["members"], [lone.id])

    def test_row_keeps_code_and_extra_sites_of_members(self):
        a, b = item("a.example.test", "me", "pw"), item("b.example.test", "me", "pw")
        b = dataclasses.replace(b, meta=dataclasses.replace(b.meta, sites=["b2.example.test"]),
                                secrets=dataclasses.replace(b.secrets, totp_secret=b"x" * 10))
        self.s.apply_sync([a, b], set())
        (row,) = wire.entries(self.s.list_meta(), features={})
        self.assertEqual(row["id"], b.id)       # the member with the code leads
        self.assertTrue(row["has_totp"])
        self.assertCountEqual(row["sites"], ["a.example.test", "b2.example.test"])
        self.assertEqual(row["own_sites"], ["b2.example.test"])
