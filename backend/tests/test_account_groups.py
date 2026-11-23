"""Grouping rules and the merged wire row, on plain data (no store needed).

The same rules run against a real store in test_account_groups_store.py.
"""

import unittest

from icp.daemon import wire
from icp.vstore import Meta, groups


def rec(domain, user="me", pwmac="m1", **kw):
    d = {"domain": domain, "username": user, "pwmac": pwmac, "kind": "login",
         "has_password": True, "recently_deleted": False, "apple_title": ""}
    d.update(kw)
    return d


def doc(**entries):
    return {"entries": entries}


class ComputeTests(unittest.TestCase):
    def test_same_user_and_mac_group_on_the_smallest_id(self):
        g = groups.compute(doc(c=rec("c.test"), a=rec("a.test"), b=rec("b.test")))
        self.assertEqual(g, {"a": "a", "b": "a", "c": "a"})

    def test_alone_or_different_mac_or_user(self):
        self.assertEqual(groups.compute(doc(a=rec("a.test"))), {})
        self.assertEqual(groups.compute(doc(a=rec("a.test"), b=rec("b.test", pwmac="m2"))), {})
        self.assertEqual(groups.compute(doc(a=rec("a.test"), b=rec("b.test", user="you"))), {})

    def test_never_grouped(self):
        base = rec("a.test")
        for odd in (rec("b.test", recently_deleted=True), rec("b.test", kind="passkey"),
                    rec("b.test", has_password=False), rec("b.test", user=""),
                    rec("AirPort"), rec("b.test", deleted=True), rec("b.test", pwmac=None)):
            self.assertEqual(groups.compute(doc(a=base, b=odd)), {}, odd)

    def test_two_names_are_two_accounts(self):
        g = groups.compute(doc(a=rec("a.test", apple_title="Work"),
                               b=rec("b.test", apple_title="Home"),
                               c=rec("c.test"), d=rec("d.test", apple_title="work")))
        self.assertEqual(g, {"a": "a", "c": "a", "d": "a"})
        g = groups.compute(doc(a=rec("a.test"), b=rec("b.test")), {"a": "Mine", "b": "Yours"})
        self.assertEqual(g, {})


def meta(id, domain, group="", **kw):
    base = dict(id=id, title=domain, domain=domain, sites=[], username="me", nickname="",
                has_totp=False, has_notes=False, mdat=1.0, history_count=0, group=group)
    base.update(kw)
    return Meta(**base)


class WireRowTests(unittest.TestCase):
    def test_one_row_lists_every_website(self):
        rows = wire.entries([meta("a", "a.test", "a"), meta("b", "b.test", "a"),
                             meta("c", "c.test", "a"), meta("z", "z.test")])
        self.assertEqual(len(rows), 2)
        row = next(r for r in rows if len(r["members"]) > 1)
        self.assertCountEqual(row["members"], ["a", "b", "c"])
        self.assertEqual(row["id"], row["members"][0])
        self.assertCountEqual([row["domain"]] + row["sites"], ["a.test", "b.test", "c.test"])
        self.assertEqual(row["own_sites"], [])
        self.assertNotIn("group", row)
        self.assertEqual(next(r for r in rows if r["id"] == "z")["members"], ["z"])

    def test_row_is_the_member_with_the_code_and_keeps_extra_sites(self):
        (row,) = wire.entries([meta("a", "a.test", "a", mdat=5.0),
                               meta("b", "b.test", "a", has_totp=True, sites=["b2.test"])])
        self.assertEqual(row["id"], "b")
        self.assertTrue(row["has_totp"])
        self.assertEqual(row["mdat"], 5.0)
        self.assertCountEqual(row["sites"], ["a.test", "b2.test"])
        self.assertEqual(row["own_sites"], ["b2.test"])

    def test_ungrouped_meta_is_unchanged(self):
        (row,) = wire.entries([meta("a", "a.test", sites=["x.test"])])
        self.assertEqual((row["members"], row["sites"], row["own_sites"]),
                         (["a"], ["x.test"], ["x.test"]))


if __name__ == "__main__":
    unittest.main()
