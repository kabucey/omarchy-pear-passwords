"""Which keychain items the list hides as Apple's own (daemon/wire.py internal_reason).

A real entry was hidden: a named entry with no website and a Google API client id as the username
(`<digits>-<hash>.apps.googleusercontent.com`, about 72 characters) and its secret as the
password. The long-username rule, meant for Apple's key-like records, took it. Anything a
person named is theirs, and the shape rules only apply to an item with no real website.
"""

import unittest

from icp.daemon import wire
from icp.vstore import Meta

CLIENT_ID = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"
UUID_SITE = "DE6A0F2C-B80B-46B5-9541-1F02C823A022"


def meta(**kw) -> Meta:
    base = dict(id="k1-test", title="", domain="", sites=[], username="", nickname="",
                has_totp=False, has_notes=False, mdat=0.0, history_count=0)
    base.update(kw)
    return Meta(**base)


def listed(m: Meta) -> bool:
    return len(wire.entries([m], features={})) == 1


class OwnersEntriesAreListedTests(unittest.TestCase):
    def test_the_reported_entry_is_listed(self):
        # As create writes it: a UUID server, label "<uuid> (<user>)", the name as Apple's title,
        # and a tag from the notes.
        m = meta(domain=UUID_SITE, username=CLIENT_ID, title=f"{UUID_SITE} ({CLIENT_ID})",
                 apple_title="Mail API", tags=["mail"])
        self.assertGreater(len(CLIENT_ID), 60)
        self.assertTrue(listed(m))
        self.assertEqual(wire.entries([m], features={})[0]["primary"], "Mail API")

    def test_named_untagged_and_nicknamed_entries_are_listed(self):
        for extra in ({"apple_title": "My API"}, {"nickname": "api"}, {"tags": ["work"]}):
            m = meta(domain=UUID_SITE, username=CLIENT_ID, title=UUID_SITE, **extra)
            self.assertTrue(listed(m), extra)

    def test_a_real_site_keeps_a_long_or_numeric_username(self):
        self.assertTrue(listed(meta(domain="console.cloud.google.com", username=CLIENT_ID,
                                    title="console.cloud.google.com")))
        self.assertTrue(listed(meta(domain="mybank.example", username="12345678",
                                    title="mybank.example")))
        self.assertTrue(listed(meta(domain="AirPort", username="1234567", title="1234567")))


class ApplesOwnRecordsStayHiddenTests(unittest.TestCase):
    def test_apple_markers_hide_wherever_they_are(self):
        for user, title in (("PCSBoundaryKey-abc", ""), ("com.apple.account.Foo", ""),
                            ("x CHIPPlugin y", ""), ("_AppleSomething", "")):
            m = meta(domain="example.com", username=user, title=title or "example.com")
            self.assertFalse(listed(m), user)

    def test_shape_rules_still_hide_unnamed_items_without_a_site(self):
        self.assertEqual(wire.internal_reason(wire.meta_to_wire(
            meta(domain="", username="A" * 61, title="")) | {"_real_title": ""}), "long-username")
        self.assertEqual(wire.internal_reason(wire.meta_to_wire(
            meta(domain="", username="123456789", title="")) | {"_real_title": ""}), "numeric-id")
        self.assertFalse(listed(meta(domain=UUID_SITE, username="B" * 70, title=UUID_SITE)))


if __name__ == "__main__":
    unittest.main()
