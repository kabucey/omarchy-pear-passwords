"""The 1.x-shaped vault adapters (vault/store.py, history.py, nicknames.py) over the v2 store.

Run: PYTHONPATH=backend .venv/bin/python -m pytest backend/tests/test_vault.py
"""

import unittest

from test_store_v2 import UID, StoreCase

from icp import vstore
from icp.vault import history, nicknames
from icp.vault import store as vault
from icp.vault.host import Credential, CredentialStore


class VaultAdapterTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.s = vstore.UserStore.create(UID)

    def test_save_then_load(self):
        self.assertEqual(len(vault.load_vault(self.s)), 0)  # empty before save

        creds = CredentialStore([
            Credential("example.com", "alice", "pw1", "Example"),
            Credential("login.bank.test", "bob", "pw2", "Bank", notes="n",
                       totp={"secret": b"seed", "digits": 6, "period": 30, "algorithm": 0}),
        ])
        self.assertEqual(vault.save_vault(self.s, creds)["added"], 2)

        loaded = vault.load_vault(self.s)
        self.assertEqual(len(loaded), 2)
        hit = loaded.match("www.example.com")
        self.assertEqual(hit[0].username, "alice")
        self.assertEqual(loaded.match("bank.test")[0].username, "bob")
        # Tier 1 only: no secret comes back from load_vault.
        for c in loaded.all():
            self.assertEqual((c.password, c.notes, c.totp), ("", "", None))
        bob = vault.credential_id(creds.all()[1])
        got = self.s.open_entry(bob)
        self.assertEqual((got.password, got.notes, got.totp_secret), ("pw2", "n", b"seed"))
        self.assertEqual(self.s.unseal_count, 1)

    def test_full_save_tombstones_what_is_gone(self):
        vault.save_vault(self.s, CredentialStore([Credential("a.test", "u", "1"),
                                                  Credential("b.test", "u", "2")]))
        counts = vault.save_vault(self.s, CredentialStore([Credential("b.test", "u", "3")]))
        self.assertEqual(counts, {"added": 0, "changed": 1, "deleted": 1, "unchanged": 0})
        self.assertEqual([c.domain for c in vault.load_vault(self.s).all()], ["b.test"])
        self.assertEqual(self.s.unseal_count, 0)

    def test_duplicate_accounts_collapse_to_the_newest(self):
        items = vault.sync_items([Credential("a.test", "u", "1", mdat=5.0),
                                  Credential("a.test", "u", "2", mdat=9.0),
                                  Credential("b.test", "u", "3")])
        self.assertEqual([i.meta.domain for i in items], ["a.test", "b.test"])
        self.assertEqual(items[0].secrets.password, "2")
        self.assertEqual([i.meta.id for i in items], [i.id for i in items])

    def test_history_adapter(self):
        vault.save_vault(self.s, CredentialStore([Credential("a.test", "u", "old")]))
        vault.save_vault(self.s, CredentialStore([Credential("a.test", "u", "new")]))
        id = vault.credential_id(Credential("a.test", "u", ""))
        got = history.for_entry(self.s, id)
        self.assertEqual([(h["value"], h["source"]) for h in got], [("old", "local")])
        self.assertRegex(got[0]["date"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_nicknames_adapter(self):
        self.assertEqual(nicknames.load(self.s), {})
        nicknames.set_for(self.s, "kid", "  Work   VPN  ")
        self.assertEqual(nicknames.load(self.s), {"kid": "Work VPN"})
        nicknames.set_for(self.s, "kid", "   ")
        self.assertEqual(nicknames.load(self.s), {})
        self.assertEqual(len(nicknames.clean("x" * 200)), nicknames.MAX_LEN)

    def test_locked_store_raises_instead_of_discarding(self):
        vault.save_vault(self.s, CredentialStore([Credential("a.test", "u", "1")]))
        self.s.lock()
        for call in (lambda: vault.load_vault(self.s), lambda: nicknames.load(self.s),
                     lambda: vault.save_vault(self.s, CredentialStore([]))):
            with self.assertRaises(vstore.StoreLocked):
                call()
        self.s.unlock()
        self.assertEqual(len(vault.load_vault(self.s)), 1)


if __name__ == "__main__":
    unittest.main()
