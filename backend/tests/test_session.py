"""The iCloud session record lives in the per-user store (icp.auth.session).

1.x kept it in ~/.config/icp/session.enc under a master key from the login keyring, a key file
or the passphrase agent. In 2.0 none of those exist: the daemon's store seals it, and this
module only reads and writes through the store it is handed.
"""

import os
import unittest

from icp.auth import session
from icp.vstore import StoreLocked

from apple_fakes import FakeStore

ICP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "icp")


class _LockedStore(FakeStore):
    def load_session(self):
        raise StoreLocked("locked")

    def save_session(self, d):
        raise StoreLocked("locked")


class SessionStoreTests(unittest.TestCase):
    def test_signed_out_is_none(self):
        self.assertIsNone(session.load(FakeStore()))

    def test_save_then_load(self):
        store = FakeStore()
        session.save(store, {"username": "alice@example.com", "token": "t"})
        self.assertEqual(session.load(store)["username"], "alice@example.com")

    def test_load_returns_a_copy(self):
        store = FakeStore(session={"a": 1})
        s = session.load(store)
        s["a"] = 2
        self.assertEqual(store.session, {"a": 1})

    def test_clear_signs_out(self):
        store = FakeStore(session={"a": 1})
        session.clear(store)
        self.assertEqual(store.session, {})
        self.assertIsNone(session.load(store))

    def test_a_locked_store_is_an_error_not_an_empty_session(self):
        # Treating "locked" as "signed out" would make a sync after a lock try to sign in.
        with self.assertRaises(StoreLocked):
            session.load(_LockedStore())
        with self.assertRaises(StoreLocked):
            session.save(_LockedStore(), {"a": 1})

    def test_no_key_source_of_its_own(self):
        with open(os.path.join(ICP, "auth", "session.py"), encoding="utf-8") as f:
            src = f.read()
        for word in ("_master_key", "secretstorage", "SecretBox", "nacl", "master.key",
                     "ICP_ALLOW_KEYFILE", "paths."):
            self.assertNotIn(word, src)
        self.assertFalse(os.path.exists(os.path.join(ICP, "auth", "agent.py")))
        self.assertFalse(os.path.exists(os.path.join(ICP, "auth", "prompt.py")))


if __name__ == "__main__":
    unittest.main()
