"""The Hide My Email alias cache (hme/store.py) over the v2 store.

1.x deleted this cache whenever it would not decrypt. The adapter must never do that: a
damaged aliases.v2 raises and stays on disk.

Run: PYTHONPATH=backend .venv/bin/python -m pytest backend/tests/test_hme_store.py
"""

import unittest

from test_store_v2 import UID, StoreCase

from icp import vstore
from icp.hme import store as aliases_store
from icp.hme.client import HmeAlias

ALIAS = HmeAlias(anonymous_id="a1", address="quiet-otter@icloud.example", label="Claude",
                 note="signup", forward_to="me@example.test", is_active=True,
                 domain="claude.ai", created_at=1700000000.0)


class AliasesRoundTripTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.s = vstore.UserStore.create(UID)

    def test_save_then_load(self):
        self.assertEqual(aliases_store.load_aliases(self.s), [])  # empty before save
        aliases_store.save_aliases(self.s, [ALIAS])
        self.assertEqual(aliases_store.load_aliases(self.s), [ALIAS])
        self.s.lock()
        again = vstore.UserStore.open(UID)
        again.unlock()
        self.assertEqual(aliases_store.load_aliases(again), [ALIAS])

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(aliases_store.load_aliases(self.s), [])

    def test_incomplete_records_are_skipped(self):
        self.s.save_aliases([{"anonymous_id": "x"}, ALIAS.__dict__])
        self.assertEqual(aliases_store.load_aliases(self.s), [ALIAS])

    def test_undecryptable_cache_is_kept_not_discarded(self):
        aliases_store.save_aliases(self.s, [ALIAS])
        f = self.udir / "aliases.v2"
        f.write_bytes(f.read_bytes()[:-2])
        data = f.read_bytes()
        with self.assertRaises(vstore.SealError):
            aliases_store.load_aliases(self.s)
        self.assertEqual(f.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
