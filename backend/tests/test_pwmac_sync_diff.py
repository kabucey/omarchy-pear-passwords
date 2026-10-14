"""Sync and edits write with PK_secret only: changes are found by pwmac and smac, old boxes
move to history unopened, and SK_secret is never unsealed.

Two independent witnesses for "never unsealed": the store's own unseal_count, and the fake
systemd-creds counting decrypt calls on the secret blob.
"""

import os

from test_store_v2 import UID, StoreCase, item

from icp import vstore
from icp.vstore import entries


class _SyncCase(StoreCase):
    def setUp(self):
        super().setUp()
        self.s = vstore.UserStore.create(UID)
        self.sk_decrypts = self.backend.count("decrypt", "secret")

    def assertNoUnseal(self):
        self.assertEqual(self.s.unseal_count, 0)
        self.assertEqual(self.backend.count("decrypt", "secret"), self.sk_decrypts)

    def box(self, id):
        return (self.udir / "entries" / f"{id}.box").read_bytes()


class SyncDiffTests(_SyncCase):
    def test_add_then_unchanged(self):
        items = [item(f"s{i}.example.test", "me", f"pw{i}") for i in range(5)]
        self.assertEqual(self.s.apply_sync(items, set()),
                         {"added": 5, "changed": 0, "deleted": 0, "unchanged": 0})
        boxes = {it.id: self.box(it.id) for it in items}
        again = [item(f"s{i}.example.test", "me", f"pw{i}") for i in range(5)]
        self.assertEqual(self.s.apply_sync(again, set()),
                         {"added": 0, "changed": 0, "deleted": 0, "unchanged": 5})
        self.assertEqual({it.id: self.box(it.id) for it in items}, boxes)  # nothing rewritten
        self.assertNoUnseal()

    def test_password_change_moves_the_old_box_unopened(self):
        it = item("a.example.test", "me", "old-pw")
        self.s.apply_sync([it], set())
        old_box = self.box(it.id)
        counts = self.s.apply_sync([item("a.example.test", "me", "new-pw")], set())
        self.assertEqual(counts["changed"], 1)
        moved = self.udir / "history" / it.id / "1.box"
        self.assertEqual(moved.read_bytes(), old_box)     # the very same ciphertext
        self.assertEqual(self.s.get_meta(it.id).history_count, 1)
        self.assertNoUnseal()
        # Only now, as a person would under a grant, open them.
        self.assertEqual(self.s.open_entry(it.id).password, "new-pw")
        hist = self.s.history(it.id)
        self.assertEqual([v for _, v in hist], ["old-pw"])
        self.assertEqual(hist[0].source, "local")
        self.assertEqual(self.s.unseal_count, 2)

    def test_notes_only_change_reseals_without_history(self):
        it = item("a.example.test", "me", "pw", notes="one")
        self.s.apply_sync([it], set())
        old_box = self.box(it.id)
        counts = self.s.apply_sync([item("a.example.test", "me", "pw", notes="two")], set())
        self.assertEqual(counts["changed"], 1)
        self.assertNotEqual(self.box(it.id), old_box)
        self.assertFalse((self.udir / "history" / it.id).exists())
        self.assertEqual(self.s.get_meta(it.id).history_count, 0)
        self.assertNoUnseal()
        self.assertEqual(self.s.open_entry(it.id).notes, "two")

    def test_metadata_only_change_keeps_the_box(self):
        it = item("a.example.test", "me", "pw", title="Old")
        self.s.apply_sync([it], set())
        old_box = self.box(it.id)
        counts = self.s.apply_sync([item("a.example.test", "me", "pw", title="New")], set())
        self.assertEqual(counts["changed"], 1)
        self.assertEqual(self.box(it.id), old_box)
        self.assertEqual(self.s.get_meta(it.id).title, "New")
        self.assertNoUnseal()

    def test_apple_history_counts_without_opening(self):
        hist = [{"date": "2026-01-01T00:00:00Z", "value": "older"}]
        it = item("a.example.test", "me", "pw", hist=hist)
        self.s.apply_sync([it], set())
        self.assertEqual(self.s.get_meta(it.id).history_count, 1)
        self.assertNoUnseal()
        got = self.s.history(it.id)
        self.assertEqual(list(got[0]), ["2026-01-01T00:00:00Z", "older"])
        self.assertEqual(got[0].source, "apple")

    def test_delete_tombstones_and_keeps_the_box(self):
        a, b = item("a.example.test", "me"), item("b.example.test", "me")
        self.s.apply_sync([a, b], set())
        counts = self.s.apply_sync([], {a.id, "kunknown"})
        self.assertEqual(counts, {"added": 0, "changed": 0, "deleted": 1, "unchanged": 0})
        self.assertEqual([m.id for m in self.s.list_meta()], [b.id])
        with self.assertRaises(vstore.EntryNotFound):
            self.s.get_meta(a.id)
        with self.assertRaises(vstore.EntryNotFound):
            self.s.open_entry(a.id)
        self.assertTrue((self.udir / "entries" / f"{a.id}.box").exists())
        self.assertEqual(self.s.pwmac_matches(["pw"]), [0])     # b still matches
        # It comes back with a new password: listed again, the old one in its history.
        counts = self.s.apply_sync([item("a.example.test", "me", "pw2")], set())
        self.assertEqual(counts["added"], 1)
        self.assertEqual(self.s.get_meta(a.id).history_count, 1)
        self.assertNoUnseal()

    def test_set_secrets_moves_history_without_sk(self):
        it = item("a.example.test", "me", "pw1")
        self.s.apply_sync([it], set())
        self.s.set_secrets(it.id, vstore.Secrets("pw2", "", None, []))
        self.s.set_secrets(it.id, vstore.Secrets("pw2", "note", None, []))   # not history
        self.assertNoUnseal()
        self.assertEqual(self.s.get_meta(it.id).history_count, 1)
        self.assertTrue(self.s.get_meta(it.id).has_notes)
        self.assertEqual(self.s.pwmac_matches(["pw1", "pw2"]), [1])
        with self.assertRaises(vstore.EntryNotFound):
            self.s.set_secrets("knope", vstore.Secrets("x", "", None, []))

    def test_history_is_capped(self):
        it = item("a.example.test", "me", "pw0")
        self.s.apply_sync([it], set())
        for n in range(1, entries.MAX_HISTORY + 4):
            self.s.apply_sync([item("a.example.test", "me", f"pw{n}")], set())
        self.assertEqual(self.s.get_meta(it.id).history_count, entries.MAX_HISTORY)
        self.assertEqual(len(os.listdir(self.udir / "history" / it.id)), entries.MAX_HISTORY)
        self.assertNoUnseal()
        values = [v for _, v in self.s.history(it.id)]
        self.assertEqual(values[0], f"pw{entries.MAX_HISTORY + 2}")
        self.assertNotIn("pw0", values)

    def test_bad_items_are_refused_before_anything_is_written(self):
        good = item("a.example.test", "me")
        bad = item("b.example.test", "me")
        bad.meta.id = "kdifferent"
        with self.assertRaises(ValueError):
            self.s.apply_sync([good, bad], set())
        evil = item("c.example.test", "me")
        evil.id = evil.meta.id = "../../etc"
        with self.assertRaises(ValueError):
            self.s.apply_sync([evil], set())
        self.assertEqual(self.s.list_meta(), [])
        self.assertEqual(os.listdir(self.udir / "entries"), [])

    def test_sync_status(self):
        self.s.set_sync_status(synced_at=5.0)
        self.assertEqual(self.s.status()["synced_at"], 5.0)
        self.assertFalse(self.s.status()["needs_login"])
        self.s.set_sync_status(needs_login=True)
        self.assertEqual(self.s.status()["synced_at"], 5.0)
        self.assertTrue(self.s.status()["needs_login"])

    def test_totp_seed_round_trips_as_bytes(self):
        it = item("a.example.test", "me", "pw", seed=b"\x00\xffseed")
        self.s.apply_sync([it], set())
        got = self.s.open_entry(it.id)
        self.assertEqual(got.totp_secret, b"\x00\xffseed")
        self.assertEqual(got.totp_params, {"digits": 6, "period": 30, "algorithm": 0})
        self.assertTrue(self.s.get_meta(it.id).has_totp)


class TagSyncTests(_SyncCase):
    """The tag line is read during sync from the plaintext already in hand: no SK."""

    def test_tags_are_extracted_without_an_unseal(self):
        it = item("a.example.test", "me", "pw", notes="body\n\nTags: #Work")
        self.s.apply_sync([it], set())
        self.assertEqual(self.s.get_meta(it.id).tags, ["work"])
        self.assertNoUnseal()

    def test_a_tag_only_change_reseals_without_history_and_updates_meta(self):
        it = item("a.example.test", "me", "pw", notes="body\n\nTags: #a")
        self.s.apply_sync([it], set())
        old_box = self.box(it.id)
        smac = self.s._doc["entries"][it.id]["smac"]
        counts = self.s.apply_sync([item("a.example.test", "me", "pw",
                                         notes="body\n\nTags: #a #b")], set())
        self.assertEqual(counts["changed"], 1)
        self.assertNotEqual(self.box(it.id), old_box)
        self.assertNotEqual(self.s._doc["entries"][it.id]["smac"], smac)
        self.assertFalse((self.udir / "history" / it.id).exists())
        self.assertEqual(self.s.get_meta(it.id).history_count, 0)
        self.assertEqual(self.s.get_meta(it.id).tags, ["a", "b"])
        self.assertNoUnseal()
        self.assertEqual(self.s.open_entry(it.id).notes, "body\n\nTags: #a #b")

    def test_set_secrets_updates_tags_too(self):
        it = item("a.example.test", "me", "pw", notes="Tags: #a")
        self.s.apply_sync([it], set())
        self.s.set_secrets(it.id, vstore.Secrets(password="pw2", notes="new\nTags: #z",
                                                 totp_secret=None, apple_history=[]))
        m = self.s.get_meta(it.id)
        self.assertEqual((m.tags, m.has_notes), (["z"], True))
        self.assertNoUnseal()

