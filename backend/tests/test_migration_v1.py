"""The one-time import of a 1.x vault (spec section 10), against the committed fixture vault
in tests/fixtures/v1_vault (fake data, known test passphrase).

Both ways the importer can get the old key are covered: the key PEEKed from a warm 1.3.2
agent (handed over as raw bytes) and the passphrase typed once in the window (Argon2id in the
daemon). A mismatch or a wrong key must leave nothing behind and change nothing in the input.
"""

import ast
import base64
import json
import os
import unittest
from pathlib import Path
from unittest import mock

import nacl.pwhash
import nacl.secret
from fixtures import V1_COUNTS, V1_PASSPHRASE, v1_files

from test_store_v2 import UID, StoreCase, item

from icp import vstore
from icp.vstore import ids, legacy

BACKEND = Path(__file__).resolve().parents[1]


def v1_key() -> bytes:
    return vstore.v1_key_from_passphrase(v1_files()["kdf.json"], V1_PASSPHRASE)


class KeyTests(StoreCase):
    def test_passphrase_derives_the_key_that_opens_check(self):
        f = v1_files()
        key = vstore.v1_key_from_passphrase(f["kdf.json"], V1_PASSPHRASE)
        self.assertEqual(len(key), 32)
        self.assertTrue(vstore.v1_key_opens(f["check.enc"], key))

    def test_wrong_passphrase_and_wrong_keys(self):
        f = v1_files()
        wrong = vstore.v1_key_from_passphrase(f["kdf.json"], V1_PASSPHRASE.upper())
        self.assertFalse(vstore.v1_key_opens(f["check.enc"], wrong))
        for bad in (b"", b"x" * 31, b"x" * 33, None, "a" * 32):
            self.assertFalse(vstore.v1_key_opens(f["check.enc"], bad))
        # A blob that opens but holds something else is not a check blob.
        key = v1_key()
        other = nacl.secret.SecretBox(key).encrypt(b"not-the-marker")
        self.assertFalse(vstore.v1_key_opens(other, key))

    def test_kdf_defaults_are_moderate(self):
        f = v1_files()
        salt = json.loads(f["kdf.json"])["salt"]
        with mock.patch("nacl.pwhash.argon2id.kdf", return_value=b"k" * 32) as kdf:
            vstore.v1_key_from_passphrase(json.dumps({"salt": salt}).encode(), "x")
        self.assertEqual(kdf.call_args.kwargs["opslimit"], nacl.pwhash.argon2id.OPSLIMIT_MODERATE)
        self.assertEqual(kdf.call_args.kwargs["memlimit"], nacl.pwhash.argon2id.MEMLIMIT_MODERATE)

    def test_kdf_json_is_bounded(self):
        salt = "00" * 16
        for doc in ({"salt": salt, "memlimit": 64 * 1024 ** 3},
                    {"salt": salt, "opslimit": 10 ** 6},
                    {"salt": salt, "opslimit": True},
                    {"salt": "00"},
                    {"salt": salt, "alg": "scrypt"},
                    {}):
            with self.assertRaises(ValueError, msg=doc):
                vstore.v1_key_from_passphrase(json.dumps(doc).encode(), "x")
        with self.assertRaises(ValueError):
            vstore.v1_key_from_passphrase(b"\xff not json", "x")


class KeyringVaultTests(StoreCase):
    """audit: a 1.x vault keyed by the login keyring (its default; no kdf.json, no check.enc)
    sent users to a 1.3.2 terminal passphrase prompt. Its key now comes from the Secret
    Service, and the daemon verifies it against vault.enc itself."""

    def keyring_files(self):
        f = v1_files()
        del f["kdf.json"], f["check.enc"]
        return f

    def test_the_key_is_verified_against_vault_enc_without_check_enc(self):
        f = self.keyring_files()
        self.assertTrue(vstore.v1_key_verifies(f, v1_key()))
        self.assertFalse(vstore.v1_key_verifies(f, bytes(32)))
        self.assertFalse(vstore.v1_key_verifies({}, v1_key()))
        for bad in (b"", b"x" * 31, None):
            self.assertFalse(vstore.v1_key_verifies(f, bad))
        # With check.enc present, check.enc decides (a passphrase vault).
        full = v1_files()
        self.assertTrue(vstore.v1_key_verifies(full, v1_key()))
        full["check.enc"] = nacl.secret.SecretBox(v1_key()).encrypt(b"not-the-marker")
        self.assertFalse(vstore.v1_key_verifies(full, v1_key()))

    def test_a_keyring_vault_imports(self):
        s = vstore.UserStore.create(UID)
        r = s.import_v1(self.keyring_files(), v1_key())
        self.assertEqual(r["counts"]["credentials"], V1_COUNTS["credentials"])
        with self.assertRaises(vstore.WrongPassphrase):
            vstore.UserStore.reset(UID).import_v1(self.keyring_files(), bytes(32))


class ImportTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.s = vstore.UserStore.create(UID)
        self.files = v1_files()
        self.pristine = {k: bytes(v) for k, v in self.files.items()}

    def tearDown(self):
        # Whatever happened, the caller's v1 bytes were not touched.
        self.assertEqual(self.files, self.pristine)
        super().tearDown()

    def by_domain(self, store):
        return {(m.domain, m.username, m.title): m for m in store.list_meta()}

    def assertNothingImported(self):
        self.assertEqual(self.s.list_meta(), [])
        self.assertFalse((self.root / f"u{UID}.tmp").exists())
        self.assertEqual(os.listdir(self.udir / "entries"), [])
        self.assertEqual(sorted(os.listdir(self.root)), [f"u{UID}"])

    def test_agent_key_path(self):
        # What PEEK gives the importer: the raw 32-byte lockbox key.
        res = self.s.import_v1(self.files, v1_key())
        self.assertEqual(res["counts"], V1_COUNTS)
        self.assertRegex(res["digest"], r"^[0-9a-f]{64}$")
        self.check_contents(self.s)
        # The import survives a lock and a fresh daemon.
        self.s.lock()
        again = vstore.UserStore.open(UID)
        again.unlock()
        self.check_contents(again)
        self.assertEqual(sorted(os.listdir(self.root)), [f"u{UID}"])

    def test_passphrase_path_matches_the_agent_path(self):
        key = vstore.v1_key_from_passphrase(self.files["kdf.json"], V1_PASSPHRASE)
        res = self.s.import_v1(self.files, key)
        self.assertEqual(res["counts"], V1_COUNTS)
        canon = legacy.to_canonical(legacy.read(self.files, key))
        self.assertEqual(res["digest"], legacy.digest(canon))

    def check_contents(self, s):
        got = self.by_domain(s)
        gh = got[("github.com", "dev@example.test", "GitHub")]
        self.assertEqual(gh.id, ids.entry_id("github.com", "dev@example.test"))
        self.assertEqual(gh.nickname, "Work GitHub")
        self.assertEqual(gh.sites, ["gist.github.com"])
        self.assertTrue(gh.has_totp)
        self.assertEqual(gh.history_count, 3)            # two local + one of Apple's
        sec = s.open_entry(gh.id)
        self.assertEqual(sec.password, "gh-TEST-pw-1")
        self.assertEqual(sec.totp_secret, b"12345678901234567890")
        self.assertEqual(sec.totp_params,
                         {"digits": 6, "period": 30, "algorithm": 0, "issuer": "GitHub"})
        hist = s.history(gh.id)
        self.assertEqual([v for _, v in hist], ["gh-TEST-old-1", "gh-TEST-old-0",
                                                "gh-TEST-old-apple"])
        self.assertEqual([h.source for h in hist], ["local", "local", "apple"])

        mail = got[("mail.example.test", "alex@example.test", "mail.example.test")]
        m = s.open_entry(mail.id)
        self.assertEqual(m.totp_secret, base64.b32decode("JBSWY3DPEHPK3PXP"))   # raw, not text
        self.assertEqual((m.totp_params["digits"], m.totp_params["period"],
                          m.totp_params["algorithm"]), (8, 60, 1))
        self.assertEqual(mail.aliases, ["webmail.example.test"])

        bank = got[("bank.example.test", "alex", "Bank")]
        self.assertEqual(bank.nickname, "TEST bank")
        self.assertTrue(bank.has_notes)
        self.assertEqual(s.open_entry(bank.id).notes, "PIN hint: TEST only")
        self.assertEqual([v for _, v in s.history(bank.id)], ["bank-TEST-old"])

        shop = [m for m in got.values() if m.domain == "shop.example.test"]
        base = ids.entry_id("shop.example.test", "sam")
        self.assertEqual([m.id for m in shop], [base])
        self.assertEqual(shop[0].title, "Shop (second item)")             # the newer item
        self.assertEqual(s.open_entry(base).password, "shop-TEST-pw-b")
        self.assertEqual([(v, h.source) for v, h in ((h[1], h) for h in s.history(base))],
                         [("shop-TEST-pw-a", "local")])

        self.assertEqual(s.load_session()["dsid"], "0000TEST")
        self.assertEqual(len(s.load_session()), 5)
        self.assertEqual([a["anonymous_id"] for a in s.load_aliases()], ["a-TEST-1", "a-TEST-2"])
        self.assertEqual(s.load_device()["serial"], "C02TEST00000")
        self.assertTrue(s.status()["signed_in"])

    def test_orphaned_history_is_kept_on_a_tombstone(self):
        self.s.import_v1(self.files, v1_key())
        gone = ids.entry_id("gone.example.test", "old-user")
        with self.assertRaises(vstore.EntryNotFound):
            self.s.get_meta(gone)
        self.assertNotIn(gone, [m.id for m in self.s.list_meta()])
        # If iCloud brings the account back, 1.x's history for it is still there.
        self.s.apply_sync([item("gone.example.test", "old-user", "gone-TEST-pw")], set())
        self.assertEqual([v for _, v in self.s.history(gone)], ["gone-TEST-old"])

    def test_first_sync_after_import_changes_nothing(self):
        """The Apple pipeline computes ids the same way, so re-syncing the same keychain
        updates the imported entries instead of replacing them (and their history)."""
        from icp.vault import store as vault_store
        from icp.vault.host import Credential, CredentialStore
        self.s.import_v1(self.files, v1_key())
        creds = [Credential(**{k: v for k, v in c.items() if k != "totp"},
                            totp=c.get("totp"))
                 for c in legacy.read(self.files, v1_key()).credentials]
        before = self.s.unseal_count
        counts = vault_store.save_vault(self.s, CredentialStore(creds))
        self.assertEqual(counts, {"added": 0, "changed": 0, "deleted": 0, "unchanged": 5})
        self.assertEqual(self.s.unseal_count, before)

    def test_first_apple_sync_after_import_changes_nothing(self):
        """The same, through the code a real sync runs (icp.octagon.items, as daemon.apple
        calls it): no entry is added, re-sealed or tombstoned, so nicknames and history stay."""
        from icp.octagon import items as oct_items
        from icp.vault.host import Credential
        self.s.import_v1(self.files, v1_key())
        before_meta = {m.id: m for m in self.s.list_meta()}
        creds = [Credential(**{k: v for k, v in c.items() if k != "totp"},
                            totp=c.get("totp"))
                 for c in legacy.read(self.files, v1_key()).credentials]
        sync = oct_items.to_sync_items(creds, self.s.load_nicknames())
        self.assertEqual(sorted(i.id for i in sync), sorted(before_meta))
        before = self.s.unseal_count
        counts = self.s.apply_sync(sync, set(before_meta) - {i.id for i in sync})
        self.assertEqual(counts, {"added": 0, "changed": 0, "deleted": 0, "unchanged": 5})
        self.assertEqual(self.s.unseal_count, before)
        after = {m.id: m for m in self.s.list_meta()}
        self.assertEqual(after, before_meta)

    def test_wrong_key_changes_nothing(self):
        wrong = vstore.v1_key_from_passphrase(self.files["kdf.json"], "not it")
        with self.assertRaises(vstore.WrongPassphrase):
            self.s.import_v1(self.files, wrong)
        self.assertNothingImported()
        # ... and the right one still works afterwards.
        self.assertEqual(self.s.import_v1(self.files, v1_key())["counts"], V1_COUNTS)

    def test_mismatch_leaves_nothing(self):
        """A conversion that does not read back the same must not be kept. Here the writer is
        made to seal one wrong password; the read-back digest catches it."""
        real = legacy.secrets_from_canonical

        def tampered(d):
            s = real(d)
            if s.password == "bank-TEST-pw":
                s.password = "bank-TEST-pw-but-wrong"
            return s

        with mock.patch.object(legacy, "secrets_from_canonical", side_effect=tampered):
            with self.assertRaises(vstore.ImportMismatch):
                self.s.import_v1(self.files, v1_key())
        self.assertNothingImported()

    def test_missing_entry_box_is_a_mismatch(self):
        from icp.vstore import entries
        real = entries.EntryFiles.write
        bank = ids.entry_id("bank.example.test", "alex")

        def drop(files_self, id, blob):
            if id != bank:
                real(files_self, id, blob)

        with mock.patch.object(entries.EntryFiles, "write", drop):
            with self.assertRaises(vstore.ImportMismatch):
                self.s.import_v1(self.files, v1_key())
        self.assertNothingImported()

    def test_v1_file_that_does_not_open_is_a_mismatch(self):
        broken = dict(self.files)
        broken["nicknames.enc"] = broken["nicknames.enc"][:-1] + b"\x00"
        with self.assertRaises(vstore.ImportMismatch):
            self.s.import_v1(broken, v1_key())
        self.assertNothingImported()

    def test_bad_input_is_refused(self):
        key = v1_key()
        for bad in ({k: v for k, v in self.files.items() if k != "vault.enc"},
                    {**self.files, "master.key": b"x"},
                    {**self.files, "vault.enc": "text, not bytes"},
                    {**self.files, "history.enc": b"x" * (4 * 1024 * 1024 + 1)}):
            with self.assertRaises(vstore.StoreError):
                self.s.import_v1(bad, key)
        self.assertNothingImported()

    def test_optional_files_may_be_absent(self):
        minimal = {k: self.files[k] for k in ("vault.enc", "kdf.json", "check.enc")}
        res = self.s.import_v1(minimal, v1_key())
        self.assertEqual(res["counts"], {"credentials": 5, "history": 1, "nicknames": 0,
                                         "aliases": 0, "session_keys": 0})
        self.assertFalse(self.s.status()["signed_in"])

    def test_never_merges_into_a_store_with_entries(self):
        self.s.apply_sync([item("x.example.test", "me")], set())
        with self.assertRaises(vstore.StoreError):
            self.s.import_v1(self.files, v1_key())

    def test_needs_the_unlocked_store(self):
        self.s.lock()
        with self.assertRaises(vstore.StoreLocked):
            self.s.import_v1(self.files, v1_key())

    def test_a_leftover_tmp_tree_is_replaced(self):
        stale = self.root / f"u{UID}.tmp"
        (stale / "entries").mkdir(parents=True)
        (stale / "entries" / "kstale.box").write_bytes(b"x")
        self.s.import_v1(self.files, v1_key())
        self.assertFalse(stale.exists())
        self.assertFalse((self.udir / "entries" / "kstale.box").exists())

    def test_settings_survive_the_swap(self):
        self.s.save_settings({"grant_s": 30, "idle_lock_s": 0, "clip_timeout_s": 30})
        self.s.import_v1(self.files, v1_key())
        self.assertEqual(self.s.load_settings()["grant_s"], 30)


class DuplicateItemTests(unittest.TestCase):
    def test_collapsing_a_duplicate_keeps_its_seed_and_notes(self):
        # function-duplicate-collapse-drops-totp-notes
        older = {"domain": "example.test", "username": "alex", "password": "OLD", "mdat": 100,
                 "notes": "recovery codes", "totp": {"secret": "JBSWY3DPEHPK3PXP"},
                 "sites": ["login.example.test"]}
        newer = {"domain": "example.test", "username": "alex", "password": "NEW", "mdat": 200}
        canon = legacy.to_canonical(legacy.V1Vault(credentials=[older, newer]))
        (id, e), = canon["entries"].items()
        self.assertEqual(e["secrets"]["password"], "NEW")
        self.assertEqual(e["secrets"]["notes"], "recovery codes")
        self.assertTrue(e["secrets"]["totp_secret"])
        self.assertTrue(e["meta"]["has_totp"] and e["meta"]["has_notes"])
        self.assertEqual(e["meta"]["sites"], ["login.example.test"])
        self.assertEqual([h[2] for h in e["history"]], ["OLD"])
        # the same answer whichever order the two items come in
        again = legacy.to_canonical(legacy.V1Vault(credentials=[newer, older]))
        self.assertEqual(legacy.digest(again), legacy.digest(canon))


class ImportTagTests(StoreCase):
    """A 1.x vault's notes keep their tag line in the box, and its tags reach meta."""

    def test_tags_come_through_the_import_and_verify(self):
        key = os.urandom(32)
        creds = [{"domain": "a.test", "username": "u", "password": "p1", "mdat": 1,
                  "notes": "recovery codes\n\nTags: #Work #bank"},
                 {"domain": "b.test", "username": "u", "password": "p2", "mdat": 1,
                  "notes": "Tags: #x"}]
        files = {"vault.enc": nacl.secret.SecretBox(key).encrypt(
            json.dumps({"credentials": creds}).encode())}
        s = vstore.UserStore.create(UID)
        res = s.import_v1(files, key)           # read back, counted and digest-checked
        self.assertEqual(res["counts"]["credentials"], 2)
        got = {m.domain: (m.tags, m.has_notes) for m in s.list_meta()}
        self.assertEqual(got, {"a.test": (["work", "bank"], True), "b.test": (["x"], False)})
        a = ids.entry_id("a.test", "u")
        self.assertEqual(s.open_entry(a).notes, "recovery codes\n\nTags: #Work #bank")
        # And the first sync of the same keychain changes nothing.
        from icp.octagon import items as oct_items
        from icp.vault.host import Credential
        sync = oct_items.to_sync_items([Credential(**c) for c in creds])
        self.assertEqual(s.apply_sync(sync, set())["unchanged"], 2)


class DuplicateTagTests(unittest.TestCase):
    def test_tag_lines_of_duplicates_merge_into_one_last_line(self):
        older = {"domain": "e.test", "username": "a", "password": "OLD", "mdat": 100,
                 "notes": "old body\n\nTags: #old #shared"}
        newer = {"domain": "e.test", "username": "a", "password": "NEW", "mdat": 200,
                 "notes": "new body\n\nTags: #Shared #new"}
        canon = legacy.to_canonical(legacy.V1Vault(credentials=[older, newer]))
        (_, e), = canon["entries"].items()
        self.assertEqual(e["secrets"]["notes"],
                         "new body\n\nold body\n\nTags: #shared #new #old")
        self.assertEqual(e["meta"]["tags"], ["shared", "new", "old"])
        again = legacy.to_canonical(legacy.V1Vault(credentials=[newer, older]))
        self.assertEqual(legacy.digest(again), legacy.digest(canon))

    def test_a_duplicate_that_adds_nothing_keeps_the_raw_notes(self):
        raw = "body\nTags:\t#Work"          # not canonical: must survive byte for byte
        older = {"domain": "e.test", "username": "a", "password": "OLD", "mdat": 100,
                 "notes": "body"}
        newer = {"domain": "e.test", "username": "a", "password": "NEW", "mdat": 200,
                 "notes": raw}
        canon = legacy.to_canonical(legacy.V1Vault(credentials=[older, newer]))
        (_, e), = canon["entries"].items()
        self.assertEqual(e["secrets"]["notes"], raw)


class LegacySourceTests(StoreCase):
    def test_legacy_reader_never_touches_the_filesystem(self):
        src = (BACKEND / "icp" / "vstore" / "legacy.py").read_text()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("unlink", "remove", "rmtree", "rename",
                                             "replace", "write_bytes", "open"), node.attr)
            if isinstance(node, ast.Name):
                self.assertNotEqual(node.id, "open")

    def test_old_lockbox_modules_are_gone(self):
        for name in ("lockbox.py", "held_key.py"):
            self.assertFalse((BACKEND / "icp" / "auth" / name).exists(), name)
