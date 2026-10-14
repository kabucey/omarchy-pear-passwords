"""The v2 per-user store: file format, modes, damage handling, tiers and settings.

Everything runs in a scratch STATE_ROOT with a fake systemd-creds (tests/fixtures); nothing
here needs root, a TPM or the real /var/lib/pear-passwords.
"""

import ast
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fixtures import FakeSealBackend, vstore_env

from icp import vstore
from icp.vstore import format as fmt
from icp.vstore import ids

BACKEND = Path(__file__).resolve().parents[1]
UID = 1000


def secrets(pw="pw", notes="", seed=None, hist=None):
    return vstore.Secrets(password=pw, notes=notes, totp_secret=seed,
                          apple_history=list(hist or []),
                          totp_params={"digits": 6, "period": 30, "algorithm": 0} if seed else {})


def item(domain, username, pw="pw", title="", **kw):
    id = ids.entry_id(domain, username)
    meta = vstore.Meta(id=id, title=title or domain, domain=domain, sites=[],
                       username=username, nickname="", has_totp=False, has_notes=False,
                       mdat=1.0, history_count=0)
    return vstore.SyncItem(id=id, meta=meta, secrets=secrets(pw, **kw))


class StoreCase(unittest.TestCase):
    tpm = False

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._env = vstore_env(self.root, FakeSealBackend(tpm=self.tpm))
        self.backend = self._env.__enter__()

    def tearDown(self):
        self._env.__exit__(None, None, None)
        self._tmp.cleanup()

    @property
    def udir(self) -> Path:
        return self.root / f"u{UID}"

    def snapshot(self) -> dict:
        """Every file under the store root with its bytes, for "nothing changed" checks."""
        out = {}
        for dirpath, _, names in os.walk(self.root):
            for n in names:
                p = Path(dirpath) / n
                out[str(p.relative_to(self.root))] = p.read_bytes()
        return out

    def populated(self, n=3) -> vstore.UserStore:
        s = vstore.UserStore.create(UID)
        s.apply_sync([item(f"site{i}.example.test", f"user{i}", f"pw-{i}") for i in range(n)],
                     set())
        return s


class FormatTests(unittest.TestCase):
    key = bytes(range(32))

    def test_round_trip(self):
        blob = fmt.encrypt(self.key, fmt.KIND_META, UID, "meta.v2", b"hello")
        self.assertEqual(blob[:4], b"PPW2")
        self.assertEqual(blob[4], fmt.KIND_META)
        self.assertEqual(fmt.decrypt(self.key, fmt.KIND_META, UID, "meta.v2", blob), b"hello")

    def test_aad_binds_kind_uid_and_name(self):
        blob = fmt.encrypt(self.key, fmt.KIND_META, UID, "meta.v2", b"hello")
        # Same key throughout: only the associated data differs, and each difference fails.
        for kind, uid, name in ((fmt.KIND_SESSION, UID, "meta.v2"),
                                (fmt.KIND_META, UID + 1, "meta.v2"),
                                (fmt.KIND_META, UID, "session.v2")):
            forged = blob[:4] + bytes([kind]) + blob[5:] if kind != fmt.KIND_META else blob
            with self.assertRaises(vstore.SealError) as cm:
                fmt.decrypt(self.key, kind, uid, name, forged)
            self.assertEqual(cm.exception.kind, "damaged")

    def test_truncated_and_flipped(self):
        blob = fmt.encrypt(self.key, fmt.KIND_META, UID, "meta.v2", b"hello world")
        for bad in (blob[:10], blob[:-1], blob[:-1] + bytes([blob[-1] ^ 1]), b""):
            with self.assertRaises(vstore.SealError):
                fmt.decrypt(self.key, fmt.KIND_META, UID, "meta.v2", bad)

    def test_atomic_write_is_0600_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.v2"
            fmt.atomic_write(f, b"one")
            fmt.atomic_write(f, b"two")
            self.assertEqual(f.read_bytes(), b"two")
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
            self.assertEqual(os.listdir(d), ["x.v2"])

    def test_failed_write_keeps_the_old_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.v2"
            fmt.atomic_write(f, b"old")
            with mock.patch("icp.vstore.format.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    fmt.atomic_write(f, b"new")
            self.assertEqual(f.read_bytes(), b"old")
            self.assertEqual(os.listdir(d), ["x.v2"])

    def test_read_refuses_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "real").write_bytes(b"x")
            os.symlink(Path(d) / "real", Path(d) / "link")
            with self.assertRaises(vstore.SealError):
                fmt.read_file(Path(d) / "link")


class IdTests(unittest.TestCase):
    def test_stable_and_safe(self):
        a = ids.entry_id("github.com", "me@example.test")
        self.assertEqual(a, ids.entry_id("github.com", "me@example.test"))
        self.assertNotEqual(a, ids.entry_id("github.com", "Me@example.test"))
        self.assertTrue(ids.valid_id(a))
        self.assertLessEqual(len(a), 128)

    def test_duplicates_collapse_to_the_newest(self):
        rows = [("a", "x", 1.0, "first"), ("b", "y", 1.0, "b"), ("a", "x", 3.0, "newest"),
                ("a", "x", 2.0, "middle"), ("a", "x", 3.0, "tie")]
        kept, dropped = ids.collapse(rows, key=lambda r: ids.entry_id(r[0], r[1]),
                                     mdat=lambda r: r[2])
        base = ids.entry_id("a", "x")
        self.assertEqual(list(kept), [base, ids.entry_id("b", "y")])     # first-seen order
        self.assertEqual(kept[base][3], "newest")                       # a tie keeps the first
        self.assertEqual(sorted(r[3] for _, r in dropped), ["first", "middle", "tie"])

    def test_the_pair_is_not_joined_with_a_separator(self):
        # Hashing "a\x1fb" + "c" and "a" + "b\x1fc" the 1.x way would give one id for two.
        self.assertNotEqual(ids.entry_id("a\x1fb", "c"), ids.entry_id("a", "b\x1fc"))
        self.assertNotEqual(ids.entry_id("a,", "b"), ids.entry_id("a", ",b"))

    def test_path_shaped_ids_are_refused(self):
        for bad in ("", ".", "..", ".hidden", "a/b", "../x", "a" * 129, "a\x00", "é", None, 5):
            self.assertFalse(ids.valid_id(bad), repr(bad))
            with self.assertRaises(ValueError):
                ids.check_id(bad)


class LifecycleTests(StoreCase):
    def test_open_on_nothing_is_empty_and_touches_nothing(self):
        s = vstore.UserStore.open(UID)
        self.assertEqual(s.state(), "empty")
        self.assertEqual(s.status(), {"state": "empty", "signed_in": False,
                                      "sealed_with": None, "synced_at": None,
                                      "needs_login": None})
        self.assertFalse(self.udir.exists())

    def test_create_layout_and_modes(self):
        s = vstore.UserStore.create(UID)
        self.assertEqual(s.state(), "unlocked")
        for d in ("", "keys", "entries", "history"):
            self.assertEqual(stat.S_IMODE((self.udir / d).stat().st_mode), 0o700, d)
        for f in ("keys/list.cred", "keys/secret.cred", "keys/secret.pub", "keys/keys.json",
                  "meta.v2"):
            self.assertEqual(stat.S_IMODE((self.udir / f).stat().st_mode), 0o600, f)
        self.assertEqual(s.status()["sealed_with"], "host")
        self.assertEqual(s.list_meta(), [])

    def test_create_refuses_an_existing_store(self):
        vstore.UserStore.create(UID)
        with self.assertRaises(vstore.StoreError):
            vstore.UserStore.create(UID)

    def test_failed_create_leaves_no_half_store(self):
        self.backend.corrupt_next_encrypts = 1
        with self.assertRaises(vstore.SealError):
            vstore.UserStore.create(UID)
        self.assertEqual(vstore.UserStore.open(UID).state(), "empty")

    def test_lock_wipes_and_unlock_restores(self):
        s = self.populated()
        before = [m.id for m in s.list_meta()]
        s.set_sync_status(synced_at=123.0, needs_login=True)
        s.lock()
        self.assertEqual(s.state(), "locked")
        st = s.status()
        self.assertIsNone(st["synced_at"])
        self.assertIsNone(st["needs_login"])
        for call in (s.list_meta, s.load_session, s.load_aliases, s.load_nicknames,
                     lambda: s.open_entry(before[0]), lambda: s.history(before[0]),
                     lambda: s.get_meta(before[0]), lambda: s.pwmac_matches(["x"]),
                     lambda: s.apply_sync([], set()), lambda: s.set_sync_status(synced_at=1)):
            with self.assertRaises(vstore.StoreLocked):
                call()
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual([m.id for m in s2.list_meta()], before)
        self.assertEqual(s2.status()["synced_at"], 123.0)
        self.assertTrue(s2.status()["needs_login"])
        self.assertEqual(s2.open_entry(before[0]).password, "pw-0")

    def test_lock_zeroes_the_key_buffers(self):
        s = vstore.UserStore.create(UID)
        rk, sub = s._rk, dict(s._sub)
        s.lock()
        self.assertEqual(len(rk), 0)
        self.assertTrue(all(len(k) == 0 for k in sub.values()))
        self.assertIsNone(s._doc)

    def test_reset_moves_the_old_store_aside(self):
        s = self.populated()
        old = self.snapshot()
        s.lock()
        fresh = vstore.UserStore.reset(UID)
        self.assertEqual(fresh.state(), "unlocked")
        self.assertEqual(fresh.list_meta(), [])
        aside = [d for d in os.listdir(self.root) if d.startswith(f"u{UID}.broken-")]
        self.assertEqual(len(aside), 1)
        for rel, data in old.items():
            moved = self.root / rel.replace(f"u{UID}", aside[0], 1)
            self.assertEqual(moved.read_bytes(), data, rel)


    def _aside(self):
        return [d for d in os.listdir(self.root) if d.startswith(f"u{UID}.broken-")]

    def test_reset_deletes_a_store_that_keeps_nothing_when_asked(self):
        # Round 2 gate, bug 3: every start-over of an import left another u<uid>.broken-<ts>
        # holding only key wrappers.
        vstore.UserStore.create(UID).lock()
        fresh = vstore.UserStore.reset(UID, discard_empty=True)
        self.assertEqual(fresh.state(), "unlocked")
        self.assertEqual(self._aside(), [])
        fresh.lock()
        vstore.UserStore.reset(UID, discard_empty=True)
        self.assertEqual(self._aside(), [])

    def test_reset_keeps_a_store_that_keeps_nothing_by_default(self):
        # After tpm-cleared or damaged the daemon never asks: the files stay for diagnosis.
        vstore.UserStore.create(UID).lock()
        vstore.UserStore.reset(UID)
        self.assertEqual(len(self._aside()), 1)

    def test_reset_never_deletes_a_store_that_keeps_something(self):
        s = self.populated()
        old = self.snapshot()
        s.lock()
        vstore.UserStore.reset(UID, discard_empty=True)
        aside = self._aside()
        self.assertEqual(len(aside), 1)
        for rel, data in old.items():
            moved = self.root / rel.replace(f"u{UID}", aside[0], 1)
            self.assertEqual(moved.read_bytes(), data, rel)


class HoldsNothingTests(StoreCase):
    """Round 2 audit, problem 3: migrate-begin may replace a store only when it keeps
    nothing anyone could lose, and that has to be known without a key."""

    def test_no_store_and_a_fresh_store_hold_nothing(self):
        self.assertTrue(vstore.UserStore.open(UID).holds_nothing())
        s = vstore.UserStore.create(UID)
        s.lock()
        self.assertTrue(vstore.UserStore.open(UID).holds_nothing())

    def test_an_entry_a_session_aliases_or_nicknames_count(self):
        s = self.populated(1)
        self.assertFalse(vstore.UserStore.open(UID).holds_nothing())
        for setup in (lambda st: st.save_session({"username": "x"}),
                      lambda st: st.save_aliases([{"address": "a@icloud.com"}]),
                      lambda st: st.save_nicknames({"e.1": "n"})):
            vstore.UserStore.reset(UID)
            st = vstore.UserStore.open(UID)
            st.unlock()
            self.assertTrue(st.holds_nothing())
            setup(st)
            st.lock()
            self.assertFalse(vstore.UserStore.open(UID).holds_nothing())
        del s

    def test_history_alone_counts(self):
        vstore.UserStore.create(UID).lock()
        (self.udir / "history" / "e.1").mkdir()
        self.assertFalse(vstore.UserStore.open(UID).holds_nothing())


class DamageTests(StoreCase):
    def test_truncated_meta_is_damaged_and_kept(self):
        s = self.populated()
        s.lock()
        f = self.udir / "meta.v2"
        f.write_bytes(f.read_bytes()[:40])
        before = self.snapshot()
        s2 = vstore.UserStore.open(UID)
        with self.assertRaises(vstore.SealError) as cm:
            s2.unlock()
        self.assertEqual(cm.exception.kind, "damaged")
        self.assertEqual(s2.state(), "damaged")
        self.assertEqual(s2.status()["state"], "damaged")
        self.assertEqual(self.snapshot(), before)          # nothing deleted or rewritten

    def test_missing_meta_is_damaged_not_empty(self):
        s = self.populated()
        s.lock()
        (self.udir / "meta.v2").unlink()
        with self.assertRaises(vstore.SealError):
            vstore.UserStore.open(UID).unlock()

    def test_swapped_tier1_files_do_not_open(self):
        s = vstore.UserStore.create(UID)
        s.save_nicknames({"x": "y"})
        s.save_aliases([{"a": 1}])
        s.lock()
        (self.udir / "nicknames.v2").write_bytes((self.udir / "aliases.v2").read_bytes())
        with self.assertRaises(vstore.SealError):
            vstore.UserStore.open(UID).unlock()

    def test_damaged_box_raises_and_is_kept(self):
        s = self.populated()
        id = s.list_meta()[0].id
        box = self.udir / "entries" / f"{id}.box"
        box.write_bytes(box.read_bytes()[:-3])
        data = box.read_bytes()
        with self.assertRaises(vstore.SealError) as cm:
            s.open_entry(id)
        self.assertEqual(cm.exception.kind, "damaged")
        self.assertEqual(box.read_bytes(), data)
        self.assertEqual(s.state(), "unlocked")              # one bad box is not a bad store

    def test_box_copied_over_another_entry_is_refused(self):
        s = self.populated()
        a, b = [m.id for m in s.list_meta()][:2]
        (self.udir / "entries" / f"{b}.box").write_bytes(
            (self.udir / "entries" / f"{a}.box").read_bytes())
        with self.assertRaises(vstore.SealError):
            s.open_entry(b)

    def test_history_box_renamed_back_is_refused(self):
        s = self.populated(1)
        it = item("site0.example.test", "user0", "pw-new")
        s.apply_sync([it], set())
        hist = self.udir / "history" / it.id / "1.box"
        os.replace(hist, self.udir / "entries" / f"{it.id}.box")
        with self.assertRaises(vstore.SealError):
            s.open_entry(it.id)

    def test_substituted_public_key_is_detected(self):
        s = vstore.UserStore.create(UID)
        s.lock()
        pub = self.udir / "keys" / "secret.pub"
        pub.write_bytes(os.urandom(32) + pub.read_bytes()[32:])
        with self.assertRaises(vstore.SealError) as cm:
            vstore.UserStore.open(UID).unlock()
        self.assertEqual(cm.exception.kind, "damaged")

    def test_box_files_are_0600(self):
        s = self.populated(1)
        for p in (self.udir / "entries").iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)


class TierOneTests(StoreCase):
    def test_meta_shape_and_nicknames(self):
        s = vstore.UserStore.create(UID)
        it = item("github.com", "me", "pw", title="GitHub", notes="n", seed=b"k" * 20)
        it.meta.sites = ["gist.github.com"]
        s.apply_sync([it], set())
        s.save_nicknames({it.id: "Work"})
        m = s.get_meta(it.id)
        self.assertEqual((m.title, m.domain, m.sites, m.username, m.nickname),
                         ("GitHub", "github.com", ["gist.github.com"], "me", "Work"))
        self.assertTrue(m.has_totp)
        self.assertTrue(m.has_notes)
        self.assertEqual(m.history_count, 0)
        with self.assertRaises(vstore.EntryNotFound):
            s.get_meta("knope")
        with self.assertRaises(vstore.EntryNotFound):
            s.open_entry("knope")

    def test_session_save_load_and_signout(self):
        s = vstore.UserStore.create(UID)
        self.assertEqual(s.load_session(), {})
        self.assertFalse(s.status()["signed_in"])
        s.save_session({"dsid": "TEST", "token": "TEST"})
        self.assertEqual(s.load_session(), {"dsid": "TEST", "token": "TEST"})
        s.lock()
        self.assertTrue(vstore.UserStore.open(UID).status()["signed_in"])  # no key needed
        s.unlock()
        s.save_session({})
        self.assertFalse((self.udir / "session.v2").exists())
        self.assertFalse(s.status()["signed_in"])

    def test_session_file_holds_no_plaintext(self):
        s = vstore.UserStore.create(UID)
        s.save_session({"password": "TEST-plaintext-marker"})
        s.apply_sync([item("a.example.test", "u", "TEST-entry-marker")], set())
        for data in self.snapshot().values():
            self.assertNotIn(b"TEST-plaintext-marker", data)
            self.assertNotIn(b"TEST-entry-marker", data)

    def test_device_is_plain_0600_and_works_locked(self):
        s = vstore.UserStore.create(UID)
        s.lock()
        self.assertEqual(s.load_device(), {})
        s.save_device({"device_id": "TEST"})
        self.assertEqual(s.load_device(), {"device_id": "TEST"})
        self.assertEqual(stat.S_IMODE((self.udir / "device.json").stat().st_mode), 0o600)

    def test_pwmac_matches_compares_macs_only(self):
        s = self.populated(3)
        n = self.backend.count("decrypt", "secret")
        self.assertEqual(s.pwmac_matches(["nope", "pw-2", "pw-0", 5, "pw-1x"]), [1, 2])
        self.assertEqual(s.unseal_count, 0)
        self.assertEqual(self.backend.count("decrypt", "secret"), n)


class TagMetaTests(StoreCase):
    """Tags and the other list fields added for categories (features spec 4.1, 4.4)."""

    def test_tags_and_has_notes_follow_the_body(self):
        s = vstore.UserStore.create(UID)
        a = item("a.example.test", "me", notes="PIN 1234\n\nTags: #Work #finance")
        b = item("b.example.test", "me", notes="Tags: #work")
        c = item("c.example.test", "me", notes="  \n\nTags: #x")
        d = item("d.example.test", "me", notes="plain note")
        s.apply_sync([a, b, c, d], set())
        got = {m.domain: (m.tags, m.has_notes) for m in s.list_meta()}
        self.assertEqual(got, {"a.example.test": (["work", "finance"], True),
                               "b.example.test": (["work"], False),
                               "c.example.test": (["x"], False),
                               "d.example.test": ([], True)})
        # The box keeps the whole raw notes, tag line and all.
        self.assertEqual(s.open_entry(a.id).notes, "PIN 1234\n\nTags: #Work #finance")

    def test_new_fields_round_trip_meta_v2(self):
        s = vstore.UserStore.create(UID)
        it = item("pk.example.test", "kim", pw="", notes="Tags: #a")
        it.meta.kind, it.meta.has_passkey, it.meta.has_password = "passkey", True, False
        rd = item("rd.example.test", "kim")
        rd.meta.recently_deleted = True
        s.apply_sync([it, rd], set())
        s.lock()
        again = vstore.UserStore.open(UID)
        again.unlock()
        m = again.get_meta(it.id)
        self.assertEqual((m.tags, m.kind, m.has_passkey, m.has_password, m.recently_deleted),
                         (["a"], "passkey", True, False, False))
        self.assertTrue(again.get_meta(rd.id).recently_deleted)
        self.assertEqual(again.get_meta(rd.id).kind, "login")

    def test_an_old_meta_v2_loads_with_defaults_and_causes_no_change_storm(self):
        s = vstore.UserStore.create(UID)
        items = [item(f"s{i}.example.test", "me", f"pw{i}", notes="n" if i else "")
                 for i in range(4)]
        s.apply_sync(items, set())
        # What a meta.v2 written before these fields existed holds.
        for rec in s._doc["entries"].values():
            for k in ("tags", "has_passkey", "kind", "has_password", "recently_deleted"):
                del rec[k]
        s._write_meta()
        s.lock()
        old = vstore.UserStore.open(UID)
        old.unlock()
        for m in old.list_meta():
            self.assertEqual((m.tags, m.has_passkey, m.kind, m.has_password,
                              m.recently_deleted), ([], False, "login", True, False))
        again = [item(f"s{i}.example.test", "me", f"pw{i}", notes="n" if i else "")
                 for i in range(4)]
        self.assertEqual(old.apply_sync(again, set()),
                         {"added": 0, "changed": 0, "deleted": 0, "unchanged": 4})

    def test_an_old_record_with_a_tag_line_gets_its_tags_on_the_next_sync(self):
        s = vstore.UserStore.create(UID)
        it = item("t.example.test", "me", notes="body\n\nTags: #a")
        s.apply_sync([it], set())
        rec = s._doc["entries"][it.id]
        del rec["tags"]
        rec["has_notes"] = True
        counts = s.apply_sync([item("t.example.test", "me", notes="body\n\nTags: #a")], set())
        self.assertEqual(counts["changed"], 1)
        self.assertEqual(s.get_meta(it.id).tags, ["a"])

    def passkey(self, domain, username, **kw):
        it = item(domain, username, pw="", **kw)
        it.meta.kind, it.meta.has_passkey, it.meta.has_password = "passkey", True, False
        return it

    def test_a_passkey_only_row_gaining_a_password_files_no_blank_history(self):
        # The passkey-only row and the login for the same account share one id.
        s = vstore.UserStore.create(UID)
        pk = self.passkey("pk.example.test", "kim", notes="n")
        s.apply_sync([pk], set())
        login = item("pk.example.test", "kim", pw="first", notes="n")
        self.assertEqual(login.id, pk.id)
        self.assertEqual(s.apply_sync([login], set())["changed"], 1)
        m = s.get_meta(pk.id)
        self.assertEqual((m.kind, m.has_password, m.history_count), ("login", True, 0))
        self.assertEqual(s._doc["entries"][pk.id]["hist"], [])
        self.assertEqual(s.open_entry(pk.id).password, "first")
        # A real change after that is history as always.
        s.apply_sync([item("pk.example.test", "kim", pw="second", notes="n")], set())
        self.assertEqual(s.get_meta(pk.id).history_count, 1)
        self.assertEqual([p for _, p in s.history(pk.id)][:1], ["first"])

    def test_a_blank_password_box_is_never_history(self):
        # The same for a login whose box held no password (no kind recorded on it).
        s = vstore.UserStore.create(UID)
        s.apply_sync([item("b.example.test", "me", pw="")], set())
        s.apply_sync([item("b.example.test", "me", pw="now")], set())
        self.assertEqual(s.get_meta(ids.entry_id("b.example.test", "me")).history_count, 0)

    def test_a_login_turning_passkey_only_keeps_its_password_as_history(self):
        s = vstore.UserStore.create(UID)
        login = item("pk.example.test", "kim", pw="real")
        s.apply_sync([login], set())
        s.apply_sync([self.passkey("pk.example.test", "kim")], set())
        m = s.get_meta(login.id)
        self.assertEqual((m.kind, m.has_password, m.history_count), ("passkey", False, 1))
        self.assertEqual([p for _, p in s.history(login.id)], ["real"])
        # Back to a login: the passkey-only box (no password) is not filed on top of it.
        s.apply_sync([item("pk.example.test", "kim", pw="again")], set())
        self.assertEqual(s.get_meta(login.id).history_count, 1)
        self.assertEqual([p for _, p in s.history(login.id)], ["real"])

    def test_fields_from_normalises(self):
        from icp.vstore import meta as vmeta
        m = item("x.example.test", "me").meta
        m.kind, m.tags = "something-else", [f"t{i}" for i in range(20)]
        f = vmeta.fields_from(m)
        self.assertEqual(f["kind"], "login")
        self.assertEqual(len(f["tags"]), 16)


class SettingsTests(StoreCase):
    def test_defaults_and_overlay_work_while_locked(self):
        s = vstore.UserStore.open(UID)
        self.assertEqual(s.load_settings(),
                         {"grant_s": 120, "idle_lock_s": 300, "clip_timeout_s": 30,
                          "window_mode": "floating"})
        s.save_settings({"grant_s": 60, "idle_lock_s": 300, "clip_timeout_s": 30})
        self.assertEqual(s.load_settings()["grant_s"], 60)
        self.assertEqual(stat.S_IMODE((self.udir / "state.json").stat().st_mode), 0o600)

    def test_window_mode_survives_a_reload(self):
        s = vstore.UserStore.open(UID)
        s.save_settings({**s.load_settings(), "window_mode": "regular"})
        self.assertEqual(vstore.UserStore.open(UID).load_settings()["window_mode"], "regular")
        for bad in ("tiled", 1, None, True):
            fmt.atomic_write(self.udir / "state.json", json.dumps({"window_mode": bad}).encode())
            self.assertEqual(s.load_settings()["window_mode"], "floating", bad)

    def test_no_lease_setting_survives(self):
        s = vstore.UserStore.open(UID)
        s.save_settings({"grant_s": 10, "sync_lease_h": 12})
        self.assertNotIn("sync_lease_h", s.load_settings())
        fmt.atomic_write(self.udir / "state.json", b'{"sync_lease_h": 4, "grant_s": 5}')
        got = s.load_settings()
        self.assertNotIn("sync_lease_h", got)
        self.assertFalse(any("lease" in k for k in got))
        self.assertEqual(got["grant_s"], 5)

    def test_old_copy_round_trip(self):
        s = vstore.UserStore.open(UID)
        rec = {"dir": "/home/u/.config/icp.v1-backup-20261008",
               "files": [{"name": "vault.enc", "sha256": "0" * 64}], "migrated_at": 1.0}
        s.save_settings({**s.load_settings(), "old_copy": rec})
        self.assertEqual(s.load_settings()["old_copy"], rec)
        settings = s.load_settings()
        del settings["old_copy"]
        s.save_settings(settings)
        self.assertNotIn("old_copy", s.load_settings())

    def test_migration_pending_round_trip(self):
        # The daemon marks a migrate-begin that has not committed, so a retry after a lock,
        # a crash or a mismatch starts over instead of finding a non-empty store forever.
        s = vstore.UserStore.open(UID)
        s.save_settings({**s.load_settings(), "migration_pending": True})
        self.assertIs(s.load_settings()["migration_pending"], True)
        settings = s.load_settings()
        del settings["migration_pending"]
        s.save_settings(settings)
        self.assertNotIn("migration_pending", s.load_settings())
        s.save_settings({**s.load_settings(), "migration_pending": "yes"})   # only True counts
        self.assertNotIn("migration_pending", s.load_settings())

    def test_feature_flags_round_trip(self):
        # op features keeps the Passkeys / Recently Deleted flags here; the gate VM found the
        # real store dropping them (the fake one keeps any key), so they never outlived the
        # daemon.
        s = vstore.UserStore.open(UID)
        s.save_settings({**s.load_settings(), "features": {"passkeys": False, "apple_deleted": True}})
        self.assertEqual(s.load_settings()["features"], {"passkeys": False, "apple_deleted": True})
        # Only the known flags, and only a real True is on.
        s.save_settings({**s.load_settings(),
                         "features": {"passkeys": "yes", "apple_deleted": 1, "other": True}})
        self.assertEqual(s.load_settings()["features"], {"passkeys": False, "apple_deleted": False})
        fmt.atomic_write(self.udir / "state.json", b'{"features": {"passkeys": true}, "grant_s": 60}')
        self.assertEqual(s.load_settings()["features"], {"passkeys": True, "apple_deleted": False})
        fmt.atomic_write(self.udir / "state.json", b'{"features": ["passkeys"]}')
        self.assertNotIn("features", s.load_settings())

    def test_garbage_state_file_gives_defaults_and_is_kept(self):
        s = vstore.UserStore.open(UID)
        fmt.ensure_dir(self.udir)
        (self.udir / "state.json").write_bytes(b"{not json")
        self.assertEqual(s.load_settings()["grant_s"], 120)
        self.assertEqual((self.udir / "state.json").read_bytes(), b"{not json")


class SourceRuleTests(unittest.TestCase):
    """vstore never prompts, never names polkit, never reads $HOME, and its loaders never
    unlink in reaction to a read (independent of the behavioural tests above)."""

    def sources(self):
        d = BACKEND / "icp" / "vstore"
        return {p.name: p.read_text() for p in sorted(d.glob("*.py"))}

    def test_no_polkit_no_home_no_prompt(self):
        for name, src in self.sources().items():
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mods = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
                    self.assertFalse(any("polkit" in m or "getpass" in m or "prompt" in m
                                         for m in mods), (name, mods))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, ("expanduser", "home", "getpass"), name)
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn("XDG_CONFIG_HOME", node.value, name)
                    self.assertNotIn("zenity", node.value, name)

    def test_unlink_only_where_allowed(self):
        # Removal is allowed in exactly these places: a temp file of a failed write, a
        # sign-out's session.v2, the re-seal's own .new/.prev files, the history cap, a create
        # that failed before it became a store (its files, then its own empty directories by
        # rmdir, which never removes anything that is not empty), and the importer's own
        # tmp/aside trees.
        allowed = {"format.py": 1, "session_store.py": 1, "entries.py": 2, "__init__.py": 4,
                   "importer.py": 1}
        for name, src in self.sources().items():
            n = sum(1 for node in ast.walk(ast.parse(src))
                    if isinstance(node, ast.Attribute)
                    and node.attr in ("unlink", "remove", "rmtree", "rmdir"))
            self.assertEqual(n, allowed.get(name, 0), name)


if __name__ == "__main__":
    unittest.main()


class LockRaceTests(StoreCase):
    """crypto-lock-race-corrupts-meta / function-lock-races-apply-sync: Registry.lock() runs on
    the event loop while a worker thread is inside a store call."""

    def test_lock_waits_for_a_running_apply_sync(self):
        import threading
        import time
        from unittest import mock
        from icp.vstore import entries as E
        a, b = item("a.example.test", "me", "OLD-a"), item("b.example.test", "me", "b1")
        s = vstore.UserStore.create(UID)
        s.apply_sync([a, b], set())
        started, proceed = threading.Event(), threading.Event()
        real = E.EntryFiles.write

        def write(files, id, blob):
            real(files, id, blob)
            if id == a.id:
                started.set()
                proceed.wait(5)
        errors = []

        def sync():
            try:
                s.apply_sync([item("a.example.test", "me", "NEW-a"),
                              item("b.example.test", "me", "b2")], set())
            except Exception as e:                       # noqa: BLE001
                errors.append(e)
        with mock.patch.object(E.EntryFiles, "write", write):
            worker = threading.Thread(target=sync)
            worker.start()
            self.assertTrue(started.wait(5))
            locker = threading.Thread(target=s.lock)     # what Registry.lock() does
            locker.start()
            time.sleep(0.2)
            self.assertTrue(locker.is_alive(), "lock() wiped the keys under a running sync")
            proceed.set()
            worker.join(5)
            locker.join(5)
        self.assertEqual(errors, [])
        self.assertEqual(s.state(), "locked")
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual(s2.open_entry(a.id).password, "NEW-a")
        self.assertEqual([v for _, v, *_ in s2.history(a.id)], ["OLD-a"])
        self.assertEqual(s2.open_entry(b.id).password, "b2")

    def test_meta_is_never_sealed_as_null(self):
        s = self.populated(1)
        before = (self.udir / "meta.v2").read_bytes()
        s._doc = None                       # the doc already wiped, the meta key not yet
        with self.assertRaises(vstore.StoreLocked):
            s._write_meta()
        self.assertEqual((self.udir / "meta.v2").read_bytes(), before)
        s.lock()
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual(len(s2.list_meta()), 1)
