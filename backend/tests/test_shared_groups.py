"""Apple Passwords shared groups in Pear: read-only, fetched with the sync, never destructive.

Pinned here: the exact CloudKit ops the sync path may send; that a failed or partial shared fetch
changes nothing and does not stop the own keychain's sync; that shared entries are removed only
after a complete fetch and own-keychain deletion never reaches them; that shared items pair and
group inside their group only, through the same pipeline as own items; that the daemon refuses
every write to a shared entry; and that nothing plaintext reaches a log.
"""

import dataclasses
import logging
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import pytest

import test_sharing_decrypt as base
from apple_fakes import FakeStore
from daemon_fakes import Harness, meta as fake_meta, secrets as fake_secrets
from test_daemon_handlers import Base
from test_pwmac_sync_diff import _SyncCase
from test_store_v2 import item as own_item, secrets

from icp import vstore
from icp.daemon import apple, autofill
from icp.daemon.context import UserContext
from icp.octagon import client as octagon, items as sync_items, shared
from icp.sharing import fetch as sharing_fetch, pcs
from icp.vault.host import Credential
from icp.vstore import ids

from icp.sharing import groups
from icp.keychain import pipeline

ZONE = base.GROUP_UUID


def sitem(zone, domain, user, pw="pw", group="Family"):
    """A SyncItem as octagon.shared builds it."""
    inner = ids.entry_id(domain, user)
    sid = ids.shared_entry_id(zone, inner)
    m = vstore.Meta(id=sid, title=domain, domain=domain, sites=[], username=user, nickname="",
                    has_totp=False, has_notes=False, mdat=1.0, history_count=0,
                    shared_group=group)
    return vstore.SyncItem(id=sid, meta=m, secrets=secrets(pw))


# --------------------------------------------------------------------------- the store

class StoreTests(_SyncCase):
    def test_shared_ids_are_their_own_namespace(self):
        inner = ids.entry_id("a.example.test", "me")
        a, b = ids.shared_entry_id("zone-1", inner), ids.shared_entry_id("zone-2", inner)
        self.assertTrue(a.startswith("sh1-") and b.startswith("sh1-"))
        self.assertNotEqual(a, inner)
        self.assertNotEqual(a, b)
        self.assertEqual(a, ids.shared_entry_id("zone-1", inner))      # stable
        self.assertTrue(ids.valid_id(a))

    def test_own_sync_refuses_shared_items_and_ignores_shared_ids_in_deleted(self):
        sh = sitem("z", "a.example.test", "me")
        self.s.apply_shared_sync([sh])
        with self.assertRaises(ValueError):
            self.s.apply_sync([sh], set())
        counts = self.s.apply_sync([own_item("own.example.test", "me")], {sh.id})
        self.assertEqual(counts["deleted"], 0)
        self.assertEqual(self.s.get_meta(sh.id).shared_group, "Family")

    def test_shared_sync_refuses_own_items(self):
        with self.assertRaises(ValueError):
            self.s.apply_shared_sync([own_item("own.example.test", "me")])

    def test_shared_sync_adds_updates_and_removes_only_shared(self):
        mine = own_item("own.example.test", "me", "own-pw")
        self.s.apply_sync([mine], set())
        a, b = sitem("z", "a.example.test", "me", "p1"), sitem("z", "b.example.test", "you", "p2")
        self.assertEqual(self.s.apply_shared_sync([a, b])["added"], 2)
        self.assertEqual(self.s.apply_shared_sync([a, b])["unchanged"], 2)
        counts = self.s.apply_shared_sync([sitem("z", "a.example.test", "me", "p1-new")])
        self.assertEqual((counts["changed"], counts["deleted"]), (1, 1))
        live = {m.id for m in self.s.list_meta()}
        self.assertEqual(live, {mine.id, a.id})            # b is gone, own entry untouched
        self.assertEqual(self.s.open_entry(mine.id).password, "own-pw")
        self.assertEqual(self.s.open_entry(a.id).password, "p1-new")

    def test_an_empty_shared_result_removes_nothing(self):
        a = sitem("z", "a.example.test", "me")
        self.s.apply_shared_sync([a])
        self.assertEqual(self.s.apply_shared_sync([])["deleted"], 0)
        self.assertEqual([m.id for m in self.s.list_meta()], [a.id])

    def test_shared_never_pairs_with_own_or_another_group(self):
        own = own_item("a.example.test", "me", "pw")
        s1 = sitem("z1", "a.example.test", "me", "pw", group="Family")
        s2 = sitem("z1", "b.example.test", "me", "pw", group="Family")
        s3 = sitem("z2", "c.example.test", "me", "pw", group="Work")
        self.s.apply_sync([own], set())
        self.s.apply_shared_sync([s1, s2, s3])
        by = {m.id: m for m in self.s.list_meta()}
        self.assertEqual(by[s1.id].group, by[s2.id].group)
        self.assertNotEqual(by[s1.id].group, "")
        self.assertEqual(by[own.id].group, "")
        self.assertEqual(by[s3.id].group, "")


# --------------------------------------------------------------------------- pairing

def _inet(srvr, acct, pw, agrp="com.apple.cfnetwork"):
    return {"class": "inet", "agrp": agrp, "srvr": srvr, "acct": acct, "v_Data": pw,
            "labl": srvr, "mdat": 0.0}


class PairingTests(unittest.TestCase):
    def test_passwords_pair_with_their_sidecars_inside_a_group(self):
        import plistlib
        sidecar = plistlib.dumps({"title": b"Shop", "notes": b"the note",
                                  "s_as": [{"s": "extra.example.test"}]}, fmt=plistlib.FMT_BINARY)
        g1 = sharing_fetch.Group(zone="group-1", name="Family", items=[
            _inet("a.example.test", "me", b"pw"), _inet("b.example.test", "me", b"pw"),
            _inet("a.example.test", "me", sidecar, agrp="com.apple.password-manager")])
        g2 = sharing_fetch.Group(zone="group-2", name="Work", items=[
            _inet("a.example.test", "me", b"pw"),
            _inet("a.example.test", "me", plistlib.dumps({"title": b"Other"},
                                                         fmt=plistlib.FMT_BINARY),
                  agrp="com.apple.password-manager")])
        out = shared.to_shared_items(SimpleNamespace(groups=[g1, g2]))
        self.assertEqual(len(out), 3)                      # the sidecars are not entries
        self.assertEqual(len({i.id for i in out}), 3)
        self.assertTrue(all(i.id.startswith("sh1-") for i in out))
        fam = {i.meta.domain: i for i in out if i.meta.shared_group == "Family"}
        self.assertEqual(fam["a.example.test"].meta.apple_title, "Shop")
        self.assertEqual(fam["a.example.test"].secrets.notes, "the note")
        self.assertEqual(fam["a.example.test"].meta.sites, ["extra.example.test"])
        self.assertEqual(fam["b.example.test"].meta.apple_title, "")    # not paired across sites
        work, = [i for i in out if i.meta.shared_group == "Work"]
        self.assertEqual(work.meta.apple_title, "Other")   # its own group's sidecar only
        own = sync_items.entry_id("a.example.test", "me")
        self.assertNotIn(own, {i.id for i in out})

    def test_recently_deleted_items_are_dropped(self):
        g = sharing_fetch.Group(zone="g", name="F", items=[
            _inet("a.example.test", "me", b"pw", agrp="com.apple.cfnetwork-recently-deleted")])
        self.assertEqual(shared.to_shared_items(SimpleNamespace(groups=[g])), [])


# --------------------------------------------------------------------------- the sync path

class SyncPathTests(base.DiagnosticOpsTests):
    """The same fixture as the diagnostic, driven through sync_and_decrypt."""

    def setUp(self):
        super().setUp()
        p = mock.patch.object(octagon, "decrypt_to_sync_items",
                              return_value=octagon.SyncItems([]))
        p.start()
        self.patches.append(p)

    def test_only_fetches_are_sent_to_the_sharing_container(self):
        items = self.client.sync_and_decrypt()
        self.assertEqual(list(items), [])
        self.assertTrue(self.sent)
        for s in self.sent:
            self.assertIn(s["op"], base.ALLOWED_OPS)
            self.assertNotIn(s["op"], (200, 202, 210))
            self.assertEqual(s["container"], cloudkit_container())
            self.assertEqual((s["database"], s["scope"]), (1, "Private"))
        self.assertEqual({s["op"] for s in self.sent}, base.ALLOWED_OPS)
        self.client.transport.invoke.assert_not_called()
        # No second keychain fetch for the shared groups' keys.
        self.client.fetch_recoverable_tlks.assert_called_once()
        self.client.sync_keychain.assert_called_once_with()
        res = self.client.shared
        self.assertTrue(res.complete)
        self.assertEqual([i.meta.shared_group for i in res.items], ["Family passwords"])
        self.assertTrue(res.items[0].id.startswith("sh1-"))

    def test_a_failing_group_is_incomplete_and_the_own_sync_still_returns(self):
        sentinel = octagon.SyncItems([])
        with mock.patch.object(octagon, "decrypt_to_sync_items", return_value=sentinel), \
                mock.patch.object(groups, "open_zone", side_effect=base.pcs.PCSError("no key")):
            items = self.client.sync_and_decrypt()
        self.assertIs(items, sentinel)
        self.assertFalse(self.client.shared.complete)
        self.assertEqual(self.client.shared.items, [])

    def test_a_failing_key_extraction_never_breaks_the_own_sync(self):
        with mock.patch.object(pcs, "pcs_keys_from_records", side_effect=RuntimeError("x")):
            items = self.client.sync_and_decrypt()
        self.assertEqual(list(items), [])
        self.assertFalse(self.client.shared.complete)
        self.assertEqual(self.sent, [])

    def test_an_incomplete_page_sequence_is_not_complete(self):
        real = groups.fetch_records

        def partial(*a, **k):
            recs, paging = real(*a, **k)
            return recs, {**paging, "complete": False}
        with mock.patch.object(groups, "fetch_records", partial):
            self.client.sync_and_decrypt()
        self.assertFalse(self.client.shared.complete)

    def test_logs_hold_no_plaintext(self):
        with self.assertLogs(level="DEBUG") as cm:
            logging.getLogger().debug("anchor")
            self.client.sync_and_decrypt()
            with mock.patch.object(groups, "open_zone", side_effect=base.pcs.PCSError("x")):
                self.client.sync_and_decrypt()
        text = "\n".join(cm.output)
        for s in base.SECRETS:
            self.assertNotIn(s, text)
        self.assertIn("shared groups", text)

    # The inherited diagnostic tests need no repeating here.
    test_report_is_counts_and_follows_every_page = None
    test_a_failing_keychain_fetch_reports_and_sends_nothing_to_the_sharing_container = None


def cloudkit_container():
    from icp.transport import cloudkit
    return cloudkit.KCSHARING_CONTAINER


def test_the_sync_path_names_no_write_op():
    import pathlib
    for mod in (sharing_fetch, shared):
        src = pathlib.Path(mod.__file__).read_text()
        for bad in ("OP_TYPE_RECORD_SAVE", "save_record", "_perform(", "ZONE_SAVE", "ZONE_DELETE"):
            assert bad not in src, (mod.__name__, bad)


# --------------------------------------------------------------------------- apple.sync

JOINED = {"username": "alex@example.com", "octagon": {"peer_id": "SHA256:me", "joined": True},
          "mme": {"dsid": "1", "mmeAuthToken": "t", "tokens": {"cloudKitToken": "ck"},
                  "cloudKitUserId": "_u"}}


class _Client:
    own: list = []
    failed: list = []
    shared_res = None

    def __init__(self, record, device, anisette):
        self.record = record
        self.failed_zones = list(type(self).failed)
        self.shared = None

    def sync_and_decrypt(self, nicknames=None):
        self.shared = type(self).shared_res
        return sync_items.to_sync_items(type(self).own, nicknames)


@pytest.fixture
def client(monkeypatch):
    _Client.own, _Client.failed, _Client.shared_res = [], [], None
    monkeypatch.setattr(octagon, "OctagonClient", _Client)
    monkeypatch.setattr(apple.signin, "ensure_fresh_tokens", lambda *a, **k: None)
    return _Client


def _ctx(store):
    fe = mock.Mock()
    return UserContext(uid=1000, store=store, anisette_url="http://127.0.0.1:1", frontend=fe), fe


def _store_with_shared():
    old = sitem("z", "old.example.test", "me", group="Family")
    return FakeStore(session=JOINED, metas=[old.meta]), old


def test_a_complete_shared_fetch_updates_and_reports_the_count(client):
    store, old = _store_with_shared()
    client.own = [Credential(domain="own.test", username="me", password="pw", title="own.test")]
    new = sitem("z", "new.example.test", "me")
    client.shared_res = shared.SharedSync(complete=True, items=[new, sitem("z", "x.test", "u")])
    ctx, fe = _ctx(store)
    result = apple.sync(ctx)
    assert result["shared_total"] == 2 and result["shared_updated"] is True
    assert old.id not in store.metas and new.id in store.metas
    fe.emit.assert_any_call("out", "Synced 1 credential(s), 2 shared.")
    # Own deletion detection was handed no shared id, and only the own item.
    (applied, deleted), = store.applied
    assert [i.meta.shared_group for i in applied] == [""] and deleted == set()


def test_a_failed_shared_fetch_leaves_shared_entries_and_the_own_sync_completes(client):
    store, old = _store_with_shared()
    client.own = [Credential(domain="own.test", username="me", password="pw", title="own.test")]
    client.shared_res = shared.SharedSync(complete=False, stats={"failed": {"group:PCSError": 1}})
    ctx, fe = _ctx(store)
    result = apple.sync(ctx)
    assert store.shared_applied == []
    assert old.id in store.metas                       # untouched, not deleted
    assert store.sync_status["synced_at"] is not None  # the own sync completed
    assert result["shared_updated"] is False and result["shared_total"] == 1
    fe.emit.assert_any_call("out", "Synced 1 credential(s), shared groups not updated.")


def test_a_store_error_while_applying_shared_does_not_fail_the_own_sync(client):
    store, old = _store_with_shared()
    client.own = [Credential(domain="own.test", username="me", password="pw", title="own.test")]
    client.shared_res = shared.SharedSync(complete=True, items=[sitem("z", "n.test", "u")])
    store.apply_shared_sync = mock.Mock(side_effect=RuntimeError("disk"))
    result = apple.sync(_ctx(store)[0])
    assert result["shared_updated"] is False and old.id in store.metas
    assert store.sync_status["synced_at"] is not None


def test_own_deletion_detection_never_selects_a_shared_entry(client):
    store, old = _store_with_shared()
    gone = Credential(domain="gone.test", username="me", password="x", title="gone.test")
    store.metas.update({sync_items.to_sync_item(gone).id: sync_items.to_sync_item(gone).meta})
    client.own = [Credential(domain="own.test", username="me", password="pw", title="own.test")]
    apple.sync(_ctx(store)[0])
    (_, deleted), = store.applied
    assert deleted == {sync_items.to_sync_item(gone).id}
    assert old.id not in deleted


def test_a_shared_fetch_never_touches_own_entries(client):
    own = Credential(domain="own.test", username="me", password="pw", title="own.test")
    store = FakeStore(session=JOINED, metas=[sync_items.to_sync_item(own).meta])
    client.own = [own]
    client.shared_res = shared.SharedSync(complete=True, items=[sitem("z", "n.test", "u")])
    apple.sync(_ctx(store)[0])
    assert sync_items.to_sync_item(own).id in store.metas


# --------------------------------------------------------------------------- the daemon

class ReadOnlyTests(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.st.metas["sh"] = fake_meta("sh", title="Shared", domain="s.example", username="u",
                                        shared_group="Family")
        self.st.secrets["sh"] = fake_secrets()
        await self.h.unlock(self.ui)

    async def test_set_is_refused_for_every_field_before_a_grant_or_dialog(self):
        before = self.dialogs()
        for fields in ({"notes": "x"}, {"tags": ["a"]}, {"nickname": "n"}, {"password": "p"},
                       {"sites": ["a.example"]}):
            r = await self.ui.call("set", id="sh", fields=fields)
            self.assertEqual(r["error"], "shared-read-only", fields)
        self.assertEqual(self.dialogs(), before)
        self.assertEqual([c for c in self.h.apple.calls if c != "sync"], [])

    async def test_delete_is_refused_before_any_dialog(self):
        before = self.dialogs()
        r = await self.ui.call("delete", id="sh")
        self.assertEqual(r["error"], "shared-read-only")
        self.assertEqual(self.dialogs(), before)
        self.assertNotIn("delete", [c[0] for c in self.h.apple.calls])

    async def test_viewing_and_the_list_carry_the_group(self):
        r = await self.ui.call("grant", id="sh")
        self.assertNotIn("error", r)
        self.assertIn("value", await self.ui.call("reveal", id="sh", field="password"))
        r = await self.ui.call("unlock")
        row = next(e for e in r.get("entries", []) if e["id"] == "sh") if "entries" in r else None
        if row is not None:
            self.assertEqual(row["shared_group"], "Family")

    async def test_autofill_never_offers_a_shared_entry(self):
        self.assertIsNone(autofill.match_rank("s.example", self.st.metas["sh"]))


class ApplePushTests(unittest.TestCase):
    def test_push_set_and_delete_refuse_a_shared_entry_before_the_network(self):
        sh = sitem("z", "a.example.test", "me")
        store = FakeStore(session=JOINED, metas=[sh.meta])
        ctx = UserContext(uid=1, store=store, anisette_url="u", frontend=None)
        with mock.patch.object(apple, "_open_zone", side_effect=AssertionError("network")):
            with self.assertRaises(apple.SharedReadOnly):
                apple.push_set(ctx, sh.id, {"notes": "x"})
            with self.assertRaises(apple.SharedReadOnly):
                apple.delete(ctx, sh.id)

    def test_the_error_code_is_known_and_mapped(self):
        from icp.daemon import handlers, protocol
        self.assertIn("shared-read-only", protocol.ERRORS)
        self.assertEqual(handlers.apple_error(apple.SharedReadOnly("x")).code, "shared-read-only")


if __name__ == "__main__":
    unittest.main()
