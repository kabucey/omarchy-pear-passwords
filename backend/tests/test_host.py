"""Offline tests for the native-messaging host: framing, domain matching, dispatch.

Run: .venv/bin/python -m unittest tests.test_host
"""

import io
import json
import plistlib
import struct
import unittest

from icp.hme.client import HmeAlias
from icp.vault import host
from icp.vault.host import Credential, CredentialStore


class DomainMatchTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(host.domains_match("example.com", "example.com"))

    def test_www_normalized(self):
        self.assertTrue(host.domains_match("www.example.com", "example.com"))

    def test_subdomain_either_way(self):
        self.assertTrue(host.domains_match("login.example.com", "example.com"))
        self.assertTrue(host.domains_match("example.com", "accounts.example.com"))

    def test_url_input_normalized(self):
        self.assertTrue(host.domains_match("https://login.example.com/path?x=1", "example.com"))

    def test_no_false_suffix(self):
        self.assertFalse(host.domains_match("notexample.com", "example.com"))
        self.assertFalse(host.domains_match("example.com.evil.com", "example.com"))

    def test_empty(self):
        self.assertFalse(host.domains_match("", "example.com"))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore([
            Credential("example.com", "alice", "pw1", "Example"),
            Credential("login.example.com", "bob", "pw2", "Example Login"),
            Credential("other.org", "carol", "pw3", "Other"),
        ])

    def test_match_returns_relevant(self):
        hits = self.store.match("www.example.com")
        self.assertEqual({c.username for c in hits}, {"alice", "bob"})

    def test_exact_host_first(self):
        hits = self.store.match("example.com")
        self.assertEqual(hits[0].username, "alice")  # exact host sorts before subdomain

    def test_no_match(self):
        self.assertEqual(self.store.match("nowhere.test"), [])

    def test_label_only_item_matches_hostname_label(self):
        store = CredentialStore([Credential("", "me@example.com", "pw", "Cloudflare")])
        hits = store.match("dash.cloudflare.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].username, "me@example.com")

    def test_generic_label_only_item_does_not_match(self):
        store = CredentialStore([Credential("", "me@example.com", "pw", "Login")])
        self.assertEqual(store.match("login.example.com"), [])


def _alias(domain, address="quiet-otter@icloud.com", label="Claude"):
    return HmeAlias(anonymous_id="a1", address=address, label=label, note="",
                    forward_to="me@example.com", is_active=True, domain=domain,
                    created_at=0.0)


class MatchAliasesTests(unittest.TestCase):
    def test_matches_same_domains_match_rule_as_credentials(self):
        aliases = [_alias("claude.ai"), _alias("other.org", address="x@icloud.com")]
        hits = host.match_aliases("www.claude.ai", aliases)
        self.assertEqual([a.address for a in hits], ["quiet-otter@icloud.com"])

    def test_no_domain_never_matches(self):
        aliases = [_alias("")]
        self.assertEqual(host.match_aliases("claude.ai", aliases), [])

    def test_no_match(self):
        self.assertEqual(host.match_aliases("nowhere.test", [_alias("claude.ai")]), [])

    def test_service_field_can_act_as_label_only_domain(self):
        store = CredentialStore.from_items([
            {"svce": "Cloudflare", "acct": "me@example.com", "v_Data": b"pw",
             "labl": "Cloudflare"},
        ])
        self.assertEqual(store.match("dash.cloudflare.com")[0].password, "pw")

    def test_from_items_drops_internal_records(self):
        # PCS service blobs and per-site "Website Metadata" sync alongside real logins but are
        # not credentials.
        store = CredentialStore.from_items([
            {"srvr": "idmsa.apple.com", "acct": "me@gmail.com", "v_Data": b"pw",
             "labl": "idmsa.apple.com", "class": "inet"},
            {"acct": "0Z825FXfO144", "labl": "PCS com.apple.Accessibility - 0Z825FXf",
             "svce": "com.apple.Accessibility"},
            {"srvr": "apple.com", "labl": "Website Metadata for apple.com"},  # no user/pw
        ])
        self.assertEqual(len(store), 1)  # only the real login survives ingest
        self.assertEqual(store.match("idmsa.apple.com")[0].username, "me@gmail.com")
        # the page still matches just the one real login - no PCS/metadata noise
        self.assertEqual([c.username for c in store.match("apple.com")], ["me@gmail.com"])

    def test_match_sorts_recent_first_within_tier(self):
        store = CredentialStore([
            Credential("example.com", "old", "p", "Example", mdat=1000),
            Credential("example.com", "new", "p", "Example", mdat=2000),
        ])
        self.assertEqual([c.username for c in store.match("example.com")], ["new", "old"])

    def test_from_items_carries_mdat(self):
        import datetime
        when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        store = CredentialStore.from_items([
            {"srvr": "ex.com", "acct": "a", "v_Data": b"p", "mdat": when},
        ])
        self.assertEqual(store.all()[0].mdat, when.timestamp())

    def test_from_items_apple_fields(self):
        store = CredentialStore.from_items([
            # the real iCloud web-login shape: an `inet` item uses `srvr`, not `server`.
            {"srvr": "accounts.google.com", "acct": "me@gmail.com", "v_Data": b"hunter2",
             "labl": "Google", "class": "inet", "agrp": "com.apple.cfnetwork"},
            {"server": "apple.com", "acct": "me@icloud.com", "v_Data": b"secret", "labl": "Apple"},
            {"domain": "git.example", "username": "dev", "password": "hunter2"},
            {"acct": "noserver"},  # kept (has username)
            {},                    # dropped (no domain/username)
        ])
        self.assertEqual(len(store), 4)
        g = store.match("accounts.google.com")[0]
        self.assertEqual((g.domain, g.username, g.password),
                         ("accounts.google.com", "me@gmail.com", "hunter2"))
        apple = store.match("apple.com")[0]
        self.assertEqual(apple.username, "me@icloud.com")
        self.assertEqual(apple.password, "secret")


# --- passkeys, Recently Deleted and the shape diagnostic (features spec 4.3) -----------------
#
# Synthetic plists in the shapes Apple's Passwords view holds: a password record
# (com.apple.cfnetwork), its details record (com.apple.password-manager, a bplist v_Data), a
# passkey (class keys, com.apple.webkit.webauthn, v_Data = private key, klbl = credential id)
# and the -recently-deleted copies of each. Every value is made up.

PK_KEY = bytes(range(101, 133))            # "private key" bytes that must never be kept
PK_KEY2 = bytes(range(140, 172))
CID = bytes(range(1, 17)) * 2               # credential ids
CID2 = bytes(range(17, 33)) * 2


def _login(srvr, acct, pw, agrp="com.apple.cfnetwork", **kw):
    return {"class": "inet", "agrp": agrp, "srvr": srvr, "acct": acct,
            "v_Data": pw.encode(), "labl": f"{srvr} ({acct})", **kw}


def _details(srvr, acct, agrp="com.apple.password-manager", **inner):
    blob = {k: (v.encode() if isinstance(v, str) else v) for k, v in inner.items()}
    return {"class": "inet", "agrp": agrp, "srvr": srvr, "acct": acct,
            "v_Data": plistlib.dumps(blob, fmt=plistlib.FMT_BINARY)}


def _passkey(rp, key, cid, agrp="com.apple.webkit.webauthn", **kw):
    return {"class": "keys", "agrp": agrp, "labl": rp, "klbl": cid, "v_Data": key,
            "kcls": 1, "atag": b"user-entity", **kw}


def _values(obj, out=None):
    """Every str/bytes leaf of nested dicts, lists, tuples and dataclasses."""
    import dataclasses as dc
    out = [] if out is None else out
    if dc.is_dataclass(obj) and not isinstance(obj, type):
        obj = vars(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            _values(k, out)
            _values(v, out)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            _values(v, out)
    elif isinstance(obj, (str, bytes, bytearray)):
        out.append(obj)
    return out


def _leaks(obj, key: bytes) -> list:
    """Every leaf of `obj` that holds `key` as bytes, hex, or text decoded either way."""
    texts = (key.hex(), key.decode("latin-1"), key.decode("utf-8", "replace"))
    hits = []
    for v in _values(obj):
        if isinstance(v, (bytes, bytearray)):
            if key in v or key.hex().encode() in v:
                hits.append(v)
        elif any(t in v for t in texts):
            hits.append(v)
    return hits


def test_the_leak_scan_finds_a_leak():
    from icp.vault.host import Credential as C
    for form in (PK_KEY, PK_KEY.hex(), PK_KEY.decode("latin-1"),
                 PK_KEY.decode("utf-8", "replace")):
        leaked = C("x", "y", "", notes=form if isinstance(form, str) else "", apple_history=(
            {"password": form},))
        assert _leaks(leaked, PK_KEY), form


class _NoKeyRead(dict):
    """A keys item that fails the test if anything reads its v_Data before it is deleted."""

    def __getitem__(self, k):
        if k == "v_Data" and dict.__contains__(self, k):
            raise AssertionError("v_Data was read")
        return dict.__getitem__(self, k)

    def get(self, k, default=None):
        if k == "v_Data" and dict.__contains__(self, k):
            raise AssertionError("v_Data was read")
        return dict.get(self, k, default)


class PasskeyTests(unittest.TestCase):
    def items(self):
        return [
            _login("github.com", "alex", "pw-gh"),
            _details("github.com", "alex", notes="n"),
            _passkey("github.com", PK_KEY, CID),
            # passkey-only: its account name lives in its own details record ("sidecar"),
            # which holds the credential id.
            _details("passkey.example", "kim", title="Passkey Site",
                     pk={"credentialID": CID2}),
            _passkey("passkey.example", PK_KEY2, CID2),
        ]

    def test_login_gets_has_passkey_and_a_passkey_only_row_is_emitted(self):
        store = CredentialStore.from_items(self.items())
        by = {(c.domain, c.username): c for c in store.all()}
        self.assertEqual(set(by), {("github.com", "alex"), ("passkey.example", "kim")})
        gh = by[("github.com", "alex")]
        self.assertTrue(gh.has_passkey)
        self.assertEqual((gh.kind, gh.password, gh.notes), ("login", "pw-gh", "n"))
        pk = by[("passkey.example", "kim")]
        self.assertEqual((pk.kind, pk.has_passkey, pk.password), ("passkey", True, ""))
        self.assertEqual(pk.apple_title, "Passkey Site")

    def test_no_key_bytes_reach_any_credential_meta_or_secrets(self):
        from icp.octagon import items as sync_items
        items = self.items()
        store = CredentialStore.from_items(items)
        synced = sync_items.to_sync_items(store.all())
        for key in (PK_KEY, PK_KEY2):
            self.assertEqual(_leaks([c.storage_dict() for c in store.all()], key), [])
            self.assertEqual(_leaks(store.all(), key), [])
            self.assertEqual(_leaks([(i.meta, i.secrets) for i in synced], key), [])
            self.assertEqual(_leaks(store.item_shape, key), [])
        # And the decrypted dicts themselves no longer hold it: deleted in place.
        for it in items:
            if it["class"] == "keys":
                self.assertNotIn("v_Data", it)
        kinds = {i.meta.kind for i in synced}
        self.assertEqual(kinds, {"login", "passkey"})
        pk = next(i for i in synced if i.meta.kind == "passkey")
        self.assertFalse(pk.meta.has_password)
        self.assertEqual(pk.secrets.password, "")

    def test_v_data_is_deleted_before_anything_reads_it(self):
        items = [_NoKeyRead(it) if it["class"] == "keys" else it for it in self.items()]
        store = CredentialStore.from_items(items)        # raises if v_Data was read
        self.assertEqual(len(store.all()), 2)
        self.assertTrue(all("v_Data" not in it for it in items if it["class"] == "keys"))

    def test_the_old_agrp_spelling_and_an_explicit_account(self):
        store = CredentialStore.from_items([
            _login("site.example", "sam", "pw"),
            _passkey("site.example", PK_KEY, CID, agrp="com.apple.WebKit.WebAuthn",
                     acct="sam")])
        (c,) = store.all()
        self.assertTrue(c.has_passkey)

    def test_a_passkey_for_another_account_does_not_mark_the_login(self):
        store = CredentialStore.from_items([
            _login("github.com", "alex", "pw"),
            _passkey("github.com", PK_KEY, CID, acct="bob")])
        by = {c.username: c for c in store.all()}
        self.assertFalse(by["alex"].has_passkey)
        self.assertEqual((by["bob"].kind, by["bob"].domain), ("passkey", "github.com"))

    def test_www_and_case_still_find_the_login(self):
        store = CredentialStore.from_items([
            _login("www.GitHub.com", "alex", "pw"),
            _passkey("github.com", PK_KEY, CID, acct="alex")])
        (c,) = store.all()
        self.assertTrue(c.has_passkey)

    def test_an_ambiguous_account_gives_an_empty_user_never_a_guess(self):
        store = CredentialStore.from_items([
            _details("two.example", "a"), _details("two.example", "b"),
            _passkey("two.example", PK_KEY, CID)])
        (c,) = store.all()
        self.assertEqual((c.domain, c.username, c.kind), ("two.example", "", "passkey"))

    def test_the_credential_id_picks_the_sidecar(self):
        store = CredentialStore.from_items([
            _details("two.example", "a"), _details("two.example", "b", pk={"id": CID}),
            _passkey("two.example", PK_KEY, CID)])
        (c,) = store.all()
        self.assertEqual(c.username, "b")

    def test_a_passkey_with_no_rp_is_dropped(self):
        store = CredentialStore.from_items([_passkey("", PK_KEY, CID)])
        self.assertEqual(store.all(), [])

    def test_other_key_items_are_stripped_and_never_listed(self):
        other = {"class": "keys", "agrp": "com.apple.other", "labl": "x.example",
                 "acct": "u", "v_Data": PK_KEY}
        store = CredentialStore.from_items([other])
        self.assertEqual(store.all(), [])
        self.assertNotIn("v_Data", other)

    def test_passkey_rows_never_match_a_page(self):
        store = CredentialStore.from_items(self.items())
        self.assertEqual([c.username for c in store.match("passkey.example")], [])
        self.assertEqual([c.username for c in store.match("github.com")], ["alex"])


class RecentlyDeletedTests(unittest.TestCase):
    RD = "-recently-deleted"

    def items(self):
        return [
            _login("site.example", "u", "live-pw", mdat=100.0),
            _details("site.example", "u", notes="live notes"),
            # The deleted copy is newer and carries other notes: it must neither win the
            # (domain, username) collapse nor lend the live entry anything.
            _login("site.example", "u", "old-pw", agrp="com.apple.cfnetwork" + self.RD,
                   mdat=200.0),
            _details("site.example", "u", agrp="com.apple.password-manager" + self.RD,
                     notes="deleted notes", totp={"secret": b"12345678901234567890"}),
            # A deleted stub naming the account elsewhere is no alias for the live login.
            _details("elsewhere.example", "u", agrp="com.apple.password-manager" + self.RD,
                     title="x"),
            _passkey("site.example", PK_KEY, CID, agrp="com.apple.webkit.webauthn" + self.RD,
                     acct="u"),
        ]

    def test_flagged_and_kept_apart_from_the_live_copy(self):
        store = CredentialStore.from_items(self.items())
        live = [c for c in store.all() if not c.recently_deleted]
        gone = [c for c in store.all() if c.recently_deleted]
        self.assertEqual(len(live), 1)
        (lv,) = live
        self.assertEqual((lv.password, lv.notes, lv.totp, lv.aliases, lv.has_passkey),
                         ("live-pw", "live notes", None, (), False))
        rd_login = next(c for c in gone if c.kind == "login")
        self.assertEqual((rd_login.password, rd_login.notes), ("old-pw", "deleted notes"))
        self.assertTrue(rd_login.has_passkey)            # the deleted passkey, deleted login

    def test_ids_are_salted_and_never_collapse(self):
        from icp.octagon import items as sync_items
        from icp.vstore import ids
        synced = sync_items.to_sync_items(CredentialStore.from_items(self.items()).all())
        by = {i.id: i for i in synced}
        live_id = ids.entry_id("site.example", "u")
        rd_id = ids.entry_id("site.example", "u", ids.RECENTLY_DELETED)
        self.assertEqual(set(by), {live_id, rd_id})
        self.assertNotEqual(live_id, rd_id)
        self.assertEqual(by[live_id].secrets.password, "live-pw")
        self.assertFalse(by[live_id].meta.recently_deleted)
        self.assertTrue(by[rd_id].meta.recently_deleted)
        # The salt cannot be faked by a domain that starts with it.
        self.assertNotEqual(rd_id, ids.entry_id("rd:site.example", "u"))

    def test_never_listed_live_never_matched_never_edited(self):
        from icp.cli import push
        store = CredentialStore.from_items(self.items())
        self.assertEqual([c.password for c in store.match("site.example")], ["live-pw"])
        self.assertEqual(push.find(store, "site.example", "u").password, "live-pw")
        only_deleted = CredentialStore([c for c in store.all() if c.recently_deleted])
        self.assertIsNone(push.find(only_deleted, "site.example", "u"))


class ShapeTests(unittest.TestCase):
    def test_counts_and_names_only(self):
        items = [_login("a.example", "me", "s3cret-pw-value"),
                 _login("b.example", "me", "s3cret-pw-value-2"),
                 _details("a.example", "me", notes="secret notes text", title="Title X"),
                 _passkey("a.example", PK_KEY, CID),
                 {"class": "inet", "agrp": "com.apple.cfnetwork-recently-deleted",
                  "srvr": "c.example", "acct": "me", "v_Data": b"old-secret",
                  "weird key!": 1}]
        shape = host.strip_and_shape(items)
        self.assertEqual(shape[("inet", "com.apple.cfnetwork")]["count"], 2)
        self.assertEqual(shape[("keys", "com.apple.webkit.webauthn")]["count"], 1)
        self.assertIn("klbl", shape[("keys", "com.apple.webkit.webauthn")]["keys"])
        self.assertEqual(shape[("inet", "com.apple.password-manager")]["inner_keys"],
                         {"notes", "title"})
        self.assertIn("?", shape[("inet", "com.apple.cfnetwork-recently-deleted")]["keys"])
        text = repr(shape)
        for value in ("s3cret", "secret notes", "Title X", "a.example", "old-secret", "me'"):
            self.assertNotIn(value, text)
        self.assertEqual(_leaks(shape, PK_KEY), [])
        self.assertNotIn("v_Data", items[3])

    def test_string_values_inside_a_metadata_blob_never_show(self):
        # Apple's blobs hold plist strings as well as data, and short ones look like names
        # ("Bank", an account): only the blob's own top-level names may come out.
        blob = {"title": "Bank", "acct": "kim", "totp": {"secret": "JBSWY3DP"}, "n": 3}
        items = [{"class": "inet", "agrp": "com.apple.password-manager", "srvr": "bank.example",
                  "acct": "kim", "v_Data": plistlib.dumps(blob, fmt=plistlib.FMT_BINARY)}]
        shape = host.strip_and_shape(items)
        slot = shape[("inet", "com.apple.password-manager")]
        self.assertEqual(slot["inner_keys"], {"title", "acct", "totp", "n"})
        self.assertEqual(slot["keys"], {"class", "agrp", "srvr", "acct", "v_Data"})
        for value in ("Bank", "kim", "JBSWY3DP", "bank.example"):
            self.assertNotIn(value, repr(shape))

    def test_from_items_exposes_it(self):
        store = CredentialStore.from_items([_login("a.example", "me", "pw")])
        self.assertEqual(store.item_shape[("inet", "com.apple.cfnetwork")]["count"], 1)


if __name__ == "__main__":
    unittest.main()
