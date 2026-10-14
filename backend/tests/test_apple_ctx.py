"""The Apple pipeline inside the daemon (icp.daemon.apple) over a UserContext.

What these pin down:
- a run with nobody to ask (frontend None) turns every question into NeedsLogin, latches
  needs_login, and once latched stands down without contacting Apple again;
- no prompt module from 1.x is importable or reachable, and nothing in the pipeline reads a
  terminal, opens a dialog or looks for a key on its own;
- a sync hands SyncItems to the store and never opens an entry (unseal_count stays 0), and an
  entry missing because its zone failed is not tombstoned;
- edits re-read what they wrote and only then touch the store.
"""

import ast
import importlib.util
import os
import re
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import pytest

from icp.auth import signin
from icp.auth.anisette import Anisette
from icp.auth.icloud import ICloudError
from icp.cli import push
from icp.daemon import apple
from icp.daemon.context import Cancelled, NeedsLogin, UserContext
from icp.octagon import client as octagon, items
from icp.vault.host import Credential, CredentialStore
from icp.vstore import Meta

from apple_fakes import FakeStore, ScriptedFrontend

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICP = os.path.join(BACKEND, "icp")

JOINED = {"username": "alex@example.com", "octagon": {"peer_id": "SHA256:me", "joined": True},
          "mme": {"dsid": "1", "mmeAuthToken": "t", "tokens": {"cloudKitToken": "ck"},
                  "cloudKitUserId": "_u"}}


def _cred(domain="github.com", username="alex", password="pw", **kw):
    return Credential(domain=domain, username=username, password=password,
                      title=kw.pop("title", domain), **kw)


def _meta_for(c) -> Meta:
    return items.to_sync_item(c).meta


def _ctx(store, frontend=None):
    return UserContext(uid=1000, store=store, anisette_url="http://127.0.0.1:1", frontend=frontend)


class _FakeClient:
    """Stands in for OctagonClient: returns the given credentials as SyncItems."""

    creds: list = []
    failed: list = []
    instances: list = []

    def __init__(self, record, device, anisette):
        self.record = record
        self.failed_zones = list(type(self).failed)
        type(self).instances.append(self)

    def sync_and_decrypt(self, nicknames=None):
        return items.to_sync_items(type(self).creds, nicknames)


@pytest.fixture
def fake_client(monkeypatch):
    _FakeClient.creds, _FakeClient.failed, _FakeClient.instances = [], [], []
    monkeypatch.setattr(octagon, "OctagonClient", _FakeClient)
    return _FakeClient


@pytest.fixture
def client(monkeypatch, fake_client):
    monkeypatch.setattr(signin, "ensure_fresh_tokens", lambda *a, **k: None)
    return fake_client


# --------------------------------------------------------------------------- nobody to ask

def test_background_login_asks_nothing_and_raises_needs_login(monkeypatch):
    monkeypatch.setattr(Anisette, "headers", lambda self: pytest.fail("no network"))
    monkeypatch.setattr(signin, "mint_tokens", lambda *a, **k: pytest.fail("no sign-in"))
    store = FakeStore()
    with pytest.raises(NeedsLogin):
        apple.login(_ctx(store))
    with pytest.raises(NeedsLogin):
        apple.relogin(_ctx(FakeStore(session=JOINED)))
    assert store.session == {} and store.device == {}


def test_background_refresh_that_needs_2fa_raises_and_latches(monkeypatch, fake_client):
    def expired(*a, **k):
        raise ICloudError("iCloud credentials expired")

    def mint(record, username, password, device, anisette, *, twofa):
        # Nobody can answer a code here, so no callback is handed down: grandslam stands
        # down before asking Apple to push one.
        assert twofa is None
        from icp.auth.gsa import GSAError
        raise GSAError("2FA required and nobody is present to answer it")

    monkeypatch.setattr(signin, "refresh_webservices", expired)
    monkeypatch.setattr(signin, "mint_tokens", mint)
    store = FakeStore(session={**JOINED, "password": "secret"})
    with pytest.raises(NeedsLogin):
        apple.sync(_ctx(store))
    assert store.sync_status["needs_login"] is True
    assert store.applied == [] and fake_client.instances == []


def test_expired_token_without_a_saved_password_latches_in_the_background(monkeypatch, client):
    monkeypatch.setattr(signin, "ensure_fresh_tokens",
                        lambda *a, **k: (_ for _ in ()).throw(ICloudError("expired")))
    store = FakeStore(session=JOINED)
    with pytest.raises(NeedsLogin):
        apple.sync(_ctx(store))
    assert store.sync_status["needs_login"] is True


def test_interactive_refresh_failure_is_reported_not_latched(monkeypatch, client):
    monkeypatch.setattr(signin, "ensure_fresh_tokens",
                        lambda *a, **k: (_ for _ in ()).throw(ICloudError("expired")))
    store = FakeStore(session=JOINED)
    with pytest.raises(ICloudError):
        apple.sync(_ctx(store, ScriptedFrontend()))
    assert store.sync_status["needs_login"] is False


def test_latched_needs_login_stands_down_without_contacting_apple(monkeypatch, client):
    monkeypatch.setattr(signin, "ensure_fresh_tokens",
                        lambda *a, **k: pytest.fail("must not refresh while latched"))
    store = FakeStore(session=JOINED, needs_login=True)
    with pytest.raises(NeedsLogin):
        apple.sync(_ctx(store))
    assert client.instances == [] and store.applied == []


def test_an_edit_in_the_background_honours_the_latch_too(monkeypatch, client):
    monkeypatch.setattr(signin, "ensure_fresh_tokens",
                        lambda *a, **k: pytest.fail("must not refresh while latched"))
    c = _cred()
    store = FakeStore(session=JOINED, metas=[_meta_for(c)], needs_login=True)
    with pytest.raises(NeedsLogin):
        apple.push_set(_ctx(store), items.entry_id(c.domain, c.username), {"notes": "n"})


def test_not_signed_in_and_not_joined(client):
    with pytest.raises(apple.NotSignedIn):
        apple.sync(_ctx(FakeStore()))
    with pytest.raises(apple.NotSignedIn):
        apple.sync(_ctx(FakeStore(session={"username": "a", "octagon": {"peer_id": "p"}})))
    with pytest.raises(apple.NotSignedIn):
        apple.relogin(_ctx(FakeStore(), ScriptedFrontend()))


# --------------------------------------------------------------------------- no prompt paths

DELETED = ("icp.auth.agent", "icp.auth.prompt", "icp.ui.reauth", "icp.ui.polkit_gate",
           "icp.cli.appapi", "icp.ui")


def test_the_1x_prompt_modules_are_gone():
    for name in DELETED:
        try:
            spec = importlib.util.find_spec(name)
        except ModuleNotFoundError:
            spec = None
        assert spec is None, name


def test_importing_the_pipeline_pulls_in_no_prompt_or_keyring_module():
    code = ("import sys, icp.daemon.apple as a, icp.cli.push, icp.cli.app, icp.cli.jsonui, "
            "icp.auth.signin, icp.auth.webauth, icp.hme.client, icp.octagon.client, "
            "icp.octagon.bottles; "
            "bad = [m for m in ('getpass', 'secretstorage', 'icp.auth.agent', 'icp.auth.prompt', "
            "'icp.ui', 'icp.cli.appapi', 'icp.auth.lockbox', 'icp.auth.held_key', "
            "'icp.vault.store') if m in sys.modules]; print(','.join(bad))")
    env = dict(os.environ, PYTHONPATH=BACKEND, PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True,
                         check=True)
    assert out.stdout.strip() == ""


def _wp3_sources():
    paths = [os.path.join(ICP, "daemon", "apple.py")]
    for sub in ("auth", "cli", "octagon"):
        d = os.path.join(ICP, sub)
        paths += [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".py")]
    # Two files in auth/ are the store's to delete; they are not part of the pipeline.
    return [p for p in paths if os.path.basename(p) not in ("lockbox.py", "held_key.py")]


FORBIDDEN = ("zenity", "systemd-ask-password", "getpass", "ask_passphrase", "secretstorage",
             "_master_key", "pkexec", "notify-send")


def test_no_prompt_or_keyring_words_in_the_pipeline():
    hits = []
    for p in _wp3_sources():
        with open(p, encoding="utf-8") as f:
            src = f.read()
        hits += [(os.path.relpath(p, ICP), w) for w in FORBIDDEN if w in src]
        if re.search(r"(?<![\w.])input\s*\(", src):
            hits.append((os.path.relpath(p, ICP), "input("))
    assert hits == []


def test_no_prompt_calls_by_ast_either():
    # An independent matcher: names and calls, not text, so a string or comment cannot hide one
    # and a rename of the import cannot either.
    bad = []
    for p in _wp3_sources():
        with open(p, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] + [node.module or ""] \
                    if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
                bad += [m for m in mods if m.split(".")[-1] in
                        ("getpass", "secretstorage", "prompt", "agent", "reauth", "appapi",
                         "polkit_gate", "lockbox", "held_key")]
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in ("input", "getpass"):
                bad.append(f"{p}: {node.func.id}()")
    assert bad == []
    assert len(_wp3_sources()) >= 15        # the walk really covered the package


# --------------------------------------------------------------------------- sync

def test_sync_hands_items_to_the_store_and_never_opens_an_entry(client):
    gh, gl = _cred("github.com", "alex", "pw1"), _cred("gitlab.com", "alex", "pw2")
    gone = _cred("old.example", "alex", "x")
    client.creds = [gh, gl]
    store = FakeStore(session=JOINED, metas=[_meta_for(gh), _meta_for(gone)])
    result = apple.sync(_ctx(store))

    (applied, deleted), = store.applied
    assert sorted(i.id for i in applied) == sorted(items.entry_id(c.domain, c.username)
                                                   for c in (gh, gl))
    assert deleted == {items.entry_id("old.example", "alex")}
    assert store.unseal_count == 0
    assert store.sync_status["needs_login"] is False
    assert result["synced_at"] == store.sync_status["synced_at"]
    assert {"added", "changed", "deleted", "unchanged"} <= set(result)
    assert store.session_saves >= 1          # refreshed tokens are written back


def test_a_zone_that_failed_to_load_tombstones_nothing(client):
    gh, gone = _cred("github.com"), _cred("wifi-home", "AirPort")
    client.creds, client.failed = [gh], ["WiFi"]
    store = FakeStore(session=JOINED, metas=[_meta_for(gh), _meta_for(gone)])
    apple.sync(_ctx(store))
    assert store.applied[0][1] == set()
    assert items.entry_id("wifi-home", "AirPort") in store.metas


def test_a_fetch_that_decrypted_nothing_tombstones_nothing(client):
    gh = _cred("github.com")
    client.creds = []
    store = FakeStore(session=JOINED, metas=[_meta_for(gh)])
    apple.sync(_ctx(store))
    assert store.applied[0][1] == set()


def test_sync_carries_local_nicknames_into_meta(client):
    gh = _cred("github.com")
    eid = items.entry_id(gh.domain, gh.username)
    client.creds = [gh]
    store = FakeStore(session=JOINED, nicknames={eid: "Work Git"})
    apple.sync(_ctx(store))
    assert store.applied[0][0][0].meta.nickname == "Work Git"


def test_sync_without_a_saved_password_skips_hide_my_email_quietly(monkeypatch, client):
    monkeypatch.setattr(signin, "ensure_web_session",
                        lambda *a, **k: pytest.fail("no web session without a password"))
    client.creds = [_cred()]
    store = FakeStore(session=JOINED, aliases=[{"address": "a@icloud.com"}])
    apple.sync(_ctx(store))
    assert store.aliases == [{"address": "a@icloud.com"}]


def test_signout_forgets_the_session_only():
    gh = _cred()
    store = FakeStore(session=JOINED, metas=[_meta_for(gh)])
    apple.signout(_ctx(store))
    assert store.session == {} and len(store.metas) == 1


# --------------------------------------------------------------------------- sign-in

class _JoinClient(_FakeClient):
    bottles = [
        {"id": "a", "otbottle": b"x", "meta": {"ClientMetadata": {"device_name": "Alex's iPhone",
                                                                  "device_model": "iPhone"}}},
        {"id": "b", "otbottle": b"y", "meta": {"ClientMetadata": {"device_model": "iPad"}}},
    ]
    joins: list = []

    def list_recoverable_bottles(self, escrow_host, email, pet, *, warn=None):
        return list(self.bottles)

    def join_via_escrow(self, host, email, pet, passcode, chosen, *, confirm_irreversible):
        type(self).joins.append((chosen["id"], passcode, confirm_irreversible))
        self.record["octagon"]["joined"] = True


@pytest.fixture
def signin_env(monkeypatch):
    _JoinClient.creds, _JoinClient.failed, _JoinClient.instances, _JoinClient.joins = \
        [_cred()], [], [], []
    monkeypatch.setattr(octagon, "OctagonClient", _JoinClient)
    monkeypatch.setattr(Anisette, "headers", lambda self: {"X-Apple-I-MD": "x"})

    def mint(record, username, password, device, anisette, *, twofa):
        record.update({"username": username, "dsid": "D",
                       "mme": {"dsid": "1", "mmeAuthToken": "t",
                               "tokens": {"cloudKitToken": "ck"}, "cloudKitUserId": "_u"}})

    def refresh(record, device, anisette):
        record["webservices"] = {"keychainsync": "https://p1-escrowproxy.icloud.com"}
        return 1

    monkeypatch.setattr(signin, "mint_tokens", mint)
    monkeypatch.setattr(signin, "refresh_webservices", refresh)
    monkeypatch.setattr(signin, "mint_pet", lambda *a, **k: "PET")
    monkeypatch.setattr(signin, "ensure_web_session",
                        lambda *a, **k: (_ for _ in ()).throw(
                            __import__("icp.auth.webauth", fromlist=["x"]).WebAuthError("nope")))
    monkeypatch.setattr(octagon, "ensure_peer_identity",
                        lambda s, device: s.setdefault("octagon", {"peer_id": "SHA256:me"}))
    return _JoinClient


def test_declining_the_device_spends_no_attempt_and_keeps_the_sign_in(signin_env):
    fe = ScriptedFrontend({"apple_id": "alex@example.com", "password": "pw", "device": None})
    store = FakeStore()
    with pytest.raises(Cancelled):
        apple.login(_ctx(store, fe))
    assert signin_env.joins == []
    assert "not_joined" in fe.stages()
    assert store.session["username"] == "alex@example.com"
    assert store.session["password"] == "pw"          # sealed in the store, for silent refresh
    assert store.applied == []


def test_saying_no_at_the_irreversible_step_spends_no_attempt(signin_env):
    fe = ScriptedFrontend({"apple_id": "alex@example.com", "password": "pw", "device": 0,
                           "join_confirm": False})
    with pytest.raises(Cancelled):
        apple.login(_ctx(FakeStore(), fe))
    assert signin_env.joins == []


def test_a_full_sign_in_joins_the_chosen_device_then_syncs(signin_env):
    fe = ScriptedFrontend({"apple_id": "alex@example.com", "password": "pw", "device": 1,
                           "join_confirm": True, "device_passcode": "123456"})
    store = FakeStore()
    apple.login(_ctx(store, fe))
    assert signin_env.joins == [("b", b"123456", True)]
    assert store.session["octagon"]["joined"] is True
    assert len(store.applied) == 1 and store.unseal_count == 0
    assert store.sync_status["needs_login"] is False
    assert fe.stages()[:2] == ["account", "signing_in"]
    assert ("emit", "warn", "Hide My Email unavailable: nope") in fe.events
    assert store.device and set(store.device) == {"device_id", "serial", "local_user_uuid"}


def test_relogin_keeps_the_peer_identity_and_skips_the_join(signin_env):
    fe = ScriptedFrontend({"apple_id": "alex@example.com", "password": "new"})
    store = FakeStore(session=JOINED, needs_login=True)
    apple.relogin(_ctx(store, fe))
    assert signin_env.joins == []
    assert store.session["octagon"] == JOINED["octagon"]
    assert store.session["password"] == "new"
    assert store.sync_status["needs_login"] is False
    assert not [e for e in fe.events if e[:2] == ("ask", "choice")]


def test_an_empty_passcode_is_refused_before_any_attempt(signin_env):
    fe = ScriptedFrontend({"apple_id": "a@example.com", "password": "pw", "device": 0,
                           "join_confirm": True, "device_passcode": ""})
    with pytest.raises(apple.FieldError) as e:
        apple.login(_ctx(FakeStore(), fe))
    assert e.value.field == "device_passcode" and signin_env.joins == []


# --------------------------------------------------------------------------- items

def test_entry_ids_are_stable_opaque_and_in_the_protocol_alphabet():
    a = items.entry_id("github.com", "alex")
    assert a == items.entry_id("github.com", "alex")
    assert a != items.entry_id("github.com", "alex2") != items.entry_id("gitlab.com", "alex")
    assert items.ID_RE.match(a) and len(a) <= 128
    assert "github" not in a and "alex" not in a
    # The separator cannot be smuggled through either field.
    assert items.entry_id("a\x1fb", "c") != items.entry_id("a", "b\x1fc")


def test_to_sync_item_splits_meta_from_secrets():
    c = _cred("github.com", "alex", "pw", title="GitHub", notes="recovery: x",
              totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": 0},
              apple_history=({"at": 1700000000.0, "password": "old"},),
              apple_title="Code", sites=("gist.github.com",), aliases=("github.io",), mdat=5.0)
    it = items.to_sync_item(c, {items.entry_id("github.com", "alex"): "Mine"})
    m, s = it.meta, it.secrets
    assert (m.title, m.domain, m.username, m.nickname, m.apple_title) == \
        ("GitHub", "github.com", "alex", "Mine", "Code")
    assert m.sites == ["gist.github.com"] and m.aliases == ["github.io"]
    assert m.has_totp and m.has_notes and m.mdat == 5.0 and m.history_count == 1
    assert s.password == "pw" and s.notes == "recovery: x"
    assert s.totp_secret == b"Hello!\xde\xad\xbe\xef"       # base32 text -> raw seed
    assert s.totp_params == {"digits": 6, "period": 30, "algorithm": 0}
    assert s.apple_history == [{"date": "2023-11-14T22:13:20Z", "value": "old"}]
    for value in vars(m).values():        # nothing secret on the metadata side
        assert value not in ("pw", "recovery: x", "old")


def test_raw_seed_bytes_are_kept_and_duplicates_collapse_to_the_newest():
    raw = b"\x01" * 20
    older = _cred("x.com", "a", "p1", mdat=1.0, totp={"secret": raw})
    newer = _cred("x.com", "a", "p2", mdat=2.0)
    got = items.to_sync_items([older, newer])
    assert len(got) == 1 and got[0].secrets.password == "p2"
    assert items.to_sync_item(older).secrets.totp_secret == raw


def test_duplicates_keep_the_older_items_seed_notes_and_sites():
    # function-duplicate-collapse-drops-totp-notes: the older item held the only seed and the
    # recovery codes; collapsing to the newest must not drop them.
    raw = b"\x02" * 20
    older = _cred("x.com", "a", "p1", mdat=1.0, totp={"secret": raw}, notes="recovery codes",
                  sites=("login.x.com",))
    newer = _cred("x.com", "a", "p2", mdat=2.0)
    got = items.to_sync_items([older, newer])
    assert len(got) == 1
    s, m = got[0].secrets, got[0].meta
    assert s.password == "p2" and s.notes == "recovery codes" and s.totp_secret == raw
    assert m.has_totp and m.has_notes and m.sites == ["login.x.com"]
    # a second, different seed is kept too, in the notes
    other = _cred("x.com", "a", "p0", mdat=0.5, totp={"secret": b"\x03" * 20})
    got = items.to_sync_items([older, newer, other])
    assert got[0].secrets.totp_secret == raw
    assert "otpauth://totp/?secret=" in got[0].secrets.notes
    assert "recovery codes" in got[0].secrets.notes


# --------------------------------------------------------------------------- edits

@pytest.fixture
def edit_env(monkeypatch):
    """apple's edit functions over a recorded fake zone: what was pushed, and what the re-fetch
    will show afterwards (`after`)."""
    env = {"pushed": [], "after": [], "opened": 0, "reopened": 0}
    zone = SimpleNamespace(client="client", generation=0)

    def reopened(client):
        env["reopened"] += 1
        return SimpleNamespace(client=client, generation=env["reopened"])

    def opened(ctx):
        env["opened"] += 1
        return zone

    monkeypatch.setattr(apple, "_open_zone", opened)
    monkeypatch.setattr(push, "open_zone", reopened)
    monkeypatch.setattr(push, "refetch", lambda z, name="Passwords": CredentialStore(env["after"]))
    monkeypatch.setattr(push, "push_password",
                        lambda z, d, u, p: env["pushed"].append(("pw", d, u, p)) or
                        env.setdefault("zones", []).append(z.generation))
    monkeypatch.setattr(push, "push_details",
                        lambda z, d, u, **kw: env["pushed"].append(("details", kw)) or
                        env.setdefault("zones", []).append(z.generation))
    monkeypatch.setattr(push, "create_entry", lambda z, *a, **kw: env["pushed"].append(("create", a)))
    return env


def test_a_password_change_lands_then_moves_the_old_box_and_updates_meta(edit_env):
    c = _cred("github.com", "alex", "old")
    eid = items.entry_id("github.com", "alex")
    edit_env["after"] = [_cred("github.com", "alex", "new")]
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    apple.push_set(_ctx(store), eid, {"password": "new"})
    assert edit_env["pushed"] == [("pw", "github.com", "alex", "new")]
    (sid, secrets), = store.secrets_set
    assert sid == eid and secrets.password == "new"
    (applied, deleted), = store.applied
    assert [i.id for i in applied] == [eid] and deleted == set()
    assert store.unseal_count == 0


def test_a_change_that_does_not_come_back_touches_nothing(edit_env):
    c = _cred("github.com", "alex", "old")
    edit_env["after"] = [c]                       # iCloud still shows the old value
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    with pytest.raises(push.PushError):
        apple.push_set(_ctx(store), items.entry_id("github.com", "alex"), {"password": "new"})
    assert store.secrets_set == [] and store.applied == []


def test_details_change_is_not_password_history(edit_env):
    c = _cred("github.com", "alex", "pw")
    edit_env["after"] = [_cred("github.com", "alex", "pw", notes="hello",
                               sites=("gist.github.com",))]
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    apple.push_set(_ctx(store), items.entry_id("github.com", "alex"),
                   {"notes": "hello", "sites": ["https://gist.github.com/x"]})
    # fields.notes is the body: push_details splices it under the stored tag line, on the
    # notes as this fetch has them, and reports what it wrote through `expect`.
    (kind, kw), = edit_env["pushed"]
    assert kind == "details" and kw.pop("expect") == {}
    assert kw == {"notes_body": "hello", "sites": ["https://gist.github.com/x"]}
    assert store.secrets_set == []
    assert store.applied[0][0][0].secrets.notes == "hello"


def test_combined_edits_each_start_from_a_fresh_fetch(monkeypatch, edit_env):
    renames = []
    monkeypatch.setattr(push, "push_nickname",
                        lambda z, d, u, name: renames.append(z.generation) or True)
    c = _cred("github.com", "alex", "old")
    edit_env["after"] = [_cred("github.com", "alex", "new", notes="n", apple_title="Work")]
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    apple.push_set(_ctx(store), items.entry_id("github.com", "alex"),
                   {"password": "new", "notes": "n", "nickname": "Work"})
    # The password step used the zone as opened; details and the rename each re-fetched it,
    # so neither rewrote the metadata record from a copy older than the step before.
    assert edit_env["zones"] == [0, 1] and renames == [2]
    assert edit_env["opened"] == 1 and edit_env["reopened"] == 2
    assert [i for i, _ in store.secrets_set] == [items.entry_id("github.com", "alex")]


@pytest.mark.parametrize("synced", [False, True])
def test_a_rename_goes_to_apple_or_stays_a_local_nickname(monkeypatch, edit_env, synced):
    c = _cred("github.com", "alex", "pw")
    eid = items.entry_id("github.com", "alex")
    monkeypatch.setattr(push, "push_nickname", lambda z, d, u, name: synced)
    edit_env["after"] = [_cred("github.com", "alex", "pw", apple_title="Work" if synced else "")]
    store = FakeStore(session=JOINED, metas=[_meta_for(c)], nicknames={eid: "Before"})
    apple.push_set(_ctx(store), eid, {"nickname": "  Work  "})
    assert store.nicknames == ({} if synced else {eid: "Work"})
    meta = store.applied[0][0][0].meta
    assert (meta.apple_title, meta.nickname) == (("Work", "") if synced else ("", "Work"))
    assert store.secrets_set == []


@pytest.mark.parametrize("fields,field", [
    ({"title": "x"}, "title"), ({"password": 5}, "password"), ({"password": ""}, "password"),
    ({"sites": "a.com"}, "sites"), ({"totp": {"setup": "not base32!"}}, "totp"),
    ({"totp": "x"}, "totp"), ({"tags": ["a b"]}, "tags"), ({"tags": "work"}, "tags"),
    ({"tags": [f"t{i}" for i in range(17)]}, "tags"),
])
def test_bad_fields_are_refused_before_anything_is_sent(edit_env, fields, field):
    c = _cred()
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    with pytest.raises(apple.FieldError) as e:
        apple.push_set(_ctx(store), items.entry_id(c.domain, c.username), fields)
    assert e.value.field == field and edit_env["opened"] == 0


def test_tags_and_notes_body_reach_push_details(monkeypatch, edit_env):
    checked = []
    monkeypatch.setattr(push, "notes_editable", lambda z, d, u: checked.append(d) or True)
    c = _cred("github.com", "alex", "pw")
    edit_env["after"] = [_cred("github.com", "alex", "pw", notes="b\n\nTags: #work")]
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    apple.push_set(_ctx(store), items.entry_id("github.com", "alex"),
                   {"notes": "b", "tags": ["#Work", "work"]})
    (kind, kw), = edit_env["pushed"]
    kw.pop("expect")
    assert kw == {"notes_body": "b", "tags": ["work"]} and checked == ["github.com"]
    assert store.applied[0][0][0].meta.tags == ["work"]


def test_the_landed_check_uses_the_exact_notes_written(monkeypatch, edit_env):
    monkeypatch.setattr(push, "notes_editable", lambda z, d, u: True)

    def details(z, d, u, expect=None, **kw):
        edit_env["pushed"].append(("details", kw))
        expect["notes"] = "\nkept leading newline\n\nTags: #a"
    monkeypatch.setattr(push, "push_details", details)
    c = _cred("github.com", "alex", "pw")
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    eid = items.entry_id("github.com", "alex")
    # iCloud gives back the notes trimmed: that is not what was written, so it did not land.
    edit_env["after"] = [_cred("github.com", "alex", "pw", notes="kept leading newline\n\nTags: #a")]
    with pytest.raises(push.PushError):
        apple.push_set(_ctx(store), eid, {"tags": ["a"]})
    assert store.applied == []
    edit_env["after"] = [_cred("github.com", "alex", "pw",
                               notes="\nkept leading newline\n\nTags: #a")]
    apple.push_set(_ctx(store), eid, {"tags": ["a"]})
    assert store.applied


def test_tags_on_notes_that_are_not_utf8_are_refused_before_any_write(monkeypatch, edit_env):
    monkeypatch.setattr(push, "notes_editable", lambda z, d, u: False)
    c = _cred("github.com", "alex", "pw")
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    with pytest.raises(apple.FieldError) as e:
        apple.push_set(_ctx(store), items.entry_id("github.com", "alex"),
                       {"password": "new", "tags": ["a"]})
    assert (e.value.field, e.value.detail) == ("notes", "not-utf8")
    assert edit_env["pushed"] == [] and store.applied == []
    from icp.daemon.handlers import apple_error
    err = apple_error(e.value)
    assert (err.code, err.extra) == ("invalid", {"field": "notes", "detail": "not-utf8"})


@pytest.mark.parametrize("flag", ["recently_deleted", "passkey"])
def test_read_only_rows_are_refused_before_any_network(edit_env, flag):
    c = _cred("github.com", "alex", "pw", recently_deleted=flag == "recently_deleted",
              kind="passkey" if flag == "passkey" else "login")
    m = _meta_for(c)
    store = FakeStore(session=JOINED, metas=[m])
    with pytest.raises(apple.FieldError) as e:
        apple.push_set(_ctx(store), m.id, {"notes": "x"})
    assert e.value.field == "id" and edit_env["opened"] == 0


def test_create_writes_tags_as_the_last_line(monkeypatch, edit_env):
    got = {}
    monkeypatch.setattr(push, "create_entry", lambda z, *a, **kw: got.update(kw))
    edit_env["after"] = [_cred("new.example", "kim", "pw3")]
    apple.create(_ctx(FakeStore(session=JOINED)),
                 {"domain": "new.example", "username": "kim", "password": "pw3",
                  "notes": "\nbody\n", "tags": ["Work"]})
    assert got["notes"] == "body\n\nTags: #work"


@pytest.mark.parametrize("notes, tags, want", [
    # A tag line typed at the end of the notes joins the field's tags: one line, last.
    ("body\nTags: #home #Work", ["work", "travel"], "body\n\nTags: #home #work #travel"),
    ("Tags: #a", ["b"], "Tags: #a #b"),
    # Not a tag line (a bad token): body text, kept as typed.
    ("body\nTags: #a,b", ["c"], "body\nTags: #a,b\n\nTags: #c"),
])
def test_create_merges_a_typed_tag_line_with_the_tags(monkeypatch, edit_env, notes, tags, want):
    got = {}
    monkeypatch.setattr(push, "create_entry", lambda z, *a, **kw: got.update(kw))
    edit_env["after"] = [_cred("new.example", "kim", "pw3")]
    apple.create(_ctx(FakeStore(session=JOINED)),
                 {"domain": "new.example", "username": "kim", "password": "pw3",
                  "notes": notes, "tags": tags})
    assert got["notes"] == want


def test_create_refuses_more_than_16_tags_counting_the_typed_line(monkeypatch, edit_env):
    monkeypatch.setattr(push, "create_entry", lambda *a, **kw: pytest.fail("written"))
    typed = "Tags: " + " ".join(f"#t{i}" for i in range(10))
    with pytest.raises(apple.FieldError) as e:
        apple.create(_ctx(FakeStore(session=JOINED)),
                     {"domain": "new.example", "username": "kim", "password": "pw3",
                      "notes": typed, "tags": [f"u{i}" for i in range(7)]})
    assert e.value.field == "tags" and edit_env["opened"] == 0


def test_a_sync_hands_its_item_shape_to_the_context(client):
    client.creds = [_cred()]
    shape = {("inet", "com.apple.cfnetwork"): {"count": 1, "keys": {"acct"}, "inner_keys": set()}}

    class Shaped(_FakeClient):
        def sync_and_decrypt(self, nicknames=None):
            self.item_shape = shape
            return super().sync_and_decrypt(nicknames)
    import icp.octagon.client as oc
    with mock.patch.object(oc, "OctagonClient", Shaped):
        ctx = _ctx(FakeStore(session=JOINED))
        apple.sync(ctx)
    assert ctx.item_shape is shape


def test_unknown_id_is_not_found_before_any_network(edit_env):
    from icp.vstore import EntryNotFound
    with pytest.raises(EntryNotFound):
        apple.push_set(_ctx(FakeStore(session=JOINED)), "k1-nope", {"notes": "x"})
    assert edit_env["opened"] == 0


def test_create_returns_the_id_the_next_sync_will_use(edit_env):
    edit_env["after"] = [_cred("new.example", "kim", "pw3", title="New")]
    store = FakeStore(session=JOINED)
    eid = apple.create(_ctx(store), {"domain": "https://new.example/login", "username": "kim",
                                     "password": "pw3", "title": "New"})
    assert eid == items.entry_id("new.example", "kim")
    assert edit_env["pushed"][0][0] == "create" and edit_env["pushed"][0][1][0] == "new.example"
    assert [i.id for i in store.applied[0][0]] == [eid]


def test_create_needs_a_site_or_a_name_and_a_password(edit_env):
    with pytest.raises(apple.FieldError) as e:
        apple.create(_ctx(FakeStore(session=JOINED)), {"domain": "", "username": "k",
                                                        "password": "p"})
    assert e.value.field == "domain"
    with pytest.raises(apple.FieldError) as e:
        apple.create(_ctx(FakeStore(session=JOINED)), {"domain": "a.com", "username": "k",
                                                        "password": ""})
    assert e.value.field == "password" and edit_env["opened"] == 0


def test_delete_is_refused_before_any_network_while_switched_off(monkeypatch, edit_env):
    monkeypatch.setattr(push, "RECORD_DELETE_VERIFIED", False)
    c = _cred()
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    with pytest.raises(push.DeleteUnavailable):
        apple.delete(_ctx(store), items.entry_id(c.domain, c.username))
    assert edit_env["opened"] == 0 and store.applied == []


def test_delete_when_enabled_removes_both_records_and_tombstones(monkeypatch, edit_env):
    monkeypatch.setattr(push, "RECORD_DELETE_VERIFIED", True)
    monkeypatch.setattr(push, "delete_entry",
                        lambda z, d, u: edit_env["pushed"].append(("delete", d, u)) or 2)
    c = _cred()
    eid = items.entry_id(c.domain, c.username)
    edit_env["after"] = []
    store = FakeStore(session=JOINED, metas=[_meta_for(c)])
    apple.delete(_ctx(store), eid)
    assert edit_env["pushed"] == [("delete", c.domain, c.username)]
    assert store.applied == [([], {eid})]


@pytest.mark.parametrize("flag", ["recently_deleted", "passkey"])
def test_delete_refuses_read_only_rows_before_any_network(monkeypatch, edit_env, flag):
    # A Recently Deleted copy keeps the live account's domain and username, and _pair matches
    # only the live access groups: deleting it by those would remove the live login.
    monkeypatch.setattr(push, "RECORD_DELETE_VERIFIED", True)
    monkeypatch.setattr(push, "delete_entry",
                        lambda z, d, u: edit_env["pushed"].append(("delete", d, u)) or 2)
    c = _cred("github.com", "alex", "pw", recently_deleted=flag == "recently_deleted",
              kind="passkey" if flag == "passkey" else "login")
    m = _meta_for(c)
    store = FakeStore(session=JOINED, metas=[m])
    with pytest.raises(apple.FieldError) as e:
        apple.delete(_ctx(store), m.id)
    assert e.value.field == "id"
    assert edit_env["pushed"] == [] and edit_env["opened"] == 0 and store.applied == []


# --------------------------------------------------------------------------- frontends

class JsonFrontendCancelTests(unittest.TestCase):
    def _fe(self, reply):
        import io
        from icp.cli.jsonui import JsonFrontend
        return JsonFrontend(out_stream=io.StringIO(), in_stream=io.StringIO(reply))

    def test_eof_cancel_and_garbage_all_cancel_the_flow(self):
        for reply in ("", '{"cancel": true}\n', "not json\n", "[1]\n"):
            with self.assertRaises(Cancelled):
                self._fe(reply).ask("Apple ID", kind="apple_id")

    def test_cancelled_is_not_swallowed_by_a_broad_except(self):
        def flow():
            try:
                self._fe("").secret("Password", kind="password")
            except Exception:                       # noqa: BLE001 - the point of the test
                return "swallowed"
        with self.assertRaises(Cancelled):
            flow()

    def test_answers_come_back(self):
        self.assertEqual(self._fe('{"value": " 123456 "}\n').ask("code", kind="code"), "123456")
        self.assertTrue(self._fe('{"value": "yes"}\n').confirm_yn("ok?"))
        self.assertEqual(self._fe('{"value": "1"}\n').choose("pick", ["a", "b"]), 1)


def test_the_device_identity_lives_in_the_store():
    from icp.auth.device import Device
    store = FakeStore()
    d1 = Device.load_or_create(store)
    d2 = Device.load_or_create(store)
    assert d1.to_dict() == d2.to_dict() == store.device
    store.device = {"device_id": "x"}              # incomplete: replaced, never half-used
    assert Device.load_or_create(store).serial
    with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/nonexistent"}):
        Device.load_or_create(FakeStore())        # touches no path at all


class _TwoFactorGSA:
    """A GSAClient whose password login is answered with a 2FA demand."""

    def __init__(self, au):
        self.au = au
        self.triggered = []

    def authenticate(self, username, password):
        return {"Status": {"au": self.au}}, {"adsid": "1", "GsIdmsToken": "t"}

    def trigger_trusted_factor(self, dsid, idms):
        self.triggered.append("trusted")
        return True

    def trigger_sms_factor(self, *a):
        self.triggered.append("sms")

    def list_phone_numbers(self, *a):
        self.triggered.append("phones")
        return [{"id": 1}]


@pytest.mark.parametrize("au", ["trustedDeviceSecondaryAuth", "secondaryAuth"])
def test_background_run_never_triggers_a_2fa_push(monkeypatch, au):
    # function-background-2fa-push: with nobody present, no code may be sent to the person's
    # devices; the run stands down (needs-login) before any trigger.
    gsa = _TwoFactorGSA(au)
    monkeypatch.setattr(signin, "GSAClient", lambda device, anisette: gsa)

    def expired(*a, **kw):
        raise ICloudError("mmeAuthToken expired")
    monkeypatch.setattr(signin, "refresh_webservices", expired)
    store = FakeStore()
    ctx = _ctx(store)                                   # no frontend: background
    s = {"username": "a@example.test", "password": "saved"}
    with pytest.raises(NeedsLogin):
        apple._fresh_tokens(ctx, s, device=None, anisette=None)
    assert gsa.triggered == []
    assert store.status().get("needs_login") is True
