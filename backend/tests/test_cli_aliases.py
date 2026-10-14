"""The web-session orchestration behind the Hide My Email lookup
(icp.auth.signin.ensure_web_session) and the daemon's best-effort alias refresh
(icp.daemon.apple.fetch_aliases)."""

from types import SimpleNamespace

import pytest

from icp.auth import signin, webauth
from icp.auth.webauth import WebAuthError
from icp.daemon import apple
from icp.daemon.context import BackgroundFrontend, UserContext
from icp.hme.client import HmeAlias

from apple_fakes import FakeStore, ScriptedFrontend


class _FakeSession:
    """Stands in for WebAuthSession; `account_login_results` is popped once per call.
    `needs_2fa_after_signin` configures what `signin()` sets `self.needs_2fa` to,
    mirroring the real class (2FA is signaled by signin() itself via HTTP 409, not by a
    later account_login() response)."""

    def __init__(self, frame_tag, session_data=None, cookies=None):
        self.frame_tag = frame_tag
        self.session_data = dict(session_data or {})
        self.http = object()
        self.needs_2fa = False
        self.cookies_need_reauth = False
        self.needs_2fa_after_signin = False
        self.signin_calls = []
        self.push_calls = 0
        self.twofa_calls = []
        self.account_login_results = []

    def account_login(self):
        return self.account_login_results.pop(0)

    def signin(self, username, password, trust_token=None):
        self.signin_calls.append((username, password, trust_token))
        self.needs_2fa = self.needs_2fa_after_signin

    def request_push_notification(self):
        self.push_calls += 1

    def submit_2fa(self, code):
        self.twofa_calls.append(code)
        self.needs_2fa = False

    def export(self):
        return {"frame_tag": self.frame_tag, "session_data": self.session_data, "cookies": {}}


def test_reuses_valid_session_without_signin(monkeypatch):
    fake = _FakeSession("auth-1", session_data={"session_token": "tok"})
    fake.account_login_results = [{"stage": "ok"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: False)

    s = {"webauth": {"session_data": {"session_token": "tok"}}}
    sess, data = signin.ensure_web_session(s, BackgroundFrontend(), interactive=False)

    assert data == {"stage": "ok"}
    assert fake.signin_calls == []
    assert s["webauth"]["session_data"]["session_token"] == "tok"


def test_stale_saved_session_falls_through_to_signin(monkeypatch):
    """A saved session_token that accountLogin accepts but flags untrusted (stale) falls through
    to a real signin, same as no session_token."""
    fake = _FakeSession("auth-1", session_data={"session_token": "stale"})
    fake.account_login_results = [{"stage": "untrusted"}, {"stage": "fresh"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    challenges = iter([True, False])
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: next(challenges))

    s = {"username": "alice", "password": "secret",
        "webauth": {"session_data": {"session_token": "stale"}}}
    sess, data = signin.ensure_web_session(s, BackgroundFrontend(), interactive=False)

    assert fake.signin_calls == [("alice", "secret", None)]
    assert data == {"stage": "fresh"}


def test_legacy_unscoped_cookies_force_full_signin(monkeypatch):
    fake = _FakeSession("auth-1", session_data={"session_token": "stale",
                                                 "trust_token": "old-trust"})
    fake.cookies_need_reauth = True
    fake.account_login_results = [{"stage": "fresh"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: False)

    s = {"username": "alice", "password": "secret", "webauth": {
        "session_data": {"session_token": "stale", "trust_token": "old-trust"},
        "cookies": {"aasp": "legacy-cookie"},
    }}
    sess, data = signin.ensure_web_session(s, BackgroundFrontend(), interactive=False)

    assert data == {"stage": "fresh"}
    assert fake.signin_calls == [("alice", "secret", None)]


def test_expired_session_signs_in_with_saved_password(monkeypatch):
    fake = _FakeSession("auth-1")
    fake.account_login_results = [{"stage": "fresh"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: False)

    s = {"username": "alice", "password": "secret", "webauth": {}}
    sess, data = signin.ensure_web_session(s, BackgroundFrontend(), interactive=False)

    assert data == {"stage": "fresh"}
    assert fake.signin_calls == [("alice", "secret", None)]


def test_2fa_challenge_requests_push_then_prompts_then_succeeds(monkeypatch):
    """The push must be explicitly requested; idmsa's 409 no longer auto-sends it."""
    fake = _FakeSession("auth-1")
    fake.needs_2fa_after_signin = True
    fake.account_login_results = [{"stage": "trusted"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: False)
    fe = ScriptedFrontend({"code": "123456"})

    s = {"username": "alice", "password": "secret", "webauth": {}}
    sess, data = signin.ensure_web_session(s, fe, interactive=True)

    assert fake.push_calls == 1
    assert fake.twofa_calls == ["123456"]
    assert data == {"stage": "trusted"}


def test_noninteractive_2fa_raises_instead_of_blocking(monkeypatch):
    fake = _FakeSession("auth-1")
    fake.needs_2fa_after_signin = True
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)

    s = {"username": "alice", "password": "secret", "webauth": {}}
    with pytest.raises(WebAuthError, match="2FA"):
        signin.ensure_web_session(s, ScriptedFrontend(), interactive=False)
    assert fake.push_calls == 0
    assert fake.twofa_calls == []


def test_no_saved_password_raises_clearly(monkeypatch):
    fake = _FakeSession("auth-1")  # no cached session_token: forces the signin path
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)

    s = {"webauth": {}}
    with pytest.raises(WebAuthError, match="no saved Apple ID password"):
        signin.ensure_web_session(s, BackgroundFrontend(), interactive=False)
    assert fake.signin_calls == []


def _ctx(store, frontend=None):
    return UserContext(uid=1000, store=store, anisette_url="http://127.0.0.1:1",
                       frontend=frontend)


def test_fetch_aliases_skips_silently_without_saved_password(monkeypatch):
    monkeypatch.setattr(signin, "ensure_web_session",
                        lambda *a, **k: pytest.fail("must not touch the network without a password"))
    fe = ScriptedFrontend()
    store = FakeStore(session={"username": "alice"}, aliases=[{"address": "kept"}])

    assert apple.fetch_aliases(_ctx(store, fe)) == 1
    assert store.aliases == [{"address": "kept"}]
    assert fe.events == []


def test_fetch_aliases_warns_but_does_not_raise_on_failure(monkeypatch):
    """On failure the aliases already in the store stay, and the count is theirs."""
    def boom(*a, **k):
        raise WebAuthError("2FA did not clear the web-session challenge")

    monkeypatch.setattr(signin, "ensure_web_session", boom)
    fe = ScriptedFrontend()
    store = FakeStore(session={"password": "secret"}, aliases=[{"address": "cached-fallback"}])

    assert apple.fetch_aliases(_ctx(store, fe)) == 1
    assert store.aliases == [{"address": "cached-fallback"}]
    assert any(e[:2] == ("emit", "warn") and "Hide My Email unavailable" in e[2]
               for e in fe.events)


def test_fetch_aliases_in_the_background_never_asks_for_2fa(monkeypatch):
    seen = {}

    def ensure(s, ui, *, interactive):
        seen["interactive"] = interactive
        raise WebAuthError("Apple asked for a 2FA code for the web session")

    monkeypatch.setattr(signin, "ensure_web_session", ensure)
    store = FakeStore(session={"password": "secret"})
    assert apple.fetch_aliases(_ctx(store)) == 0
    assert seen == {"interactive": False}


def test_fetch_aliases_stores_the_parsed_list_on_success(monkeypatch):
    from icp.hme import client as hme_client

    account_data = {"webservices": {
        "premiummailsettings": {"url": "https://p1-maildomainws.icloud.com", "status": "active"}}}
    fake_sess = SimpleNamespace(http=object())
    monkeypatch.setattr(signin, "ensure_web_session", lambda *a, **k: (fake_sess, account_data))

    alias = HmeAlias(anonymous_id="a1", address="quiet-otter@icloud.com", label="Claude",
                     note="", forward_to="me@example.com", is_active=True,
                     domain="claude.ai", created_at=0.0)

    class _FakeHmeClient:
        def __init__(self, base_url, http):
            self.base_url = base_url

        def list(self):
            return [alias]

    monkeypatch.setattr(hme_client, "HmeClient", _FakeHmeClient)
    store = FakeStore(session={"password": "secret"})

    assert apple.fetch_aliases(_ctx(store)) == 1
    assert store.aliases == [{"anonymous_id": "a1", "address": "quiet-otter@icloud.com",
                              "label": "Claude", "note": "", "forward_to": "me@example.com",
                              "is_active": True, "domain": "claude.ai", "created_at": 0.0}]
    assert store.session_saves == 1          # the refreshed web-session cookies are kept
