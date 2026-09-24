"""The web-session orchestration behind `icp show`'s Hide My Email lookup
(icp.cli.app._ensure_web_session, _fetch_aliases_best_effort)."""

from types import SimpleNamespace

import pytest

from icp.auth import webauth
from icp.auth.webauth import WebAuthError
from icp.cli import app
from icp.hme.client import HmeAlias
from icp.vault.host import Credential, CredentialStore


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
    sess, data = app._ensure_web_session(s, interactive=False)

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
    sess, data = app._ensure_web_session(s, interactive=False)

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
    sess, data = app._ensure_web_session(s, interactive=False)

    assert data == {"stage": "fresh"}
    assert fake.signin_calls == [("alice", "secret", None)]


def test_expired_session_signs_in_with_saved_password(monkeypatch):
    fake = _FakeSession("auth-1")
    fake.account_login_results = [{"stage": "fresh"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: False)

    s = {"username": "alice", "password": "secret", "webauth": {}}
    sess, data = app._ensure_web_session(s, interactive=False)

    assert data == {"stage": "fresh"}
    assert fake.signin_calls == [("alice", "secret", None)]


def test_2fa_challenge_requests_push_then_prompts_then_succeeds(monkeypatch):
    """The push must be explicitly requested; idmsa's 409 no longer auto-sends it."""
    fake = _FakeSession("auth-1")
    fake.needs_2fa_after_signin = True
    fake.account_login_results = [{"stage": "trusted"}]
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)
    monkeypatch.setattr(webauth, "hsa_challenge_required", lambda data: False)
    monkeypatch.setattr(app, "_twofa_prompt", lambda kind: "123456")

    s = {"username": "alice", "password": "secret", "webauth": {}}
    sess, data = app._ensure_web_session(s, interactive=True)

    assert fake.push_calls == 1
    assert fake.twofa_calls == ["123456"]
    assert data == {"stage": "trusted"}


def test_noninteractive_2fa_raises_instead_of_blocking(monkeypatch):
    fake = _FakeSession("auth-1")
    fake.needs_2fa_after_signin = True
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)

    s = {"username": "alice", "password": "secret", "webauth": {}}
    with pytest.raises(WebAuthError, match="2FA"):
        app._ensure_web_session(s, interactive=False)
    assert fake.push_calls == 0
    assert fake.twofa_calls == []


def test_no_saved_password_raises_clearly(monkeypatch):
    fake = _FakeSession("auth-1")  # no cached session_token: forces the signin path
    monkeypatch.setattr(webauth, "WebAuthSession", lambda *a, **k: fake)

    s = {"webauth": {}}
    with pytest.raises(WebAuthError, match="no saved Apple ID password"):
        app._ensure_web_session(s, interactive=False)
    assert fake.signin_calls == []


class _FakeSessionModule:
    """Stands in for icp.auth.session inside app.py (both `.load()` and `.save()`)."""

    def __init__(self, record):
        self.record = record
        self.saved = []

    def load(self):
        return self.record

    def save(self, s):
        self.saved.append(s)


def test_fetch_aliases_skips_silently_without_saved_password(monkeypatch, capsys):
    monkeypatch.setattr(app, "session", _FakeSessionModule({"username": "alice"}))
    monkeypatch.setattr(app, "_ensure_web_session",
                        lambda *a, **k: pytest.fail("must not touch the network without a password"))

    result = app._fetch_aliases_best_effort(interactive=False)

    assert result == []
    assert capsys.readouterr().err == ""


def test_fetch_aliases_warns_but_does_not_raise_on_failure(monkeypatch, capsys):
    """On failure, falls back to the cache (hme/store.py) rather than an empty list. The cache is
    mocked so the test doesn't depend on this machine's real aliases.enc."""
    from icp.hme import store as hme_store

    monkeypatch.setattr(app, "session", _FakeSessionModule({"password": "secret"}))
    monkeypatch.setattr(hme_store, "load_aliases", lambda: ["cached-fallback"])

    def boom(*a, **k):
        raise WebAuthError("2FA did not clear the web-session challenge")

    monkeypatch.setattr(app, "_ensure_web_session", boom)

    result = app._fetch_aliases_best_effort(interactive=False)

    assert result == ["cached-fallback"]
    assert "Hide My Email unavailable" in capsys.readouterr().err


def test_fetch_aliases_returns_parsed_list_on_success(monkeypatch):
    """`save_aliases` is mocked so the test doesn't overwrite this machine's real aliases.enc."""
    from icp.hme import client as hme_client, store as hme_store

    saved = []
    monkeypatch.setattr(hme_store, "save_aliases", lambda aliases: saved.append(aliases))
    monkeypatch.setattr(app, "session", _FakeSessionModule({"password": "secret"}))
    account_data = {"webservices": {
        "premiummailsettings": {"url": "https://p1-maildomainws.icloud.com", "status": "active"}}}
    fake_sess = SimpleNamespace(http=object())
    monkeypatch.setattr(app, "_ensure_web_session", lambda *a, **k: (fake_sess, account_data))

    alias = HmeAlias(anonymous_id="a1", address="quiet-otter@icloud.com", label="Claude",
                     note="", forward_to="me@example.com", is_active=True,
                     domain="claude.ai", created_at=0.0)

    class _FakeHmeClient:
        def __init__(self, base_url, http):
            self.base_url = base_url

        def list(self):
            return [alias]

    monkeypatch.setattr(hme_client, "HmeClient", _FakeHmeClient)

    result = app._fetch_aliases_best_effort(interactive=False)

    assert result == [alias]
    assert saved == [[alias]]
