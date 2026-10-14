"""Silent token auto-refresh before a sync (icp.auth.signin.ensure_fresh_tokens)."""

import pytest

from icp.auth import signin
from icp.auth.icloud import ICloudError
from icp.daemon.context import BackgroundFrontend, NeedsLogin

from apple_fakes import ScriptedFrontend


def test_fresh_token_no_reauth(monkeypatch):
    """If the mmeAuthToken is still valid, refresh succeeds and we never re-authenticate."""
    calls = []
    monkeypatch.setattr(signin, "refresh_webservices", lambda *a, **k: calls.append("refresh"))
    monkeypatch.setattr(signin, "mint_tokens",
                        lambda *a, **k: pytest.fail("must not re-auth when token is valid"))
    signin.ensure_fresh_tokens({"username": "u", "password": "p"}, None, None,
                               BackgroundFrontend())
    assert calls == ["refresh"]


def test_expired_token_reauths_with_saved_password(monkeypatch):
    """An expired mmeAuthToken triggers a silent re-auth with the stored password, then retry."""
    seq = []

    def fake_refresh(s, *a, **k):
        seq.append("refresh")
        if seq.count("refresh") == 1:      # first attempt: token expired
            raise ICloudError("iCloud credentials expired")
        # second attempt (after re-auth) succeeds

    def fake_mint(record, username, password, *a, **k):
        seq.append(f"mint:{username}:{password}")

    monkeypatch.setattr(signin, "refresh_webservices", fake_refresh)
    monkeypatch.setattr(signin, "mint_tokens", fake_mint)

    fe = ScriptedFrontend()
    signin.ensure_fresh_tokens({"username": "alice", "password": "secret"}, None, None, fe)
    assert seq == ["refresh", "mint:alice:secret", "refresh"]
    assert "signing_in" in fe.stages()


def test_expired_token_without_saved_password_raises(monkeypatch):
    """No stored password -> surface the expiry so the person signs in again."""
    monkeypatch.setattr(signin, "refresh_webservices",
                        lambda *a, **k: (_ for _ in ()).throw(ICloudError("expired")))
    monkeypatch.setattr(signin, "mint_tokens",
                        lambda *a, **k: pytest.fail("cannot re-auth without a password"))
    with pytest.raises(ICloudError):
        signin.ensure_fresh_tokens({"username": "u"}, None, None, BackgroundFrontend())


def test_background_2fa_raises_needs_login_instead_of_blocking():
    """The unattended 2FA callback raises instead of waiting for an answer nobody can give."""
    with pytest.raises(NeedsLogin):
        signin.twofa_prompt(BackgroundFrontend())("trusted")


def test_interactive_2fa_asks_the_frontend_for_a_code():
    fe = ScriptedFrontend({"code": "123456"})
    assert signin.twofa_prompt(fe)("sms") == "123456"
    assert ("stage", "verify", {"via": "sms"}) in fe.events
