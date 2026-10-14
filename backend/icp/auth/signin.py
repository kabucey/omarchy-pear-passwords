"""The token steps of Apple's sign-in, shared by the daemon's login, relogin and sync.

Every function that may need a person takes the frontend it should ask (`ui`, a
daemon.context.Frontend) instead of reaching for a module-level one: the daemon runs several
users' Apple work at once, and a background run's frontend raises NeedsLogin rather than
blocking. Nothing here reads a terminal, a file or a key; the session record is a plain dict the
caller loads from and saves to the store.
"""

from __future__ import annotations

import base64
import time
import uuid

from . import grandslam as auth, icloud
from .gsa import GSAClient


def twofa_prompt(ui):
    """The 2FA callback grandslam calls once Apple has sent a code. For a background frontend
    the ask raises NeedsLogin, which unwinds the whole refresh."""
    def ask(kind: str) -> str:
        where = "your trusted Apple devices" if kind == "trusted" else "SMS"
        ui.stage("verify", via=kind)
        ui.emit("step", f"A 2FA code was sent to {where}.")
        return ui.ask("6-digit code: ", kind="code")
    return ask


def mint_pet(device, anisette, username: str, password: str, *, twofa) -> str:
    """Mint a fresh GSA PET (password-equivalent token) for escrowproxy Basic auth. Silent on an
    already-trusted device (no 2FA re-prompt). Kept fresh per phase because the PET is
    short-lived."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, twofa)
    _, pet, _ = auth.extract_pet(spd)
    return pet


def refresh_webservices(s: dict, device, anisette) -> int | None:
    """Fetch account settings and cache the webservices URL map + cloudKitToken. Returns the
    endpoint count, or None when Apple listed none."""
    status, data = icloud.fetch_account_settings(s, device, anisette)
    if status == 401 or data.get("ErrorID") == "UNAUTHORIZED":
        raise icloud.ICloudError(
            f"iCloud credentials expired ({data.get('description') or 'unauthorized'})")
    if data.get("status") not in (0, None):
        raise icloud.ICloudError(f"iCloud rejected the token: {data.get('status-message')}")
    ws = icloud.extract_webservices(data)
    if not ws:
        return None
    s["webservices"] = {k: (v.get("url") if isinstance(v, dict) else v) for k, v in ws.items()}
    tokens = data.get("tokens") or {}
    if tokens.get("cloudKitToken"):
        s.setdefault("mme", {}).setdefault("tokens", {}).update(tokens)
    return len(ws)


def mint_tokens(record: dict, username: str, password: str, device, anisette, *, twofa) -> None:
    """SRP login with the password, then exchange the fresh 5-min PET for a new ~7-day
    mmeAuthToken; update `record`'s token fields in place. Preserves any already-cached
    cloudKitUserId (so a re-auth need not re-run ckAppInit). Raises on failure."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, twofa)
    dsid, pet, pet_expiry = auth.extract_pet(spd)

    sk = gsa.last_session_key
    app_tokens = spd.get("t") or {}
    record.update({
        "username": username,
        "dsid": dsid,
        "dsid_numeric": spd.get("DsPrsId"),  # mobileme auth uses the numeric dsid
        "pet": pet,
        "pet_expiry": pet_expiry,
        "logged_in_at": int(time.time()),
        "gsidms": spd.get("GsIdmsToken"),
        "sk_b64": base64.b64encode(sk).decode() if sk else None,
        "app_tokens": {
            name: {"token": e.get("token"), "expiry": e.get("expiry"),
                   "duration": e.get("duration")}
            for name, e in app_tokens.items() if isinstance(e, dict)
        },
    })

    mme_dsid, mme_token, service_data, _raw = icloud.login_mobileme(
        username, pet, dsid, device.local_user_uuid, device, anisette)
    mme = record.setdefault("mme", {})
    ck_uid = mme.get("cloudKitUserId")   # keep the per-container id resolved by an earlier ckAppInit
    mme.update({
        "dsid": mme_dsid,
        "mmeAuthToken": mme_token,
        "tokens": service_data.get("tokens") or {},
        "minted_at": int(time.time()),
    })
    if ck_uid:
        mme["cloudKitUserId"] = ck_uid


def ensure_fresh_tokens(s: dict, device, anisette, ui) -> None:
    """Make the cloudKitToken fresh before a sync. Re-mint it from the mmeAuthToken; if that
    token has expired too, re-authenticate with the saved password (no manual login).

    A 2FA demand during that re-authentication goes to `ui`; for a background run that raises
    NeedsLogin. Raises icloud.ICloudError when the token expired and no password was saved,
    and AnisetteError / GSAError when it cannot recover."""
    try:
        refresh_webservices(s, device, anisette)
        return
    except icloud.ICloudError:
        # The mmeAuthToken itself expired. Recover with the stored password if we have one.
        password = s.get("password")
        username = s.get("username")
        if not password or not username:
            raise
    ui.stage("signing_in")
    ui.emit("step", "iCloud token expired - re-authenticating with the saved password...")
    # A frontend with nobody behind it (background sync) gets no 2FA callback at all, so
    # grandslam stands down before Apple pushes a code to the person's devices.
    twofa = twofa_prompt(ui) if getattr(ui, "interactive", True) else None
    mint_tokens(s, username, password, device, anisette, twofa=twofa)
    refresh_webservices(s, device, anisette)   # retry with the fresh mmeAuthToken


def ensure_web_session(s: dict, ui, *, interactive: bool):
    """Reach a valid idmsa web session (auth/webauth.py). Reuses a saved trust token when
    possible; otherwise signs in with the saved password and, only when `interactive`, asks
    `ui` for 2FA once. Returns (WebAuthSession, account_data)."""
    from . import webauth

    wa = s.setdefault("webauth", {})
    frame_tag = wa.get("frame_tag") or f"auth-{uuid.uuid4()}"
    wa["frame_tag"] = frame_tag
    sess = webauth.WebAuthSession(frame_tag, session_data=wa.get("session_data"),
                                  cookies=wa.get("cookies"))

    account_data = None
    if getattr(sess, "cookies_need_reauth", False):
        # Older exports stored a name -> value dict.  Those values are hostless when
        # reconstructed by Requests, so WebAuthSession discards them and forces a full
        # sign-in instead of attempting accountLogin with stale session state.
        sess.session_data.clear()
    elif sess.session_data.get("session_token"):
        try:
            account_data = sess.account_login()
            if webauth.hsa_challenge_required(account_data):
                account_data = None  # saved session is stale/untrusted -> fall through to signin
        except webauth.WebAuthError:
            account_data = None

    if account_data is None:
        username, password = s.get("username"), s.get("password")
        if not username or not password:
            raise webauth.WebAuthError(
                "no saved Apple ID password for the web session - sign in again and keep "
                "the password saved")
        sess.signin(username, password, trust_token=sess.session_data.get("trust_token"))
        if sess.needs_2fa:
            if not interactive:
                # Hide My Email is a separate auth surface. A background sync must not push a
                # code to the person's phone for it; the next sign-in in the window handles it.
                raise webauth.WebAuthError(
                    "Apple asked for a 2FA code for the web session - sign in again in "
                    "Pear Passwords to re-establish trust")
            sess.request_push_notification()  # the 409 no longer auto-sends this on its own
            sess.submit_2fa(twofa_prompt(ui)("trusted"))
        account_data = sess.account_login()
        if webauth.hsa_challenge_required(account_data):
            raise webauth.WebAuthError("2FA did not clear the web-session challenge")

    wa.update(sess.export())
    return sess, account_data
