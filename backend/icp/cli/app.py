"""Command-line interface.

Interactive: the Apple ID password and 2FA code are read from the terminal and never
stored. Only the resulting tokens are persisted, encrypted.

Commands: login, sync, logout, plus the app-* JSON commands the Pear Passwords window uses.
"""
import argparse
import base64
import logging
import sys
import time
import uuid
from datetime import datetime, timezone

from . import ui
from .. import diag, paths
from ..auth import grandslam as auth, icloud, session
from ..auth.anisette import Anisette, AnisetteError
from ..auth.device import Device
from ..auth.gsa import GSAClient, GSAError
from ..auth.session import SessionError
from ..errors import EncryptedStoreError, PassphraseMigrationError

ICLOUD_AUTH_TOKEN = "com.apple.gs.icloud.auth"


def _utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, timezone.utc)


def _twofa_prompt(kind: str) -> str:
    where = "your trusted Apple devices" if kind == "trusted" else "SMS"
    ui.stage("verify", via=kind)
    ui.step(f"A 2FA code was sent to {where}.")
    return ui.ask("6-digit code: ", kind="code")


def _mint_pet(device, anisette, username: str, password: str) -> str:
    """Mint a fresh GSA PET (password-equivalent token) for escrowproxy Basic auth. Silent on an
    already-trusted device (no 2FA re-prompt). Kept fresh per phase because the PET is short-lived."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, _twofa_prompt)
    _, pet, _ = auth.extract_pet(spd)
    return pet


def _bottle_fields(b: dict) -> tuple[str | None, str | None, list[str]]:
    """(the owner's name for the device, its model, [backed-up date, passcode kind, serial])
    from escrow GETRECORDS metadata. Any of it can be missing: that lookup is best-effort."""
    meta = b.get("meta") or {}
    cm = meta.get("ClientMetadata") or {}
    own = cm.get("device_name") or cm.get("deviceName")
    model = (cm.get("device_model") or cm.get("model") or cm.get("ProductType")
             or cm.get("device_model_class"))
    facts = []
    is_mac = _bottle_is_mac(b)
    when = meta.get("com.apple.securebackup.timestamp") or cm.get("SecureBackupMetadataTimestamp")
    if isinstance(when, datetime):
        facts.append(f"backed up {when.day} {when:%b %Y}")
    elif isinstance(when, str) and when[:10].count("-") == 2:
        try:
            d = datetime.strptime(when[:10], "%Y-%m-%d")
            facts.append(f"backed up {d.day} {d:%b %Y}")
        except ValueError:
            pass
    length = cm.get("SecureBackupNumericPassphraseLength")
    if is_mac:
        facts.append("Mac login password")      # a Mac escrows with its login password
    elif cm.get("SecureBackupUsesNumericPassphrase") and isinstance(length, int) and length:
        facts.append(f"{length}-digit passcode")
    elif cm.get("SecureBackupUsesComplexPassphrase"):
        facts.append("alphanumeric passcode")
    serial = meta.get("serial")
    if serial:
        facts.append(f"serial ending {str(serial)[-4:]}")
    return own, model, facts


def _bottle_name(b: dict) -> str:
    """What the device is called: the owner's own name for it, else its model."""
    own, model, _ = _bottle_fields(b)
    return own or model or "Unknown device"


def _bottle_model(b: dict) -> str:
    """The model, when the name doesn't already say it ("" otherwise)."""
    own, model, _ = _bottle_fields(b)
    return model if own and model and model.lower() not in own.lower() else ""


def _bottle_is_mac(b: dict) -> bool:
    cm = (b.get("meta") or {}).get("ClientMetadata") or {}
    return any("mac" in str(cm.get(k, "")).lower()
               for k in ("device_model", "model", "ProductType", "device_model_class", "device_platform"))


def _bottle_details(b: dict) -> str:
    _, _, facts = _bottle_fields(b)
    model = _bottle_model(b)
    facts = ([model] if model else []) + facts
    return " · ".join(facts) if facts else "details unavailable - can't tell which device this is"


def _describe_bottle(b: dict) -> str:
    """One line for the terminal: name, then the facts that tell two similar devices apart."""
    return f"{_bottle_name(b)} - {_bottle_details(b)}"


def _select_bottle(bottles: list[dict]) -> dict | None:
    """Let the user pick which device's escrow bottle to recover. Auto-selects a lone bottle.
    Returns the chosen `{id, otbottle, meta}` dict, or None to abort."""
    if len(bottles) == 1:
        ui.step(f"Using the only escrow bottle: {_describe_bottle(bottles[0])}")
        return bottles[0]
    ui.step("Multiple escrow bottles found. Pick the device you want to use:\n")
    i = ui.choose("Select a device", [_bottle_name(b) for b in bottles], kind="device",
                  details=[_bottle_details(b) for b in bottles])
    return None if i is None else bottles[i]


def _refresh_webservices(s: dict, device, anisette, log=None, debug=False) -> int | None:
    """Fetch account settings and cache the webservices URL map + cloudKitToken. Returns the
    endpoint count, or None on failure."""
    status, data = icloud.fetch_account_settings(s, device, anisette)
    if debug and log is not None:
        diag.dump(log, "account-settings response", data)
    if status == 401 or data.get("ErrorID") == "UNAUTHORIZED":
        raise icloud.ICloudError(
            f"iCloud credentials expired ({data.get('description') or 'unauthorized'}) - "
            "run `icp login` to re-authenticate")
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


def _mint_tokens(record: dict, username: str, password: str, device, anisette,
                 *, twofa=_twofa_prompt, log=None, debug=False) -> None:
    """SRP login with the password, then exchange the fresh 5-min PET for a new ~7-day
    mmeAuthToken; update `record`'s token fields in place. Preserves any already-cached
    cloudKitUserId (so a re-auth need not re-run ckAppInit). Raises on failure."""
    gsa = GSAClient(device, anisette)
    spd = auth.authenticate(gsa, username, password, twofa)
    dsid, pet, pet_expiry = auth.extract_pet(spd)
    if debug and log is not None:
        diag.dump(log, "GSA init response", gsa.last_init_response)
        diag.dump(log, "GSA complete response", gsa.last_complete_response)
        diag.dump(log, "Full spd", spd)
        diag.dump_token_dict(log, spd)

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

    mme_dsid, mme_token, service_data, raw = icloud.login_mobileme(
        username, pet, dsid, device.local_user_uuid, device, anisette)
    if debug and log is not None:
        diag.dump(log, "loginDelegates response", raw if isinstance(raw, dict) else {})
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


def _noninteractive_twofa(kind: str) -> str:
    """2FA callback for the unattended sync path: never blocks on stdin."""
    raise GSAError(
        "Apple asked for a 2FA code during the automatic token refresh (the anisette machine "
        "identity likely changed) - run `icp login` once interactively to re-establish trust")


def _ensure_fresh_tokens(s: dict, device, anisette, *, interactive: bool) -> None:
    """Make the cloudKitToken fresh before a sync. Re-mint it from the mmeAuthToken; if that
    token has expired too, silently re-authenticate with the saved password (no manual login).
    Raises icloud.ICloudError / AnisetteError / GSAError if it cannot recover."""
    try:
        _refresh_webservices(s, device, anisette)
        return
    except icloud.ICloudError:
        # The mmeAuthToken itself expired. Recover with the stored password if we have one.
        password = s.get("password")
        username = s.get("username")
        if not password or not username:
            raise
    ui.stage("signing_in")
    ui.step("iCloud token expired - re-authenticating with the saved password...")
    twofa = _twofa_prompt if interactive else _noninteractive_twofa
    _mint_tokens(s, username, password, device, anisette, twofa=twofa)
    _refresh_webservices(s, device, anisette)   # retry with the fresh mmeAuthToken


@paths.mutation_lock
def cmd_login(args) -> int:
    """Sign in to Apple, cache the persistent tokens, then join the keychain and sync.

    A single onboarding flow: the password entered here is reused for the join's escrow
    re-authentication, so it is never prompted twice. The irreversible escrow recovery is
    still gated by an explicit y/N prompt - answer No to stop after sign-in with tokens saved.
    """
    debug_path = diag.start() if args.debug else None
    log = logging.getLogger("icp.login")

    device = Device.load_or_create()
    anisette = Anisette(args.anisette)
    try:
        anisette.headers()  # fail fast if the anisette server is down
    except AnisetteError as e:
        ui.err(str(e))
        return 2

    # Preserve the Octagon peer identity (and cached cloudKitUserId) across re-logins: keychain
    # trust membership is permanent and tied to that keypair, not to the short-lived auth tokens.
    prior = session.load() or {}

    saved_user = prior.get("username")
    ui.stage("account")
    username = args.username or ui.ask(
        f"Apple ID [{saved_user}]: " if saved_user else "Apple ID: ",
        kind="apple_id", default=saved_user) or saved_user
    if not username:
        ui.err("no Apple ID given")
        return 2
    password = ui.secret("Password: ", kind="password")
    ui.stage("signing_in")

    record: dict = {}
    if prior.get("octagon", {}).get("peer_id"):
        record["octagon"] = prior["octagon"]
    if prior.get("mme", {}).get("cloudKitUserId"):
        record.setdefault("mme", {})["cloudKitUserId"] = prior["mme"]["cloudKitUserId"]
    if not args.no_save_password:
        record["password"] = password   # in the keyring-encrypted session; enables silent refresh

    # SRP login + mint the mmeAuthToken (the one hop that needs the password).
    mme_ok = False
    try:
        _mint_tokens(record, username, password, device, anisette, log=log, debug=args.debug)
        mme_ok = True
    except (GSAError, AnisetteError) as e:
        ui.err(f"sign-in failed: {e}")
        return 1
    except icloud.ICloudError as e:
        log.warning("loginDelegates failed: %s", e)
        ui.warn(f"could not mint the persistent mmeAuthToken: {e}")

    # With the fresh mmeAuthToken, fetch the iCloud service URLs (needed for join/sync).
    n_ws = None
    if mme_ok:
        try:
            n_ws = _refresh_webservices(record, device, anisette, log, args.debug)
        except (icloud.ICloudError, AnisetteError) as e:
            ui.warn(f"could not fetch iCloud service URLs: {e}")

    session.save(record)
    ui.out(f"Signed in as {username}.")

    if not (mme_ok and n_ws):
        ui.err("sign-in succeeded but iCloud service URLs are unavailable - cannot join the keychain")
        if debug_path:
            ui.out(f"Debug transcript (redacted): {debug_path}")
        return 1

    rc = _join_and_sync(record, device, anisette, username, password)
    # Fetch Hide My Email here (interactive): its web session is a separate auth surface that may
    # need its own 2FA, so handle that during login rather than surprising a later `icp sync`.
    n_aliases = len(_fetch_aliases_best_effort(interactive=True))
    if n_aliases:
        ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
    if debug_path:
        ui.out(f"Debug transcript (redacted): {debug_path}")
    return rc


def _fetch_aliases_best_effort(interactive: bool) -> list:
    """Hide My Email aliases, fetched via the web session (auth/webauth.py). Never fails the
    caller: no saved password skips silently, any other error warns and falls back to the cached
    aliases. On success, refreshes that cache (hme/store.py)."""
    from ..auth import webauth
    from ..hme.client import HmeClient, HmeError
    from ..hme.store import load_aliases, save_aliases

    s = session.load()
    if not s or not s.get("password"):
        return []
    try:
        sess, account_data = _ensure_web_session(s, interactive=interactive)
        session.save(s)
        base = webauth.extract_webservices(account_data).get("premiummailsettings")
        if not base:
            return load_aliases()
        aliases = HmeClient(base, sess.http).list()
        save_aliases(aliases)
        return aliases
    except (webauth.WebAuthError, HmeError) as e:
        ui.warn(f"Hide My Email unavailable: {e}")
        return load_aliases()


def _join_and_sync(s: dict, device, anisette, username: str, password: str) -> int:
    """Join the iCloud Keychain Octagon trust via escrow recovery, then sync.

    Escrow recovery is IRREVERSIBLE - escrowproxy destroys the record after 10 wrong
    passcodes. Gated: safe discovery first; an attempt is only spent after a y/N proceed
    prompt that defaults to No. The given password (entered during sign-in) is reused for
    the escrow re-authentication, so it is never prompted twice.
    """
    from ..octagon import client as octagon
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError

    # Already a trusted keychain peer (e.g. a token-refresh re-login)? Octagon membership is
    # permanent, so skip the irreversible escrow join and just sync. Gate on is_joined, not a bare
    # peer_id: aborting bottle selection persists peer_id without ever joining.
    if octagon.is_joined(s):
        ui.step("Already joined; syncing...")
        try:
            client = octagon.OctagonClient(s, device, anisette)
            session.save(s)
            ui.stage("syncing")
            n = client.sync_and_decrypt()
        except (OctagonError, CloudKitError) as e:
            ui.err(f"sync failed: {e}")
            return 1
        needs_login_file().unlink(missing_ok=True)   # trust is good again
        ui.stage("synced", count=n)
        ui.out(f"Synced {n} credential(s) into the vault.")
        return 0

    escrow_host = (s.get("webservices") or {}).get("keychainsync")
    if not escrow_host:
        ui.err("no escrow URL cached - cannot join the keychain")
        return 1

    octagon.ensure_peer_identity(s, device)  # generate the peer identity once
    session.save(s)

    try:
        client = octagon.OctagonClient(s, device, anisette)
        session.save(s)  # persist the cloudKitUserId resolved by ckAppInit
        ui.stage("finding_devices")
        ui.step("Discovering escrow bottles...")
        # A PET here only lists device metadata via GETRECORDS (non-destructive, spends no
        # attempt) so the user can see WHICH device each bottle belongs to before choosing.
        list_pet = _mint_pet(device, anisette, username, password)
        bottles = client.list_recoverable_bottles(escrow_host, username, list_pet, warn=ui.warn)
    except (OctagonError, CloudKitError, GSAError, AnisetteError) as e:
        ui.err(str(e))
        return 1

    if not bottles:
        ui.err("no recoverable escrow bottle - cannot join via this path")
        return 1

    chosen = _select_bottle(bottles)
    if chosen is None:
        ui.out("Aborted before selecting a bottle - no escrow attempt spent. You're signed in "
               "but NOT joined; run `icp login` again to retry the keychain join.")
        return 0

    ui.stage("device_chosen", name=_bottle_name(chosen), model=_bottle_model(chosen),
             secret="password" if _bottle_is_mac(chosen) else "passcode")
    ui.out(f"Joining iCloud Keychain will use the passcode of: {_describe_bottle(chosen)}")
    ui.out("This is IRREVERSIBLE - a wrong passcode spends 1 of ~10 attempts, and the 10th "
           "failed attempt destroys the escrow record permanently.")
    if not ui.confirm_yn("Proceed? (y/N) ", kind="join_confirm", detail=_bottle_name(chosen)):
        ui.stage("not_joined")
        ui.out("Aborted - no escrow attempt spent. You're signed in but NOT joined; "
               "run `icp login` again to retry the keychain join.")
        return 0

    # Mint a fresh PET right before the irreversible recovery so it can't expire during the
    # selection/confirmation delay above.
    try:
        pet = _mint_pet(device, anisette, username, password)
    except (GSAError, AnisetteError) as e:
        ui.err(f"sign-in failed: {e}")
        return 1

    passcode = ui.secret("Device passcode / iCloud Security Code for that device: ",
                         kind="device_passcode", detail=_bottle_name(chosen)).encode()
    ui.stage("joining")
    if not passcode:
        ui.err("empty passcode - aborting before spending an attempt")
        return 1
    try:
        client.join_via_escrow(escrow_host, username, pet, passcode, chosen,
                               confirm_irreversible=True)
    except Exception as e:  # noqa: BLE001 - surface any failure, never crash mid-join
        ui.err(f"join failed: {e}")
        return 1
    session.save(s)  # persist the peer identity + the recovered sponsor key for later syncs

    try:
        ui.stage("syncing")
        n = client.sync_and_decrypt()
    except CloudKitError as e:
        ui.err(f"joined, but sync failed: {e}")
        return 1
    ui.stage("synced", count=n)
    ui.out(f"Joined the keychain. Synced {n} credential(s).")
    return 0


def _notify_needs_login() -> None:
    """Tell the desktop once, because the alternative is failing silently forever."""
    import shutil
    import subprocess
    if not shutil.which("notify-send"):
        return
    try:
        # Name the launcher, not a bare command: the whole failure being reported here is
        # that there was nowhere to type the code, so the fix has to be something clickable.
        subprocess.run(["notify-send", "-a", "Pear Passwords", "-u", "critical",
                        "iCloud Keychain needs sign-in",
                        "Apple wants a verification code. Open <b>Pear Passwords</b> "
                        "and choose Sign in to enter it."],
                       check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


@paths.mutation_lock
def cmd_sync(args) -> int:
    """Fetch the keychain zones and decrypt them into the vault (requires a prior join).

    Guarded by the shared mutation lock so the periodic background trigger and a manual run
    can never overlap or race on the vault."""
    from ..octagon import client as octagon
    from ..octagon.client import OctagonError
    from ..transport.cloudkit import CloudKitError
    from ..paths import needs_login_file
    interactive = sys.stdin.isatty()
    if needs_login_file().exists() and not interactive:
        ui.err("standing down: Apple wants an interactive sign-in "
               "(run `icp login`, or `icp sync` from a terminal)")
        return 1

    s = session.load()
    if not s:
        ui.err("not signed in - run: icp login")
        return 1
    if not (s.get("octagon") or {}).get("peer_id"):
        ui.err("not joined to the keychain - run: icp login")
        return 1
    device = Device.load_or_create()
    anisette = Anisette(args.anisette)
    # The cached cloudKitToken is short-lived; re-mint it from the mmeAuthToken before every
    # sync. If the mmeAuthToken has also expired, _ensure_fresh_tokens silently re-authenticates
    # with the saved password (no manual login), unless 2FA is required or no password is saved.
    try:
        _ensure_fresh_tokens(s, device, anisette, interactive=interactive)
        session.save(s)  # persist any freshly re-minted tokens
    except (icloud.ICloudError, AnisetteError, GSAError) as e:
        ui.err(f"could not refresh the iCloud token: {e}")
        if not interactive:
            # Latch, so the next unattended attempt does not push Apple another code.
            needs_login_file().touch()
            _notify_needs_login()
        return 1
    try:
        client = octagon.OctagonClient(s, device, anisette)
        session.save(s)  # persist the refreshed cloudKitToken + cloudKitUserId from ckAppInit
        ui.stage("syncing")
        n = client.sync_and_decrypt()
    except (OctagonError, CloudKitError) as e:
        ui.err(f"sync failed: {e}")
        return 1
    needs_login_file().unlink(missing_ok=True)   # trust is good again
    ui.stage("synced", count=n)
    ui.out(f"Synced {n} credential(s) into the vault.")
    # Best-effort, never interactive: refresh the Hide My Email cache only while the web
    # session's trust is still valid, otherwise keep the cache. Its 2FA is handled at login
    # (cmd_login), so sync never prompts - see _fetch_aliases_best_effort.
    n_aliases = len(_fetch_aliases_best_effort(interactive=False))
    if n_aliases:
        ui.out(f"Cached {n_aliases} Hide My Email alias(es).")
    return 0


def _ensure_web_session(s: dict, *, interactive: bool):
    """Reach a valid idmsa web session (auth/webauth.py). Reuses a saved trust token when
    possible; otherwise signs in with the saved password and prompts for 2FA once. Returns
    (WebAuthSession, account_data)."""
    from ..auth import webauth

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
                "no saved Apple ID password for the web session - run `icp login` "
                "without --no-save-password")
        sess.signin(username, password, trust_token=sess.session_data.get("trust_token"))
        if sess.needs_2fa:
            if not interactive:
                raise webauth.WebAuthError(
                    "Apple asked for a 2FA code for the web session - run `icp show` "
                    "from a terminal once to establish trust")
            sess.request_push_notification()  # the 409 no longer auto-sends this on its own
            sess.submit_2fa(_twofa_prompt("trusted"))
        account_data = sess.account_login()
        if webauth.hsa_challenge_required(account_data):
            raise webauth.WebAuthError("2FA did not clear the web-session challenge")

    wa.update(sess.export())
    return sess, account_data


@paths.mutation_lock
def cmd_logout(args) -> int:
    session.recover_passphrase_migration()
    session.clear()
    ui.out("Session cleared. Device identity kept (use --wipe-device to remove it).")
    if args.wipe_device:
        from ..paths import device_file
        f = device_file()
        if f.exists():
            f.unlink()
        ui.out("Device identity wiped.")
    return 0


@paths.mutation_lock
def cmd_lock(args) -> int:
    from ..auth import agent, held_key, lockbox
    session.recover_passphrase_migration()
    try:
        agent.lock_strict()
    except (agent.AgentError, OSError) as e:
        ui.err(f"could not lock the key agent: {e}")
        return 1
    if lockbox.is_initialised():
        # Remove copies written by older releases. Current passphrase mode never writes one,
        # and the next operation must ask for the passphrase to refill the runtime agent.
        held_key.ensure_clean()
    ui.out("Locked.")
    return 0


@paths.mutation_lock
def cmd_unlock(args) -> int:
    from ..auth import agent, lockbox, prompt
    session.recover_passphrase_migration()
    if not lockbox.is_initialised():
        ui.err("No passphrase set. Run `icp passphrase` first.")
        return 1
    agent.unlock(prompt.ask_passphrase())
    try:
        # A prior migration may have committed the new files but failed while deleting a legacy
        # key.  Treat a normal unlock as the retry point, and do not leave the agent open if the
        # fail-closed cleanup still cannot complete.
        session._master_key()
    except BaseException:
        try:
            agent.lock_strict()
        except BaseException as lock_error:
            raise PassphraseMigrationError(
                "unlock cleanup failed and the runtime key could not be invalidated: "
                f"{lock_error}") from lock_error
        raise
    ui.out(f"Unlocked ({agent.status()}).")
    return 0


@paths.mutation_lock
def cmd_status(args) -> int:
    from ..auth import agent, lockbox
    session.recover_passphrase_migration()
    ui.out(f"passphrase: {'set' if lockbox.is_initialised() else 'not set (using keyring)'}")
    ui.out(f"agent: {agent.status()}")
    return 0


def _passphrase_migration_files():
    """Every local artifact that can change during a passphrase conversion."""
    from ..auth import lockbox
    return (
        lockbox.params_file(), lockbox.check_file(),
        paths.session_file(), paths.vault_file(), paths.aliases_file(),
        paths.history_file(), paths.nicknames_file(),
        paths.fallback_key_file(), paths.vault_key_file(),
        paths.legacy_key_cleanup_file(), paths.master_key_cleanup_file(),
    )


def _stage_migration_blob(transaction: dict, name: str, blob: bytes) -> None:
    stage = session.migration_stage(transaction, name)
    paths.atomic_write_private(stage, blob)
    session.mark_migration_entry(
        transaction, name, present=True, digest=paths.private_digest(stage))


@paths.mutation_lock
def cmd_passphrase(args) -> int:
    """Set or change the passphrase, re-encrypting everything already stored.

    Read the old data with the *current* key before switching, or it becomes unreadable - the
    stores are encrypted under whatever `_master_key()` returned at write time."""
    from ..auth import agent, held_key, lockbox, prompt
    from ..hme import store as hme_store
    from ..vault import store as vault_store
    from ..vault import history as history_store, nicknames as nickname_store

    session.recover_passphrase_migration()

    old_session = session.load()
    # History and nicknames sit under the same master key; leaving them out made them
    # unreadable the moment the key changed. All reads are strict so a corrupt store cannot be
    # silently replaced by an empty ciphertext during migration.
    old_vault = vault_store.load_vault()
    old_aliases = hme_store.load_aliases()
    old_history = history_store.load()
    old_names = nickname_store.load()

    targets = session._migration_targets()
    old_files = {name: targets[name].exists()
                 for name in ("session", "vault", "aliases", "history", "nicknames")}

    new = prompt.ask_passphrase(text="Choose a passphrase for your keychain")
    again = prompt.ask_passphrase(text="Confirm passphrase")
    if new != again:
        ui.err("Passphrases did not match.")
        return 1
    if len(new) < 8:
        ui.err("Too short - use a passphrase, not a password.")
        return 1

    transaction = None
    session._set_passphrase_migration_active(True)
    try:
        transaction = session.begin_passphrase_migration({
            "params": True,
            "check": True,
            **old_files,
        })
        new_key, params_blob, check_blob = lockbox.prepare_initialisation(new)
        # Invalidate the old runtime lease before deriving a new one. A failure leaves all
        # destinations untouched and the preparing journal can be discarded safely.
        agent.lock_strict()
        agent.unlock_key(new_key)
        # Keyring mode has no active KDF files yet, so _master_key() would otherwise select the
        # old keyring key while writing the staged stores. Keep the derived key transiently in
        # this process until the journal publishes the new KDF metadata.
        session._set_passphrase_migration_key(new_key)

        if old_files["session"]:
            session.save(old_session, path=session.migration_stage(transaction, "session"))
            session.mark_migration_entry(
                transaction, "session", present=True,
                digest=paths.private_digest(session.migration_stage(transaction, "session")))
        if old_files["vault"]:
            vault_store.save_vault(old_vault, path=session.migration_stage(transaction, "vault"))
            session.mark_migration_entry(
                transaction, "vault", present=True,
                digest=paths.private_digest(session.migration_stage(transaction, "vault")))
        if old_files["aliases"]:
            hme_store.save_aliases(old_aliases, path=session.migration_stage(transaction, "aliases"))
            session.mark_migration_entry(
                transaction, "aliases", present=True,
                digest=paths.private_digest(session.migration_stage(transaction, "aliases")))
        if old_files["history"]:
            history_store.save(old_history, path=session.migration_stage(transaction, "history"))
            session.mark_migration_entry(
                transaction, "history", present=True,
                digest=paths.private_digest(session.migration_stage(transaction, "history")))
        if old_files["nicknames"]:
            nickname_store.save(old_names, path=session.migration_stage(transaction, "nicknames"))
            session.mark_migration_entry(
                transaction, "nicknames", present=True,
                digest=paths.private_digest(session.migration_stage(transaction, "nicknames")))

        _stage_migration_blob(transaction, "params", params_blob)
        _stage_migration_blob(transaction, "check", check_blob)

        # Once this state is durable, every destination can be completed from staged bytes after
        # a SIGKILL or power loss. No rollback needs the old key, and legacy cleanup is still
        # deferred until the committed files have been verified.
        session.mark_migration_committing(transaction)
        session.mark_migration_committed(transaction)
    except BaseException as error:
        session._set_passphrase_migration_active(False)
        try:
            # A failed invalidation must never be hidden. If the transaction is already
            # committing, leave its journal for deterministic completion on the next command.
            agent.lock_strict()
        except BaseException as lock_error:
            raise PassphraseMigrationError(
                "passphrase migration failed; the runtime key could not be invalidated and the "
                f"migration journal was retained: {lock_error}"
            ) from lock_error
        if transaction is not None and transaction.get("state") == "preparing":
            session.abort_passphrase_migration(transaction)
        elif transaction is not None:
            raise PassphraseMigrationError(
                "passphrase migration was interrupted after commit began; rerun the command "
                "to finish its durable journal recovery"
            ) from error
        raise
    finally:
        session._set_passphrase_migration_key(None)
        session._set_passphrase_migration_active(False)

    # These are post-commit, fail-closed cleanup steps. A failure leaves the new encrypted data
    # usable with the passphrase but deliberately does not claim that every old unlock path is
    # gone; the next unlock/explicit migration retry performs the cleanup again. The journal stays
    # in the committed state until both cleanup and its removal succeed.
    try:
        held_key.ensure_clean()
        session.ensure_legacy_master_key_clean()
        session.finish_passphrase_migration()
    except BaseException:
        raise

    ui.out(f"Passphrase set; existing data re-encrypted. The derived key is kept only in the "
           f"runtime agent and auto-locks after {agent.DEFAULT_TIMEOUT // 60} min idle "
           f"(ICP_LOCK_TIMEOUT to change); locking or restarting requires the passphrase.")
    return 0


def build_parser():
    """The CLI parser. Exposed so app-signin can materialise a complete default namespace for
    `login`/`sync` rather than constructing one by hand - a hand-built one silently loses any
    option added later, which is how `args.debug` went missing the first time."""
    return _build_parser()


def _build_parser():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(
        prog="icp",
        description="iCloud Passwords for Linux - read-only iCloud Keychain autofill")
    p.add_argument("--anisette",
                   help="anisette server URL (default: $ICP_ANISETTE_URL or localhost:6969)")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser(
        "login", help="sign in, join the iCloud Keychain trust, and do the first sync")
    lp.add_argument("-u", "--username", help="Apple ID (prompted if omitted)")
    lp.add_argument("--no-save-password", action="store_true",
                    help="don't store the password for silent token refresh (re-login manually "
                         "each time the ~7-day token expires)")
    lp.add_argument("--debug", action="store_true", help="write a redacted debug transcript")
    lp.set_defaults(func=cmd_login)

    sub.add_parser("sync", help="re-fetch and decrypt the keychain into the vault"
                   ).set_defaults(func=cmd_sync)

    op = sub.add_parser("logout", help="clear the stored session")
    op.add_argument("--wipe-device", action="store_true", help="also remove the device identity")
    op.set_defaults(func=cmd_logout)

    sub.add_parser("passphrase", help="set/change the passphrase that protects the vault"
                   ).set_defaults(func=cmd_passphrase)
    sub.add_parser("lock", help="forget the key now").set_defaults(func=cmd_lock)
    sub.add_parser("unlock", help="unlock for this session").set_defaults(func=cmd_unlock)
    sub.add_parser("status", help="show passphrase/lock state").set_defaults(func=cmd_status)

    # JSON surface for the Passwords app. Hidden from the top-level help: these are a machine
    # interface, not something to hand-run, and each gates on the fingerprint overlay itself.
    from . import appapi
    p_list = sub.add_parser("app-list", help=argparse.SUPPRESS)
    p_list.add_argument("--all", action="store_true")
    p_list.set_defaults(func=appapi.cmd_app_list)
    sub.add_parser("app-lock", help=argparse.SUPPRESS).set_defaults(func=appapi.cmd_app_lock)
    sub.add_parser("app-auth", help=argparse.SUPPRESS).set_defaults(func=appapi.cmd_app_auth)
    sub.add_parser("app-lock-app", help=argparse.SUPPRESS).set_defaults(func=appapi.cmd_app_lock_app)
    sub.add_parser("app-unlock", help=argparse.SUPPRESS).set_defaults(func=appapi.cmd_app_unlock)
    for name, fn in (("app-reveal", appapi.cmd_app_reveal),
                     ("app-history", appapi.cmd_app_history),
                     ("app-totp", appapi.cmd_app_totp),
                     ("app-set-password", appapi.cmd_app_set_password),
                     ("app-set-nickname", appapi.cmd_app_set_nickname),
                     ("app-details", appapi.cmd_app_details),
                     ("app-set-details", appapi.cmd_app_set_details),
                     ("app-set-totp", appapi.cmd_app_set_totp)):
        sp = sub.add_parser(name, help=argparse.SUPPRESS)
        sp.add_argument("id")
        sp.set_defaults(func=fn)
    p_copy = sub.add_parser("app-copy", help=argparse.SUPPRESS)
    p_copy.add_argument("id")
    p_copy.add_argument("--field", default="password",
                        choices=["password", "username", "domain"])
    p_copy.add_argument("--seconds", type=int, default=30)
    p_copy.set_defaults(func=appapi.cmd_app_copy)
    for name, fn in (("app-totp-preview", appapi.cmd_app_totp_preview),
                     ("app-scan-qr", appapi.cmd_app_scan_qr),
                     ("app-create", appapi.cmd_app_create)):
        sub.add_parser(name, help=argparse.SUPPRESS).set_defaults(func=fn)
    sub.add_parser("app-generate", help=argparse.SUPPRESS).set_defaults(
        func=appapi.cmd_app_generate)
    p_si = sub.add_parser("app-signin", help=argparse.SUPPRESS)
    p_si.add_argument("--mode", default="login", choices=["login", "sync"])
    p_si.add_argument("--username", default=None)
    p_si.set_defaults(func=appapi.cmd_app_signin)

    return p


def main(argv=None) -> int:
    p = _build_parser()
    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ui.err("aborted")
        return 130
    except (SessionError, EncryptedStoreError) as e:
        ui.err(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
