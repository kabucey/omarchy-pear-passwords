"""The Apple pipeline as the daemon calls it. These signatures are part of the daemon's contract.

Every function is blocking (network-bound) and is run by the daemon in a worker thread under the
uid's store lock. Each takes a UserContext whose store is unlocked, reads and writes the
iCloud session only through ctx.store, and asks questions only through ctx.ui - so a
background call (ctx.frontend is None) that needs a person raises NeedsLogin.

This module must never import or name the daemon's authorization module (not even in a
comment), and a sync must never unseal SK_secret: tests grep, walk the AST and count unseals.

Errors: NeedsLogin (context), Cancelled (context), icp.auth.anisette.AnisetteError for an
unreachable anisette server, and icp.errors.AppleError subclasses for everything iCloud
refuses. The daemon maps them to the error codes in docs/protocol.md. Two more are defined here:
NotSignedIn (no iCloud session, or one that never joined the keychain: `not-signed-in`) and
FieldError (a value that failed validation: `invalid` with `field`). Network failures surface
as requests.RequestException (`network`).
"""

from __future__ import annotations

import dataclasses
import logging
import time
from typing import TYPE_CHECKING

from ..auth import session as session_store, signin
from ..auth.anisette import Anisette
from ..auth.device import Device
from ..errors import AppleError
from .context import Cancelled, NeedsLogin

if TYPE_CHECKING:
    from .context import UserContext

logger = logging.getLogger(__name__)

NICKNAME_MAX = 80


class NotSignedIn(AppleError):
    """No iCloud session, or a session that never joined the keychain. Protocol `not-signed-in`."""


class FieldError(ValueError):
    """A field failed validation. Protocol `invalid`, with `field` naming it (and `detail`,
    when set: a fixed word such as "not-utf8", never a value)."""

    def __init__(self, field: str, message: str = "", detail: str = ""):
        super().__init__(message or f"invalid {field}")
        self.field = field
        self.detail = detail


# --------------------------------------------------------------------------- shared steps

def _still_unlocked(ctx: "UserContext") -> None:
    """Stop between network steps once the user has locked. The store refuses every call
    after a lock by itself; this keeps a sync from going on talking to Apple (and holding a
    fresh keychain fetch in memory) for nothing."""
    pending = getattr(ctx.store, "lock_pending", None)
    if pending is not None and pending():
        from ..vstore import StoreLocked
        raise StoreLocked("locked during the sync")


def _session(ctx: "UserContext", *, joined: bool = True) -> dict:
    s = session_store.load(ctx.store)
    if not s:
        raise NotSignedIn("not signed in to iCloud")
    if joined:
        from ..octagon import client as octagon
        if not octagon.is_joined(s):
            raise NotSignedIn("signed in, but not joined to the iCloud Keychain")
    return s


def _fresh_tokens(ctx: "UserContext", s: dict, device, anisette) -> None:
    """Make the session's tokens fresh, or stand down.

    Once Apple has asked for a person (the needs_login latch), a run with nobody to ask does
    not try again: every attempt would push another code to the person's phone that nothing
    here can accept. Only an interactive sign-in clears the latch."""
    from ..auth.gsa import GSAError
    from ..auth.icloud import ICloudError

    if not ctx.interactive and ctx.store.status().get("needs_login"):
        raise NeedsLogin("standing down until the next sign-in")
    try:
        signin.ensure_fresh_tokens(s, device, anisette, ctx.ui)
    except NeedsLogin:
        ctx.store.set_sync_status(needs_login=True)
        raise
    except (ICloudError, GSAError) as e:
        if ctx.interactive:
            raise
        # The token expired and could not be renewed without a person: no saved password,
        # a changed one, or a 2FA demand. Latch it, so the next scheduled run stands down.
        ctx.store.set_sync_status(needs_login=True)
        raise NeedsLogin(str(e)) from e
    session_store.save(ctx.store, s)


def _deleted(store, items: list, failed_zones: list) -> set:
    """Ids to tombstone: entries the store has that this fetch did not return.

    An entry missing because its zone failed to load is not a deletion, and neither is a fetch
    that decrypted nothing at all (lost TLKs look exactly like that): both skip deletions for
    this round rather than emptying the list."""
    present = {i.id for i in items}
    if failed_zones:
        logger.warning("not applying deletions: %d zone(s) did not load", len(failed_zones))
        return set()
    known = {m.id for m in store.list_meta()}
    gone = known - present
    if gone and not present:
        logger.warning("not applying deletions: the keychain returned no entries at all")
        return set()
    return gone


def _sync_with(ctx: "UserContext", s: dict, device, anisette, client=None) -> dict:
    """Fetch and decrypt the keychain over a fresh session, and hand it to the store.

    Writes go through apply_sync, which needs only PK_secret and pwmac: nothing here opens an
    entry, so the entry key stays sealed for the whole sync."""
    from ..octagon import client as octagon

    store = ctx.store
    _still_unlocked(ctx)
    if client is None:
        client = octagon.OctagonClient(s, device, anisette)
    session_store.save(store, s)   # the refreshed cloudKitToken + cloudKitUserId from ckAppInit
    ctx.ui.stage("syncing")
    items = client.sync_and_decrypt(nicknames=store.load_nicknames())
    ctx.item_shape = getattr(client, "item_shape", None)
    _still_unlocked(ctx)
    deleted = _deleted(store, items, getattr(client, "failed_zones", []))
    counts = dict(store.apply_sync(items, deleted))
    n = len(items)
    del items
    synced_at = time.time()
    store.set_sync_status(synced_at=synced_at, needs_login=False)
    ctx.ui.stage("synced", count=n)
    ctx.ui.emit("out", f"Synced {n} credential(s).")
    return {**counts, "synced_at": synced_at}


def _device(ctx: "UserContext"):
    return Device.load_or_create(ctx.store), Anisette(ctx.anisette_url)


# --------------------------------------------------------------------------- sync

def sync(ctx: "UserContext") -> dict:
    """Refresh tokens non-interactively if needed, fetch and decrypt the keychain, and hand
    the items to ctx.store.apply_sync. Refreshes Hide My Email aliases best-effort. Records
    synced_at and clears needs_login on success. Returns apply_sync's counts plus
    {"synced_at": unix seconds}."""
    s = _session(ctx)
    device, anisette = _device(ctx)
    _still_unlocked(ctx)
    _fresh_tokens(ctx, s, device, anisette)
    result = _sync_with(ctx, s, device, anisette)
    _still_unlocked(ctx)
    fetch_aliases(ctx)
    return result


# --------------------------------------------------------------------------- sign-in

def _signin(ctx: "UserContext", prior: dict) -> None:
    """Sign in to Apple, save the tokens, then join the keychain (once) and sync.

    The password typed here is reused for the join's escrow re-authentication, so it is never
    asked twice, and it is kept in the session (sealed in the store) so an expired token can
    be renewed without asking again. The irreversible escrow recovery is still gated by an
    explicit yes/no that defaults to no."""
    if not ctx.interactive:
        raise NeedsLogin("signing in needs someone to answer")   # before any network
    ui = ctx.ui
    device, anisette = _device(ctx)
    anisette.headers()   # fail fast if the anisette server is down

    saved_user = prior.get("username")
    ui.stage("account")
    username = (ui.ask(f"Apple ID [{saved_user}]: " if saved_user else "Apple ID: ",
                       kind="apple_id", default=saved_user) or saved_user or "").strip()
    if not username:
        raise FieldError("apple_id", "no Apple ID given")
    password = ui.secret("Password: ", kind="password")
    if not password:
        raise FieldError("password", "no password given")
    ui.stage("signing_in")

    # Preserve the Octagon peer identity (and cached cloudKitUserId) across re-logins: keychain
    # trust membership is permanent and tied to that keypair, not to the short-lived tokens.
    record: dict = {}
    if (prior.get("octagon") or {}).get("peer_id"):
        record["octagon"] = prior["octagon"]
    if (prior.get("mme") or {}).get("cloudKitUserId"):
        record.setdefault("mme", {})["cloudKitUserId"] = prior["mme"]["cloudKitUserId"]
    record["password"] = password

    # SRP login + mint the mmeAuthToken (the one hop that needs the password), then the
    # iCloud service URLs the join and sync need. Nothing is saved until both worked, so a
    # failed sign-in leaves the previous session exactly as it was.
    signin.mint_tokens(record, username, password, device, anisette,
                       twofa=signin.twofa_prompt(ui))
    if not signin.refresh_webservices(record, device, anisette):
        raise AppleError("signed in, but iCloud listed no service URLs - cannot join the keychain")
    session_store.save(ctx.store, record)
    ui.emit("out", f"Signed in as {username}.")

    _join_and_sync(ctx, record, device, anisette, username, password)
    # Hide My Email's web session is a separate auth surface that may want its own 2FA, so it
    # is handled here, while someone is present, rather than surprising a later sync.
    n_aliases = fetch_aliases(ctx)
    if n_aliases:
        ui.emit("out", f"Cached {n_aliases} Hide My Email alias(es).")


def _join_and_sync(ctx: "UserContext", s: dict, device, anisette, username: str,
                   password: str) -> dict:
    """Join the iCloud Keychain Octagon trust via escrow recovery, then sync.

    Escrow recovery is IRREVERSIBLE - escrowproxy destroys the record after 10 wrong
    passcodes. Discovery comes first and spends nothing; an attempt is only spent after a
    yes/no that defaults to no. Declining at either question raises Cancelled, with the
    sign-in itself kept: the next sign-in skips straight to the device choice."""
    from ..octagon import bottles, client as octagon

    ui = ctx.ui
    # Already a trusted keychain peer (e.g. a token-refresh re-login)? Octagon membership is
    # permanent, so skip the irreversible escrow join and just sync. Gate on is_joined, not a
    # bare peer_id: aborting bottle selection persists peer_id without ever joining.
    if octagon.is_joined(s):
        ui.emit("step", "Already joined; syncing...")
        return _sync_with(ctx, s, device, anisette)

    escrow_host = (s.get("webservices") or {}).get("keychainsync")
    if not escrow_host:
        raise AppleError("no escrow URL cached - cannot join the keychain")

    octagon.ensure_peer_identity(s, device)  # generate the peer identity once
    session_store.save(ctx.store, s)

    client = octagon.OctagonClient(s, device, anisette)
    session_store.save(ctx.store, s)  # persist the cloudKitUserId resolved by ckAppInit
    ui.stage("finding_devices")
    ui.emit("step", "Discovering escrow bottles...")
    twofa = signin.twofa_prompt(ui)
    # A PET here only lists device metadata via GETRECORDS (non-destructive, spends no
    # attempt) so the person can see WHICH device each bottle belongs to before choosing.
    list_pet = signin.mint_pet(device, anisette, username, password, twofa=twofa)
    found = client.list_recoverable_bottles(escrow_host, username, list_pet,
                                            warn=lambda m: ui.emit("warn", m))
    if not found:
        raise AppleError("no recoverable escrow bottle - cannot join via this path")

    chosen = bottles.select(ui, found)
    if chosen is None:
        ui.stage("not_joined")
        raise Cancelled("no device chosen - no escrow attempt spent")

    ui.stage("device_chosen", name=bottles.name(chosen), model=bottles.model(chosen),
             secret="password" if bottles.is_mac(chosen) else "passcode")
    ui.emit("out", f"Joining iCloud Keychain will use the passcode of: {bottles.describe(chosen)}")
    ui.emit("out", "This is IRREVERSIBLE - a wrong passcode spends 1 of ~10 attempts, and the "
                   "10th failed attempt destroys the escrow record permanently.")
    if not ui.confirm_yn("Proceed? (y/N) ", kind="join_confirm", detail=bottles.name(chosen)):
        ui.stage("not_joined")
        raise Cancelled("join declined - no escrow attempt spent")

    # Mint a fresh PET right before the irreversible recovery so it can't expire during the
    # selection/confirmation delay above.
    pet = signin.mint_pet(device, anisette, username, password, twofa=twofa)
    passcode = ui.secret("Device passcode / iCloud Security Code for that device: ",
                         kind="device_passcode", detail=bottles.name(chosen)).encode()
    ui.stage("joining")
    if not passcode:
        raise FieldError("device_passcode", "empty passcode - no escrow attempt spent")
    client.join_via_escrow(escrow_host, username, pet, passcode, chosen,
                           confirm_irreversible=True)
    session_store.save(ctx.store, s)  # the peer identity + the recovered sponsor key
    ui.emit("out", "Joined the keychain.")
    return _sync_with(ctx, s, device, anisette, client)


def login(ctx: "UserContext") -> None:
    """Full interactive sign-in (Apple ID, password, 2FA, escrow join), then a first sync.
    Requires ctx.frontend."""
    _signin(ctx, session_store.load(ctx.store) or {})


def relogin(ctx: "UserContext") -> None:
    """Re-authenticate an existing session after needs-login (password, 2FA), then sync.
    Requires ctx.frontend."""
    _signin(ctx, _session(ctx, joined=False))


def signout(ctx: "UserContext") -> None:
    """Forget the iCloud session: ctx.store.save_session({}). Entries stay readable locally;
    nothing syncs until the next signin."""
    session_store.clear(ctx.store)


# --------------------------------------------------------------------------- Hide My Email

def fetch_aliases(ctx: "UserContext") -> int:
    """Refresh Hide My Email aliases into ctx.store; returns how many there are.

    Best-effort and never fails its caller: with no saved password it does nothing, and any
    error keeps the aliases already stored. Its web session may want its own 2FA; that is
    asked only when someone is there (ctx.interactive) and skipped otherwise."""
    import requests
    from ..auth import webauth
    from ..hme.client import HmeClient, HmeError

    store = ctx.store
    s = session_store.load(store)
    if not s or not s.get("password"):
        return len(store.load_aliases())
    try:
        sess, account_data = signin.ensure_web_session(s, ctx.ui, interactive=ctx.interactive)
        session_store.save(store, s)
        base = webauth.extract_webservices(account_data).get("premiummailsettings")
        if not base:
            return len(store.load_aliases())
        aliases = HmeClient(base, sess.http).list()
        store.save_aliases([dataclasses.asdict(a) for a in aliases])
        return len(aliases)
    except (webauth.WebAuthError, HmeError, requests.RequestException, NeedsLogin) as e:
        ctx.ui.emit("warn", f"Hide My Email unavailable: {e}")
    except Cancelled:
        # Only the optional alias step was cancelled; the sign-in it follows stands.
        ctx.ui.emit("warn", "Hide My Email skipped")
    return len(store.load_aliases())


# --------------------------------------------------------------------------- edits

def _open_zone(ctx: "UserContext"):
    """A fresh session and every keychain zone, for one edit."""
    from ..cli import push
    from ..octagon import client as octagon

    s = _session(ctx)
    device, anisette = _device(ctx)
    _fresh_tokens(ctx, s, device, anisette)
    client = octagon.OctagonClient(s, device, anisette)
    zone = push.open_zone(client)
    session_store.save(ctx.store, s)
    return zone


def _totp_cfg(value):
    """fields.totp -> the config push_details takes: a parsed setup, or None to remove."""
    from .. import totp
    if not isinstance(value, dict):
        raise FieldError("totp")
    if value.get("remove") is True:
        return None
    try:
        return totp.parse_setup(str(value.get("setup") or ""))
    except totp.SetupError as e:
        raise FieldError("totp", str(e)) from None


def _sites(value) -> list:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise FieldError("sites")
    return list(value)


def _text(fields: dict, name: str) -> str:
    v = fields.get(name, "")
    if not isinstance(v, str):
        raise FieldError(name)
    return v


def _landed(ctx: "UserContext", zone, zone_name: str, domain: str, username: str, check):
    """Re-fetch the zone that was written and return the account as iCloud now holds it. A
    save the server accepted but that did not land where devices read it is exactly the
    failure worth catching here."""
    from ..cli import push
    c = push.find(push.refetch(zone, zone_name), domain, username)
    if c is None or not check(c):
        raise push.PushError("iCloud accepted the change, but it did not come back on sync")
    return c


def _tags(value) -> list:
    from ..keychain import tagline
    try:
        return tagline.canon_list(value)
    except ValueError:
        raise FieldError("tags") from None


def push_set(ctx: "UserContext", id: str, fields: dict) -> None:
    """Push a change to one entry: any of password, notes, sites, nickname, totp
    ({"setup": key-or-otpauth} or {"remove": true}), tags, as validated by the handler. Then
    sync that zone so meta reflects iCloud, and call ctx.store.set_secrets when secrets
    changed.

    `notes` is the notes body: the entry's current "Tags:" line is kept under it, and `tags`
    replaces only that line. Both splice into the notes as iCloud holds them right now
    (push.push_details), never into a copy the window sent. Tags on notes that are not UTF-8
    are refused (`invalid`, field notes, detail not-utf8) before anything is written.

    A nickname goes to Apple when the entry has a details record (so it reaches every
    device); otherwise it is kept as a local nickname in the store, which is the case the
    reply reports as synced:false. Fields are re-checked here as well, since a wrong type sent
    to iCloud is not something to find out about afterwards."""
    from ..cli import push
    from ..keychain.update import NotesNotUtf8
    from ..octagon import items as sync_items
    from . import protocol

    unknown = set(fields) - set(protocol.SET_FIELDS)
    if unknown:
        raise FieldError(sorted(unknown)[0])
    store = ctx.store
    meta = store.get_meta(id)
    if getattr(meta, "recently_deleted", False) or getattr(meta, "kind", "login") == "passkey":
        raise FieldError("id", "a Recently Deleted or passkey-only row is read-only")
    domain, username = meta.domain, meta.username

    new_password = None
    if "password" in fields:
        new_password = _text(fields, "password")
        if not new_password:
            raise FieldError("password")
    details = {}
    if "notes" in fields:
        details["notes_body"] = _text(fields, "notes")
    if "tags" in fields:
        details["tags"] = _tags(fields["tags"])
    if "sites" in fields:
        details["sites"] = _sites(fields["sites"])
    if "totp" in fields:
        details["totp"] = _totp_cfg(fields["totp"])
    nickname = None
    if "nickname" in fields:
        nickname = " ".join(_text(fields, "nickname").split())[:NICKNAME_MAX]

    # The password, the details and the name can all live in the same metadata record, and
    # each step rewrites that record from the copy it was fetched as. So every step after the
    # first works from a fresh fetch, or it would put back what the step before it changed.
    expect: dict = {}
    steps = []
    if new_password is not None:
        steps.append(("password", lambda z: push.push_password(z, domain, username, new_password)))
    if details:
        steps.append(("details", lambda z: push.push_details(z, domain, username,
                                                             expect=expect, **details)))
    if nickname is not None:
        steps.append(("nickname", lambda z: push.push_nickname(z, domain, username, nickname)))
    zone = _open_zone(ctx)
    if "tags" in details and not push.notes_editable(zone, domain, username):
        raise FieldError("notes", "the notes are not UTF-8", detail="not-utf8")
    renamed_in_icloud = False
    for i, (kind, step) in enumerate(steps):
        if i:
            zone = push.open_zone(zone.client)
        try:
            result = step(zone)
        except NotesNotUtf8:
            raise FieldError("notes", "the notes are not UTF-8", detail="not-utf8") from None
        if kind == "nickname":
            renamed_in_icloud = result is True

    landed = {k: v for k, v in details.items() if k in ("sites", "totp")}
    if "notes" in expect:
        landed["notes_raw"] = expect["notes"]

    def check(c):
        return ((new_password is None or c.password == new_password)
                and (not details or push.details_landed(c, domain, **landed))
                and (not renamed_in_icloud or (c.apple_title or "") == nickname))

    c = _landed(ctx, zone, push.ZONE_PASSWORDS, domain, username, check)

    names = store.load_nicknames()
    if nickname is not None:
        # A name Apple now holds comes back on every sync, so a local override would only
        # shadow it and drift. One Apple cannot hold is kept here instead.
        if renamed_in_icloud or not nickname:
            names.pop(id, None)
        else:
            names[id] = nickname
        store.save_nicknames(names)

    item = sync_items.to_sync_item(c, names)
    if item.id != id:
        raise push.PushError("the entry changed identity during the edit")
    if new_password is not None:
        store.set_secrets(id, item.secrets)   # the old box moves into history, as a local change
    store.apply_sync([item], set())


def create(ctx: "UserContext", fields: dict) -> str:
    """Create an entry from protocol.CREATE_FIELDS, sync its zone, and return the new id."""
    from ..cli import push
    from ..octagon import items as sync_items
    from . import protocol

    unknown = set(fields) - set(protocol.CREATE_FIELDS)
    if unknown:
        raise FieldError(sorted(unknown)[0])
    title = _text(fields, "title")
    username = _text(fields, "username")
    password = _text(fields, "password")
    if not password:
        raise FieldError("password", "a password is needed")
    try:
        site = push.clean_site(_text(fields, "domain"), title)
    except push.PushError as e:
        raise FieldError("domain", str(e)) from None
    notes = _text(fields, "notes")
    if "tags" in fields:
        # One tag line, last: a "Tags:" line typed at the end of the notes joins the field's
        # tags rather than staying behind as body text above a second line.
        from ..keychain import tagline
        body, typed = tagline.split(notes.strip("\n"))
        notes = tagline.compose(body, _tags(typed + _tags(fields["tags"])))
    sites = _sites(fields["sites"]) if "sites" in fields else []
    cfg = _totp_cfg(fields["totp"]) if fields.get("totp") is not None else None

    zone = _open_zone(ctx)
    push.create_entry(zone, site, username, password, title=title, notes=notes, sites=sites,
                      totp=cfg)
    c = _landed(ctx, zone, push.ZONE_PASSWORDS, site, username,
                lambda c: c.password == password)
    item = sync_items.to_sync_item(c, ctx.store.load_nicknames())
    ctx.store.apply_sync([item], set())
    return item.id


def delete(ctx: "UserContext", id: str) -> None:
    """Delete an entry in iCloud, then sync its zone so it is tombstoned locally."""
    from ..cli import push

    meta = ctx.store.get_meta(id)
    # _pair matches only the live access groups, so deleting a Recently Deleted copy by its
    # domain and username would remove the live login. Read-only, as in push_set.
    if getattr(meta, "recently_deleted", False) or getattr(meta, "kind", "login") == "passkey":
        raise FieldError("id", "a Recently Deleted or passkey-only row is read-only")
    push.require_delete()   # before any network traffic: see the switch in cli/push.py
    zone = _open_zone(ctx)
    push.delete_entry(zone, meta.domain, meta.username)
    if push.find(push.refetch(zone, push.ZONE_PASSWORDS), meta.domain, meta.username):
        raise push.PushError("iCloud accepted the deletion, but the entry is still there")
    ctx.store.apply_sync([], {id})
