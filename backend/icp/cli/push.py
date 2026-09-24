"""Push one password change to iCloud.

An Apple Passwords entry is two records and BOTH must move, which is the lesson from the
first attempt at this: rewriting only the credential record stored the new password where we
could read it back, while every Apple device kept showing the old one out of the metadata
record's `s_hi` history blob.

Blast radius is one account. Nothing here iterates, and a record that does not decrypt to the
account we were asked to change is skipped rather than guessed at.
"""

from __future__ import annotations

import logging

from ..auth import session
from ..auth.anisette import Anisette
from ..auth.device import Device
from .. import paths
from ..keychain import update as up
from ..keychain.pipeline import unwrap_class_keys, unwrap_tlkshares
from ..octagon import client as octagon
from ..octagon.client import load_peer_keys
from ..transport import ckks

logger = logging.getLogger(__name__)

AGRP_PASSWORD = "com.apple.cfnetwork"
AGRP_METADATA = "com.apple.password-manager"


class PushError(Exception):
    pass


def _open_zone(anisette=None):
    from . import app as cli_app
    s = session.load()
    if not s:
        raise PushError("not signed in - run: icp login")
    device = Device.load_or_create()
    anis = Anisette(anisette)
    cli_app._ensure_fresh_tokens(s, device, anis, interactive=False)
    session.save(s)
    client = octagon.OctagonClient(s, device, anis)
    session.save(s)
    tlks, view_synckeys = client.fetch_recoverable_tlks()
    records = client.sync_keychain()
    records.setdefault("synckey", []).extend(view_synckeys)
    keys = load_peer_keys(s["octagon"])
    merged = {**unwrap_tlkshares(records.get("tlkshare", []), s["octagon"]["peer_id"],
                                 keys.encryption.private_key), **(tlks or {})}
    return client, records, unwrap_class_keys(records.get("synckey", []), merged)


def _save(client, record, fields, *, create: bool = False, zone: str = "Passwords") -> None:
    blob = ckks.serialize_record(record.record_name, record.type, fields,
                                 user_id=client.user_id, zone=zone,
                                 references={"parentkeyref"})
    client.transport.save_record(ckks.build_record_save_request(
        blob, merge=not create,
        save_semantics=ckks.SAVE_SEMANTICS_CREATE if create else ckks.SAVE_SEMANTICS_UPDATE))


def _pair(records, class_keys, domain: str, username: str) -> dict:
    """{agrp: (record, class_key, plist)} for the one account named - nothing else."""
    targets = {}
    for rec in records.get("item", []):
        ck = class_keys.get(rec.get_str("parentkeyref"))
        if ck is None or rec.get_bytes("data") is None:
            continue
        try:
            plist = up.decrypt_item_record(rec, ck)
        except Exception:
            continue
        if plist.get("acct") != username or str(plist.get("srvr") or "") != domain:
            continue
        if plist.get("agrp") in (AGRP_PASSWORD, AGRP_METADATA):
            targets[plist["agrp"]] = (rec, ck, plist)
    return targets


def _uploadver() -> str:
    """How this computer signs its records: the same "macOS <darwin> (<build>)" form every
    Mac in the keychain uses, from the identity it signs in with."""
    from .. import const
    return f"macOS {const.DARWIN_VERSION} ({const.OS_BUILD})"


def _create(client, class_key: bytes, parent: str, plist: dict, *, zone: str = "Passwords") -> str:
    import uuid as _uuid
    from ..transport.ckks import CloudKitRecord
    name = str(_uuid.uuid4()).upper()
    fields = up.new_item_fields(class_key, parent, plist, record_name=name,
                                uploadver=_uploadver())
    _save(client, CloudKitRecord(name, "item", fields), fields, create=True, zone=zone)
    return name


def _resync(anisette):
    from . import app as cli_app
    import argparse
    cli_app.cmd_sync(argparse.Namespace(anisette=anisette))


def _check_synced(domain: str, username: str, predicate) -> None:
    """Read the change back out of the freshly synced vault. A save the server accepted but
    that did not land where devices read it is exactly the failure worth catching here."""
    from ..vault.store import load_vault
    for c in load_vault().all():
        if c.domain == domain and c.username == username and predicate(c):
            return
    raise PushError("iCloud accepted the change, but it did not come back on sync")


@paths.mutation_lock
def create_entry(site: str, username: str, password: str, *, title: str = "", notes: str = "",
                 sites=(), totp: dict | None = None, anisette=None) -> int:
    """Add one new login: its password record plus the details record Apple's Passwords app
    pairs with it. Refuses to touch an account that already exists. Returns records written."""
    cleaned = up.clean_sites([site])
    if cleaned:
        site = cleaned[0]
    elif " ".join((title or "").split()):
        # What Apple's Passwords app does for an entry with no website: the record's site
        # field holds a fresh UUID, and the title is what people see.
        import uuid as _uuid
        site = str(_uuid.uuid4()).upper()
    else:
        raise PushError("add a website, or a name for an entry without one")
    if not password:
        raise PushError("a password is needed")
    client, records, class_keys = _open_zone(anisette)
    if _pair(records, class_keys, site, username):
        raise PushError(f"an entry for {username or 'this account'} at {site} already exists")
    # Every password record in the zone hangs off the same class key; a new one does too.
    parents = {}
    for rec in records.get("item", []):
        ck = class_keys.get(rec.get_str("parentkeyref"))
        if ck is None:
            continue
        try:
            if up.decrypt_item_record(rec, ck).get("agrp") == AGRP_PASSWORD:
                parents[rec.get_str("parentkeyref")] = parents.get(rec.get_str("parentkeyref"), 0) + 1
        except Exception:
            continue
    if not parents:
        raise PushError("no existing password to learn this keychain's key from")
    parent = max(parents, key=parents.get)
    ck = class_keys[parent]
    _create(client, ck, parent, up.new_password_plist(site, username, password))
    _create(client, ck, parent, up.new_metadata_plist(site, username, title=title, notes=notes,
                                                      sites=sites, totp=totp))
    _resync(anisette)
    _check_synced(site, username, lambda c: c.password == password)
    return 2


@paths.mutation_lock
def push_details(domain: str, username: str, *, notes=up._KEEP, sites=up._KEEP,
                 totp=up._KEEP, anisette=None) -> int:
    """Change the notes, extra websites or verification code of one entry.

    Only the details record moves; the password record is never rewritten. An entry that has
    no details record yet (common for logins saved before Apple's Passwords app) gets one,
    built like Apple's own. Returns records written."""
    client, records, class_keys = _open_zone(anisette)
    targets = _pair(records, class_keys, domain, username)
    if AGRP_PASSWORD not in targets:
        raise PushError(f"no password record found for {username} at {domain}")
    if AGRP_METADATA in targets:
        mrec, mck, mplist = targets[AGRP_METADATA]
        edited = up.edit_details(mplist, notes=notes, sites=sites, totp=totp)
        if set(up.diff_plists(mplist, edited)) - {"mdat", "v_Data"}:
            raise PushError("refusing to push: the edit changed unexpected fields")
        fields = dict(mrec.fields)
        fields.update(up.encrypt_item_record(mrec, mck, edited))
        _save(client, mrec, fields)
    else:
        rec, ck, plist = targets[AGRP_PASSWORD]
        meta = up.new_metadata_plist(
            domain, username, ptcl=str(plist.get("ptcl") or "htps"),
            notes="" if notes is up._KEEP else notes,
            sites=() if sites is up._KEEP else sites,
            totp=None if totp is up._KEEP else totp)
        _create(client, ck, rec.get_str("parentkeyref"), meta)
    _resync(anisette)

    def landed(c):
        return ((notes is up._KEEP or c.notes == (notes or "").strip("\n"))
                and (sites is up._KEEP or list(c.sites) == [s for s in up.clean_sites(sites or ()) if s != domain])
                and (totp is up._KEEP or bool(c.totp) == bool(totp)))
    _check_synced(domain, username, landed)
    return 1


@paths.mutation_lock
def push_nickname(domain: str, username: str, name: str, *, anisette=None) -> bool:
    """Rename one entry in iCloud so the new name reaches every device.

    Only the metadata record moves - the password record is not touched at all, so a rename
    cannot put a password at risk. Returns False when the entry has no metadata record, which
    is most of them: an entry Apple's Passwords app never managed has nowhere to put a name,
    and the caller falls back to a local nickname.
    """
    client, records, class_keys = _open_zone(anisette)
    for rec in records.get("item", []):
        ck = class_keys.get(rec.get_str("parentkeyref"))
        if ck is None or rec.get_bytes("data") is None:
            continue
        try:
            plist = up.decrypt_item_record(rec, ck)
        except Exception:
            continue
        if plist.get("acct") != username or str(plist.get("srvr") or "") != domain:
            continue
        if plist.get("agrp") != AGRP_METADATA:
            continue
        renamed = up.set_title(plist, name)
        if set(up.diff_plists(plist, renamed)) - {"mdat", "v_Data"}:
            raise PushError("refusing to push: the rename changed unexpected fields")
        fields = dict(rec.fields)
        fields.update(up.encrypt_item_record(rec, ck, renamed))
        _save(client, rec, fields)
        from . import app as cli_app
        import argparse
        cli_app.cmd_sync(argparse.Namespace(anisette=anisette))
        return True
    return False


@paths.mutation_lock
def push_password(domain: str, username: str, new_password: str, *, anisette=None,
                  newest_first: bool = True) -> int:
    """Rewrite both records for one account and re-sync. Returns how many records were written.

    The closing sync is not optional. The Zen extension is served from the local vault, so
    without it the browser would keep autofilling the old password until the next timer tick -
    the change would look like it had not taken, in exactly the place it is most used.
    """
    client, records, class_keys = _open_zone(anisette)
    targets = {}
    for rec in records.get("item", []):
        ck = class_keys.get(rec.get_str("parentkeyref"))
        if ck is None or rec.get_bytes("data") is None:
            continue
        try:
            plist = up.decrypt_item_record(rec, ck)
        except Exception:
            continue
        if plist.get("acct") != username:
            continue
        # srvr is the keychain's own domain field; match it rather than the display title.
        if str(plist.get("srvr") or "") != domain:
            continue
        agrp = plist.get("agrp")
        if agrp in (AGRP_PASSWORD, AGRP_METADATA):
            targets[agrp] = (rec, ck, plist)

    if AGRP_PASSWORD not in targets:
        raise PushError(f"no password record found for {username} at {domain}")

    written = 0
    rec, ck, _ = targets[AGRP_PASSWORD]
    fields, before, after = up.set_password(rec, ck, new_password)
    if up.diff_plists(before, after) != {"mdat": "changed", "v_Data": "changed"}:
        raise PushError("refusing to push: the password record changed in unexpected ways")
    _save(client, rec, fields)
    written += 1

    if AGRP_METADATA in targets:
        mrec, mck, mplist = targets[AGRP_METADATA]
        try:
            new_meta = up.set_password_history(mplist, new_password, newest_first=newest_first)
            if up.diff_plists(mplist, new_meta) != {"mdat": "changed", "v_Data": "changed"}:
                raise PushError("metadata record changed in unexpected ways")
            mfields = dict(mrec.fields)
            mfields.update(up.encrypt_item_record(mrec, mck, new_meta))
            _save(client, mrec, mfields)
            written += 1
        except Exception as e:
            # The password itself is already live; a stale history blob is a display bug, not
            # a lost change, so say so loudly rather than unwinding a good write.
            logger.warning("password updated but its history blob was not: %s", e)
    else:
        logger.info("no metadata record for %s@%s - password-only entry", username, domain)

    # Re-sync so the local vault (and therefore the Zen extension) serves the new value now.
    from . import app as cli_app
    import argparse
    cli_app.cmd_sync(argparse.Namespace(anisette=anisette))
    return written


@paths.mutation_lock
def create_wifi(ssid: str, password: str, *, anisette=None) -> int:
    """Add one Wi-Fi network password. It lives in the WiFi zone under that zone's own class
    key, so the key is taken from an existing network there - never guessed."""
    ssid = (ssid or "").strip()
    if not ssid or not password:
        raise PushError("a network name and a password are needed")
    client, records, class_keys = _open_zone(anisette)
    parents = {}
    for rec in records.get("item", []):
        ck = class_keys.get(rec.get_str("parentkeyref"))
        if ck is None:
            continue
        try:
            p = up.decrypt_item_record(rec, ck)
        except Exception:
            continue
        if p.get("svce") == "AirPort":
            if p.get("acct") == ssid:
                raise PushError(f"a password for the network {ssid} already exists")
            parents[rec.get_str("parentkeyref")] = parents.get(rec.get_str("parentkeyref"), 0) + 1
    if not parents:
        raise PushError("no existing Wi-Fi password to learn the Wi-Fi zone's key from")
    parent = max(parents, key=parents.get)
    _create(client, class_keys[parent], parent, up.new_wifi_plist(ssid, password), zone="WiFi")
    _resync(anisette)
    _check_synced("AirPort", ssid, lambda c: c.password == password)
    return 1
