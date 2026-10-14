"""Push one change to iCloud: a password, an entry's details, a rename, a new entry.

An Apple Passwords entry is two records and BOTH must move, which is the lesson from the
first attempt at this: rewriting only the credential record stored the new password where we
could read it back, while every Apple device kept showing the old one out of the metadata
record's `s_hi` history blob.

Blast radius is one account. Nothing here iterates, and a record that does not decrypt to the
account we were asked to change is skipped rather than guessed at.

In 2.0 this runs inside the daemon, called by daemon/apple.py with a Zone it opened from the
user's store. Nothing here loads a session, re-enters a sync command or touches a vault file:
after a write the caller re-fetches just the zone that was written (`refetch`), checks the
change came back, and hands that one entry to the store.
"""

from __future__ import annotations

import logging
import uuid as _uuid

from ..errors import AppleError
from ..keychain import update as up
from ..keychain.pipeline import decrypt_items, unwrap_class_keys, unwrap_tlkshares
from ..octagon.client import load_peer_keys
from ..transport import ckks
from ..vault.host import CredentialStore

logger = logging.getLogger(__name__)

AGRP_PASSWORD = "com.apple.cfnetwork"
AGRP_METADATA = "com.apple.password-manager"
ZONE_PASSWORDS = "Passwords"
ZONE_WIFI = "WiFi"

# Deleting an entry is CloudKit's RecordDelete operation. The request was checked against an
# independent client that sends it to Apple, OpenBubbles/rustpush (cloudkit-proto/src/
# cloudkit.proto and src/icloud/cloudkit.rs, DeleteRecordOperation): RecordDeleteRequest
# { RecordIdentifier record = 1 } as request field 214, operation type RECORD_DELETE_TYPE =
# 214, POSTed to .../ckdatabase/api/client/record/delete - the message, numbers and endpoint
# below. It names exactly one record, so a mistake could only fail, never remove another
# entry; delete_entry re-fetches the zone afterwards and reports an entry still there. First
# used on a throwaway entry on the owner's account (2026-10-09). It removes the item from
# iCloud Keychain everywhere, and Apple's devices do not keep it in Recently Deleted. The
# switch stays so a build can turn deleting off again.
RECORD_DELETE_VERIFIED = True
RECORD_DELETE_URL = "https://gateway.icloud.com/ckdatabase/api/client/record/delete"
OP_TYPE_RECORD_DELETE = 214
FIELD_RECORD_DELETE = 214


class PushError(AppleError):
    """iCloud refused the change, or it did not come back on the re-fetch."""


class DeleteUnavailable(PushError):
    """Deleting from iCloud is switched off in this build (RECORD_DELETE_VERIFIED)."""


class Zone:
    """The keychain as one edit sees it: a live Octagon client, every fetched record grouped by
    type, and the class keys that open them. Built by `open_zone`; the session dict the client
    holds may have been refreshed on the way, so the caller saves it afterwards."""

    def __init__(self, client, records: dict, class_keys: dict):
        self.client = client
        self.records = records
        self.class_keys = class_keys


def open_zone(client) -> Zone:
    """Fetch every keychain zone through `client` (an OctagonClient over a fresh session) and
    unwrap the class keys. The caller refreshes tokens first and saves the session after."""
    s = client.record
    tlks, view_synckeys = client.fetch_recoverable_tlks()
    records = client.sync_keychain()
    records.setdefault("synckey", []).extend(view_synckeys)
    keys = load_peer_keys(s["octagon"])
    merged = {**unwrap_tlkshares(records.get("tlkshare", []), s["octagon"]["peer_id"],
                                 keys.encryption.private_key), **(tlks or {})}
    return Zone(client, records, unwrap_class_keys(records.get("synckey", []), merged))


def refetch(zone: Zone, zone_name: str = ZONE_PASSWORDS) -> CredentialStore:
    """Re-read one keychain zone after a write and decrypt it with the class keys already held.
    Only that zone: the change cannot have landed anywhere else, and a full fetch of every zone
    to confirm one edit is the cost 1.x paid by re-running its whole sync."""
    client = zone.client
    zid = ckks.record_zone_identifier(zone_name, client.user_id)
    items, continuation = [], None
    while True:
        raw = client.transport.fetch_records(ckks.build_retrieve_changes_request(zid, continuation))
        page = ckks.parse_retrieve_changes_response(raw)
        items.extend(r for r in page["records"] if r.type == "item")
        continuation = page.get("continuation_token")
        if page.get("status") != 1 or not continuation:
            break
    return CredentialStore.from_items(decrypt_items(items, zone.class_keys))


def find(store: CredentialStore, domain: str, username: str):
    """The newest live login for exactly (domain, username), or None. A copy in Recently
    Deleted or a passkey-only row is never the entry an edit wrote."""
    hits = [c for c in store.all() if c.domain == domain and c.username == username
            and not c.recently_deleted and c.kind == "login"]
    return max(hits, key=lambda c: c.mdat) if hits else None


def _save(client, record, fields, *, create: bool = False, zone: str = ZONE_PASSWORDS) -> None:
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


def _create(client, class_key: bytes, parent: str, plist: dict, *, zone: str = ZONE_PASSWORDS) -> str:
    from ..transport.ckks import CloudKitRecord
    name = str(_uuid.uuid4()).upper()
    fields = up.new_item_fields(class_key, parent, plist, record_name=name,
                                uploadver=_uploadver())
    _save(client, CloudKitRecord(name, "item", fields), fields, create=True, zone=zone)
    return name


def clean_site(site: str, title: str = "") -> str:
    """The keychain's server field for a new entry: the bare host, or - for an entry with no
    website, as Apple's Passwords app does it - a fresh UUID with the title as what people see."""
    cleaned = up.clean_sites([site])
    if cleaned:
        return cleaned[0]
    if " ".join((title or "").split()):
        return str(_uuid.uuid4()).upper()
    raise PushError("add a website, or a name for an entry without one")


def create_entry(zone: Zone, site: str, username: str, password: str, *, title: str = "",
                 notes: str = "", sites=(), totp: dict | None = None) -> int:
    """Add one new login: its password record plus the details record Apple's Passwords app
    pairs with it. `site` must already be cleaned (`clean_site`). Refuses to touch an account
    that already exists. Returns records written."""
    if not site:
        raise PushError("add a website, or a name for an entry without one")
    if not password:
        raise PushError("a password is needed")
    records, class_keys = zone.records, zone.class_keys
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
    _create(zone.client, ck, parent, up.new_password_plist(site, username, password))
    _create(zone.client, ck, parent, up.new_metadata_plist(site, username, title=title,
                                                           notes=notes, sites=sites, totp=totp))
    return 2


def push_details(zone: Zone, domain: str, username: str, *, notes=up._KEEP, sites=up._KEEP,
                 totp=up._KEEP, notes_body=up._KEEP, tags=up._KEEP,
                 expect: dict | None = None) -> int:
    """Change the notes, extra websites or verification code of one entry.

    Only the details record moves; the password record is never rewritten. An entry that has
    no details record yet (common for logins saved before Apple's Passwords app) gets one,
    built like Apple's own. `notes_body` and `tags` splice into the notes as this fetch has
    them, never into a copy the window or a grant holds, so a note edited on an Apple device a
    moment ago is not overwritten (update.edit_details). With `expect`, expect["notes"] is set
    to the exact notes text written, for details_landed. Returns records written."""
    from ..keychain import metadata as md
    from ..keychain import tagline
    targets = _pair(zone.records, zone.class_keys, domain, username)
    if AGRP_PASSWORD not in targets:
        raise PushError(f"no password record found for {username} at {domain}")
    if AGRP_METADATA in targets:
        mrec, mck, mplist = targets[AGRP_METADATA]
        edited = up.edit_details(mplist, notes=notes, sites=sites, totp=totp,
                                 notes_body=notes_body, tags=tags)
        if set(up.diff_plists(mplist, edited)) - {"mdat", "v_Data"}:
            raise PushError("refusing to push: the edit changed unexpected fields")
        fields = dict(mrec.fields)
        fields.update(up.encrypt_item_record(mrec, mck, edited))
        _save(zone.client, mrec, fields)
    else:
        rec, ck, plist = targets[AGRP_PASSWORD]
        text = "" if notes is up._KEEP else notes
        if tags is not up._KEEP:
            text = tagline.replace_tags(text, list(tags or ()))
        if notes_body is not up._KEEP:
            text = tagline.replace_body(text, (notes_body or "").strip("\n"))
        edited = up.new_metadata_plist(
            domain, username, ptcl=str(plist.get("ptcl") or "htps"), notes=text,
            sites=() if sites is up._KEEP else sites,
            totp=None if totp is up._KEEP else totp)
        _create(zone.client, ck, rec.get_str("parentkeyref"), edited)
    if expect is not None:
        expect["notes"] = md.notes(md.parse(edited["v_Data"]))
    return 1


def notes_editable(zone: Zone, domain: str, username: str) -> bool:
    """Whether a tag edit can splice this entry's stored notes: False only when its details
    record holds notes that are not UTF-8. Checked before anything is written, so a combined
    edit is refused whole rather than half pushed."""
    targets = _pair(zone.records, zone.class_keys, domain, username)
    if AGRP_METADATA not in targets:
        return True
    blob = targets[AGRP_METADATA][2].get("v_Data")
    try:
        import plistlib
        up.stored_notes(plistlib.loads(bytes(blob)), strict=True)
    except up.NotesNotUtf8:
        return False
    except Exception:
        return True           # not a blob it can read: push_details refuses that itself
    return True


def details_landed(c, domain: str, *, notes=up._KEEP, sites=up._KEEP, totp=up._KEEP,
                   notes_raw=up._KEEP) -> bool:
    """Whether a re-fetched credential shows the details edit. `notes_raw` is the exact text
    push_details wrote (its `expect`), compared byte for byte."""
    return ((notes is up._KEEP or c.notes == (notes or "").strip("\n"))
            and (notes_raw is up._KEEP or c.notes == notes_raw)
            and (sites is up._KEEP
                 or list(c.sites) == [s for s in up.clean_sites(sites or ()) if s != domain])
            and (totp is up._KEEP or bool(c.totp) == bool(totp)))


def push_nickname(zone: Zone, domain: str, username: str, name: str) -> bool:
    """Rename one entry in iCloud so the new name reaches every device.

    Only the metadata record moves - the password record is not touched at all, so a rename
    cannot put a password at risk. Returns False when the entry has no metadata record, which
    is most of them: an entry Apple's Passwords app never managed has nowhere to put a name,
    and the caller falls back to a local nickname.
    """
    targets = _pair(zone.records, zone.class_keys, domain, username)
    if AGRP_METADATA not in targets:
        return False
    rec, ck, plist = targets[AGRP_METADATA]
    renamed = up.set_title(plist, name)
    if set(up.diff_plists(plist, renamed)) - {"mdat", "v_Data"}:
        raise PushError("refusing to push: the rename changed unexpected fields")
    fields = dict(rec.fields)
    fields.update(up.encrypt_item_record(rec, ck, renamed))
    _save(zone.client, rec, fields)
    return True


def push_password(zone: Zone, domain: str, username: str, new_password: str, *,
                  newest_first: bool = True) -> int:
    """Rewrite both records for one account. Returns how many records were written."""
    targets = _pair(zone.records, zone.class_keys, domain, username)
    if AGRP_PASSWORD not in targets:
        raise PushError(f"no password record found for {username} at {domain}")

    written = 0
    rec, ck, _ = targets[AGRP_PASSWORD]
    fields, before, after = up.set_password(rec, ck, new_password)
    if up.diff_plists(before, after) != {"mdat": "changed", "v_Data": "changed"}:
        raise PushError("refusing to push: the password record changed in unexpected ways")
    _save(zone.client, rec, fields)
    written += 1

    if AGRP_METADATA in targets:
        mrec, mck, mplist = targets[AGRP_METADATA]
        try:
            new_meta = up.set_password_history(mplist, new_password, newest_first=newest_first)
            if up.diff_plists(mplist, new_meta) != {"mdat": "changed", "v_Data": "changed"}:
                raise PushError("metadata record changed in unexpected ways")
            mfields = dict(mrec.fields)
            mfields.update(up.encrypt_item_record(mrec, mck, new_meta))
            _save(zone.client, mrec, mfields)
            written += 1
        except Exception as e:
            # The password itself is already live; a stale history blob is a display bug, not
            # a lost change, so say so loudly rather than unwinding a good write.
            logger.warning("password updated but its history blob was not: %s", e)
    else:
        logger.info("no metadata record for this entry - password-only entry")
    return written


def create_wifi(zone: Zone, ssid: str, password: str) -> int:
    """Add one Wi-Fi network password. It lives in the WiFi zone under that zone's own class
    key, so the key is taken from an existing network there - never guessed."""
    ssid = (ssid or "").strip()
    if not ssid or not password:
        raise PushError("a network name and a password are needed")
    parents = {}
    for rec in zone.records.get("item", []):
        ck = zone.class_keys.get(rec.get_str("parentkeyref"))
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
    _create(zone.client, zone.class_keys[parent], parent, up.new_wifi_plist(ssid, password),
            zone=ZONE_WIFI)
    return 1


def require_delete() -> None:
    """Raise DeleteUnavailable while deleting is switched off."""
    if not RECORD_DELETE_VERIFIED:
        raise DeleteUnavailable(
            "deleting from iCloud isn't available on Linux yet - delete it on an iPhone, iPad "
            "or Mac and it disappears here on the next sync")


def build_record_delete_request(record_name: str, *, user_id: str, zone: str) -> bytes:
    """RecordDeleteRequest { record(1): RecordIdentifier } (unverified, see the switch above)."""
    from ..proto.codec import Writer
    return Writer().message(1, ckks._record_identifier(record_name, user_id, zone)).finish()


def delete_entry(zone: Zone, domain: str, username: str) -> int:
    """Delete one entry: its password record and, when it has one, its details record.

    Refuses unless RECORD_DELETE_VERIFIED is set - and until then sends nothing at all."""
    require_delete()
    targets = _pair(zone.records, zone.class_keys, domain, username)
    if AGRP_PASSWORD not in targets:
        raise PushError(f"no password record found for {username} at {domain}")
    from ..transport import cloudkit
    client = zone.client
    written = 0
    # The details record first: an entry left with a password and no details record is an
    # ordinary pre-Passwords-app login, while the reverse is an orphan Apple shows nowhere.
    for agrp in (AGRP_METADATA, AGRP_PASSWORD):
        if agrp not in targets:
            continue
        rec = targets[agrp][0]
        client.transport._perform(
            RECORD_DELETE_URL, OP_TYPE_RECORD_DELETE, FIELD_RECORD_DELETE,
            build_record_delete_request(rec.record_name, user_id=client.user_id,
                                        zone=ZONE_PASSWORDS),
            bundle=cloudkit.SECURITYD_BUNDLE)
        written += 1
    return written
