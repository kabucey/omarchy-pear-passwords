"""Re-encrypt a keychain item so a changed value can be pushed back to iCloud.

The read path is in pipeline.py; this is its mirror for a single record. Deliberately narrow:
it rewrites one existing `item` record's payload and touches nothing else, because that is the
whole blast radius we are willing to accept for a password edit.

Two details are not guesswork and must not be "simplified":

* A write mints a **fresh 64-byte item key** and a fresh IV, exactly as Apple's own client
  does - the old item key is never reused. The new key is wrapped with the same parent class
  key, so every device that can read the zone can still read the item.
* The AAD is rebuilt from the record's fields, but for a password item every field is on the
  excluded list (everything `server_*`, plus data/wrappedkey/parentkeyref/uploadver/gen/encver),
  so it reduces to UUID + encver + gen + parent key id. Changing the payload therefore does not
  change the AAD, which is why the parent key reference stays valid.
"""

from __future__ import annotations

import base64
import os
import plistlib

from . import crypto as kc
from .pipeline import authenticated_data_v2


class ItemUpdateError(Exception):
    pass


class NotesNotUtf8(ItemUpdateError):
    """The stored notes are not valid UTF-8, so a tag edit cannot splice them without writing
    U+FFFD over the user's bytes. Refused, never repaired."""


def decrypt_item_record(record, class_key: bytes) -> dict:
    """The record's plist, or raise. Mirrors pipeline.decrypt_items for a single record."""
    data = record.get_bytes("data")
    wrapped = record.get_str("wrappedkey")
    parent = record.get_str("parentkeyref")
    if data is None or not wrapped or not parent:
        raise ItemUpdateError(f"record {record.record_name} is not a decryptable item")
    item_key = kc.siv_unwrap(class_key, base64.b64decode(wrapped))
    aad = authenticated_data_v2(record.record_name, record.fields,
                                encver=record.fields.get("encver", 2),
                                gen=record.fields.get("gen", 0), parent_key_id=parent)
    return plistlib.loads(kc.decrypt_item(item_key, data, aad))


def encrypt_item_record(record, class_key: bytes, plist: dict, *,
                        iv: bytes | None = None, item_key: bytes | None = None,
                        pad_to: int | None = None) -> dict:
    """{data, wrappedkey} for `plist` under a freshly minted item key.

    iv/item_key/pad_to exist so a test can pin them and reproduce a known record byte for
    byte; production always takes the random path.
    """
    parent = record.get_str("parentkeyref")
    if not parent:
        raise ItemUpdateError(f"record {record.record_name} has no parentkeyref")
    item_key = item_key or os.urandom(64)
    if len(item_key) != 64:
        raise ItemUpdateError(f"item key must be 64 bytes, got {len(item_key)}")
    aad = authenticated_data_v2(record.record_name, record.fields,
                                encver=record.fields.get("encver", 2),
                                gen=record.fields.get("gen", 0), parent_key_id=parent)
    payload = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY)
    return {
        "data": kc.encrypt_item(item_key, payload, aad, iv=iv or os.urandom(16), pad_to=pad_to),
        "wrappedkey": base64.b64encode(kc.siv_wrap(class_key, item_key)).decode(),
    }


def set_password(record, class_key: bytes, new_password: str, *, now: float | None = None):
    """Return (new_fields, before_plist, after_plist) for a password change.

    Only `v_Data` and `mdat` move. Everything else in the plist is carried across untouched,
    so a field this code does not understand cannot be dropped by rewriting the record.
    """
    import time
    before = decrypt_item_record(record, class_key)
    if "v_Data" not in before:
        raise ItemUpdateError(f"record {record.record_name} holds no v_Data to replace")
    after = dict(before)
    after["v_Data"] = new_password.encode()
    after["mdat"] = _apple_date(now if now is not None else time.time())
    fields = dict(record.fields)
    fields.update(encrypt_item_record(record, class_key, after))
    return fields, before, after


def set_password_history(meta_plist: dict, new_password: str, *, now: float | None = None,
                         newest_first: bool = True) -> dict:
    """Return the password-manager *metadata* plist with the new password in its history.

    An Apple Passwords entry is two records. The `com.apple.cfnetwork` one holds the live
    password; the `com.apple.password-manager` one holds a bplist in v_Data with a `s_hi`
    password-history list of {d: date, id: uuid, p: password, t: 4-char tag}. Rewriting only
    the first leaves the second still quoting the old value, which is what the Passwords app
    shows - so an edit that does not touch both looks like it silently did nothing.
    """
    import plistlib
    import time
    import uuid as _uuid
    blob = meta_plist.get("v_Data")
    if not isinstance(blob, (bytes, bytearray)):
        raise ItemUpdateError("metadata record has no v_Data blob")
    inner = plistlib.loads(bytes(blob))
    history = list(inner.get("s_hi") or [])
    previous = history[0] if history else {}
    prev_id = previous.get("id", "")
    new_id = str(_uuid.uuid4())
    if prev_id and prev_id == prev_id.upper():
        new_id = new_id.upper()          # match the casing Apple used in this account
    stamp = _apple_date(now if now is not None else time.time())
    entry = {"d": stamp, "id": new_id, "p": new_password, "t": previous.get("t", "pass")}
    inner["s_hi"] = [entry] + history if newest_first else history + [entry]
    out = dict(meta_plist)
    out["v_Data"] = plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)
    out["mdat"] = stamp
    return out


def set_title(meta_plist: dict, name: str, *, now: float | None = None) -> dict:
    """Return the metadata plist renamed to `name` (empty clears it back to Apple's default).

    The name lives inside the v_Data bplist as `title`, stored as **bytes**. Writing it as a
    str would decode fine here and read as nothing on every Apple device, so the type is
    preserved deliberately. `s_as` and `s_hi` are carried across untouched - a rename must not
    quietly drop the password history living in the same blob.
    """
    import plistlib
    import time
    blob = meta_plist.get("v_Data")
    if not isinstance(blob, (bytes, bytearray)):
        raise ItemUpdateError("metadata record has no v_Data blob")
    inner = plistlib.loads(bytes(blob))
    name = " ".join((name or "").split())
    if name:
        inner["title"] = name.encode("utf-8")
    else:
        inner.pop("title", None)
    out = dict(meta_plist)
    out["v_Data"] = plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)
    out["mdat"] = _apple_date(now if now is not None else time.time())
    return out


def _apple_date(unix_seconds: float):
    """Keychain plists carry dates as plistlib datetimes, not floats."""
    import datetime
    return datetime.datetime.fromtimestamp(unix_seconds, tz=datetime.timezone.utc).replace(tzinfo=None)


def diff_plists(before: dict, after: dict) -> dict:
    """{key: (kind)} for every key that differs. Values are never returned - a diff of a
    keychain item would otherwise print passwords."""
    out = {}
    for k in sorted(set(before) | set(after)):
        if k not in before:
            out[k] = "added"
        elif k not in after:
            out[k] = "removed"
        elif before[k] != after[k]:
            out[k] = "changed"
    return out


# --------------------------------------------------------------------------- details edits

_KEEP = object()


def stored_notes(inner: dict, *, strict: bool) -> str:
    """The notes text of a metadata blob's inner dict ("" when it has none). `strict` raises
    NotesNotUtf8 for bytes that are not UTF-8; otherwise they decode with U+FFFD, as the read
    path (metadata.notes) does."""
    v = inner.get("notes")
    if isinstance(v, (bytes, bytearray)):
        try:
            return bytes(v).decode("utf-8")
        except UnicodeDecodeError:
            if strict:
                raise NotesNotUtf8("the notes are not UTF-8") from None
            return bytes(v).decode("utf-8", "replace")
    return v if isinstance(v, str) else ""


def edit_details(meta_plist: dict, *, notes=_KEEP, sites=_KEEP, totp=_KEEP,
                 notes_body=_KEEP, tags=_KEEP, now: float | None = None) -> dict:
    """Return the metadata plist with notes / extra websites / verification code changed.

    Each argument left at its default is not touched. Every other key in the blob - password
    history, title, context - is carried across as-is, so an edit to one field cannot drop
    another. Types follow what Apple itself writes: notes as UTF-8 bytes, `s_as` as a list of
    {"s": site}, the TOTP secret as the decoded key bytes.

    `notes` replaces the whole notes (trimmed of outer newlines). `notes_body` and `tags`
    splice into the notes as they are stored in this blob instead (keychain/tagline.py): the
    body is replaced and the final "Tags:" line kept, or that one line is replaced and every
    byte before it kept. A body is still trimmed of outer newlines, as an explicit edit; the
    rest is not normalised. Tags on notes that are not UTF-8 raise NotesNotUtf8.
    """
    import time
    from . import tagline
    blob = meta_plist.get("v_Data")
    if not isinstance(blob, (bytes, bytearray)):
        raise ItemUpdateError("metadata record has no v_Data blob")
    if notes is not _KEEP and (notes_body is not _KEEP or tags is not _KEEP):
        raise ItemUpdateError("notes replaces what notes_body and tags splice")
    inner = plistlib.loads(bytes(blob))
    stamp = _apple_date(now if now is not None else time.time())
    if notes_body is not _KEEP or tags is not _KEEP:
        text = stored_notes(inner, strict=tags is not _KEEP)
        # Tags first: a "Tags:" line typed at the end of the body then joins them, as on create.
        if tags is not _KEEP:
            text = tagline.replace_tags(text, list(tags or ()))
        if notes_body is not _KEEP:
            text = tagline.replace_body(text, (notes_body or "").strip("\n"))
        if text:
            inner["notes"] = text.encode("utf-8")
        else:
            inner.pop("notes", None)
    if notes is not _KEEP:
        text = (notes or "").strip("\n")
        if text:
            inner["notes"] = text.encode("utf-8")
        else:
            inner.pop("notes", None)
    if sites is not _KEEP:
        primary = str(meta_plist.get("srvr") or "")     # the record's own site is implicit
        inner["s_as"] = [{"s": s} for s in clean_sites(sites or ()) if s != primary]
    if totp is not _KEEP:
        if totp:
            inner["totp"] = totp_plist(totp, now=now)
        else:
            inner.pop("totp", None)
    out = dict(meta_plist)
    out["v_Data"] = plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)
    out["mdat"] = stamp
    return out


def clean_sites(sites) -> list:
    """Bare hostnames, deduplicated, in the order given: "https://www.X.com/login" -> "www.X.com".
    Apple stores hosts, not URLs."""
    out = []
    for raw in sites:
        s = (raw or "").strip()
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip().lower()
        if s and " " not in s and s not in out:
            out.append(s)
    return out


def totp_plist(cfg: dict, *, now: float | None = None) -> dict:
    """Apple's `totp` dict from our config: {secret(bytes), digits, period, algorithm,
    _initialDate, and issuer/accountName/originalURL when known}."""
    import time
    secret = cfg.get("secret")
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise ItemUpdateError("a verification code needs the decoded secret bytes")
    out = {"secret": bytes(secret), "digits": int(cfg.get("digits") or 6),
           "period": int(cfg.get("period") or 30), "algorithm": int(cfg.get("algorithm") or 0),
           "_initialDate": _apple_date(now if now is not None else time.time())}
    for k in ("issuer", "accountName", "originalURL"):
        if cfg.get(k):
            out[k] = str(cfg[k])
    return out


# --------------------------------------------------------------------------- new records
#
# Every value below is what all of this keychain's own entries carry: 442/442 password
# records and 276/276 metadata records agree on class, atyp, pdmn, path, sdmn, port and desc,
# and metadata labels are "Password Manager Metadata: <site> (<account>)" on 270/276.

AGRP_PASSWORD = "com.apple.cfnetwork"
AGRP_METADATA = "com.apple.password-manager"
METADATA_TYPE = 1835626085          # FourCC 'mine'


def _base_plist(site: str, username: str, ptcl: str, stamp) -> dict:
    return {"class": "inet", "atyp": "form", "ptcl": ptcl, "pdmn": "ak", "port": 0,
            "path": "", "sdmn": "", "srvr": site, "acct": username, "musr": b"",
            "tomb": 0, "cdat": stamp, "mdat": stamp}


def new_password_plist(site: str, username: str, password: str, *, ptcl: str = "htps",
                       now: float | None = None) -> dict:
    import time
    stamp = _apple_date(now if now is not None else time.time())
    p = _base_plist(site, username, ptcl, stamp)
    p.update({"agrp": AGRP_PASSWORD, "desc": "Web form password", "icmt": "default",
              "labl": f"{site} ({username})", "v_Data": password.encode("utf-8")})
    return p


def new_metadata_plist(site: str, username: str, *, title: str = "", notes: str = "",
                       sites=(), totp: dict | None = None, ptcl: str = "htps",
                       now: float | None = None) -> dict:
    import time
    now = now if now is not None else time.time()
    stamp = _apple_date(now)
    inner = {"ctxt": {"": {"lUsed": stamp}},
             "s_as": [{"s": s} for s in clean_sites(sites) if s != site]}
    name = " ".join((title or "").split())
    if name:
        inner["title"] = name.encode("utf-8")
    if (notes or "").strip():
        inner["notes"] = notes.strip("\n").encode("utf-8")
    if totp:
        inner["totp"] = totp_plist(totp, now=now)
    p = _base_plist(site, username, ptcl, stamp)
    p.update({"agrp": AGRP_METADATA, "desc": "Password Manager Metadata",
              "type": METADATA_TYPE,
              "labl": f"Password Manager Metadata: {site} ({username})",
              "v_Data": plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)})
    return p


def new_item_fields(class_key: bytes, parent_key_id: str, plist: dict, *, record_name: str,
                    uploadver: str) -> dict:
    """The CKKS record fields for a brand-new item: payload encrypted under a fresh item key,
    wrapped with the zone's class key, plus the bookkeeping every record carries."""
    from ..transport.ckks import CloudKitRecord
    fields = {"parentkeyref": parent_key_id, "encver": 2, "gen": 0, "uploadver": uploadver}
    stub = CloudKitRecord(record_name=record_name, type="item", fields=fields)
    fields = dict(fields)
    fields.update(encrypt_item_record(stub, class_key, plist))
    return fields


def new_wifi_plist(ssid: str, password: str, *, now: float | None = None) -> dict:
    """A Wi-Fi password as Apple syncs it (WiFi zone). All 50 in this keychain agree on every
    field below; the network name is both the account and the label."""
    import time
    stamp = _apple_date(now if now is not None else time.time())
    return {"class": "genp", "agrp": "apple", "svce": "AirPort", "acct": ssid, "labl": ssid,
            "desc": "AirPort network password", "pdmn": "ck", "musr": b"", "tomb": 0,
            "cdat": stamp, "mdat": stamp, "v_Data": password.encode("utf-8")}
