"""Fetch and open the zones of Apple Passwords shared groups you own, with fetches only.

Adapted from icp/sharing/groups.py in Sank6/iCloud-Keychain-for-Linux (MIT, Copyright (c) 2026
Sankarsh Makam, see the repository LICENSE): the zone and record parsing, the PCS opening and the
SharingInternetPassword shape are theirs; the transport calls, paging and error handling are this
repository's.

The only CloudKit operations here are op 201 (ZoneRetrieve, for a zone's protection info) and
op 213 (RecordRetrieveChanges, for its records). Neither writes. Nothing here reads or writes a
store; decrypted values are returned to the caller, who holds them in memory only.
"""

from __future__ import annotations

import struct

from ..proto.codec import decode_fields, first, first_str
from ..transport import ckks, cloudkit
from . import pcs

MAX_RECORD_PAGES = 200
STATUS_MORE, STATUS_DONE = 1, 3          # op 213, as OctagonClient.sync_keychain reads them


def fetch_zone_protection(transport, zone_raw: bytes, *, database: int, scope: str) -> dict:
    """Op 201: {protection, record_protection}, the zone's PCS protection blobs (or None)."""
    resp = transport.probe_zone_retrieve(zone_raw, bundle=cloudkit.KCSHARING_BUNDLE,
                                         database=database, scope=scope)
    summary = first(decode_fields(resp), 1)
    zone = first(decode_fields(summary), 1) if summary else None
    zf = decode_fields(zone) if zone else {}

    def blob(n):
        info = first(zf, n)
        return first(decode_fields(info), 1) if info else None
    return {"protection": blob(3), "record_protection": blob(6)}


def parse_record(raw: bytes) -> dict:
    """A record with the per-record protection (field 13) that ckks.parse_record leaves out.
    Field values stay raw: {name: (bytes value or None, signed int value or None)}."""
    f = decode_fields(raw)
    rid = first(f, 2)
    name = ""
    if rid is not None:
        idval = first(decode_fields(rid), 1)
        name = first_str(decode_fields(idval), 1, "") if idval is not None else ""
    tblob = first(f, 3)
    rtype = first_str(decode_fields(tblob), 1, "") if tblob is not None else ""
    fields = {}
    for fld in f.get(7, []):
        ff = decode_fields(fld)
        ident, val = first(ff, 1), first(ff, 2)
        if ident is None or val is None:
            continue
        vf = decode_fields(val)
        fields[first_str(decode_fields(ident), 1, "")] = (first(vf, 2), first(vf, 4))
    prot = first(f, 13)
    return {"name": name, "type": rtype, "fields": fields,
            "protection": first(decode_fields(prot), 1) if prot else None}


def fetch_records(transport, zone_raw: bytes, *, database: int, scope: str) -> tuple[list, dict]:
    """Every record of a zone, paged the way sync_keychain pages (status 1 = another page,
    3 = done, anything else is not complete). Returns (records, paging) where paging is
    {pages, statuses: {status: count}, complete, changes_without_record}; no value in it."""
    out: list[dict] = []
    paging = {"pages": 0, "statuses": {}, "complete": False, "changes_without_record": 0}
    continuation, seen = None, set()
    for _ in range(MAX_RECORD_PAGES):
        raw = transport.probe_records(ckks.build_retrieve_changes_request(zone_raw, continuation),
                                      bundle=cloudkit.KCSHARING_BUNDLE,
                                      database=database, scope=scope)
        f = decode_fields(raw)
        paging["pages"] += 1
        for change in f.get(1, []):
            rec = first(decode_fields(change), 5)
            if rec is None:
                paging["changes_without_record"] += 1
            else:
                out.append(parse_record(rec))
        status, continuation = first(f, 4), first(f, 2)
        key = str(status)
        paging["statuses"][key] = paging["statuses"].get(key, 0) + 1
        if status == STATUS_DONE:
            paging["complete"] = True
            break
        if status != STATUS_MORE or not continuation or continuation in seen:
            break
        seen.add(continuation)
    return out, paging


def _double(v) -> float:
    return struct.unpack("<d", v.to_bytes(8, "little"))[0] if isinstance(v, int) else 0.0


def sharing_item_to_keychain(payload: bytes) -> dict | None:
    """A SharingInternetPassword (payload field 3) as the usual keychain item shape, or None for
    any other kind of payload."""
    ip = first(decode_fields(payload), 3)
    if ip is None:
        return None
    f = decode_fields(ip)
    item = {
        "agrp": first_str(f, 1, ""),
        "mdat": _double(first(f, 2)),
        "cdat": _double(first(f, 3)),
        "acct": first_str(f, 4, ""),
        "srvr": first_str(f, 6, ""),
        "v_Data": first(f, 9, b""),
        "labl": first_str(f, 12, ""),
        "desc": first_str(f, 24, ""),
    }
    if first(f, 10):
        item["path"] = first_str(f, 10, "")
    return item


def open_zone(protection: dict, keychain_keys: dict[bytes, bytes]):
    """(identity keys, zone-wide record keys) for a zone, from the service key in `keychain_keys`
    ({public X: private key DER}). PCSError when no key of ours opens it."""
    if not protection["protection"]:
        raise pcs.PCSError("zone has no protection info")
    prot = pcs.ShareProtection.parse(protection["protection"])
    privs = [pcs.private_key_from_der(keychain_keys[x]) for x in prot.public_keys()
             if x in keychain_keys]
    if not privs:
        raise pcs.PCSError("no service key in the keychain for this group")
    _, idents = prot.open(privs)
    record_keys: list = []
    if protection["record_protection"]:
        record_keys, _ = pcs.ShareProtection.parse(protection["record_protection"]).open(idents)
    return idents, record_keys


def has_service_key(protection: dict, keychain_keys: dict[bytes, bytes]) -> bool:
    """Whether the keychain holds a key for this zone's protection (no decryption)."""
    if not protection["protection"]:
        return False
    return any(x in keychain_keys
               for x in pcs.ShareProtection.parse(protection["protection"]).public_keys())


def record_keys(rec: dict, idents, default_keys, cache: dict | None = None) -> list:
    """The keys for one record: its own protection when it has one (opened once per distinct
    protection blob when a `cache` is given), else the zone's."""
    blob = rec["protection"]
    if not blob:
        return default_keys
    if cache is not None and blob in cache:
        return cache[blob]
    keys, _ = pcs.ShareProtection.parse(blob).open(idents)
    if cache is not None:
        cache[blob] = keys
    return keys


def decrypt_field(rec: dict, zone_name: str, fname: str, keys) -> bytes | None:
    data = rec["fields"].get(fname, (None, None))[0]
    if not data:
        return None
    return pcs.decrypt_with_any(keys, data, f"{zone_name}-{rec['name']}-{fname}".encode())
