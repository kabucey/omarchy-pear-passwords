"""READ-ONLY diagnostic: decrypt the shared groups you own and report counts, nothing else.

What it may send: op 203 (list the private database's zones), op 201 (one zone's protection
info) and op 213 (a zone's records), to the shared-keychain container, plus the fetches a normal
keychain sync already makes (OctagonClient.probe_sharing_decrypt). It never saves, deletes or
joins anything, never touches the vault or a sync token, and keeps no plaintext: passwords,
usernames, sites, group names and group UUIDs live in local variables here, are counted, and
are dropped. The report holds integers, booleans, record types, exception class names and
access-group names that match a plain identifier pattern; never a value, a name or an id.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import time

from ..keychain import pipeline
from ..proto.codec import decode_fields, first, first_str
from ..transport import ckks, cloudkit
from . import groups, pcs

log = logging.getLogger(__name__)

PCS_AGRP_PREFIX = "com.apple.ProtectedCloudStorage"
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _name(value) -> str:
    """An access group as the report may show it, or "?"."""
    return value if isinstance(value, str) and _NAME_RE.match(value) else "?"


def _bump(counter: dict, key: str, n: int = 1) -> None:
    counter[key] = counter.get(key, 0) + n


# --------------------------------------------------------------------------- the service keys

def pcs_keys_from_records(records_by_type: dict, tlks: dict) -> tuple[dict[bytes, bytes], dict]:
    """The PCS service keys held in the keychain, {public X: private key DER}, plus counts.

    Normal sync turns decrypted items into credentials and keeps none of these, so this runs
    the same unwrap chain (tlkshare -> TLK -> class key -> item key) over the records a sync
    already fetched and keeps only the items whose access group starts with
    com.apple.ProtectedCloudStorage. `tlks` are the merged TLKs of a normal sync. One bad item
    is counted, not fatal. Nothing is stored."""
    class_keys = pipeline.unwrap_class_keys(records_by_type.get("synckey", []), tlks)
    stats = {"items": 0, "undecryptable": 0, "pcs_keys": 0}
    keys: dict[bytes, bytes] = {}
    for rec in records_by_type.get("item", []):
        stats["items"] += 1
        try:
            plist = pipeline.decrypt_items([rec], class_keys)[0]
        except Exception:  # noqa: BLE001 - counted, never fatal for a diagnostic
            stats["undecryptable"] += 1
            continue
        if not str(plist.get("agrp") or "").startswith(PCS_AGRP_PREFIX):
            continue
        acct, data = plist.get("acct"), plist.get("v_Data")
        if not isinstance(acct, str) or not isinstance(data, (bytes, bytearray)):
            continue
        try:
            keys[base64.b64decode(acct)] = bytes(data)
        except (ValueError, TypeError):
            continue
    stats["pcs_keys"] = len(keys)
    return keys, stats


# --------------------------------------------------------------------------- one group

def _field_numbers(payload: bytes, kind: int) -> str:
    """The field numbers inside payload field `kind`, "1+2+5": a shape, never a value."""
    try:
        inner = first(decode_fields(payload), kind)
        nums = sorted(decode_fields(inner)) if isinstance(inner, (bytes, bytearray)) else []
    except Exception:  # noqa: BLE001
        nums = []
    return "+".join(str(n) for n in nums) or "-"


class _Distinct:
    """Counts distinct values without keeping them: a salted digest per value, in memory."""

    def __init__(self, salt: bytes):
        self.salt, self.seen = salt, set()

    def add(self, *parts: str) -> None:
        h = hashlib.blake2b(key=self.salt, digest_size=16)
        for p in parts:
            h.update(p.encode("utf-8", "replace"))
            h.update(b"\x00")
        self.seen.add(h.digest())

    def __len__(self) -> int:
        return len(self.seen)


def _empty_stats() -> dict:
    return {"records": 0, "types": {}, "type_field": {}, "duplicate_record_names": 0,
            "items": 0, "items_without_payload": 0, "decrypted": 0, "failed": {},
            "payload_kinds": {}, "payload_shapes": {}, "agrp": {},
            "internet_passwords": 0, "empty_password": 0, "empty_server": 0,
            "empty_account": 0}


def analyse_group(zone_name: str, records: list[dict], protection: dict | None,
                  keychain_keys: dict[bytes, bytes], distinct: dict) -> dict:
    """Counts for one group. `distinct` holds _Distinct sets {accounts, with_password}
    that the caller may share across groups. Returns no value of any kind."""
    st = _empty_stats()
    st["name_decrypted"] = False
    opened, open_error = False, None
    idents, default_keys = [], []
    st["service_key_found"] = False
    try:
        if protection is None:
            raise pcs.PCSError("no protection")
        st["service_key_found"] = groups.has_service_key(protection, keychain_keys)
        idents, default_keys = groups.open_zone(protection, keychain_keys)
        opened = True
    except Exception as e:  # noqa: BLE001
        open_error = type(e).__name__
    st["zone_opened"] = opened
    if open_error:
        st["open_error"] = open_error

    local_acct, local_pw = _Distinct(distinct["accounts"].salt), _Distinct(distinct["accounts"].salt)
    names: set[str] = set()
    key_cache: dict = {}
    for rec in records:
        st["records"] += 1
        rtype = rec["type"] or "?"
        _bump(st["types"], _name(rtype))
        if rec["name"] in names:
            st["duplicate_record_names"] += 1
        names.add(rec["name"])
        tb, ti = rec["fields"].get("type", (None, None))
        _bump(st["type_field"], str(ti) if ti is not None else ("bytes" if tb is not None else "absent"))
        if rtype == "item":
            st["items"] += 1
            if not rec["fields"].get("payload", (None, None))[0]:
                st["items_without_payload"] += 1
                continue
        elif rtype != "cloudkit.share":
            continue
        if not opened:
            if rtype == "item":
                _bump(st["failed"], f"zone:{open_error}")
            continue
        fname = "displayName" if rtype == "cloudkit.share" else "payload"
        stage = "keys"
        try:
            keys = groups.record_keys(rec, idents, default_keys, key_cache)
            stage = "decrypt"
            plain = groups.decrypt_field(rec, zone_name, fname, keys)
            if rtype == "cloudkit.share":
                stage = "parse"
                st["name_decrypted"] = bool(plain and first_str(decode_fields(plain), 6, ""))
                continue
            stage = "parse"
            kinds = sorted(decode_fields(plain))
            _bump(st["payload_kinds"], "+".join(str(k) for k in kinds) or "empty")
            for k in kinds:
                if k != 3:       # what the sync skips: the field numbers inside it, no value
                    _bump(st["payload_shapes"], f"{k}:" + _field_numbers(plain, k))
            item = groups.sharing_item_to_keychain(plain)
            st["decrypted"] += 1
        except Exception as e:  # noqa: BLE001 - counted by class name only
            if rtype == "item":
                _bump(st["failed"], f"{stage}:{type(e).__name__}")
            continue
        if item is None:
            continue
        st["internet_passwords"] += 1
        _bump(st["agrp"], _name(item["agrp"]))
        srvr, acct, pw = item["srvr"], item["acct"], item["v_Data"]
        if not pw:
            st["empty_password"] += 1
        if not srvr:
            st["empty_server"] += 1
        if not acct:
            st["empty_account"] += 1
        pw_s = pw.decode("utf-8", "replace") if isinstance(pw, (bytes, bytearray)) else str(pw)
        for d in (local_acct, distinct["accounts"]):
            d.add(srvr, acct)
        for d in (local_pw, distinct["with_password"]):
            d.add(srvr, acct, pw_s)
        del item, plain, pw, pw_s
    st["distinct_server_account"] = len(local_acct)
    st["distinct_server_account_password"] = len(local_pw)
    return st


def _merge(total: dict, st: dict) -> None:
    for k, v in st.items():
        if isinstance(v, dict):
            for kk, vv in v.items():
                _bump(total.setdefault(k, {}), kk, vv)
        elif isinstance(v, bool):
            total[k] = total.get(k, 0) + (1 if v else 0)
        elif isinstance(v, int):
            total[k] = total.get(k, 0) + v


# --------------------------------------------------------------------------- the run

_list_zones = groups.list_zones


def run(transport, kc_user: str, keychain_keys: dict[bytes, bytes]) -> dict:
    """Decrypt every group you own (private database) and return the counts report."""
    salt = os.urandom(16)
    distinct = {"accounts": _Distinct(salt), "with_password": _Distinct(salt)}
    report: dict = {"container": cloudkit.KCSHARING_CONTAINER, "mode": "decrypt", "groups": []}
    try:
        zones = _list_zones(transport)
    except Exception as e:  # noqa: BLE001
        report["error"] = {"type": type(e).__name__, "code": getattr(e, "code", None)}
        return report
    owned = [z for z in zones if z.get("owner") in ("", kc_user, "__defaultOwner__")]
    report["zones_listed"] = len(zones)
    report["groups_owned"] = len(owned)
    total = _empty_stats()
    for i, z in enumerate(owned, 1):
        g: dict = {"group": i}
        try:
            time.sleep(0.2)
            prot = groups.fetch_zone_protection(transport, z["raw"], database=cloudkit.DB_PRIVATE,
                                                scope="Private")
        except Exception as e:  # noqa: BLE001
            prot = None
            g["protection_error"] = type(e).__name__
        try:
            records, paging = groups.fetch_records(transport, z["raw"],
                                                   database=cloudkit.DB_PRIVATE, scope="Private")
        except Exception as e:  # noqa: BLE001
            g["error"] = {"type": type(e).__name__, "code": getattr(e, "code", None)}
            report["groups"].append(g)
            continue
        g["paging"] = paging
        st = analyse_group(z["name"], records, prot, keychain_keys, distinct)
        del records
        g.update(st)
        _merge(total, st)
        report["groups"].append(g)
    total["distinct_server_account"] = len(distinct["accounts"])
    total["distinct_server_account_password"] = len(distinct["with_password"])
    report["totals"] = total
    return report
