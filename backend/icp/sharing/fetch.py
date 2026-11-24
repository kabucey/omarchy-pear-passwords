"""Fetch and decrypt every Apple Passwords shared group you own, for a sync. Fetches only.

The same three operations as the diagnostic (diagnose.py) and nothing else, all to the
shared-keychain container's private database: op 203 (list the zones), op 201 (a zone's
protection info) and op 213 (its records). Never op 200, 202 or 210, never anything that
saves, deletes, shares or joins. This module reads and writes no store; it returns what it
decrypted to the caller, who holds it in memory and drops it.

The result says whether the fetch was COMPLETE. It is only if the zone list, every group's
protection, every page of every group and every item's decryption all succeeded. A caller must
change nothing it keeps from a fetch that is not complete: a partial answer looks exactly like
a group whose entries were removed.

No plaintext leaves through the logs or `stats`: stats holds integers keyed by fixed words,
payload kind numbers and exception class names.
"""

from __future__ import annotations

import dataclasses
import logging
import time

from ..proto.codec import decode_fields, first_str
from ..transport import cloudkit
from . import groups, pcs

log = logging.getLogger(__name__)

UNNAMED = "Shared group"
KEYCHAIN_CLASS = "inet"          # what the pipeline expects of a password item


@dataclasses.dataclass
class Group:
    """One owned group. `zone` and `name` are plaintext: held in memory only."""

    zone: str
    name: str
    items: list = dataclasses.field(default_factory=list)   # keychain item dicts


@dataclasses.dataclass
class Fetch:
    complete: bool = False
    groups: list = dataclasses.field(default_factory=list)
    stats: dict = dataclasses.field(default_factory=dict)   # counts only


def _bump(counter: dict, key: str, n: int = 1) -> None:
    counter[key] = counter.get(key, 0) + n


def _fail(out: Fetch, where: str, exc: BaseException) -> Fetch:
    _bump(out.stats.setdefault("failed", {}), f"{where}:{type(exc).__name__}")
    out.complete = False
    return out


def _read_group(transport, z: dict, keys: dict, stats: dict) -> Group:
    """One group's items, or an exception (its class is what the caller reports)."""
    prot = groups.fetch_zone_protection(transport, z["raw"], database=cloudkit.DB_PRIVATE,
                                        scope="Private")
    records, paging = groups.fetch_records(transport, z["raw"], database=cloudkit.DB_PRIVATE,
                                           scope="Private")
    if not paging["complete"]:
        raise pcs.PCSError("incomplete")
    idents, default_keys = groups.open_zone(prot, keys)
    cache: dict = {}
    group = Group(zone=z["name"], name="")
    for rec in records:
        rtype = rec["type"]
        if rtype == "cloudkit.share":
            try:
                plain = groups.decrypt_field(rec, z["name"], "displayName",
                                             groups.record_keys(rec, idents, default_keys, cache))
                group.name = first_str(decode_fields(plain), 6, "") if plain else ""
            except Exception:  # noqa: BLE001 - the name is a label; the group still opens
                _bump(stats, "name_unreadable")
            continue
        if rtype != "item":
            continue
        _bump(stats, "items")
        if not rec["fields"].get("payload", (None, None))[0]:
            raise pcs.PCSError("item without a payload")
        plain = groups.decrypt_field(rec, z["name"], "payload",
                                     groups.record_keys(rec, idents, default_keys, cache))
        item = groups.sharing_item_to_keychain(plain)
        if item is None:
            kinds = "+".join(str(k) for k in sorted(decode_fields(plain))) or "empty"
            _bump(stats.setdefault("skipped_kinds", {}), kinds)
            continue
        item["class"] = KEYCHAIN_CLASS
        group.items.append(item)
    group.name = group.name or UNNAMED
    return group


def fetch_owned_groups(transport, kc_user: str, keychain_keys: dict[bytes, bytes],
                       *, pause: float = 0.2) -> Fetch:
    """Every owned group's items as keychain item dicts. Never raises."""
    out = Fetch(stats={"groups": 0, "items": 0})
    try:
        zones = groups.list_zones(transport)
    except Exception as e:  # noqa: BLE001
        return _fail(out, "zones", e)
    owned = [z for z in zones if z.get("owner") in ("", kc_user, "__defaultOwner__")]
    out.stats["groups"] = len(owned)
    for i, z in enumerate(owned):
        if i:
            time.sleep(pause)
        try:
            out.groups.append(_read_group(transport, z, keychain_keys, out.stats))
        except Exception as e:  # noqa: BLE001 - one bad group makes the whole fetch partial
            out.groups.clear()
            return _fail(out, "group", e)
    out.complete = True
    return out
