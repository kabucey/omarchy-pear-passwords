"""Apple Passwords shared groups as SyncItems for UserStore.apply_shared_sync.

icp.sharing fetches and decrypts the groups the person owns (fetches only) into keychain item
dicts. Here those go through the SAME pairing and grouping as the person's own keychain
(vault.host.CredentialStore.from_items, then octagon.items.to_sync_items), one group at a time,
so a password item pairs with its Apple Passwords sidecar and an account on several websites
becomes one row exactly as it does for an own account, and a shared item is never paired with
an own item or with another group's. Each result is given an id in the shared namespace
(vstore.ids.shared_entry_id) and its group's name as `meta.shared_group`.

The result carries `complete`: only a fetch that fully succeeded may be applied to the vault.
"""

from __future__ import annotations

import dataclasses
import logging

from ..vault.host import CredentialStore
from ..vstore import SyncItem
from ..vstore import ids as _ids
from . import items as sync_items

log = logging.getLogger(__name__)


@dataclasses.dataclass
class SharedSync:
    """What a sync learned about the shared groups. `items` is meaningful only when
    `complete`; `stats` holds counts and exception class names, never a value."""

    complete: bool = False
    items: list = dataclasses.field(default_factory=list)
    stats: dict = dataclasses.field(default_factory=dict)


def to_shared_items(fetch) -> list[SyncItem]:
    out: list[SyncItem] = []
    for g in fetch.groups:
        creds = [c for c in CredentialStore.from_items(g.items).all()
                 if not c.recently_deleted and c.kind != "passkey"]
        for it in sync_items.to_sync_items(creds, None):
            sid = _ids.shared_entry_id(g.zone, it.id)
            meta = dataclasses.replace(it.meta, id=sid, nickname="", shared_group=g.name)
            out.append(SyncItem(id=sid, meta=meta, secrets=it.secrets))
    return out


def collect(transport, kc_user: str, keychain_keys: dict) -> SharedSync:
    """Fetch every owned group and convert it. Never raises; `complete` False on any failure."""
    from ..sharing import fetch as sharing_fetch

    f = sharing_fetch.fetch_owned_groups(transport, kc_user, keychain_keys)
    res = SharedSync(complete=f.complete, stats=dict(f.stats))
    try:
        if f.complete:
            res.items = to_shared_items(f)
    except Exception as e:  # noqa: BLE001
        res.complete, res.items = False, []
        res.stats.setdefault("failed", {})[f"convert:{type(e).__name__}"] = 1
    finally:
        f.groups.clear()
    res.stats["entries"] = len(res.items)
    return res
