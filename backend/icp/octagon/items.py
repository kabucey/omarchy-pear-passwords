"""From decrypted keychain credentials to the store's SyncItems.

The pipeline (keychain/pipeline.py) turns CKKS records into Credentials; this module turns
those into what UserStore.apply_sync takes: one SyncItem per entry, split into the metadata
tier 1 may release (Meta) and the secrets only a grant may open (Secrets).

Entry ids. An id is opaque to every client but has to be stable for the same keychain item
across syncs, and the same for a v1 entry imported by migration and that entry's next sync -
otherwise every migrated account would look deleted and re-added, and its nickname and local
history (both keyed by id) would be orphaned. The keychain identifies an account by its server
and account fields (srvr, acct), which is also what an edit matches records on, so the id is a
hash of exactly those two: `entry_id(domain, username)`. 1.x used the same pair joined with a
\\x1f, which the 2.0 id alphabet does not allow, so the importer maps 1.x keys through this
function too.
"""

from __future__ import annotations

import dataclasses
import re

from ..vstore import SyncItem
from ..vstore import ids as _ids
from ..vstore import legacy as _legacy

ID_PREFIX = _ids.PREFIX
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# One definition for the importer, the sync and the adapters: vstore owns entry ids.
entry_id = _ids.entry_id


def v1_entry_key(domain: str, username: str) -> str:
    """How 1.x keyed nicknames and history: domain, unit separator, username."""
    return f"{domain}\x1f{username}"


def credential_id(c) -> str:
    """The entry id of a Credential. A copy in Apple's Recently Deleted is salted, so it is
    never the live entry and never collapses into it."""
    salt = _ids.RECENTLY_DELETED if getattr(c, "recently_deleted", False) else ""
    return entry_id(c.domain, c.username, salt)


def to_sync_item(c, nicknames: dict | None = None) -> SyncItem:
    """One Credential as a SyncItem. `nicknames` are the store's local names by entry id.

    The Meta/Secrets split is vstore.legacy's, the same code the 1.x importer uses, so the
    first sync after a migration finds every imported box already holding exactly these
    secrets (TOTP seed as raw bytes, Apple history as {date, value}) and rewrites nothing."""
    eid = credential_id(c)
    m, secrets = _legacy.credential_parts(c.storage_dict())
    meta = dataclasses.replace(m, id=eid, nickname=str((nicknames or {}).get(eid, "")),
                               history_count=len(secrets.apple_history))
    return SyncItem(id=eid, meta=meta, secrets=secrets)


def to_sync_items(credentials, nicknames: dict | None = None) -> list[SyncItem]:
    """Every credential as a SyncItem, one per id. Two password items for the same account
    (it happens: a site saved twice, or over two protocols) collapse to the newest, which is
    also the one any Apple device fills."""
    kept, dropped = _ids.collapse((to_sync_item(c, nicknames) for c in credentials),
                                  key=lambda it: it.id, mdat=lambda it: it.meta.mdat)
    # What only the older item held (notes, a code seed, websites) is folded in, exactly as
    # the 1.x importer does, so nothing is lost and the first sync rewrites nothing.
    for id, it in sorted(dropped, key=lambda d: -d[1].meta.mdat):  # newest first, stable
        k = kept[id]
        m, s = _legacy.merge_duplicate((k.meta, k.secrets), (it.meta, it.secrets))
        kept[id] = SyncItem(id=id, meta=m, secrets=s)
    return list(kept.values())
