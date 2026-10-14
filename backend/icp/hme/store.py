"""Hide My Email aliases, cached in the 2.0 store (aliases.v2, sealed under K_alias).

Refreshed by the daemon's sync, so the app shows a snapshot, never a live fetch. 1.x deleted
this cache when it would not decrypt; the store never deletes - an unreadable file is reported
as damaged and kept.
"""

from __future__ import annotations

import dataclasses

from ..vstore import UserStore
from .client import HmeAlias

_FIELDS = tuple(f.name for f in dataclasses.fields(HmeAlias))


def save_aliases(store: UserStore, aliases: list[HmeAlias]) -> None:
    """Raises StoreLocked."""
    store.save_aliases([dataclasses.asdict(a) for a in aliases])


def load_aliases(store: UserStore) -> list[HmeAlias]:
    """Raises StoreLocked. A stored alias missing a field (an older shape) is skipped rather
    than failing the whole list."""
    out = []
    for a in store.load_aliases():
        if all(k in a for k in _FIELDS):
            out.append(HmeAlias(**{k: a[k] for k in _FIELDS}))
    return out
