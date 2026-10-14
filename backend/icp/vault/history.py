"""Password change history, as the 2.0 store keeps it.

Apple keeps a history of its own - the `s_hi` list inside a Passwords *metadata* record - but
only for entries its Passwords app manages. Most keychain items have no metadata record at all,
so for them Apple remembers nothing. The store covers every entry: whenever a sync or an edit
brings a different password (told apart by pwmac, without opening anything), the previous
entry box is moved, unopened, to history/<id>/. 1.x's encrypted journal (history.enc) was
converted into such boxes by the one-time import.

Reading history opens those boxes, so it needs the entry key and happens only under a grant.
This module only reshapes what `UserStore.history` returns.
"""

from __future__ import annotations

from ..vstore import UserStore

SOURCE_LOCAL = "local"    # a change this machine saw (a sync diff, an edit, or the 1.x journal)
SOURCE_APPLE = "apple"    # lifted from Apple's own s_hi history

MAX_PER_ACCOUNT = 50      # a runaway rotation must not grow the store without bound


def for_entry(store: UserStore, entry_id: str) -> list[dict]:
    """[{"date": iso8601, "value": str, "source": "local"|"apple"}] newest first - the item
    shape of the protocol's `history` reply. Unseals SK_secret once; raises StoreLocked,
    EntryNotFound or SealError like UserStore.history."""
    out = []
    for item in store.history(entry_id):
        date, value = item
        out.append({"date": date, "value": value,
                    "source": getattr(item, "source", SOURCE_LOCAL)})
    return out
