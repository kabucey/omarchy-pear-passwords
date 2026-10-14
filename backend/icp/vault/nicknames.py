"""User-chosen names for entries.

The keychain's own title is whatever the site called itself when the password was saved, which
is why the list is full of `account.bellmedia.ca` and bare UUIDs. A nickname overrides it.

Stored sealed under K_nick in the 2.0 store rather than in the clear: on its own a nickname is
not a secret, but a file listing "Work VPN", "Mum's bank", "old Gmail" against account
identifiers is a map of someone's life.

Local to this machine. Apple's own `labl` field is where a synced rename would have to go, and
that means a two-record push per rename - worth doing, deliberately not bundled in here.
"""

from __future__ import annotations

from ..vstore import UserStore

MAX_LEN = 80


def load(store: UserStore) -> dict:
    """{entry id: nickname}. Raises StoreLocked."""
    return store.load_nicknames()


def save(store: UserStore, names: dict) -> None:
    store.save_nicknames(names)


def clean(value: str) -> str:
    """Collapse whitespace and cap the length. An empty result means 'use the real title'."""
    return " ".join((value or "").split())[:MAX_LEN]


def set_for(store: UserStore, entry_id: str, value: str) -> dict:
    names = load(store)
    value = clean(value)
    if value:
        names[entry_id] = value
    else:
        names.pop(entry_id, None)
    save(store, names)
    return names
