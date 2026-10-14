"""The iCloud session record: tokens, the saved Apple ID password (if any), web-auth cookies,
the Octagon peer identity and the escrow sponsor key.

In 2.0 this is a thin view over the per-user store. The daemon holds the store unlocked while
the Pear window has tier 1 open, and session.v2 is sealed under a subkey of RK_list there; there
is no master key here, no keyring item and no key file. Anything that needs the session is
handed the store by its caller (daemon/apple.py, through a UserContext) - nothing in this module
finds a key on its own, so nothing here can prompt.
"""

from __future__ import annotations

from ..errors import AppleError


class SessionError(AppleError):
    """The session exists but is not usable for what was asked (for example, not joined)."""


def load(store) -> dict | None:
    """The session record, or None when signed out. Raises vstore.StoreLocked while locked."""
    d = store.load_session()
    return dict(d) if d else None


def save(store, data: dict) -> None:
    """Replace the session record. An empty dict signs out (session.v2 is removed)."""
    store.save_session(dict(data or {}))


def clear(store) -> None:
    store.save_session({})
