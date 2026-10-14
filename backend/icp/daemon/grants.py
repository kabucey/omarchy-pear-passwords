"""Per-entry grants: the second dialog opens one account for `grant_s` seconds, and no other.

One grant per uid. A grant holds the entry's opened Secrets for its lifetime, so reveal, copy,
totp and edit never unseal SK_secret again; when it ends the buffer is dropped (and zeroed
where Python allows: the TOTP seed is bytes, strings are only dereferenced).

A grant ends when it expires, when `grant_s` is 0 and it has been used once, on `release`, on
a new `grant`, and on every lock. Checks always compare the clock, so a grant whose timer is
late is still refused on time.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .protocol import OpError


@dataclass
class Grant:
    uid: int
    id: str
    secrets: object                    # vstore.Secrets
    single_use: bool
    expires_mono: float | None         # None when single use
    expires_wall: float | None
    used: bool = False

    def wipe(self) -> None:
        s, self.secrets = self.secrets, None
        wipe_secrets(s)


def wipe_secrets(s) -> None:
    """Drop what a Secrets object holds: zero a bytearray seed, dereference the rest."""
    if s is None:
        return
    seed = getattr(s, "totp_secret", None)
    if isinstance(seed, bytearray):
        seed[:] = bytes(len(seed))
    for name, empty in (("password", ""), ("notes", ""), ("totp_secret", None),
                        ("apple_history", []), ("totp_params", {})):
        try:
            setattr(s, name, empty)
        except AttributeError:
            pass


class GrantTable:
    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time):
        self._clock = clock
        self._wall = wall
        self._grants: dict[int, Grant] = {}
        self._last_ended: dict[int, str] = {}    # uid -> id of the grant that ran out last

    def put(self, uid: int, id: str, secrets, grant_s: int) -> Grant:
        """Replace the uid's grant with a new one on `id`. The old one is wiped."""
        self.drop(uid)
        self._last_ended.pop(uid, None)
        single = grant_s <= 0
        g = Grant(uid=uid, id=id, secrets=secrets, single_use=single,
                  expires_mono=None if single else self._clock() + grant_s,
                  expires_wall=None if single else self._wall() + grant_s)
        self._grants[uid] = g
        return g

    def current(self, uid: int) -> Grant | None:
        return self._grants.get(uid)

    def check(self, uid: int, id: str) -> Grant:
        """The live grant on exactly `id`, or OpError no-grant / grant-expired."""
        g = self._grants.get(uid)
        if g is not None and g.expires_mono is not None and self._clock() >= g.expires_mono:
            self.end(uid)
            g = None
        if g is None or g.id != id or g.used:
            if g is None and self._last_ended.get(uid) == id:
                raise OpError("grant-expired")
            raise OpError("no-grant")
        return g

    def use(self, uid: int, id: str) -> tuple[Grant, bool]:
        """check(), then mark a single-use grant spent. Returns (grant, ended_now); the caller
        reads what it needs from grant.secrets, then calls end() when ended_now is True."""
        g = self.check(uid, id)
        if g.single_use:
            g.used = True
            return g, True
        return g, False

    def end(self, uid: int) -> str | None:
        """The grant ran out (expiry or single use): wipe it and remember its id, so the next
        call on that id hears grant-expired rather than no-grant. Returns the id."""
        g = self._grants.pop(uid, None)
        if g is None:
            return None
        self._last_ended[uid] = g.id
        g.wipe()
        return g.id

    def drop(self, uid: int) -> str | None:
        """Release, a new grant or a lock: wipe it without the grant-expired memory."""
        self._last_ended.pop(uid, None)
        g = self._grants.pop(uid, None)
        if g is None:
            return None
        g.wipe()
        return g.id

    def due(self) -> list[tuple[int, str]]:
        now = self._clock()
        return [(uid, g.id) for uid, g in self._grants.items()
                if g.expires_mono is not None and now >= g.expires_mono]
