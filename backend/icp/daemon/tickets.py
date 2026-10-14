"""Single-use tickets: how a clip or migrate process proves the Pear window started it.

A `clip` or `migrate` connection carries no authority of its own. The window asks for a ticket
on its own (tier-1) connection, starts `pear-exec clip|migrate` and writes the ticket to the
child's stdin. The child's hello presents it, and the daemon accepts the child only if:

- the ticket is live (TICKET_TTL_S from issue), unused, for this role and this uid;
- the window connection that asked for it is still open;
- the child's PPid is that window's pid, and that pid still has the window's start time.

Every hello consumes the ticket it presents, whether it passes or not, and a uid that presents
BAD_TICKETS_PER_MIN bad ones in a minute is refused outright until the minute is over. A lock
revokes all of a uid's tickets.

The value snapshot a copy ticket carries is the only plaintext here. It is dropped at redeem,
at expiry and at revoke; Python strings cannot be zeroed, which docs/security.md states.
"""

from __future__ import annotations

import base64
import secrets
import time
from collections import deque
from dataclasses import dataclass, field as _field
from typing import Any, Callable

from . import protocol


class TicketError(Exception):
    """Any refusal. The client only ever sees `bad-ticket`; the reason is for the journal."""


@dataclass
class Ticket:
    token: str
    uid: int
    role: str                          # "clip" | "migrate"
    purpose: str                       # "copy" | "import" | "purge"
    ui_conn: Any                       # the issuing window connection
    ui_pid: int
    ui_start_time: int
    issued: float
    id: str | None = None              # copy: which entry and field
    field: str | None = None
    value: str | None = None           # copy: the snapshot taken at issue
    sensitive: bool = False
    extra: dict = _field(default_factory=dict)

    def wipe(self) -> None:
        self.value = None
        self.extra = {}


def new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(protocol.TICKET_BYTES)).rstrip(
        b"=").decode("ascii")


class TicketBook:
    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 ttl: float = protocol.TICKET_TTL_S):
        self._clock = clock
        self._ttl = ttl
        self._tickets: dict[str, Ticket] = {}
        self._bad: dict[int, deque] = {}

    def issue(self, *, uid: int, role: str, purpose: str, ui_conn, id: str | None = None,
              field: str | None = None, value: str | None = None, sensitive: bool = False,
              extra: dict | None = None) -> str:
        if role not in protocol.TICKET_ROLES:
            raise ValueError(f"no tickets for role {role!r}")
        self._sweep()
        token = new_token()
        self._tickets[token] = Ticket(
            token=token, uid=uid, role=role, purpose=purpose, ui_conn=ui_conn,
            ui_pid=ui_conn.pid, ui_start_time=ui_conn.start_time, issued=self._clock(),
            id=id, field=field, value=value, sensitive=sensitive, extra=dict(extra or {}))
        return token

    def redeem(self, token, *, uid: int, role: str, ppid: int,
               parent_start_time: Callable[[int], int | None]) -> Ticket:
        """Consume `token` for a hello from a `role` process of `uid` whose parent is `ppid`.
        Returns the ticket or raises TicketError; the ticket is gone either way."""
        ticket = self._tickets.pop(token, None) if isinstance(token, str) else None
        try:
            if self._throttled(uid):
                raise TicketError("too many bad tickets this minute")
            if ticket is None:
                raise TicketError("unknown or already used ticket")
            if self._clock() - ticket.issued > self._ttl:
                raise TicketError("ticket expired")
            if ticket.uid != uid:
                raise TicketError("ticket of another uid")
            if ticket.role != role:
                raise TicketError(f"ticket for {ticket.role}, not {role}")
            if getattr(ticket.ui_conn, "closed", True):
                raise TicketError("the window that asked for it is gone")
            if ppid != ticket.ui_pid:
                raise TicketError(f"parent {ppid} is not the window ({ticket.ui_pid})")
            if parent_start_time(ppid) != ticket.ui_start_time:
                raise TicketError("the window's pid was recycled")
        except TicketError:
            self._bad.setdefault(uid, deque()).append(self._clock())
            if ticket is not None:
                ticket.wipe()
            raise
        return ticket

    def revoke_uid(self, uid: int, role: str | None = None) -> int:
        """Drop every unredeemed ticket of `uid` (of `role` only, when given)."""
        gone = [t for t in self._tickets.values()
                if t.uid == uid and (role is None or t.role == role)]
        for t in gone:
            del self._tickets[t.token]
            t.wipe()
        return len(gone)

    def pending(self, uid: int | None = None) -> int:
        self._sweep()
        return sum(1 for t in self._tickets.values() if uid is None or t.uid == uid)

    def _throttled(self, uid: int) -> bool:
        q = self._bad.get(uid)
        if not q:
            return False
        now = self._clock()
        while q and now - q[0] >= 60:
            q.popleft()
        return len(q) >= protocol.BAD_TICKETS_PER_MIN

    def _sweep(self) -> None:
        now = self._clock()
        for token in [k for k, t in self._tickets.items() if now - t.issued > self._ttl]:
            self._tickets.pop(token).wipe()
