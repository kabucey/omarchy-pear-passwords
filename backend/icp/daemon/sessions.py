"""Per-uid state, and the shared services every op handler uses (protocol.SessionRegistry).

A Session is one uid: its store, its one window connection, whether tier 1 is open on that
connection, its settings, and what is running for it. The Registry holds every session plus
the things that must be decided in exactly one place:

- authorize(): the only way any handler raises a polkit dialog. It enforces one outstanding
  dialog per (uid, bucket) and PROMPT_ANSWERED_PER_MIN refused (dismissed or denied) dialogs
  per (uid, bucket, action) per rolling minute,
  supersedes a pending `grant` with a new one, and cancels on EOF.
- lock(): every lock trigger in docs/protocol.md 4.2 ends here. It marks the uid locked first,
  then wipes the grant, revokes tickets, withdraws clip and migrate processes, cancels dialogs
  and a running sign-in, and wipes the store's keys. It never waits: it runs on the event loop,
  which serves every uid, and a store call can sit in systemd-creds for up to a minute on a
  slow TPM. When no store call is running the keys are wiped at once; when one is, the uid is
  marked wipe-after and the store is asked to wipe (UserStore.try_lock): the store method in
  progress wipes the keys the moment it returns, still under the store's mutex, and every
  store method after it is refused - also inside the same run_store call, which can be many
  store methods (a sync). New run_store calls for the uid are refused until then. Never a
  half-applied sync, never a meta.v2 sealed from a wiped doc.
- run_store(): blocking UserStore and Apple calls go to a worker thread under the uid's store
  lock, and wipe the keys again on the way out when a lock landed meanwhile.
"""

from __future__ import annotations

import asyncio
import contextvars
import itertools
import logging
import math
import secrets
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from . import paths, protocol
from .context import Cancelled
from .grants import GrantTable
from .peer import start_time_of
from .polkit import (AUTHORIZED, CANCELLED, COUNTED, DENIED, DENIED_UNANSWERED, NO_AGENT,
                     Authority, Subject, sanitize)
from .protocol import OpError
from .tickets import TicketBook

logger = logging.getLogger(__name__)

ANISETTE_URL = "http://127.0.0.1:6969"

# UserStore methods that read no key and hold no store mutex (plaintext files and flags only).
KEYLESS_STORE_CALLS = frozenset({"status", "state", "load_settings", "holds_nothing",
                                 "create_blocked"})


# --- the request being handled --------------------------------------------------------------
# The server sets this for each request's task. Handlers use after_reply() for events their
# request causes, so those events follow the reply (docs/protocol.md 1, ordering).

class Request:
    __slots__ = ("conn", "rid", "after")

    def __init__(self, conn, rid):
        self.conn = conn
        self.rid = rid
        self.after: list[Callable[[], Any]] = []


_current: contextvars.ContextVar[Request | None] = contextvars.ContextVar(
    "pear_request", default=None)


def current_request() -> Request | None:
    return _current.get()


def set_request(req: Request | None):
    return _current.set(req)


def reset_request(token) -> None:
    _current.reset(token)


def after_reply(fn: Callable[[], Any]) -> None:
    """Run `fn` right after the current request's reply is queued (at once outside one)."""
    req = _current.get()
    if req is None:
        fn()
    else:
        req.after.append(fn)


def spawn(coro) -> asyncio.Task:
    """A background task that belongs to no request, so its events are sent when they
    happen rather than queued behind a reply that has already gone."""
    return asyncio.get_running_loop().create_task(coro, context=contextvars.Context())


class WorkerCancelled(Exception):
    """context.Cancelled raised in a worker thread, carried back as an ordinary exception: a
    KeyboardInterrupt reaching an asyncio task would be re-raised out of the event loop."""


def _call(fn, args):
    try:
        return fn(*args)
    except Cancelled:
        raise WorkerCancelled() from None
    except KeyboardInterrupt:
        raise WorkerCancelled() from None


# --- sessions ---------------------------------------------------------------------------------

class Session:
    def __init__(self, uid: int, store):
        self.uid = uid
        self.store = store
        self.ui = None                     # the one window connection
        self.tier1 = None                  # the connection tier 1 is open on (always self.ui)
        self.settings: dict = dict(protocol.DEFAULT_SETTINGS)
        self.old_copy: dict | None = None
        self.settings_loaded = False
        self.show_all = False              # unlock{all:true}
        self.epoch = 0                     # bumped by every lock
        self.busy: str | None = None       # "sync" | "signin" | "edit" while Apple work runs
        self.signin = None                 # the live SocketFrontend
        self.migrating = False             # migrate-begin made a store, import not committed
        self.autofill_enabled = False      # turned on in the window, behind .manage (persisted)
        self.features: dict = dict(protocol.DEFAULT_FEATURES)   # behind .manage (persisted)
        # The last full sync's (class, agrp) counts and attribute names, no value; for op
        # diag-items, and dropped on every lock.
        self.item_shape: dict | None = None
        self.copy_texts: deque = deque()  # when each copy-text ticket was issued (clock)
        self.autofill_key: bytes | None = None   # keys autofill handles; only while unlocked
        # The autofill connection a browser-made unlock (autofill-names) is open for, and when
        # it ends; None when the store is open only for the window, or not at all.
        self.autofill_conn = None
        self.autofill_until = 0.0
        self.autofill_timer = None
        self.last_ui_request = 0.0
        self.next_sync_at: float | None = None
        self.store_lock = asyncio.Lock()
        # A lock landed while a store call held the store's mutex: the keys are wiped as soon
        # as that call returns, and no other store call for this uid starts before then.
        self.wipe_after = False
        # A create()/reset() is running: it builds a new store object that comes back
        # unlocked, which a lock cannot reach through self.store (round 2 audit, problem 2).
        self.replacing = False

    def unlocked(self) -> bool:
        t = self.tier1
        return t is not None and t is self.ui and not t.closed


class _Pending:
    __slots__ = ("conn", "rid", "action", "cancel_id", "cancelled", "key")

    def __init__(self, conn, rid, action, key):
        self.conn = conn
        self.rid = rid
        self.action = action
        self.key = key
        self.cancel_id = f"pear-{secrets.token_hex(8)}"
        self.cancelled = False


def validate_settings(d: dict) -> dict:
    """The public settings from whatever load_settings returned, each key checked against its
    range and replaced by the default when it fails."""
    out = dict(protocol.DEFAULT_SETTINGS)
    for key in protocol.SETTINGS_KEYS:
        if key in d and setting_ok(key, d[key]):
            out[key] = d[key]
    return out


def validate_features(d) -> dict:
    """The feature flags from state.json: known keys, booleans, the rest off."""
    d = d if isinstance(d, dict) else {}
    return {k: d.get(k) is True for k in protocol.FEATURES}


def setting_ok(key: str, value) -> bool:
    if key == "window_mode":
        return isinstance(value, str) and value in protocol.WINDOW_MODES
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    if key == "grant_s":
        lo, hi = protocol.GRANT_S_RANGE
        return lo <= value <= hi
    if key == "clip_timeout_s":
        lo, hi = protocol.CLIP_TIMEOUT_S_RANGE
        return lo <= value <= hi
    if key == "idle_lock_s":
        return value in protocol.IDLE_LOCK_S_CHOICES
    return False


class Registry:
    """Implements protocol.SessionRegistry, plus the lifecycle the server and the lock
    triggers drive."""

    def __init__(self, *, store_cls=None, authority=None, apple=None,
                 clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time,
                 anisette_url: str = ANISETTE_URL,
                 parent_start_time: Callable[[int], int | None] = start_time_of):
        self._store_cls = store_cls
        self._authority = authority
        self._apple = apple
        self.clock = clock
        self.wall = wall
        self.anisette_url = anisette_url
        self.parent_start_time = parent_start_time
        self.sessions: dict[int, Session] = {}
        self.conns: set = set()
        self.tickets = TicketBook(clock)
        self.grants = GrantTable(clock, wall)
        self._pending: dict[tuple, _Pending] = {}
        self._answered: dict[tuple, deque] = {}
        self._grant_timers: dict[int, asyncio.TimerHandle] = {}
        self._store_pool = ThreadPoolExecutor(8, thread_name_prefix="pear-store")
        self._prompt_pool = ThreadPoolExecutor(8, thread_name_prefix="pear-polkit")
        self._conn_ids = itertools.count(1)

    # --- lazily bound collaborators (tests pass fakes) ---------------------------------------
    @property
    def store_cls(self):
        if self._store_cls is None:
            from ..vstore import UserStore
            self._store_cls = UserStore
        return self._store_cls

    @property
    def authority(self):
        if self._authority is None:
            self._authority = Authority()
        return self._authority

    @property
    def apple(self):
        if self._apple is None:
            from . import apple
            self._apple = apple
        return self._apple

    # --- protocol.SessionRegistry -------------------------------------------------------------
    def get(self, uid: int) -> Session | None:
        return self.sessions.get(uid)

    def connections(self, uid: int, role: str) -> list:
        return [c for c in self.conns if c.uid == uid and c.role == role and not c.closed]

    async def authorize(self, conn, action: str, details: dict[str, str]) -> None:
        bucket = protocol.PROMPT_BUCKET.get(conn.role)
        if bucket is None or action not in protocol.PROMPT_ACTION.values():
            raise OpError("forbidden")
        if conn.closed:
            raise OpError("cancelled")
        key = (conn.uid, bucket)
        old = self._pending.get(key)
        if old is not None:
            if action == paths.ACTION_REVEAL and old.action == paths.ACTION_REVEAL \
                    and old.conn is conn:
                self._cancel(old)            # a new grant supersedes the pending one
            else:
                raise OpError("prompt-pending")
        # Answers that said no are counted per action, so dismissing reveal dialogs never
        # holds up an unlock, and approvals are not counted at all.
        answered = self._answered.setdefault((*key, action), deque())
        now = self.clock()
        while answered and now - answered[0] >= 60:
            answered.popleft()
        if len(answered) >= protocol.PROMPT_ANSWERED_PER_MIN:
            raise OpError("rate-limited",
                          retry_after=max(1, math.ceil(60 - (now - answered[0]))))
        req = _current.get()
        p = _Pending(conn, req.rid if req else None, action, key)
        self._pending[key] = p
        subject = Subject(pid=conn.pid, pidfd=conn.pidfd, uid=conn.uid,
                          start_time=conn.start_time)
        clean = {str(k): sanitize(v) for k, v in (details or {}).items()}
        try:
            outcome = await self._in_pool(self._prompt_pool, self._check, subject, action,
                                          clean, p.cancel_id)
        finally:
            if self._pending.get(key) is p:
                del self._pending[key]
        if p.cancelled:
            outcome = CANCELLED
        if outcome == DENIED_UNANSWERED:
            outcome = DENIED                     # reported as such, but nobody answered it
        elif outcome in COUNTED:
            answered.append(self.clock())
        if outcome == AUTHORIZED and conn.closed:
            outcome = CANCELLED                  # nobody left to use the approval
        if outcome != AUTHORIZED:
            raise OpError(outcome)

    def _check(self, subject, action, details, cancel_id) -> str:
        try:
            return self.authority.check(subject, action, details, cancel_id)
        except Exception:
            logger.exception("polkit check raised")
            return NO_AGENT

    async def run_store(self, uid: int, fn: Callable[..., Any], *args: Any,
                        keyless: bool = False, replaces: bool = False) -> Any:
        s = self.sessions.get(uid)
        if s is None:
            raise OpError("internal")
        if keyless:
            # status/state/load_settings/holds_nothing/create_blocked read no key and take no
            # store mutex, so
            # they need neither the store lock nor to wait out a pending wipe: a window opened
            # meanwhile is told "locked", not refused.
            name = getattr(fn, "__name__", "")
            if name not in KEYLESS_STORE_CALLS:
                raise OpError("internal")
            return await self._in_pool(self._store_pool, fn, *args)
        if s.wipe_after:
            raise OpError("locked")         # a lock is waiting for the running call to end
        async with s.store_lock:
            if s.wipe_after:
                raise OpError("locked")
            epoch = s.epoch
            made: list = []
            returned = False
            s.replacing = replaces
            if replaces:
                make = fn

                def fn(*a):                 # keep the new store even if this call is cancelled
                    made.append(make(*a))
                    return made[0]
            try:
                result = await self._in_pool(self._store_pool, fn, *args)
                returned = True
                return result
            finally:
                # replaces: fn is create()/reset() and returns the new store, unlocked. A lock
                # that landed meanwhile wiped only the old object (and left wipe_after set, so
                # sleep was held back and nothing else ran): wipe the new one too, and so if
                # this call was cancelled and nobody will ever hold it. The caller sees the
                # epoch change and does not open tier 1 on it.
                s.replacing = False
                if made and (s.epoch != epoch or not returned):
                    try:
                        made[0].lock()
                    except Exception:
                        logger.exception("uid %d: wiping the new store failed", uid)
                if s.wipe_after or (s.epoch != epoch and not s.unlocked()):
                    self._wipe_store(s)

    def wipes_pending(self) -> bool:
        """Whether any uid still has keys in memory waiting for a store call to return."""
        try:
            return any(s.wipe_after for s in list(self.sessions.values()))
        except RuntimeError:                 # read from the logind thread mid-update
            return True

    def notify_ui(self, uid: int, event: dict) -> None:
        s = self.sessions.get(uid)
        if s is not None and s.ui is not None and not s.ui.closed:
            s.ui.send_event(event)

    # --- workers ------------------------------------------------------------------------------
    async def _in_pool(self, pool, fn, *args):
        fut = asyncio.get_running_loop().run_in_executor(pool, _call, fn, args)
        try:
            return await asyncio.shield(fut)
        except asyncio.CancelledError:
            # Never let go of the store lock while the worker still uses the store.
            await asyncio.wait({fut})
            raise

    def shutdown(self) -> None:
        if self._authority is not None and hasattr(self._authority, "close"):
            try:
                self._authority.close()
            except Exception:
                pass
        self._store_pool.shutdown(wait=False, cancel_futures=True)
        self._prompt_pool.shutdown(wait=False, cancel_futures=True)

    # --- sessions and connections -------------------------------------------------------------
    async def session_for(self, uid: int) -> Session:
        s = self.sessions.get(uid)
        if s is None:
            s = Session(uid, self.store_cls.open(uid))
            self.sessions[uid] = s
        if not s.settings_loaded:
            s.settings_loaded = True
            try:
                d = await self.run_store(uid, s.store.load_settings, keyless=True)
            except OpError:
                s.settings_loaded = False
                d = {}
            except Exception:
                logger.exception("uid %d: settings unreadable, using defaults", uid)
                d = {}
            s.settings = validate_settings(d or {})
            s.autofill_enabled = (d or {}).get("autofill_enabled") is True
            s.features = validate_features((d or {}).get("features"))
            oc = (d or {}).get("old_copy")
            s.old_copy = oc if isinstance(oc, dict) else None
        return s

    def attach(self, conn) -> None:
        self.conns.add(conn)
        if conn.role == "autofill":
            self.notify_autofill_hosts(conn.uid)

    def detach(self, conn) -> None:
        """A connection is gone (EOF, error, or closed by us)."""
        was = conn in self.conns
        self.conns.discard(conn)
        self.cancel_prompts(conn=conn)
        if was and conn.role == "autofill":
            self.notify_autofill_hosts(conn.uid)
        s = self.sessions.get(conn.uid)
        if s is None:
            return
        if conn.role == "autofill" and s.autofill_conn is conn:
            self.close_autofill(s)                  # the browser's unlock ends with its host
        if conn.role == "ui" and s.ui is conn:
            # EOF on the window locks the uid; there is nobody to tell.
            self.lock(conn.uid, None, notify=False)
            s.ui = None

    def touch(self, conn) -> None:
        if conn.role == "ui":
            s = self.sessions.get(conn.uid)
            if s is not None and s.ui is conn:
                s.last_ui_request = self.clock()

    def active(self) -> bool:
        """Anything that keeps the daemon from exiting when idle."""
        return bool(self.conns) or any(s.unlocked() for s in self.sessions.values())

    # --- tier 1 -------------------------------------------------------------------------------
    def open_tier1(self, s: Session, conn, show_all: bool = False) -> None:
        s.tier1 = conn
        s.show_all = bool(show_all)
        s.autofill_key = secrets.token_bytes(32)   # new handles for every unlock
        s.next_sync_at = None              # the scheduler starts the 2 h clock from here
        s.last_ui_request = self.clock()
        self.notify_autofill(s.uid)

    # --- the browser's own unlock (autofill-names while tier 1 is closed) -----------------------
    def open_autofill(self, s: Session, conn) -> None:
        """The store was unlocked for this autofill connection (an approved .autofill-names
        dialog). It serves that connection only, and locks again AUTOFILL_OPEN_S after the
        connection's last request, when it disconnects, or on any other lock trigger."""
        s.autofill_conn = conn
        if s.autofill_key is None:
            s.autofill_key = secrets.token_bytes(32)
        self.touch_autofill(s, conn)
        self.notify_autofill(s.uid)

    def autofill_open(self, s: Session | None, conn) -> bool:
        return (s is not None and conn is not None and s.autofill_conn is conn
                and not conn.closed and self.clock() < s.autofill_until)

    def touch_autofill(self, s: Session, conn) -> None:
        if s.autofill_conn is not conn:
            return
        s.autofill_until = self.clock() + protocol.AUTOFILL_OPEN_S
        if s.autofill_timer is not None:
            s.autofill_timer.cancel()
        s.autofill_timer = asyncio.get_running_loop().call_later(
            protocol.AUTOFILL_OPEN_S, self._autofill_timeout, s.uid, conn)

    def _autofill_timeout(self, uid: int, conn) -> None:
        s = self.sessions.get(uid)
        if s is None or s.autofill_conn is not conn:
            return
        if self.clock() < s.autofill_until:          # touched since this timer was set
            return
        self.close_autofill(s)

    def close_autofill(self, s: Session) -> None:
        """End the browser's unlock: a full lock unless the window has tier 1 open."""
        if s.autofill_conn is None:
            return
        if s.unlocked():
            self._clear_autofill(s)
        else:
            self.lock(s.uid, "autofill-timeout", notify=False)

    def _clear_autofill(self, s: Session) -> None:
        s.autofill_conn = None
        s.autofill_until = 0.0
        if s.autofill_timer is not None:
            s.autofill_timer.cancel()
            s.autofill_timer = None

    def lock(self, uid: int, reason: str | None, *, notify: bool = True) -> bool:
        """Every lock trigger. Returns whether tier 1 was open."""
        s = self.sessions.get(uid)
        if s is None:
            return False
        was = s.tier1 is not None
        was_autofill = s.autofill_conn is not None
        self._clear_autofill(s)
        s.tier1 = None
        s.show_all = False
        s.autofill_key = None                       # every handle handed out is void
        s.item_shape = None
        s.epoch += 1
        s.next_sync_at = None
        self._drop_grant(uid, event=False)
        self.tickets.revoke_uid(uid)
        self.withdraw(uid)
        self.cancel_prompts(uid=uid)
        if s.signin is not None:
            s.signin.cancel()
        self._wipe_store(s)
        if notify and reason and (was or reason == "user"):
            self.notify_ui(uid, {"event": "locked", "reason": reason})
        if was or was_autofill:
            self.notify_autofill(uid)
            logger.info("uid %d locked (%s)", uid, reason or "window closed")
        return was

    def lock_all(self, reason: str) -> None:
        for uid in list(self.sessions):
            self.lock(uid, reason)

    def _wipe_store(self, s: Session) -> None:
        """Wipe the store's keys without ever waiting on the event loop. If a store call holds
        the store right now, flag wipe-after: run_store wipes when that call returns and
        refuses new calls until then. While a create()/reset() runs (s.replacing) the wipe
        stays pending even when the old object was wiped: the new one is still being built."""
        try:
            try_lock = getattr(s.store, "try_lock", None)
            if try_lock is None:
                s.store.lock()
                done = True
            else:
                done = try_lock()
        except Exception:
            logger.exception("uid %d: store.lock() failed", s.uid)
            return
        if done and not s.replacing:
            s.wipe_after = False
        elif not s.wipe_after:
            s.wipe_after = True
            logger.info("uid %d: a store call is running; its keys are wiped when it returns",
                        s.uid)

    def withdraw(self, uid: int, roles=("clip", "migrate")) -> None:
        for c in list(self.conns):
            if c.uid == uid and c.role in roles and not c.closed:
                if c.role != "autofill":
                    c.send_event({"event": "withdraw"})
                c.close()

    # --- autofill visibility ------------------------------------------------------------------
    def autofill_state(self, s: Session | None) -> str:
        if s is None:
            return "locked"
        if s.unlocked():
            return "unlocked"
        try:
            st = s.store.state()
        except Exception:
            return "unavailable"
        return "unavailable" if st == "empty" or st in protocol.SEAL_STATES else "locked"

    def notify_autofill_hosts(self, uid: int) -> None:
        """The window shows whether a browser autofill host is connected right now."""
        self.notify_ui(uid, {"event": "autofill-hosts",
                             "count": len(self.connections(uid, "autofill"))})

    def notify_autofill(self, uid: int) -> None:
        conns = self.connections(uid, "autofill")
        if not conns:
            return
        state = self.autofill_state(self.sessions.get(uid))
        for c in conns:
            c.send_event({"event": "state", "state": state})

    # --- grants -------------------------------------------------------------------------------
    def put_grant(self, s: Session, id: str, secrets_):
        self._drop_grant(s.uid, event=True)
        g = self.grants.put(s.uid, id, secrets_, s.settings["grant_s"])
        if not g.single_use:
            self._grant_timers[s.uid] = asyncio.get_running_loop().call_later(
                s.settings["grant_s"], self._grant_timeout, s.uid, g)
        return g

    def _grant_timeout(self, uid: int, g) -> None:
        if self.grants.current(uid) is g:
            self.end_grant(uid)

    def end_grant(self, uid: int) -> None:
        """The grant ran out (timer or single use)."""
        self._cancel_timer(uid)
        gid = self.grants.end(uid)
        if gid is not None:
            after_reply(lambda: self.notify_ui(uid, {"event": "grant-expired", "id": gid}))

    def _drop_grant(self, uid: int, *, event: bool) -> None:
        self._cancel_timer(uid)
        gid = self.grants.drop(uid)
        if gid is not None and event:
            after_reply(lambda: self.notify_ui(uid, {"event": "grant-expired", "id": gid}))

    def release_grant(self, uid: int) -> None:
        self._drop_grant(uid, event=True)

    def _cancel_timer(self, uid: int) -> None:
        h = self._grant_timers.pop(uid, None)
        if h is not None:
            h.cancel()

    def grant_check(self, uid: int, id: str):
        """The live grant on `id` (OpError no-grant / grant-expired). A grant past its time
        is ended here, with its event, even if its timer has not fired yet."""
        self.check_grant_expiry()
        return self.grants.check(uid, id)

    def grant_use(self, uid: int, id: str):
        self.check_grant_expiry()
        return self.grants.use(uid, id)

    def check_grant_expiry(self) -> None:
        """Catch-up for timers that fire late (a suspended machine)."""
        for uid, _ in self.grants.due():
            self.end_grant(uid)

    # --- dialogs ------------------------------------------------------------------------------
    def cancel_prompts(self, *, uid: int | None = None, conn=None, rid=None,
                       action: str | None = None) -> int:
        n = 0
        for key, p in list(self._pending.items()):
            if uid is not None and p.conn.uid != uid:
                continue
            if conn is not None and p.conn is not conn:
                continue
            if rid is not None and p.rid != rid:
                continue
            if action is not None and p.action != action:
                continue
            self._cancel(p)
            n += 1
        return n

    def _cancel(self, p: _Pending) -> None:
        if p.cancelled:
            return
        p.cancelled = True
        if self._pending.get(p.key) is p:
            del self._pending[p.key]
        try:
            self._prompt_pool.submit(self._cancel_call, p.cancel_id)
        except RuntimeError:                  # pool shut down at exit
            pass

    def _cancel_call(self, cancel_id: str) -> None:
        try:
            self.authority.cancel(cancel_id)
        except Exception:
            logger.debug("cancel raised", exc_info=True)

    def prompt_pending(self, uid: int, bucket: str) -> bool:
        return (uid, bucket) in self._pending

    def new_conn_id(self) -> int:
        return next(self._conn_ids)
