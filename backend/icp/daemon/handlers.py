"""Every op of the `ui`, `clip` and `migrate` roles (docs/protocol.md 6-8), the hello replies,
the background sync, and the dispatch table the server calls.

Each handler is `await handler(registry, conn, req)` and returns the reply payload without its
rid, or raises OpError. The two autofill ops are the autofill host's (daemon/autofill.py); they are reached
through thin wrappers here so that module is imported only when a browser first asks.

Rules every handler keeps:
- A dialog is raised only through registry.authorize(), and only by the ops in
  protocol.PROMPT_ACTION. The checks that can fail without a dialog run before it, and the
  state a dialog was raised for is checked again after it (a lock may have landed meanwhile).
- Secrets leave the daemon only in the reply of reveal, history and redeem, and in nothing
  that is logged.
- Events a request causes are sent after its reply (sessions.after_reply).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import functools
import hashlib
import logging
import time
import math
import re
import unicodedata

from .. import vstore
from ..keychain import tagline
from . import paths, protocol, wire
from .context import NeedsLogin, UserContext
from .frontend import SocketFrontend
from .grants import wipe_secrets
from .protocol import OpError
from .sessions import WorkerCancelled, after_reply, setting_ok, spawn
from .tickets import TicketError

logger = logging.getLogger(__name__)

VERSION = "2.0.3"

_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
MAX_PASSWORD = 1024
MAX_NOTES = 16 * 1024
MAX_TEXT = 256
MAX_SITES = 32
MAX_CHECK_ITEMS = 1000
MAX_CHECK_ITEM = 1024
MAX_PASSPHRASE = 1024
SYNC_FAILED_REASONS = ("anisette-unavailable", "network", "needs-login", "apple")


# --- small helpers --------------------------------------------------------------------------

def _hello_base() -> dict:
    return {"proto": protocol.PROTO, "version": VERSION}


def _need(req: dict, key: str, typ, *, optional: bool = False, default=None):
    if key not in req:
        if optional:
            return default
        raise OpError("bad-request")
    value = req[key]
    if typ is int and (isinstance(value, bool) or not isinstance(value, int)):
        raise OpError("bad-request")
    if not isinstance(value, typ):
        raise OpError("bad-request")
    return value


def _need_id(req: dict) -> str:
    value = _need(req, "id", str)
    if not wire.valid_id(value):
        raise OpError("not-found")
    return value


def _session(reg, conn):
    s = reg.get(conn.uid)
    if s is None:
        raise OpError("internal")
    return s


def _tier1(reg, conn):
    """The session, if tier 1 is open on exactly this connection."""
    s = _session(reg, conn)
    if not s.unlocked() or s.tier1 is not conn:
        raise OpError("locked")
    return s


def _still(s, conn, epoch: int) -> None:
    """After an await: nothing locked the uid and this is still its tier-1 window."""
    if s.epoch != epoch or not s.unlocked() or s.tier1 is not conn:
        raise OpError("locked")


def _detail(text) -> str:
    return " ".join(_CONTROL_RE.sub(" ", str(text)).split())[:200]


def _store_error(e: BaseException) -> OpError | None:
    if isinstance(e, OpError):
        return e
    if isinstance(e, WorkerCancelled):
        return OpError("cancelled")
    if isinstance(e, vstore.StoreLocked):
        return OpError("locked")
    if isinstance(e, vstore.EntryNotFound):
        return OpError("not-found")
    if isinstance(e, vstore.SealError):
        return OpError(e.kind)
    from ..vstore.seal import SealRefused, SealUnavailable
    if isinstance(e, SealRefused):
        # Sealing worked but bound the keys to something Pear refuses (a signed PCR policy,
        # or a key type it does not know). Not transient: the window says what it is.
        return OpError("seal-refused", reason=e.reason)
    if isinstance(e, SealUnavailable):
        # systemd-creds (or the seal service) could not run at all: says nothing about the
        # blobs, so it is never reported as a seal state. Try again later.
        return OpError("seal-unavailable")
    return None


async def _store(reg, uid: int, fn, *args, keyless: bool = False, replaces: bool = False):
    try:
        if replaces:
            return await reg.run_store(uid, fn, *args, replaces=True)
        return await reg.run_store(uid, fn, *args, keyless=keyless)
    except Exception as e:
        err = _store_error(e)
        if err is None:
            logger.exception("uid %d: store call %s failed", uid, getattr(fn, "__name__", fn))
            raise OpError("internal") from None
        raise err from None


async def _replace_store(reg, s, conn, make) -> int:
    """s.store = make(uid), where make is create() or reset(): a new store object that comes
    back unlocked. A lock that lands while it runs (sleep, logind Lock, the Lock button, the
    window closing) cannot reach that object through s.store; run_store wipes it, and here the
    op ends instead of opening tier 1 on it (round 2 audit, problem 2). Returns the epoch the
    caller checks again (_not_locked_since) before it opens tier 1 after further awaits."""
    epoch = s.epoch
    new = await _store(reg, conn.uid, make, conn.uid, replaces=True)
    s.store = new                      # the store on disk now, whatever happens next
    _not_locked_since(reg, s, conn, epoch)
    return epoch


def _not_locked_since(reg, s, conn, epoch: int) -> None:
    """Before opening tier 1 on a store this op made: nothing locked the uid since `epoch`
    and this is still its window. Otherwise wipe the store and end the op."""
    if s.epoch != epoch or conn.closed or s.ui is not conn:
        reg._wipe_store(s)
        raise OpError("cancelled")


def apple_error(e: BaseException) -> OpError:
    """Map whatever the Apple pipeline raised to a protocol error (docs/protocol.md 6.6)."""
    err = _store_error(e)
    if err is not None:
        return err
    if isinstance(e, NeedsLogin):
        return OpError("needs-login")
    from ..errors import AppleError
    from .apple import FieldError, NotSignedIn
    if isinstance(e, NotSignedIn):
        return OpError("not-signed-in")
    if isinstance(e, FieldError):
        extra = {"detail": _detail(e.detail)[:64]} if getattr(e, "detail", "") else {}
        return OpError("invalid", field=_detail(e.field)[:64], **extra)
    try:
        from ..auth.anisette import AnisetteError
        if isinstance(e, AnisetteError):
            return OpError("anisette-unavailable")
    except ImportError:                             # pragma: no cover - requests missing
        pass
    try:
        import requests
        if isinstance(e, requests.RequestException):
            return OpError("network")
    except ImportError:                             # pragma: no cover
        pass
    if isinstance(e, (ConnectionError, TimeoutError)):
        return OpError("network")
    if isinstance(e, AppleError):
        return OpError("apple", detail=_detail(e))
    logger.error("Apple call failed: %s", type(e).__name__, exc_info=e)
    return OpError("internal")


async def _apple_call(reg, s, fn, *args):
    try:
        return await reg.run_store(s.uid, fn, *args)
    except Exception as e:
        err = apple_error(e)
        if err.code == "needs-login":
            await _mark_needs_login(reg, s)
        raise err from None


async def _mark_needs_login(reg, s) -> None:
    try:
        await reg.run_store(s.uid, lambda: s.store.set_sync_status(needs_login=True))
    except Exception:
        logger.debug("uid %d: could not record needs_login", s.uid, exc_info=True)
    after_reply(lambda: reg.notify_ui(s.uid, {"event": "needs-login"}))


async def _wire_list(reg, s) -> tuple[list, dict]:
    metas = await _store(reg, s.uid, s.store.list_meta)
    st = await _store(reg, s.uid, s.store.status)
    return wire.entries(metas, s.show_all, s.features), st


def _where_is(metas, entries, id: str) -> str:
    """Where one entry stands, for the journal: booleans and an id prefix, never a value."""
    m = next((m for m in metas if m.id == id), None)
    listed = any(e.get("id") == id for e in entries)
    if m is None:
        return f"{id[:12]}…: not in the store"
    w = wire.meta_to_wire(m, None)
    return (f"{id[:12]}…: in the store, listed={listed}, deleted={bool(getattr(m, 'deleted', False))}, "
            f"visible={wire.visible(m, None)}, internal={wire.is_internal(w)}")


def _notify_list_after(reg, s, watch: str | None = None) -> None:
    """After an edit: send the fresh list as a `synced` event once the reply has gone. `watch`
    is an entry the edit created; where it stands goes to the journal."""
    epoch = s.epoch

    async def send():
        if s.epoch != epoch or not s.unlocked():
            return
        try:
            entries, st = await _wire_list(reg, s)
        except OpError:
            return
        if watch:
            metas = await _store(reg, s.uid, s.store.list_meta)
            logger.info("uid %d: after create, %d listed; %s", s.uid, len(entries),
                        _where_is(metas, entries, watch))
        if s.epoch == epoch and s.unlocked():
            reg.notify_ui(s.uid, {"event": "synced", "entries": entries,
                                  "synced_at": st.get("synced_at"),
                                  "counts": {"added": 0, "changed": 0, "deleted": 0,
                                             "unchanged": len(entries)},
                                  "features": dict(s.features)})
    after_reply(lambda: spawn(send()))


def _totp_now(reg, secrets_) -> tuple[str, float, int]:
    from .. import totp
    params = getattr(secrets_, "totp_params", None) or {}
    period = int(params.get("period") or totp.DEFAULT_PERIOD)
    now = reg.wall()
    code = totp.code(secrets_.totp_secret, digits=int(params.get("digits") or 6),
                     period=period, algorithm=int(params.get("algorithm") or 0), at=now)
    return code, (math.floor(now / period) + 1) * period, period


def _clean_text(value, field: str, max_len: int, *, allow_newlines: bool = False) -> str:
    if not isinstance(value, str):
        raise OpError("bad-request")
    if len(value) > max_len or "\x00" in value:
        raise OpError("invalid", field=field)
    if not allow_newlines and _CONTROL_RE.search(value):
        raise OpError("invalid", field=field)
    return value


def _clean_host(value, field: str) -> str:
    if not isinstance(value, str):
        raise OpError("bad-request")
    host = value.strip().lower()
    if not _HOST_RE.match(host):
        raise OpError("invalid", field=field)
    return host


def validate_fields(fields: dict, generate, allowed: frozenset) -> dict:
    """The `fields` (and `generate`) of set or create, checked and normalized."""
    if not isinstance(fields, dict):
        raise OpError("bad-request")
    if generate is not None and not isinstance(generate, dict):
        raise OpError("bad-request")
    out: dict = {}
    for key, value in fields.items():
        if key not in allowed:
            raise OpError("invalid", field=str(key)[:64])
        if key == "password":
            v = _clean_text(value, key, MAX_PASSWORD, allow_newlines=True)
            if not v:
                raise OpError("invalid", field=key)
            out[key] = v
        elif key == "notes":
            out[key] = _clean_text(value, key, MAX_NOTES, allow_newlines=True)
        elif key in ("nickname", "title", "username"):
            out[key] = _clean_text(value, key, MAX_TEXT).strip()
        elif key == "domain":
            out[key] = "" if value == "" else _clean_host(value, key)
        elif key == "sites":
            if not isinstance(value, list) or len(value) > MAX_SITES:
                raise OpError("invalid", field=key)
            out[key] = [_clean_host(v, key) for v in value]
        elif key == "totp":
            out[key] = _clean_totp(value)
        elif key == "tags":
            try:
                out[key] = tagline.canon_list(value)
            except ValueError:
                raise OpError("invalid", field=key) from None
    if generate is not None:
        if "password" in out:
            raise OpError("invalid", field="generate")
        from ..vault.generate import generate as make_password
        out["password"] = make_password()
    return out


def _clean_totp(value) -> dict:
    if not isinstance(value, dict):
        raise OpError("bad-request")
    if value.get("remove") is True and "setup" not in value:
        return {"remove": True}
    setup = value.get("setup")
    if not isinstance(setup, str) or len(setup) > 4096:
        raise OpError("invalid", field="totp")
    from .. import totp
    try:
        totp.parse_setup(setup)
    except totp.SetupError:
        raise OpError("invalid", field="totp") from None
    return {"setup": setup}


# --- hello ------------------------------------------------------------------------------------

async def hello(reg, conn, req: dict) -> dict:
    """The reply to a verified hello whose role the server already set on `conn`."""
    s = await reg.session_for(conn.uid)
    if conn.role == "ui":
        if s.ui is not None and not s.ui.closed:
            s.ui.send_event({"event": "focus"})
            raise OpError("already-running")
        if s.tier1 is not None:
            reg.lock(conn.uid, None, notify=False)
        s.ui = conn
        st = await _store(reg, conn.uid, s.store.status, keyless=True)
        state = st.get("state") or "locked"
        if state == "unlocked":            # never: the last window's EOF locked the uid
            reg.lock(conn.uid, None, notify=False)
            state = "locked"
        oc = s.old_copy
        # A migrate-begin whose import never committed: the window offers the move again
        # instead of unlocking an empty store and signing in afresh.
        pending = state != "empty" and await _migration_pending(reg, s)
        return {**_hello_base(), "state": state, "signed_in": bool(st.get("signed_in")),
                "migration_pending": bool(pending),
                "sealed_with": st.get("sealed_with"), "synced_at": None, "needs_login": None,
                "settings": dict(s.settings),
                "autofill": {"enabled": bool(s.autofill_enabled),
                             "hosts": len(reg.connections(conn.uid, "autofill"))},
                "old_copy": ({"dir": oc.get("dir"), "migrated_at": oc.get("migrated_at")}
                             if oc else None)}
    if conn.role in protocol.TICKET_ROLES:
        try:
            t = reg.tickets.redeem(req.get("ticket"), uid=conn.uid, role=conn.role,
                                   ppid=conn.ppid, parent_start_time=reg.parent_start_time)
        except TicketError as e:
            logger.warning("uid %d: %s hello refused: %s", conn.uid, conn.role, e)
            raise OpError("bad-ticket") from None
        if t.ui_conn is not s.ui:
            t.wipe()
            raise OpError("bad-ticket")
        conn.ticket = t
        if conn.role == "clip":
            return {**_hello_base(), "purpose": "copy"}
        if t.purpose == "purge":
            return {**_hello_base(), "purpose": "purge", "files": list(t.extra.get("files", [])),
                    "dir": t.extra.get("dir")}
        return {**_hello_base(), "purpose": "import"}
    if conn.role == "autofill":
        # Opt-in, enforced here: `pear-passwords-autofill register` only writes a browser
        # manifest, and pear-exec runs the autofill role for any program of yours. Until the
        # user turns autofill on in the window (behind .manage), no autofill host is served.
        if not s.autofill_enabled:
            raise OpError("forbidden")
        if len(reg.connections(conn.uid, "autofill")) >= protocol.MAX_AUTOFILL_CONNS:
            raise OpError("too-many")
        return {**_hello_base(), "state": reg.autofill_state(s)}
    raise OpError("forbidden")


# --- sync --------------------------------------------------------------------------------------

async def background_sync(reg, uid: int) -> str:
    """One sync for an unlocked uid; never prompts. Returns what happened, for the log and the
    scheduler: synced, locked, running, signed-out or failed."""
    s = reg.get(uid)
    if s is None or not s.unlocked():
        logger.info("uid %d: locked: skipped", uid)
        return "locked"
    if s.busy:
        return "running"
    s.busy = "sync"
    epoch = s.epoch
    try:
        st = await reg.run_store(uid, s.store.status)
        if not st.get("signed_in"):
            return "signed-out"
        if st.get("needs_login"):
            # Apple already asked for a person and the window already says so (hello, unlock
            # and the first needs-login event). Each later tick stands down quietly instead
            # of re-announcing it every 2 h; only a sign-in clears the latch.
            logger.info("uid %d: needs login: skipped", uid)
            return "needs-login"
        ctx = UserContext(uid, s.store, reg.anisette_url, None)
        try:
            counts = await reg.run_store(uid, reg.apple.sync, ctx) or {}
        except Exception as e:
            err = apple_error(e)
            if s.epoch != epoch:
                return "locked"
            reason = err.code if err.code in SYNC_FAILED_REASONS else "apple"
            if reason == "needs-login":
                await _mark_needs_login(reg, s)
            logger.info("uid %d: sync failed: %s", uid, reason)
            event = {"event": "sync-failed", "reason": reason}
            if err.extra.get("detail"):
                event["detail"] = err.extra["detail"]
            reg.notify_ui(uid, event)
            return "failed"
        if s.epoch != epoch or not s.unlocked():
            return "locked"
        if ctx.item_shape is not None:
            s.item_shape = ctx.item_shape
        metas = await reg.run_store(uid, s.store.list_meta)
        st = await reg.run_store(uid, s.store.status)
        if s.epoch != epoch or not s.unlocked():
            return "locked"
        listed = wire.entries(metas, s.show_all, s.features)
        hidden_flag = sum(1 for m in metas if not wire.visible(m, s.features))
        hidden_internal = sum(1 for m in metas if wire.visible(m, s.features)
                              and wire.is_internal(wire.meta_to_wire(m, s.features)))
        logger.info("uid %d: sync: added %d, changed %d, deleted %d, unchanged %d; %d in the store, "
                    "%d listed (%d waiting for a feature flag, %d Apple-internal)", uid,
                    *(int(counts.get(k, 0) or 0) for k in ("added", "changed", "deleted", "unchanged")),
                    len(metas), len(listed), hidden_flag, hidden_internal)
        for cid in getattr(s, "created_ids", None) or ():
            logger.info("uid %d: created this run: %s", uid, _where_is(metas, listed, cid))
        # Entries changed in the last 3 days that the list hides, and which rule hides them:
        # an id prefix, the rule and the time only.
        recent = time.time() - 3 * 86400
        shown = {e.get("id") for e in listed}
        for m in metas:
            if m.id in shown or float(m.mdat or 0) < recent:
                continue
            why = ("feature flag" if not wire.visible(m, s.features)
                   else wire.internal_reason(wire.meta_to_wire(m, s.features)) or "?")
            logger.info("uid %d: hidden %s… (%s), changed %s", uid, m.id[:12], why,
                        time.strftime("%Y-%m-%d %H:%M", time.localtime(float(m.mdat))))
        reg.notify_ui(uid, {
            "event": "synced", "entries": listed,
            "synced_at": counts.get("synced_at", st.get("synced_at")),
            "counts": {k: int(counts.get(k, 0) or 0)
                       for k in ("added", "changed", "deleted", "unchanged")},
            "features": dict(s.features)})
        return "synced"
    except Exception:
        logger.exception("uid %d: sync failed", uid)
        return "failed"
    finally:
        s.busy = None


def _sync_after_reply(reg, uid: int) -> None:
    after_reply(lambda: spawn(background_sync(reg, uid)))


# --- ui: tier 1 ---------------------------------------------------------------------------------

async def op_unlock(reg, conn, req):
    s = _session(reg, conn)
    show_all = _need(req, "all", bool, optional=True, default=False)
    if s.unlocked() and s.tier1 is conn:
        s.show_all = show_all
        return await _unlocked_reply(reg, s)
    if s.ui is not conn:
        raise OpError("forbidden")
    if s.wipe_after:
        # The last lock is still waiting for a store call to return; no dialog until then.
        raise OpError("seal-unavailable")
    state = await _store(reg, conn.uid, s.store.state)
    if state == "empty":
        return {"locked": True, "reason": "empty"}
    try:
        await reg.authorize(conn, paths.ACTION_UNLOCK, {})
    except OpError as e:
        if e.code in protocol.UNLOCK_REFUSALS:
            return {"locked": True, "reason": e.code, **e.extra}
        raise
    epoch = s.epoch
    try:
        await reg.run_store(conn.uid, s.store.unlock)
    except vstore.SealError as e:
        return {"locked": True, "reason": e.kind}
    except Exception as e:
        err = _store_error(e)
        if err is None:
            logger.exception("uid %d: unlock failed", conn.uid)
            raise OpError("internal") from None
        raise err from None
    if s.epoch != epoch or conn.closed or s.ui is not conn:
        reg._wipe_store(s)
        raise OpError("cancelled")
    # No automatic move onto the TPM here: that rotation opens every entry, so it waits for
    # its own button and .manage dialog (op tpm-move). The window is only told it can.
    try:
        tpm_move = await reg.run_store(conn.uid, s.store.tpm_move_state) == "available"
    except Exception:
        logger.debug("uid %d: TPM state unknown", conn.uid, exc_info=True)
        tpm_move = False
    if s.epoch != epoch or conn.closed:
        reg._wipe_store(s)
        raise OpError("cancelled")
    reg.open_tier1(s, conn, show_all)
    reply = await _unlocked_reply(reg, s)
    reply["tpm_move"] = tpm_move
    _sync_after_reply(reg, conn.uid)
    return reply


async def op_tpm_move(reg, conn, req):
    """"Move your keys onto the security chip": the one-time rotation to new keys sealed with
    host+tpm2 (UserStore.reseal_if_tpm_available), only on a click and behind .manage."""
    s = _tier1(reg, conn)
    state = await _store(reg, conn.uid, s.store.tpm_move_state)
    if state == "pcr-policy":
        raise OpError("seal-refused", reason="pcr-policy")
    if state != "available":
        raise OpError("invalid", field="tpm")
    if s.busy:
        raise OpError("busy-sync")
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    _still(s, conn, epoch)
    if s.busy:
        raise OpError("busy-sync")
    s.busy = "edit"
    try:
        moved = await _store(reg, conn.uid, s.store.reseal_if_tpm_available)
    finally:
        s.busy = None
    if not moved:
        # The rotation did not verify, or the TPM refused: nothing changed (logged).
        raise OpError("seal-unavailable")
    logger.info("uid %d: keys moved onto the TPM", conn.uid)
    return {"sealed_with": "host+tpm2"}


async def _unlocked_reply(reg, s) -> dict:
    entries, st = await _wire_list(reg, s)
    return {"entries": entries, "synced_at": st.get("synced_at"),
            "needs_login": bool(st.get("needs_login")), "features": dict(s.features)}


async def op_lock(reg, conn, req):
    reg.lock(conn.uid, "user", notify=False)
    after_reply(lambda: reg.notify_ui(conn.uid, {"event": "locked", "reason": "user"}))
    return {"locked": True}


async def op_release(reg, conn, req):
    reg.release_grant(conn.uid)
    reg.cancel_prompts(conn=conn, action=paths.ACTION_REVEAL)
    return {"released": True}


async def op_cancel(reg, conn, req):
    target = _need(req, "target", int)
    n = reg.cancel_prompts(conn=conn, rid=target)
    s = reg.get(conn.uid)
    fe = s.signin if s is not None else None
    if fe is not None and fe.conn is conn and fe.rid == target and not fe.cancelled:
        fe.cancel()
        n += 1
    return {"cancelled": n > 0}


# --- ui: one entry ----------------------------------------------------------------------------

async def op_grant(reg, conn, req):
    id = _need_id(req)
    s = _tier1(reg, conn)
    meta = await _store(reg, conn.uid, s.store.get_meta, id)
    reg.release_grant(conn.uid)
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_REVEAL, {"account": wire.account_label(meta)})
    _still(s, conn, epoch)
    secrets_ = await _store(reg, conn.uid, s.store.open_entry, id)
    if s.epoch != epoch or not s.unlocked():
        raise OpError("locked")
    g = reg.put_grant(s, id, secrets_)
    fields = ["password"] if getattr(meta, "has_password", True) else []
    if meta.has_notes:                       # the body, without the tag line
        fields.append("notes")
    if meta.has_totp:
        fields.append("code")
    if meta.history_count:
        fields.append("history")
    return {"id": id, "expires": g.expires_wall, "grant_s": s.settings["grant_s"],
            "single_use": g.single_use, "fields": fields}


def _notes_body(secrets_) -> str:
    return tagline.split(getattr(secrets_, "notes", "") or "")[0]


def _use_grant(reg, s, id):
    """The live grant on `id`; ended is True when this use spent a single-use grant."""
    return reg.grant_use(s.uid, id)


async def op_reveal(reg, conn, req):
    id = _need_id(req)
    field = _need(req, "field", str)
    if field not in protocol.REVEAL_FIELDS:
        raise OpError("invalid", field="field")
    s = _tier1(reg, conn)
    g, ended = _use_grant(reg, s, id)
    # Notes are the body: the tag line is list metadata and reaches the window as `tags`.
    value = g.secrets.password if field == "password" else _notes_body(g.secrets)
    if ended:
        reg.end_grant(conn.uid)
    return {"id": id, "field": field, "value": value,
            "hide_after": protocol.REVEAL_HIDE_AFTER_S}


async def op_totp(reg, conn, req):
    id = _need_id(req)
    s = _tier1(reg, conn)
    g = reg.grant_check(conn.uid, id)
    if not g.secrets.totp_secret:
        raise OpError("invalid", field="id")
    g, ended = _use_grant(reg, s, id)
    code, valid_until, _ = _totp_now(reg, g.secrets)
    if ended:
        reg.end_grant(conn.uid)
    return {"id": id, "code": code, "valid_until": valid_until}


async def op_history(reg, conn, req):
    id = _need_id(req)
    s = _tier1(reg, conn)
    g, ended = _use_grant(reg, s, id)
    apple = {(h.get("date"), h.get("value")) for h in (g.secrets.apple_history or [])
             if isinstance(h, dict)}
    if ended:
        reg.end_grant(conn.uid)
    epoch = s.epoch
    items = await _store(reg, conn.uid, s.store.history, id)
    _still(s, conn, epoch)
    # The read ran in a worker: a release or another account's grant may have landed since.
    # A spent single-use grant was this read itself; anything else must still be that grant.
    if not ended and reg.grants.current(conn.uid) is not g:
        items = None
        raise OpError("no-grant")
    # The store labels each item (vstore.entries.HistoryItem.source); a store that returns
    # plain (date, value) tuples falls back to matching the grant's copy of Apple's history.
    out = []
    for item in items:
        d, v = item
        src = getattr(item, "source", None)
        if src not in ("apple", "local"):
            src = "apple" if (d, v) in apple else "local"
        out.append({"date": d, "value": v, "source": src})
    return {"id": id, "items": out}


async def op_copy(reg, conn, req):
    id = _need_id(req)
    field = _need(req, "field", str)
    if field not in protocol.COPY_FIELDS:
        raise OpError("invalid", field="field")
    s = _tier1(reg, conn)
    if field in protocol.COPY_FIELDS_NEED_GRANT:
        g = reg.grant_check(conn.uid, id)
        if field == "code":
            if not g.secrets.totp_secret:
                raise OpError("invalid", field="field")
            value = _totp_now(reg, g.secrets)[0]
        elif field == "password":
            value = g.secrets.password
        else:
            value = _notes_body(g.secrets)
        _, ended = _use_grant(reg, s, id)
        if ended:
            reg.end_grant(conn.uid)
    else:
        epoch = s.epoch
        meta = await _store(reg, conn.uid, s.store.get_meta, id)
        _still(s, conn, epoch)
        value = meta.username if field == "username" else meta.domain
    # One offer at a time: a new copy withdraws the previous one.
    reg.tickets.revoke_uid(conn.uid, role="clip")
    reg.withdraw(conn.uid, roles=("clip",))
    token = reg.tickets.issue(uid=conn.uid, role="clip", purpose="copy", ui_conn=conn, id=id,
                              field=field, value=value or "",
                              sensitive=field in protocol.COPY_FIELDS_SENSITIVE)
    return {"ticket": token, "ttl": protocol.TICKET_TTL_S}


async def op_copy_text(reg, conn, req):
    """Selected text in one of the window's secret fields (Ctrl+C, the context menu's Copy),
    put on the clipboard through pear-clip like `copy`, so it never lands on the persistent
    clipboard or in its history.

    No dialog: the text is already in the window, so a prompt would protect nothing and would
    make Copy unusable. The guard is the fixed list of sources, a live grant on the entry for
    the edit fields (checked, never consumed: nothing is read from the store), the length,
    and COPY_TEXT_PER_MIN per uid. The text is held only in the ticket; it is never stored,
    logged or MACed."""
    source = _need(req, "source", str)
    text = _need(req, "text", str)
    s = _tier1(reg, conn)
    if source not in protocol.COPY_TEXT_SOURCES:
        raise OpError("invalid", field="source")
    id = None
    if source in protocol.COPY_TEXT_SOURCES_GRANT:
        id = _need_id(req)
    elif "id" in req:
        raise OpError("invalid", field="id")
    text = unicodedata.normalize("NFC", text)
    if not 1 <= len(text) <= protocol.COPY_TEXT_MAX or "\x00" in text:
        raise OpError("invalid", field="text")
    if id is not None:
        reg.grant_check(conn.uid, id)
    now = reg.clock()
    times = s.copy_texts
    while times and now - times[0] >= 60:
        times.popleft()
    if len(times) >= protocol.COPY_TEXT_PER_MIN:
        raise OpError("rate-limited", retry_after=max(1, math.ceil(60 - (now - times[0]))))
    times.append(now)
    # One offer at a time, as for copy: a new one withdraws the previous one.
    reg.tickets.revoke_uid(conn.uid, role="clip")
    reg.withdraw(conn.uid, roles=("clip",))
    token = reg.tickets.issue(uid=conn.uid, role="clip", purpose="copy", ui_conn=conn, id=id,
                              field="text", value=text, sensitive=True)
    return {"ticket": token, "ttl": protocol.TICKET_TTL_S}


async def op_set(reg, conn, req):
    id = _need_id(req)
    fields = _need(req, "fields", dict)
    generate = req.get("generate")
    clean = validate_fields(fields, generate, protocol.SET_FIELDS)
    s = _tier1(reg, conn)
    reg.grant_check(conn.uid, id)
    # A Recently Deleted copy and a passkey-only row are read-only: nothing to push them to.
    epoch = s.epoch
    meta = await _store(reg, conn.uid, s.store.get_meta, id)
    _still(s, conn, epoch)
    if getattr(meta, "recently_deleted", False) or getattr(meta, "kind", "login") == "passkey":
        raise OpError("invalid", field="id")
    # A Wi-Fi network has no details record (the WiFi zone keeps none), so its notes, and the
    # tags that live in them, its websites and its code have nowhere to go.
    if (getattr(meta, "domain", "") or "") == "AirPort":
        for key in ("tags", "notes", "sites", "totp"):
            if key in clean:
                raise OpError("invalid", field=key)
    reg.grant_check(conn.uid, id)
    if s.busy:
        raise OpError("busy-sync")
    g, ended = _use_grant(reg, s, id)
    # A rename goes to iCloud like any other field: apple.push_set writes it to the entry's
    # details record when it has one (so it reaches every device) and keeps it as a local
    # nickname otherwise, as 1.x did. Without an iCloud session a rename alone stays local.
    push = dict(clean)
    synced = True
    s.busy = "edit"
    try:
        signed_in = bool((await _store(reg, conn.uid, s.store.status) or {}).get("signed_in"))
        if set(clean) == {"nickname"} and not signed_in:
            push = {}
            names = dict(await _store(reg, conn.uid, s.store.load_nicknames) or {})
            if clean["nickname"]:
                names[id] = clean["nickname"]
            else:
                names.pop(id, None)
            await _store(reg, conn.uid, s.store.save_nicknames, names)
            synced = False
        if push:
            ctx = UserContext(conn.uid, s.store, reg.anisette_url, None)
            await _apple_call(reg, s, reg.apple.push_set, ctx, id, push)
            if set(clean) == {"nickname"} and clean["nickname"]:
                # push_set keeps the name locally when Apple had nowhere to put it.
                names = await _store(reg, conn.uid, s.store.load_nicknames) or {}
                synced = id not in names
    finally:
        s.busy = None
    if ended:
        reg.end_grant(conn.uid)
    elif push and set(push) != {"nickname"} and s.epoch == epoch \
            and reg.grants.current(conn.uid) is g:
        # The grant stays on this entry; its buffer now holds what iCloud has.
        fresh = await _store(reg, conn.uid, s.store.open_entry, id)
        if reg.grants.current(conn.uid) is g and s.epoch == epoch:
            fresh, g.secrets = g.secrets, fresh
        wipe_secrets(fresh)
    _notify_list_after(reg, s)
    return {"id": id, "synced": synced}


async def op_create(reg, conn, req):
    fields = _need(req, "fields", dict)
    generate = req.get("generate")
    clean = validate_fields(fields, generate, protocol.CREATE_FIELDS)
    if "password" not in clean:
        raise OpError("invalid", field="password")
    s = _tier1(reg, conn)
    if s.busy:
        raise OpError("busy-sync")
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    _still(s, conn, epoch)
    if s.busy:
        raise OpError("busy-sync")
    s.busy = "edit"
    try:
        ctx = UserContext(conn.uid, s.store, reg.anisette_url, None)
        new_id = await _apple_call(reg, s, reg.apple.create, ctx, clean)
    finally:
        s.busy = None
    if isinstance(new_id, str):
        created = getattr(s, "created_ids", None)
        if created is None:
            created = s.created_ids = []
        created.append(new_id)
    _notify_list_after(reg, s, watch=new_id if isinstance(new_id, str) else None)
    return {"id": new_id}


async def op_delete(reg, conn, req):
    id = _need_id(req)
    s = _tier1(reg, conn)
    meta = await _store(reg, conn.uid, s.store.get_meta, id)
    # Read-only rows, as in op_set. A Recently Deleted copy keeps the live account's domain and
    # username, so a delete would remove the LIVE login. Refused before any dialog.
    if getattr(meta, "recently_deleted", False) or getattr(meta, "kind", "login") == "passkey":
        raise OpError("invalid", field="id")
    # A Wi-Fi network lives in the WiFi zone, which delete_entry does not touch.
    if (getattr(meta, "domain", "") or "") == "AirPort":
        raise OpError("invalid", field="id")
    if s.busy:
        raise OpError("busy-sync")
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    _still(s, conn, epoch)
    if s.busy:
        raise OpError("busy-sync")
    s.busy = "edit"
    try:
        ctx = UserContext(conn.uid, s.store, reg.anisette_url, None)
        await _apple_call(reg, s, reg.apple.delete, ctx, id)
    finally:
        s.busy = None
    g = reg.grants.current(conn.uid)
    if g is not None and g.id == id:
        reg.release_grant(conn.uid)
    _notify_list_after(reg, s)
    return {"deleted": True}


async def op_totp_preview(reg, conn, req):
    setup = _need(req, "setup", str)
    _tier1(reg, conn)
    if len(setup) > 4096:
        raise OpError("invalid", field="setup")
    from .. import totp
    try:
        cfg = totp.parse_setup(setup)
    except totp.SetupError:
        raise OpError("invalid", field="setup") from None
    now = reg.wall()
    code = totp.code(cfg["secret"], digits=cfg["digits"], period=cfg["period"],
                     algorithm=cfg["algorithm"], at=now)
    return {"code": code, "seconds": totp.seconds_remaining(cfg["period"], at=now),
            "issuer": cfg.get("issuer", ""), "account": cfg.get("accountName", "")}


# --- ui: sign-in --------------------------------------------------------------------------------

async def op_signin(reg, conn, req):
    mode = _need(req, "mode", str)
    if mode not in ("login", "relogin"):
        raise OpError("invalid", field="mode")
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    if s.busy:
        raise OpError("busy-sync")
    st = await _store(reg, conn.uid, s.store.status)
    fresh = False
    if mode == "login":
        if st.get("state") == "empty":
            fresh = True
        elif await _migration_pending(reg, s):
            # Signing in over an import that never committed would join escrow afresh and
            # leave the 1.x history behind; the window offers the move again instead.
            raise OpError("migration-pending")
        elif not (s.unlocked() and s.tier1 is conn):
            raise OpError("locked")
        elif st.get("signed_in"):
            raise OpError("invalid", field="mode")
    else:
        if not (s.unlocked() and s.tier1 is conn):
            raise OpError("locked")
        if not st.get("signed_in"):
            raise OpError("not-signed-in")
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    if conn.closed or s.ui is not conn or s.epoch != epoch:
        raise OpError("cancelled")
    if s.busy:
        raise OpError("busy-sync")
    s.busy = "signin"
    fe = SocketFrontend(asyncio.get_running_loop(), conn, _rid(req))
    try:
        if fresh:
            if await _store(reg, conn.uid, s.store.state) != "empty":
                raise OpError("not-locked")
            if s.epoch != epoch:
                raise OpError("cancelled")
            await _replace_store(reg, s, conn, reg.store_cls.create)
            # open_tier1 does not move the epoch: a lock from here on still ends the op.
            reg.open_tier1(s, conn)
        _still(s, conn, epoch)
        s.signin = fe
        ctx = UserContext(conn.uid, s.store, reg.anisette_url, fe)
        fn = reg.apple.login if mode == "login" else reg.apple.relogin
        await _apple_call(reg, s, fn, ctx)
    finally:
        s.signin = None
        s.busy = None
    _still(s, conn, epoch)
    if ctx.item_shape is not None:
        s.item_shape = ctx.item_shape
    s.next_sync_at = None
    _notify_list_after(reg, s)
    return {"ok": True}


def _rid(req) -> int:
    from .sessions import current_request
    r = current_request()
    return r.rid if r is not None else req.get("rid")


async def op_answer(reg, conn, req):
    ask_id = _need(req, "ask_id", int)
    cancel = _need(req, "cancel", bool, optional=True, default=False)
    value = req.get("value")
    if not cancel and not isinstance(value, str):
        raise OpError("bad-request")
    if isinstance(value, str) and len(value) > MAX_PASSPHRASE:
        raise OpError("invalid", field="value")
    s = _session(reg, conn)
    fe = s.signin
    if fe is None or fe.conn is not conn or not fe.answer(ask_id, value, cancel):
        raise OpError("invalid", field="ask_id")
    return {"ok": True}


async def op_signout(reg, conn, req):
    s = _tier1(reg, conn)
    if s.busy:
        raise OpError("busy-sync")
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    _still(s, conn, epoch)
    if s.busy:
        raise OpError("busy-sync")
    s.busy = "edit"
    try:
        ctx = UserContext(conn.uid, s.store, reg.anisette_url, None)
        await _apple_call(reg, s, reg.apple.signout, ctx)
    finally:
        s.busy = None
    reg.lock(conn.uid, "signout", notify=False)
    after_reply(lambda: reg.notify_ui(conn.uid, {"event": "locked", "reason": "signout"}))
    return {"signed_out": True}


# --- ui: sync and settings ------------------------------------------------------------------------

async def op_sync(reg, conn, req):
    s = _session(reg, conn)
    if not s.unlocked() or s.tier1 is not conn:
        return {"skipped": "locked"}
    if s.busy:
        return {"skipped": "running"}
    st = await _store(reg, conn.uid, s.store.status)
    if not st.get("signed_in"):
        return {"skipped": "signed-out"}
    if st.get("needs_login"):
        return {"skipped": "needs-login"}
    _sync_after_reply(reg, conn.uid)
    return {"queued": True}


async def op_settings(reg, conn, req):
    s = _session(reg, conn)
    if "set" in req:
        new = _need(req, "set", dict)
        for key, value in new.items():
            if key not in protocol.SETTINGS_KEYS or not setting_ok(key, value):
                raise OpError("invalid", field=str(key)[:64])
        merged = {**s.settings, **new}
        full = dict(await _store(reg, conn.uid, s.store.load_settings) or {})
        full.update(merged)
        await _store(reg, conn.uid, s.store.save_settings, full)
        s.settings = merged
        if "idle_lock_s" in new:
            s.last_ui_request = reg.clock()
    elif req.get("get") is not True:
        raise OpError("bad-request")
    return {"settings": dict(s.settings)}


async def op_autofill_enable(reg, conn, req):
    """Turn browser autofill on (one .manage dialog) or off (no dialog; every autofill host
    connected right now is disconnected)."""
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    enabled = _need(req, "enabled", bool)
    if enabled and not s.autofill_enabled:
        await reg.authorize(conn, paths.ACTION_MANAGE, {})
    await _save_setting_keys(reg, s, autofill_enabled=True if enabled else None)
    s.autofill_enabled = enabled
    if not enabled:
        reg.withdraw(conn.uid, roles=("autofill",))
    return {"autofill": {"enabled": enabled,
                         "hosts": len(reg.connections(conn.uid, "autofill"))}}


async def op_features(reg, conn, req):
    """The categories that wait for a check on a real keychain (protocol.FEATURES), both off
    by default. Reading them never asks; changing one raises .manage, so the window alone can
    never turn them on. They decide which rows the list carries (wire.visible)."""
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    if "set" not in req:
        if req.get("get") is not True:
            raise OpError("bad-request")
        return {"features": dict(s.features)}
    new = _need(req, "set", dict)
    for key, value in new.items():
        if key not in protocol.FEATURES or not isinstance(value, bool):
            raise OpError("invalid", field=str(key)[:64])
    merged = {**s.features, **new}
    if merged != s.features:
        epoch = s.epoch
        await reg.authorize(conn, paths.ACTION_MANAGE, {})
        if conn.closed or s.ui is not conn or s.epoch != epoch:
            raise OpError("cancelled")
        await _save_setting_keys(reg, s, features=dict(merged))
        s.features = merged
        if s.unlocked() and s.tier1 is conn:
            _notify_list_after(reg, s)
    return {"features": dict(s.features)}


async def op_diag_items(reg, conn, req):
    """What the last sync since this unlock decrypted, as counts of (class, agrp) pairs and the
    attribute names each pair carries: never a value. Run once on the owner's machine to
    confirm the passkey and Recently Deleted names before those categories are turned on.
    Needs tier 1 and raises .manage."""
    s = _tier1(reg, conn)
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    _still(s, conn, epoch)
    shape = s.item_shape
    if shape is None:
        return {"available": False, "items": []}
    items = [{"class": cls, "agrp": agrp, "count": int(v["count"]),
              "keys": sorted(v["keys"]), "inner_keys": sorted(v["inner_keys"])}
             for (cls, agrp), v in sorted(shape.items())]
    return {"available": True, "items": items}


# --- ui: migration and cleanup ------------------------------------------------------------------

async def _save_setting_keys(reg, s, **changes) -> None:
    full = dict(await _store(reg, s.uid, s.store.load_settings) or {})
    for key, value in changes.items():
        if value is None:
            full.pop(key, None)
        else:
            full[key] = value
    await _store(reg, s.uid, s.store.save_settings, full)


async def op_migrate_begin(reg, conn, req):
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    state = await _store(reg, conn.uid, s.store.state)
    # A store created by an earlier migrate-begin that never committed is started over, not
    # refused: it holds keys and nothing else. So is any store that holds nothing at all -
    # an import abandoned (by "Start fresh instead", or by a window that could not see the
    # 1.x vault) or a reset store never signed in - so a 1.x vault that is there can always
    # still be moved.
    retry = state != "empty" and (await _migration_pending(reg, s)
                                  or await _holds_nothing(reg, s))
    if state != "empty" and not retry:
        raise OpError("not-locked")
    await _refuse_certain_seal_refusal(reg, conn.uid)
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    if conn.closed or s.ui is not conn or s.epoch != epoch:
        raise OpError("cancelled")
    if s.unlocked():
        reg.lock(conn.uid, None, notify=False)
    # A retry replaces a store that opens normally and keeps nothing: it is deleted, not
    # kept as another u<uid>.broken-<time> (round 2 gate, bug 3).
    make = (functools.partial(reg.store_cls.reset, discard_empty=state in OPENS) if retry
            else reg.store_cls.create)
    epoch = await _replace_store(reg, s, conn, make)
    s.migrating = True
    try:
        await _save_setting_keys(reg, s, migration_pending=True)
    except OpError:
        logger.warning("uid %d: could not record the pending migration", conn.uid)
    _not_locked_since(reg, s, conn, epoch)
    reg.open_tier1(s, conn)
    token = reg.tickets.issue(uid=conn.uid, role="migrate", purpose="import", ui_conn=conn)
    return {"ticket": token, "ttl": protocol.TICKET_TTL_S}


async def op_migrate_abandon(reg, conn, req):
    """The window found no 1.x vault left to import (or the user chose to start fresh) while
    an import that never committed is recorded: drop the record so the store is an ordinary
    one again and "Sign in to iCloud" works. No dialog: it reveals nothing and changes no
    key, and the sign-in that follows raises its own .manage dialog. A running importer is
    withdrawn first."""
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    if await _store(reg, conn.uid, s.store.state) == "empty":
        return {"migration_pending": False}
    if not await _migration_pending(reg, s):
        return {"migration_pending": False}
    reg.withdraw(conn.uid, roles=("migrate",))
    s.migrating = False
    await _save_setting_keys(reg, s, migration_pending=None)
    logger.info("uid %d: the unfinished 1.x import was abandoned", conn.uid)
    return {"migration_pending": False}


# States of a store that opens normally: only such a store, when it keeps nothing, is deleted
# rather than moved aside by a reset.
OPENS = ("locked", "unlocked")


async def _refuse_certain_seal_refusal(reg, uid: int) -> None:
    """A new store sealed here would certainly be refused (a TPM with a signed PCR policy,
    `pcr-policy`): say so before the .manage dialog, not after the user approved it."""
    fn = getattr(reg.store_cls, "create_blocked", None)
    if fn is None:
        return
    try:
        reason = await _store(reg, uid, fn, keyless=True)
    except OpError:
        return                     # cannot tell: create() still refuses it after the dialog
    if reason:
        raise OpError("seal-refused", reason=reason)


async def _holds_nothing(reg, s) -> bool:
    """No entry, history, session, aliases or nicknames, with signed_in false: read without a
    key, so it works while locked. False when it cannot tell."""
    fn = getattr(s.store, "holds_nothing", None)
    if fn is None:
        return False
    try:
        st = await _store(reg, s.uid, s.store.status, keyless=True)
        return not st.get("signed_in") and bool(await _store(reg, s.uid, fn, keyless=True))
    except OpError:
        return False


async def _migration_pending(reg, s) -> bool:
    if getattr(s, "migrating", False):
        return True
    try:
        full = await _store(reg, s.uid, s.store.load_settings, keyless=True) or {}
    except OpError:
        return False
    return full.get("migration_pending") is True


async def op_purge_old_copy(reg, conn, req):
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    oc = s.old_copy
    if not oc or not oc.get("files") or not oc.get("dir"):
        raise OpError("not-found")
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    if conn.closed or s.ui is not conn or s.epoch != epoch:
        raise OpError("cancelled")
    token = reg.tickets.issue(uid=conn.uid, role="migrate", purpose="purge", ui_conn=conn,
                              extra={"files": list(oc["files"]), "dir": oc["dir"]})
    return {"ticket": token, "ttl": protocol.TICKET_TTL_S}


async def _resettable(reg, s) -> bool:
    """reset is the way out of tpm-cleared, damaged, an import that never committed, and a
    store that holds nothing (it loses nothing)."""
    state = await _store(reg, s.uid, s.store.state)
    if state in ("tpm-cleared", "damaged"):
        return True
    return state != "empty" and (await _migration_pending(reg, s)
                                 or await _holds_nothing(reg, s))


async def op_reset(reg, conn, req):
    s = _session(reg, conn)
    if s.ui is not conn:
        raise OpError("forbidden")
    if not await _resettable(reg, s):
        raise OpError("not-locked")
    await _refuse_certain_seal_refusal(reg, conn.uid)
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    if conn.closed or s.ui is not conn or s.epoch != epoch:
        raise OpError("cancelled")
    if not await _resettable(reg, s):
        raise OpError("not-locked")
    # Only a store that opens normally (an import never committed, or one that keeps nothing)
    # may be deleted when it keeps nothing; after tpm-cleared or damaged it is always kept.
    discard = await _store(reg, conn.uid, s.store.state) in OPENS
    # A lock that landed during the reads above (sleep, logind Lock, the Lock button) ends the
    # op here: the lock below would bump the epoch again and _replace_store would never see it
    # (round 3 audit, problem 1).
    if conn.closed or s.ui is not conn or s.epoch != epoch:
        raise OpError("cancelled")
    reg.lock(conn.uid, None, notify=False)
    reg.withdraw(conn.uid, roles=("migrate",))
    s.migrating = False
    epoch = await _replace_store(reg, s, conn,
                                 functools.partial(reg.store_cls.reset, discard_empty=discard))
    try:
        await _save_setting_keys(reg, s, migration_pending=None)
    except OpError:
        logger.warning("uid %d: could not clear the pending migration record", conn.uid)
    _not_locked_since(reg, s, conn, epoch)
    # The old keys are gone and the fresh store holds nothing; tier 1 stays open on it so the
    # sign-in that follows needs only its own dialog.
    reg.open_tier1(s, conn)
    return {"state": "empty"}


async def op_clip_history_check(reg, conn, req):
    items = _need(req, "items", list)
    if len(items) > MAX_CHECK_ITEMS or any(
            not isinstance(i, str) or len(i) > MAX_CHECK_ITEM for i in items):
        raise OpError("invalid", field="items")
    s = _tier1(reg, conn)
    epoch = s.epoch
    await reg.authorize(conn, paths.ACTION_MANAGE, {})
    _still(s, conn, epoch)
    matches = await _store(reg, conn.uid, s.store.pwmac_matches, list(items))
    return {"matches": sorted(int(i) for i in matches)}


# --- clip ---------------------------------------------------------------------------------------

async def op_redeem(reg, conn, req):
    t = getattr(conn, "ticket", None)
    if t is None or conn.data.get("redeemed"):
        raise OpError("bad-ticket")
    conn.data["redeemed"] = True
    value, t.value = t.value, None
    s = _session(reg, conn)
    return {"value": value or "", "sensitive": bool(t.sensitive),
            "timeout": s.settings["clip_timeout_s"]}


async def op_clip_result(reg, conn, req):
    outcome = _need(req, "outcome", str)
    if outcome not in protocol.CLIP_OUTCOMES:
        raise OpError("invalid", field="outcome")
    t = getattr(conn, "ticket", None)
    if t is None or not conn.data.get("redeemed"):
        raise OpError("bad-ticket")
    if conn.data.get("result"):
        raise OpError("invalid", field="outcome")
    conn.data["result"] = outcome
    event = {"event": "clip", "id": t.id, "field": t.field, "outcome": outcome}
    after_reply(lambda: reg.notify_ui(conn.uid, event))
    return {"ok": True}


# --- migrate ------------------------------------------------------------------------------------

def _import_ticket(conn, purpose: str):
    t = getattr(conn, "ticket", None)
    if t is None or t.purpose != purpose:
        raise OpError("forbidden")
    return t


def _import_files(conn) -> dict:
    return conn.data.setdefault("files", {})


def _discard(files: dict, name: str) -> None:
    f = files.pop(name, None)
    if f is not None:
        f["buf"][:] = bytes(len(f["buf"]))


async def op_import_file(reg, conn, req):
    _import_ticket(conn, "import")
    name = _need(req, "name", str)
    seq = _need(req, "seq", int)
    b64 = _need(req, "b64", str)
    eof = _need(req, "eof", bool, optional=True, default=False)
    if name not in protocol.IMPORT_FILES:
        raise OpError("invalid", field="name")
    files = _import_files(conn)
    f = files.get(name)
    if f is not None and f["done"]:
        _discard(files, name)
        raise OpError("invalid", field="name")
    expected = 0 if f is None else f["seq"]
    if seq != expected:
        _discard(files, name)
        raise OpError("invalid", field="seq")
    try:
        chunk = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        _discard(files, name)
        raise OpError("invalid", field="b64") from None
    if len(chunk) > protocol.IMPORT_CHUNK_MAX:
        _discard(files, name)
        raise OpError("invalid", field="b64")
    if f is None:
        f = files[name] = {"buf": bytearray(), "seq": 0, "done": False}
    if len(f["buf"]) + len(chunk) > protocol.IMPORT_FILE_MAX:
        _discard(files, name)
        raise OpError("invalid", field="name")
    f["buf"] += chunk
    f["seq"] += 1
    if not eof:
        return {"ok": True}
    f["done"] = True
    f["sha256"] = hashlib.sha256(f["buf"]).hexdigest()
    return {"ok": True, "size": len(f["buf"]), "sha256": f["sha256"]}


def _done(conn, name: str) -> bytes | None:
    f = _import_files(conn).get(name)
    return bytes(f["buf"]) if f is not None and f["done"] else None


async def op_import_key(reg, conn, req):
    _import_ticket(conn, "import")
    has_key, has_pass = "key_b64" in req, "passphrase" in req
    if has_key == has_pass:
        raise OpError("bad-request")
    # A key is checked against check.enc (a passphrase vault), or against vault.enc itself
    # (a vault 1.x keyed by the login keyring: no check.enc, no kdf.json, no passphrase).
    check = _done(conn, "check.enc")
    vault = _done(conn, "vault.enc")
    if check is None and (vault is None or has_pass):
        raise OpError("incomplete")
    lock = conn.data.setdefault("key_lock", asyncio.Lock())
    async with lock:
        if has_key:
            try:
                key = base64.b64decode(_need(req, "key_b64", str), validate=True)
            except (binascii.Error, ValueError):
                raise OpError("invalid", field="key_b64") from None
            if len(key) != 32:
                raise OpError("invalid", field="key_b64")
        else:
            passphrase = _need(req, "passphrase", str)
            if not passphrase or len(passphrase) > MAX_PASSPHRASE:
                raise OpError("invalid", field="passphrase")
            kdf = _done(conn, "kdf.json")
            if kdf is None:
                raise OpError("incomplete")
            try:
                key = await asyncio.to_thread(vstore.v1_key_from_passphrase, kdf, passphrase)
            except (ValueError, KeyError, TypeError):
                raise OpError("invalid", field="kdf.json") from None
            finally:
                passphrase = None
        proof = {"check.enc": check} if check is not None else {"vault.enc": vault}
        ok = await asyncio.to_thread(vstore.v1_key_verifies, proof, key)
        if not ok:
            raise OpError("wrong-passphrase")
        old = conn.data.get("key")
        if isinstance(old, bytearray):
            old[:] = bytes(len(old))
        conn.data["key"] = bytearray(key)
    return {"ok": True}


async def op_import_commit(reg, conn, req):
    _import_ticket(conn, "import")
    backup_dir = _need(req, "backup_dir", str, optional=True)
    if backup_dir is not None and (not backup_dir.startswith("/") or "\x00" in backup_dir
                                   or len(backup_dir) > 4096):
        raise OpError("invalid", field="backup_dir")
    files = _import_files(conn)
    key = conn.data.get("key")
    if key is None or any(_done(conn, n) is None for n in protocol.IMPORT_REQUIRED):
        raise OpError("incomplete")
    s = _session(reg, conn)
    if not s.unlocked():
        raise OpError("locked")
    payload = {n: bytes(f["buf"]) for n, f in files.items() if f["done"]}
    digests = [{"name": n, "sha256": f["sha256"]} for n, f in sorted(files.items())
               if f["done"]]
    try:
        result = await reg.run_store(conn.uid, s.store.import_v1, payload, bytes(key))
    except vstore.ImportMismatch:
        raise OpError("mismatch") from None
    except vstore.WrongPassphrase:
        raise OpError("wrong-passphrase") from None
    except Exception as e:
        err = _store_error(e)
        if err is None:
            logger.exception("uid %d: import failed", conn.uid)
            raise OpError("internal") from None
        raise err from None
    finally:
        payload = None
        key[:] = bytes(len(key))
        conn.data.pop("key", None)
        for name in list(files):
            _discard(files, name)
    s.migrating = False
    oc = None
    if backup_dir is not None:
        oc = {"dir": backup_dir, "files": digests, "migrated_at": reg.wall()}
        s.old_copy = oc
    try:
        await _save_setting_keys(reg, s, old_copy=oc, migration_pending=None)
    except OpError:
        logger.warning("uid %d: could not record the old copy", conn.uid)
    counts = dict(result.get("counts", {}))
    after_reply(lambda: reg.notify_ui(conn.uid, {"event": "migrated", "counts": counts}))
    _sync_after_reply(reg, conn.uid)
    return {"counts": counts, "digest": result.get("digest")}


async def op_purge_result(reg, conn, req):
    _import_ticket(conn, "purge")
    removed = _need(req, "removed", list)
    kept = _need(req, "kept", list)
    if not all(isinstance(n, str) for n in removed + kept):
        raise OpError("bad-request")
    s = _session(reg, conn)
    s.old_copy = None
    await _save_setting_keys(reg, s, old_copy=None)
    logger.info("uid %d: old copy purged (%d removed, %d kept)", conn.uid, len(removed),
                len(kept))
    return {"ok": True}


# --- autofill, imported on first use -----------------------------------------------------------

async def op_autofill_query(reg, conn, req):
    from . import autofill
    return await autofill.handle_autofill_query(reg, conn, req)


async def op_autofill_names(reg, conn, req):
    from . import autofill
    return await autofill.handle_autofill_names(reg, conn, req)


async def op_autofill_fill(reg, conn, req):
    from . import autofill
    return await autofill.handle_autofill_fill(reg, conn, req)


HANDLERS = {
    "unlock": op_unlock, "lock": op_lock, "release": op_release, "cancel": op_cancel,
    "grant": op_grant, "reveal": op_reveal, "totp": op_totp, "history": op_history,
    "copy": op_copy, "set": op_set, "create": op_create, "delete": op_delete,
    "totp-preview": op_totp_preview, "signin": op_signin, "answer": op_answer,
    "signout": op_signout, "sync": op_sync, "settings": op_settings,
    "migrate-begin": op_migrate_begin, "migrate-abandon": op_migrate_abandon,
    "tpm-move": op_tpm_move,
    "reset": op_reset, "purge-old-copy": op_purge_old_copy,
    "clip-history-check": op_clip_history_check,
    "redeem": op_redeem, "clip-result": op_clip_result,
    "import-file": op_import_file, "import-key": op_import_key,
    "import-commit": op_import_commit, "purge-result": op_purge_result,
    "autofill-query": op_autofill_query, "autofill-names": op_autofill_names,
    "autofill-fill": op_autofill_fill,
    "autofill-enable": op_autofill_enable,
    "copy-text": op_copy_text, "features": op_features, "diag-items": op_diag_items,
}
