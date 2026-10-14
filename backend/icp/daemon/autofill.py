"""Browser autofill, daemon side: the three ops an `autofill` connection may send.

The daemon's dispatch table calls the three handlers for role "autofill" and nothing else
does. The browser extension is not part of this repository - anyone can write one against
docs/autofill-protocol.md - so the daemon trusts nothing the extension says except the origin,
and treats that only as being as trustworthy as the browser that reported it.

The rules these handlers implement (docs/protocol.md 'Autofill' is the normative text):

- Off until the user turns it on in the window (op autofill-enable, behind .manage): hello
  refuses the role, and both ops refuse with "forbidden" once it is turned off again. pear-exec
  runs the autofill role for any program of yours, so the browser manifest alone is no opt-in.
- A query names accounts (username, label) only to a connection that has had a fill approved
  since the last unlock, or for a site whose names it was shown by an approved
  `.autofill-names` dialog (autofill-names) since then; before that it gives handles and match
  kinds only. Any program of
  yours that gets one fill dialog approved receives that one password - the dialog says a
  browser extension is asking, and the window shows whether an autofill host is connected.
- An autofill client never sees an entry id. Entry ids are an unkeyed hash of (domain,
  username), so handing them out would let any program confirm a guessed username offline.
  Every reply carries a handle instead: HMAC-SHA256 of the id under a random key that exists
  only while the uid is unlocked (made by the unlock, dropped by every lock), so handles mean
  nothing after a lock and cannot be computed from a guess. A real entry id sent to fill is
  just an unknown handle (no-match).

- A locked Pear reveals nothing. Unless the uid's tier-1 UI session is unlocked, or the store
  is open for this connection, query and fill answer as if no account exists for any site:
  autofill-query returns {"state": "locked"} with no other field, autofill-fill raises
  OpError("locked"). Neither unseals a key, raises a dialog, or touches the store then. The
  one way in is autofill-names, whose approved `.autofill-names` dialog unlocks the store for
  that connection only (SessionRegistry.open_autofill), until AUTOFILL_OPEN_S after its last
  request, its disconnect, or any lock.
- The autofill role never gets a tier-1 or tier-2 grant and never uses the UI's grants. Every
  fill raises its own `.autofill` polkit dialog against the autofill process's pidfd.
- Matching is by site, never by name: the origin host must be the entry's `domain` or one of
  its `sites`, or a subdomain/parent of one at a dot boundary, within the same registrable
  domain. Name-only and inferred-alias matches (`Meta.aliases`) are never used.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import TYPE_CHECKING

from . import paths
from .protocol import SEAL_STATES, Connection, OpError, SessionRegistry  # noqa: F401
from ..vstore import EntryNotFound, SealError, StoreLocked

if TYPE_CHECKING:
    from ..vstore import Meta

MAX_ACCOUNTS = 20                    # per autofill-query reply
MAX_ORIGIN_CHARS = 2048              # far above any real origin; anything longer is malformed
_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")   # docs/protocol.md 3.1
_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]*")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PORT_RE = re.compile(r"[0-9]{1,5}")
_MAX_HOST_CHARS = 253

# There is no public suffix list on the target and no new dependency is allowed, so the
# registrable-domain rule is conservative instead of complete: a sub/parent match needs the
# shorter host to have two or more labels (no bare TLD) and not to be one of these suffixes,
# under which unrelated people own the next label. A suffix missing from this list only matters
# if an entry's own domain or the page host IS that suffix, because siblings never match
# (bank.com.au and evil.com.au share no dot-boundary relation). Frozen: changing it changes which
# sites a saved password may be filled on, so it goes through review like a protocol change.
PUBLIC_SUFFIX_GUARD = frozenset({
    # second-level country registries
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk",
    "sch.uk", "police.uk",
    "asn.au", "com.au", "edu.au", "gov.au", "id.au", "net.au", "org.au",
    "ac.nz", "co.nz", "geek.nz", "gen.nz", "govt.nz", "net.nz", "org.nz", "school.nz",
    "ac.jp", "co.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp", "ne.jp", "or.jp",
    "ac.kr", "co.kr", "go.kr", "ne.kr", "or.kr", "re.kr",
    "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn",
    "com.hk", "edu.hk", "gov.hk", "net.hk", "org.hk",
    "com.tw", "edu.tw", "gov.tw", "net.tw", "org.tw",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.my", "edu.my", "gov.my", "net.my", "org.my",
    "ac.id", "co.id", "go.id", "or.id", "web.id",
    "ac.th", "co.th", "go.th", "in.th", "or.th",
    "com.ph", "com.vn", "com.pk", "com.bd", "com.np", "com.lk",
    "ac.in", "co.in", "firm.in", "gen.in", "gov.in", "ind.in", "net.in", "org.in",
    "ac.il", "co.il", "gov.il", "org.il", "net.il",
    "com.tr", "gov.tr", "org.tr", "net.tr",
    "com.sa", "com.eg", "com.qa", "com.kw", "com.lb",
    "ac.za", "co.za", "gov.za", "net.za", "org.za", "web.za",
    "co.ke", "or.ke", "com.ng", "co.ug", "co.tz",
    "com.br", "gov.br", "net.br", "org.br", "edu.br",
    "com.ar", "gob.ar", "com.mx", "gob.mx", "org.mx", "com.co", "com.pe", "com.uy",
    "com.ve", "com.ec", "cl.cl",
    "co.at", "or.at", "gv.at", "com.pl", "net.pl", "org.pl", "com.es", "org.es",
    "com.pt", "com.gr", "com.cy", "com.mt", "com.ua", "org.ua", "com.ru", "org.ru",
    "co.rs", "com.hr", "co.hu", "com.ro",
    # hosting platforms whose customers get sibling subdomains
    "appspot.com", "azurewebsites.net", "blogspot.com", "cloudfront.net",
    "codeberg.page", "duckdns.org", "dyndns.org", "firebaseapp.com", "fly.dev",
    "github.io", "gitlab.io", "glitch.me", "herokuapp.com", "myshopify.com",
    "netlify.app", "ngrok-free.app", "ngrok.io", "no-ip.org", "onrender.com",
    "pages.dev", "readthedocs.io", "s3.amazonaws.com", "sourceforge.io",
    "vercel.app", "web.app", "workers.dev",
})

# Keychain records that exist for Apple's own services (1.3.2's app-list hid the same ones).
# Nobody signs in to a web page with them, so autofill never offers them.
_INTERNAL_USER_PREFIXES = ("PCSBoundaryKey", "com.apple.", "_Apple")
_INTERNAL_MARKS = ("pcs ", "pcs-", "website metadata")


def parse_origin(origin: str) -> str:
    """Validate an origin string from the extension and return its host.

    Accepts exactly `https://<host>` or `https://<host>:<port>`: lowercase it, require an
    ASCII host (IDNs arrive punycoded from the browser) of dot-separated [a-z0-9-] labels with
    at least two labels, no userinfo, path, query, fragment, trailing dot or IP literal.
    Strips one leading "www.". Raises OpError("insecure-origin") for any other scheme and
    OpError("bad-origin") for everything else malformed. The port is ignored for matching."""
    if not isinstance(origin, str) or not origin or len(origin) > MAX_ORIGIN_CHARS:
        raise OpError("bad-origin")
    # ASCII before lowercasing: str.lower() maps some non-ASCII letters onto ASCII ones (the
    # Kelvin sign becomes "k"), which would let a look-alike host pass as a real one.
    if not origin.isascii():
        raise OpError("bad-origin")
    scheme, sep, rest = origin.lower().partition("://")
    if not sep or not _SCHEME_RE.fullmatch(scheme):
        raise OpError("bad-origin")
    if scheme != "https":
        raise OpError("insecure-origin")
    if any(c in rest for c in "/?#@\\[]"):
        raise OpError("bad-origin")
    host, colon, port = rest.partition(":")
    if colon and (not _PORT_RE.fullmatch(port) or not 0 < int(port) <= 65535):
        raise OpError("bad-origin")
    canon = _canonical_host(host)
    if canon is None:
        raise OpError("bad-origin")
    return canon


def _canonical_host(host: str) -> str | None:
    """A lowercase ASCII DNS name of two or more labels, one leading "www." removed, or None.

    The last label must contain a letter, which rules out IPv4 literals and numeric
    nonsense. "www." is only removed when two labels remain, so www.com stays itself."""
    if not host or len(host) > _MAX_HOST_CHARS or host.endswith("."):
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.fullmatch(lb) for lb in labels):
        return None
    if labels[-1].isdigit():
        return None
    if labels[0] == "www" and len(labels) > 2:
        labels = labels[1:]
    return ".".join(labels)


def _entry_host(value) -> str | None:
    """Reduce an entry's stored domain or site to a canonical host, or None if it is not one.

    Apple stores bare hosts, but older items carry whole URLs, ports or a trailing dot, and an
    entry's own IDN may be in Unicode. Anything that is not a DNS name (Wi-Fi's "AirPort", an
    IP address, an app id) gives None and so can never match an origin."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    for cut in "/?#":
        v = v.split(cut, 1)[0]
    v = v.rsplit("@", 1)[-1]
    head, colon, port = v.rpartition(":")
    if colon and port.isdigit():
        v = head
    v = v.rstrip(".")
    if not v.isascii():
        try:
            v = v.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    return _canonical_host(v.lower())


def _is_public_suffix(host: str) -> bool:
    return host.count(".") < 1 or host in PUBLIC_SUFFIX_GUARD


def _related(a: str, b: str) -> bool:
    """One host is a subdomain of the other at a dot boundary, and the shorter one is a
    registrable domain rather than a public suffix."""
    if a.endswith("." + b):
        shorter = b
    elif b.endswith("." + a):
        shorter = a
    else:
        return False
    return not _is_public_suffix(shorter)


def _is_internal(meta: "Meta") -> bool:
    user = meta.username or ""
    title = meta.apple_title or meta.title or ""
    if user.startswith(_INTERNAL_USER_PREFIXES) or title.startswith("_Apple"):
        return True
    if "CHIPPlugin" in user or "CHIPPlugin" in title:
        return True
    for tag in (meta.domain or "", title):
        t = tag.strip().lower()
        if t.startswith(_INTERNAL_MARKS) or "com.apple." in t:
            return True
    return False


def match_rank(host: str, meta: "Meta") -> int | None:
    """How well an entry matches a page host from parse_origin(), or None for no match.

    0: `host` equals the entry's domain or one of its sites (both www-stripped).
    1: one is a subdomain of the other at a dot boundary, and the shorter of the two is not a
       public suffix (it has at least two labels and is not in the module's frozen guard list
       of multi-label public suffixes such as co.uk or github.io).
    None otherwise - including name-only matches and `meta.aliases`, which are never used.

    Apple's internal service records (PCS keys, HomeKit commissioning, "_Apple..." items) are
    never a match either, whatever their domain says, and neither is a copy in Apple's
    Recently Deleted or a passkey-only row (it has no password to fill)."""
    # The page host is held to parse_origin's form, not tidied up like a stored value.
    page = _canonical_host(host) if isinstance(host, str) and host.isascii() else None
    if page is None or _is_internal(meta):
        return None
    if getattr(meta, "recently_deleted", False) or getattr(meta, "kind", "login") == "passkey":
        return None
    best = None
    for value in [meta.domain, *(meta.sites or ())]:
        stored = _entry_host(value)
        if stored is None:
            continue
        if stored == page:
            return 0
        if _related(page, stored):
            best = 1
    return best


def account_label(meta: "Meta") -> str:
    """The text for polkit's $(account) and for the query result: "<title> — <username>",
    using the nickname when one is set, falling back to the domain when there is no title.
    Unsanitized; SessionRegistry.authorize() sanitizes details values itself.

    The title is chosen the way the window's list chooses its primary line: nickname, then
    Apple's own title, then the derived title, then the domain."""
    name = (meta.nickname or meta.apple_title or meta.title or meta.domain or "").strip()
    user = (meta.username or "").strip()
    if name and user:
        return f"{name} — {user}"
    return name or user


# --- handlers --------------------------------------------------------------------------------

def _field(req: dict, name: str) -> str:
    """A required string field. Its content is checked by the caller: an over-long origin is
    bad-origin and an over-long id is no-match, like any other origin or id that is wrong."""
    v = req.get(name)
    if not isinstance(v, str):
        raise OpError("bad-request", field=name)
    return v


def _open_session(reg: SessionRegistry, uid: int, conn=None):
    """The uid's session if tier 1 is open right now, or the store is open for this autofill
    connection (an unlock made by autofill-names); else None. A request on the connection the
    browser's unlock serves keeps it open for another AUTOFILL_OPEN_S."""
    session = reg.get(uid)
    if session is None:
        return None
    if session.unlocked():
        return session
    autofill_open = getattr(reg, "autofill_open", None)
    if autofill_open is not None and autofill_open(session, conn):
        reg.touch_autofill(session, conn)
        return session
    return None


def _require_enabled(reg: SessionRegistry, uid: int) -> None:
    """Autofill turned off in the window since this connection's hello: serve nothing."""
    session = reg.get(uid)
    if session is not None and not getattr(session, "autofill_enabled", False):
        raise OpError("forbidden")


def _names_approved(conn, session, host: str) -> bool:
    """Were this site's account names approved for this connection (autofill-names) since the
    uid last unlocked? The approval names that one host, as its dialog says."""
    epoch, hosts = getattr(conn, "autofill_names", (None, frozenset()))
    return epoch == getattr(session, "epoch", 0) and host in hosts


def _approved(conn, session) -> bool:
    """Has this connection had a fill approved since the uid last unlocked? Only then does a
    query name accounts: any program of yours can run `pear-exec autofill`, so the list of
    usernames is not handed to a connection the user has not approved once."""
    return getattr(conn, "autofill_epoch", None) == getattr(session, "epoch", 0)


def _closed_state(reg: SessionRegistry, uid: int) -> str:
    """"locked" or "unavailable" for a uid whose tier 1 is not open.

    Uses only the store's cheap, keyless state() - the same fact hello already reports - so a
    locked Pear says nothing more than it would to any autofill hello."""
    session = reg.get(uid)
    if session is None:
        return "locked"
    try:
        state = session.store.state()
    except Exception:
        return "unavailable"
    return "unavailable" if state == "empty" or state in SEAL_STATES else "locked"


async def _matching_meta(reg: SessionRegistry, session, uid: int, entry_id: str,
                         host: str) -> "Meta":
    """The entry's Meta if it exists and matches `host`; one error code for both failures."""
    if not _ID_RE.fullmatch(entry_id):
        raise OpError("no-match")
    try:
        meta = await reg.run_store(uid, session.store.get_meta, entry_id)
    except EntryNotFound:
        raise OpError("no-match") from None
    except (StoreLocked, SealError):
        raise OpError("locked") from None
    if match_rank(host, meta) is None:
        raise OpError("no-match")
    return meta


_HANDLE_CONTEXT = b"pear/v2/autofill-handle\x00"
HANDLE_HEX = 32                      # 128 bits of HMAC-SHA256


def _totp_code(reg, secrets_) -> str:
    """The account's current one-time code, as op totp computes it for the window."""
    import time as _time
    from .. import totp
    params = getattr(secrets_, "totp_params", None) or {}
    wall = getattr(reg, "wall", None) or _time.time
    return totp.code(secrets_.totp_secret, digits=int(params.get("digits") or 6),
                     period=int(params.get("period") or totp.DEFAULT_PERIOD),
                     algorithm=int(params.get("algorithm") or 0), at=wall())


def handle_for(key: bytes, entry_id: str) -> str:
    """The opaque handle an autofill client sees for `entry_id` during this unlock."""
    mac = hmac.new(key, _HANDLE_CONTEXT + entry_id.encode("utf-8"), hashlib.sha256)
    return "h-" + mac.hexdigest()[:HANDLE_HEX]


def _handle_key(session) -> bytes | None:
    key = getattr(session, "autofill_key", None)
    return key if isinstance(key, (bytes, bytearray)) and len(key) >= 32 else None


async def _resolve(reg: SessionRegistry, session, uid: int, handle: str) -> str:
    """The entry id behind `handle` in this unlock, or OpError("no-match")."""
    key = _handle_key(session)
    if key is None or not _ID_RE.fullmatch(handle) or not handle.startswith("h-"):
        raise OpError("no-match")
    try:
        metas = await reg.run_store(uid, session.store.list_meta)
    except (StoreLocked, SealError):
        raise OpError("locked") from None
    for m in metas:
        if hmac.compare_digest(handle_for(key, m.id), handle):
            return m.id
    raise OpError("no-match")


def _notify(reg: SessionRegistry, uid: int, entry_id: str, host: str, outcome: str) -> None:
    reg.notify_ui(uid, {"event": "autofill", "id": entry_id, "origin": host,
                        "outcome": outcome})


async def handle_autofill_query(session_registry: SessionRegistry, conn: Connection,
                                req: dict) -> dict:
    """op "autofill-query" {origin}.

    Never prompts. When the uid's tier-1 session is not unlocked it returns only
    {"state": "locked"} (store locked or no UI connection) or {"state": "unavailable"} (store
    empty, tpm-missing, tpm-cleared or damaged): no count, no hint whether the site has
    accounts, and the origin is validated but not used. Unlocked: returns
        {"state": "unlocked", "host": <parsed host>,
         "accounts": [{"id": <handle>, "match": "exact"|"related"[, "username", "label"]}]}
    ranked by match_rank, then newest mdat, then label; at most 20 accounts. "id" is the
    entry's handle (handle_for), never its entry id. "username" and "label" appear only once
    a fill on this connection has been approved since the last unlock; before that the
    handles are all a query gives away, and they say nothing about the username. Never
    includes a password, notes, a code or any other entry's data.

    Raises OpError("bad-origin" | "insecure-origin" | "bad-request")."""
    reg, uid = session_registry, conn.uid
    _require_enabled(reg, uid)
    host = parse_origin(_field(req, "origin"))
    session = _open_session(reg, uid, conn)
    if session is None:
        return {"state": _closed_state(reg, uid)}
    try:
        metas = await reg.run_store(uid, session.store.list_meta)
    except (StoreLocked, SealError):
        return {"state": _closed_state(reg, uid)}
    # A lock that landed while the list was being read wins: nothing read under the old
    # session leaves the daemon.
    if _open_session(reg, uid, conn) is not session:
        return {"state": _closed_state(reg, uid)}
    ranked = []
    for meta in metas:
        rank = match_rank(host, meta)
        if rank is not None:
            ranked.append((rank, -float(meta.mdat or 0), account_label(meta).casefold(), meta))
    ranked.sort(key=lambda r: r[:3])
    named = _approved(conn, session) or _names_approved(conn, session, host)
    key = _handle_key(session)
    if key is None:
        return {"state": _closed_state(reg, uid)}
    accounts = []
    for rank, _, _, m in ranked[:MAX_ACCOUNTS]:
        a = {"id": handle_for(key, m.id), "match": "exact" if rank == 0 else "related"}
        if named:
            a["username"], a["label"] = m.username or "", account_label(m)
        accounts.append(a)
    return {"state": "unlocked", "host": host, "accounts": accounts}


async def _unlock_for_names(reg: SessionRegistry, conn: Connection, uid: int, host: str,
                            req: dict) -> dict:
    """autofill-names while tier 1 is closed: the one `.autofill-names` dialog also unlocks
    the store, for this autofill connection only (SessionRegistry.open_autofill), so the
    browser needs no Pear window. Unavailable (empty, seal states) or no session: the query
    answer and no dialog. The unlock ends AUTOFILL_OPEN_S after the connection's last request,
    when it disconnects, or on any lock trigger; every fill still raises its own dialog."""
    s = reg.get(uid)
    state = _closed_state(reg, uid)
    if s is None or state != "locked" or getattr(s, "wipe_after", False):
        return {"state": state}
    await reg.authorize(conn, paths.ACTION_AUTOFILL_NAMES, {"origin": host})
    if conn.closed:
        raise OpError("cancelled")
    if s.unlocked():                        # the window unlocked while the dialog was up
        conn.autofill_names = (s.epoch, frozenset({host}))
        return await handle_autofill_query(reg, conn, req)
    epoch = s.epoch
    try:
        await reg.run_store(uid, s.store.unlock)
    except (StoreLocked, SealError):
        return {"state": _closed_state(reg, uid)}
    if s.epoch != epoch or conn.closed:
        reg._wipe_store(s)
        raise OpError("cancelled")
    reg.open_autofill(s, conn)
    conn.autofill_names = (s.epoch, frozenset({host}))
    return await handle_autofill_query(reg, conn, req)


async def handle_autofill_names(session_registry: SessionRegistry, conn: Connection,
                                req: dict) -> dict:
    """op "autofill-names" {origin}: autofill-query, with this site's accounts named.

    The browser's picker otherwise shows "Account 1, 2, ..." until a fill is approved. Locked
    or unavailable: the same answer as autofill-query, and no dialog. Already named (a fill or
    an earlier autofill-names since the last unlock): the query answer, no dialog. Otherwise
    one `.autofill-names` dialog naming the site; once approved, and the session and the
    connection are still there, that host's names are given to this connection until Pear
    locks, and the reply is autofill-query's. Raises OpError for every refusal authorize()
    raises, plus cancelled and the query's own errors."""
    reg, uid = session_registry, conn.uid
    _require_enabled(reg, uid)
    host = parse_origin(_field(req, "origin"))
    session = _open_session(reg, uid, conn)
    if session is None:
        return await _unlock_for_names(reg, conn, uid, host, req)
    if not (_approved(conn, session) or _names_approved(conn, session, host)):
        await reg.authorize(conn, paths.ACTION_AUTOFILL_NAMES, {"origin": host})
        if conn.closed:
            raise OpError("cancelled")
        approved_in = _open_session(reg, uid, conn)
        if approved_in is not session:
            return {"state": _closed_state(reg, uid)}
        epoch, hosts = getattr(conn, "autofill_names", (None, frozenset()))
        if epoch != getattr(session, "epoch", 0):
            hosts = frozenset()
        conn.autofill_names = (getattr(session, "epoch", 0), hosts | {host})
    return await handle_autofill_query(reg, conn, req)


async def handle_autofill_fill(session_registry: SessionRegistry, conn: Connection,
                               req: dict) -> dict:
    """op "autofill-fill" {origin, id}. `id` is a handle from autofill-query, never an
    entry id; the reply carries the same handle back.

    In order: parse the origin; require the uid's session unlocked (else OpError("locked"));
    resolve the handle to its entry under this unlock's key, look the entry up and require match_rank(host, meta) is not None (else OpError("no-match") -
    the same code for an unknown id, so ids cannot be probed); raise the `.autofill` dialog via
    session_registry.authorize(conn, ACTION_AUTOFILL, {"account": account_label(meta),
    "origin": host}); after approval, re-check the session is still unlocked and the entry
    still matches, then open the entry (a transient SK unseal via run_store) and return
        {"id", "username", "password"[, "code"]}
    ("code": the entry's current one-time code, when it has one.) Notifies the UI with {"event": "autofill", "id", "origin": host, "outcome"} where outcome
    is "filled", "dismissed", "denied" or "failed". Holds the secret only for the reply.

    Raises OpError for every refusal authorize() raises, plus locked, no-match, bad-origin,
    insecure-origin and bad-request.

    Outcome events are sent only once a dialog was shown and answered (or approved and then
    failed): refusals before any dialog - locked, no-match, rate-limited, prompt-pending,
    no-agent, busy, cancelled - tell the window nothing, so a page cannot use them to make the
    window flash. A fill that fails after approval because the store went away answers
    "locked" (an id that vanished answers "no-match")."""
    reg, uid = session_registry, conn.uid
    _require_enabled(reg, uid)
    origin = _field(req, "origin")
    handle = _field(req, "id")
    host = parse_origin(origin)
    session = _open_session(reg, uid, conn)
    if session is None:
        raise OpError("locked")
    entry_id = await _resolve(reg, session, uid, handle)
    meta = await _matching_meta(reg, session, uid, entry_id, host)

    try:
        await reg.authorize(conn, paths.ACTION_AUTOFILL,
                            {"account": account_label(meta), "origin": host})
    except OpError as e:
        if e.code in ("dismissed", "denied"):
            _notify(reg, uid, entry_id, host, e.code)
        raise

    # The dialog can stay up for half a minute: the window may have locked, the entry may have
    # been edited or deleted by a sync, and the browser may have gone. Re-check all of it.
    try:
        if conn.closed:
            raise OpError("cancelled")
        session = _open_session(reg, uid, conn)
        if session is None:
            raise OpError("locked")
        meta = await _matching_meta(reg, session, uid, entry_id, host)
        try:
            secrets = await reg.run_store(uid, session.store.open_entry, entry_id)
        except EntryNotFound:
            raise OpError("no-match") from None
        except (StoreLocked, SealError):
            raise OpError("locked") from None
        if _open_session(reg, uid, conn) is not session:
            secrets = None
            raise OpError("locked")
        reply = {"id": handle, "username": meta.username or "",
                 "password": secrets.password or ""}
        if getattr(secrets, "totp_secret", None):
            # The same approval covers the account's current one-time code, so a site's
            # second step (a 6-digit code) needs no other dialog for this fill.
            reply["code"] = _totp_code(reg, secrets)
        secrets = None
        conn.autofill_epoch = getattr(session, "epoch", 0)
    except OpError:
        _notify(reg, uid, entry_id, host, "failed")
        raise
    _notify(reg, uid, entry_id, host, "filled")
    return reply
