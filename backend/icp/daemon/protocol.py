"""The frozen numbers, names and internal interfaces of the daemon protocol.

docs/protocol.md is the specification; this module is the same contract in code, so the daemon,
the clients and the autofill host import one set of values instead of each copying them.
backend/tests/test_protocol_contract.py checks the two against each other.

Nothing in here talks to a socket or to polkit. The `Connection`, `Session` and
`SessionRegistry` protocols describe what the daemon's server hands to an op handler kept in
its own module (daemon/autofill.py), so that handler can be tested against fakes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Protocol, runtime_checkable

from . import paths

if TYPE_CHECKING:
    from ..vstore import UserStore

PROTO = 2

# --- framing ---------------------------------------------------------------------------------
# Lines a client sends are small and are the daemon's attack surface, so they are capped hard.
# Lines the daemon sends can carry the whole account list (554 entries is ~150 KiB), so the cap
# is larger and every client must accept it.
MAX_REQUEST_LINE = 64 * 1024
MAX_REPLY_LINE = 8 * 1024 * 1024
HELLO_TIMEOUT_S = 5
MAX_INFLIGHT = 16                    # requests awaiting a reply, per connection
MAX_RID = 2**53 - 1                  # rids are JSON integers a JS/QML client can hold exactly

# --- states ----------------------------------------------------------------------------------
STATES = ("empty", "locked", "unlocked", "tpm-missing", "tpm-cleared", "damaged")
SEAL_STATES = ("tpm-missing", "tpm-cleared", "damaged")
SEALED_WITH = ("host", "host+tpm2")
# What an autofill connection may learn: nothing that tells a locked Pear apart from a broken
# or empty one.
AUTOFILL_STATES = ("locked", "unlocked", "unavailable")

# --- timings and limits ----------------------------------------------------------------------
TICKET_TTL_S = 10
TICKET_BYTES = 32                    # base64url without padding on the wire: 43 characters
GRANT_S_DEFAULT = 120
# An unlock made from the browser (autofill-names while the window is closed or locked) lasts
# this long after the browser's last request, and ends at once when that host disconnects.
AUTOFILL_OPEN_S = 120
GRANT_S_RANGE = (0, 600)             # 0 = single use
CLIP_TIMEOUT_S_DEFAULT = 30
CLIP_TIMEOUT_S_RANGE = (5, 60)
CLIP_REREQUEST_GRACE_S = 1.5
IDLE_LOCK_S_DEFAULT = 300            # lock after five idle minutes unless explicitly changed
IDLE_LOCK_S_CHOICES = (0, 300, 900, 1800)
REVEAL_HIDE_AFTER_S = 20
PROMPT_ANSWERED_PER_MIN = 3          # dismissed/denied per (uid, bucket, action); approvals,
                                     # no-agent, busy and unanswered denials do not count
PROMPT_OUTSTANDING = 1               # per (uid, bucket)
NO_AGENT_FAST_FAIL_S = 0.3           # G7 fallback: a non-dismissed failure this fast = no agent
MAX_AUTOFILL_CONNS = 4               # per uid
SYNC_INTERVAL_S = 2 * 3600
SYNC_JITTER_S = 60
DAEMON_IDLE_EXIT_S = 60
DETAIL_MAX_CHARS = 64                # polkit details values, after sanitizing
BAD_TICKETS_PER_MIN = 5              # per uid, then that uid's clip/migrate hellos are refused

# How the window opens: "floating" (960x640, centred) or "regular" (tiled like other apps).
WINDOW_MODES = ("floating", "regular")
WINDOW_MODE_DEFAULT = "floating"

DEFAULT_SETTINGS = {
    "grant_s": GRANT_S_DEFAULT,
    "idle_lock_s": IDLE_LOCK_S_DEFAULT,
    "clip_timeout_s": CLIP_TIMEOUT_S_DEFAULT,
    "window_mode": WINDOW_MODE_DEFAULT,
}

# --- migration -------------------------------------------------------------------------------
IMPORT_FILES = ("session.enc", "vault.enc", "history.enc", "nicknames.enc", "aliases.enc",
                "kdf.json", "check.enc", "device.json")
IMPORT_REQUIRED = ("vault.enc",)    # kdf.json + check.enc only for a passphrase vault
IMPORT_PASSPHRASE_FILES = ("kdf.json", "check.enc")
IMPORT_FILE_MAX = 4 * 1024 * 1024
IMPORT_CHUNK_MAX = 32 * 1024         # raw bytes per import-file line (b64 keeps it < 64 KiB)

# --- roles and ops ---------------------------------------------------------------------------
ROLES = paths.ROLES                  # ("ui", "clip", "migrate", "autofill")
TICKET_ROLES = ("clip", "migrate")

ROLE_OPS: dict[str, frozenset[str]] = {
    "ui": frozenset({
        "unlock", "lock", "release", "grant", "reveal", "totp", "history", "copy", "set",
        "create", "delete", "totp-preview", "signin", "answer", "signout", "sync", "settings",
        "migrate-begin", "migrate-abandon", "reset", "purge-old-copy", "clip-history-check",
        "cancel", "tpm-move",
        "autofill-enable", "copy-text", "features", "diag-items",
    }),
    "clip": frozenset({"redeem", "clip-result"}),
    "migrate": frozenset({"import-file", "import-key", "import-commit", "purge-result"}),
    "autofill": frozenset({"autofill-query", "autofill-names", "autofill-fill"}),
}
ALL_OPS = frozenset({"hello"}).union(*ROLE_OPS.values())

# Ops that raise a polkit dialog, and which action. Everything else never prompts.
PROMPT_ACTION: dict[str, str] = {
    "unlock": paths.ACTION_UNLOCK,
    "create": paths.ACTION_MANAGE,
    "delete": paths.ACTION_MANAGE,
    "signin": paths.ACTION_MANAGE,
    "signout": paths.ACTION_MANAGE,
    "migrate-begin": paths.ACTION_MANAGE,
    "reset": paths.ACTION_MANAGE,
    "purge-old-copy": paths.ACTION_MANAGE,
    "clip-history-check": paths.ACTION_MANAGE,
    "autofill-enable": paths.ACTION_MANAGE,      # turning it on only; off never asks
    "tpm-move": paths.ACTION_MANAGE,
    "features": paths.ACTION_MANAGE,             # changing a flag only; reading never asks
    "diag-items": paths.ACTION_MANAGE,
    "autofill-fill": paths.ACTION_AUTOFILL,
    "autofill-names": paths.ACTION_AUTOFILL_NAMES,   # only when this site is not yet named
}
# Rate-limit bucket per role: the UI and the browser never starve each other.
PROMPT_BUCKET = {"ui": "ui", "autofill": "autofill"}

# Ops that need a live grant on the entry they name.
GRANT_OPS = frozenset({"reveal", "totp", "history", "set"})

REVEAL_FIELDS = frozenset({"password", "notes"})
COPY_FIELDS = frozenset({"username", "domain", "password", "code", "notes"})
COPY_FIELDS_NEED_GRANT = frozenset({"password", "code", "notes"})
COPY_FIELDS_SENSITIVE = COPY_FIELDS_NEED_GRANT
SET_FIELDS = frozenset({"password", "notes", "sites", "nickname", "totp", "tags"})
CREATE_FIELDS = frozenset({"domain", "username", "password", "title", "notes", "sites",
                           "totp", "tags"})
SETTINGS_KEYS = frozenset(DEFAULT_SETTINGS)

# copy-text: selected text in one of the window's secret fields, put on the clipboard through
# pear-clip like a copy. No dialog: the text is already in the window.
COPY_TEXT_SOURCES_GRANT = frozenset({"notes-edit", "totp-setup-edit", "new-password"})
COPY_TEXT_SOURCES_CREATE = frozenset({"create-password", "create-notes", "create-totp-setup"})
COPY_TEXT_SOURCES = COPY_TEXT_SOURCES_GRANT | COPY_TEXT_SOURCES_CREATE
COPY_TEXT_MAX = 16 * 1024            # characters after NFC, the notes limit
COPY_TEXT_PER_MIN = 10               # per uid, rolling; shares nothing with the prompt limits

# Categories that wait for a check on a real keychain. Both off until the user turns them on,
# which is a .manage dialog (op features), never the window alone.
FEATURES = ("passkeys", "apple_deleted")
DEFAULT_FEATURES = {k: False for k in FEATURES}

CLIP_OUTCOMES = ("pasted", "expired", "replaced", "withdrawn", "failed")
LOCK_REASONS = ("user", "screen-locked", "sleep", "session-ended", "idle", "reset",
                "signout", "error")
UNLOCK_REFUSALS = ("dismissed", "denied", "no-agent", "busy", "rate-limited", "empty") + SEAL_STATES

# --- events (daemon -> client, no rid unless noted) ------------------------------------------
EVENTS: dict[str, frozenset[str]] = {
    "ui": frozenset({"locked", "synced", "sync-failed", "grant-expired", "clip", "focus",
                     "needs-login", "autofill", "autofill-hosts", "migrated",
                     # sign-in stream, these three carry the signin request's rid
                     "stage", "out", "ask"}),
    "clip": frozenset({"withdraw"}),
    "migrate": frozenset({"withdraw"}),
    "autofill": frozenset({"state"}),
}

# --- error codes -----------------------------------------------------------------------------
ERRORS: dict[str, str] = {
    # framing and session
    "bad-request": "malformed JSON, wrong types, or a missing field",
    "too-large": "request line over MAX_REQUEST_LINE; the connection is closed",
    "hello-required": "first line was not hello; the connection is closed",
    "proto": "unsupported proto in hello; the connection is closed",
    "unknown-op": "op name not in the protocol",
    "forbidden": "op not allowed for this connection's role",
    "too-many": "MAX_INFLIGHT requests pending, or MAX_AUTOFILL_CONNS reached",
    "already-running": "a second ui hello for this uid; the existing window is focused",
    "bad-ticket": "ticket missing, expired, used, of another role or uid, or wrong parent",
    "peer": "peer verification failed; the connection is closed",
    "internal": "a daemon bug; logged, never carries detail",
    # state
    "locked": "needs tier 1, and this uid is locked",
    "not-locked": "migrate-begin or reset while data is unlocked or present",
    "no-grant": "needs a grant on this id, and there is none",
    "grant-expired": "the grant on this id ran out",
    "not-found": "no entry with this id",
    "no-match": "autofill: no such id, or its sites do not match the origin",
    "not-signed-in": "needs an iCloud session and there is none",
    "migration-pending": "a 1.x import was started and never committed; finish or retry it first",
    "needs-login": "Apple wants an interactive sign-in",
    "empty": "no vault yet for this uid",
    "tpm-missing": "seal state, see docs/protocol.md 'States'",
    "tpm-cleared": "seal state",
    "damaged": "seal state",
    "seal-unavailable": "systemd-creds or the seal service could not run; transient, retry",
    "seal-refused": "sealing bound the keys to a signed PCR policy or an unknown key type; "
                    "nothing kept; 'reason' is pcr-policy or key-type",
    # prompts
    "dismissed": "the user closed the polkit dialog",
    "denied": "polkit said no (wrong password, fingerprint failure, policy)",
    "no-agent": "no polkit agent registered; not counted against the rate limit",
    "busy": "the agent is showing another dialog; not counted",
    "rate-limited": "PROMPT_ANSWERED_PER_MIN refused prompts of this action in the last minute",
    "prompt-pending": "this bucket already has a dialog open",
    "cancelled": "the request was cancelled (cancel op, superseded, or EOF)",
    # work
    "busy-sync": "a sync, sign-in or edit for this uid is already running",
    "anisette-unavailable": "the anisette server on 127.0.0.1:6969 did not answer",
    "network": "iCloud could not be reached",
    "apple": "iCloud refused the change; text is in 'detail'",
    "invalid": "a field value failed validation; the field is named in 'field'",
    # migration
    "wrong-passphrase": "the old passphrase or PEEKed key does not open check.enc",
    "mismatch": "the converted store did not verify; nothing was kept",
    "incomplete": "import-commit before every required file and a key arrived",
    # autofill
    "bad-origin": "origin is not scheme://host[:port] with an ASCII host",
    "insecure-origin": "origin is not https",
}


class OpError(Exception):
    """Raised by an op handler to send `{"rid": n, "error": code, ...extra}`.

    `code` must be a key of ERRORS. `extra` is merged into the reply and must never contain a
    secret: it is for things like `field`, `retry_after` or a sanitized Apple `detail`.
    """

    def __init__(self, code: str, **extra: Any):
        if code not in ERRORS:
            raise ValueError(f"unknown error code {code!r}")
        super().__init__(code)
        self.code = code
        self.extra = extra

    def reply(self, rid) -> dict:
        return {"rid": rid, "error": self.code, **self.extra}


# --- what the daemon's server hands to a handler ----------------------------------------------------

@runtime_checkable
class Connection(Protocol):
    """One verified client connection (daemon/server.py builds it after peer checks)."""

    uid: int                 # SO_PEERCRED uid, verified against /proc
    pid: int
    pidfd: int               # SO_PEERPIDFD, held for the life of the connection
    start_time: int          # /proc/<pid>/stat field 22, for subject fallback and PPid binding
    role: str                # one of ROLES, fixed at hello
    closed: bool

    def send_event(self, event: dict) -> None:
        """Queue one event line for this client. Never blocks; drops nothing silently (a
        client that stops reading is disconnected by the server)."""
        ...


@runtime_checkable
class Session(Protocol):
    """The per-uid state machine (daemon/sessions.py)."""

    uid: int
    store: "UserStore"
    ui: Connection | None            # the one UI connection, or None
    settings: dict                   # DEFAULT_SETTINGS keys, validated

    def unlocked(self) -> bool:
        """True only while tier 1 is open: a UI connection is live and polkit #1 succeeded
        on it. Every lock trigger makes this False before any other work."""
        ...


@runtime_checkable
class SessionRegistry(Protocol):
    """All sessions plus the shared services an op handler may use."""

    def get(self, uid: int) -> Session | None:
        """The session for `uid`, or None if this uid has never connected since start."""
        ...

    def connections(self, uid: int, role: str) -> list[Connection]:
        """Live connections of `uid` with `role`; used to count MAX_AUTOFILL_CONNS."""
        ...

    async def authorize(self, conn: Connection, action: str, details: dict[str, str]) -> None:
        """Raise the polkit dialog for `action` against `conn`'s pidfd subject and return
        only if it was approved.

        Applies the rules in docs/protocol.md 'Prompts': sanitizes `details` values, enforces
        PROMPT_OUTSTANDING and PROMPT_ANSWERED_PER_MIN for the role's bucket, cancels on EOF.
        Otherwise raises OpError with code dismissed, denied, no-agent, busy, rate-limited,
        prompt-pending or cancelled.
        """
        ...

    async def run_store(self, uid: int, fn: Callable[..., Any], *args: Any,
                        keyless: bool = False) -> Any:
        """Run a blocking UserStore call in a worker thread under that uid's store lock.
        keyless=True (status, state, load_settings, holds_nothing only) skips the lock and
        is served while a wipe is pending."""
        ...

    def notify_ui(self, uid: int, event: dict) -> None:
        """Send `event` to the uid's UI connection if there is one; otherwise drop it."""
        ...


Handler = Callable[[SessionRegistry, Connection, dict], Awaitable[dict]]
"""Every op handler: `await handler(registry, conn, req)` returns the reply payload without
`rid` (the server adds it) or raises OpError. `req` has been parsed and its `op` checked
against the connection's role; the handler validates the remaining fields itself."""
