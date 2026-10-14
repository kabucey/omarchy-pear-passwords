"""The v2 per-user store: /var/lib/pear-passwords/u<uid>/, read and written only by the daemon.

This file is the interface between the store (implemented in this package) and its callers:
the daemon's handlers and the Apple pipeline. Signatures, field names and exception kinds are
shared by both sides; change them together.

Key hierarchy (spec section 3): RK_list unlocks meta, session, aliases and nicknames through
HKDF subkeys; SK_secret opens one entry box at a time and is wiped at once. Writes only ever
need PK_secret, so sync and edits never unseal SK_secret - `unseal_count` lets a test prove it.

Rules every implementation keeps:
- A decrypt or AEAD error never deletes or rewrites anything; it surfaces as SealError("damaged").
- Every write is O_EXCL temp 0600, fsync, rename, fsync of the directory.
- Nothing here prompts, imports polkit, or reads $HOME.
- There is no sync lease: lock() wipes every key and subkey, always.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal

SealKind = Literal["tpm-missing", "tpm-cleared", "damaged"]
StoreState = Literal["empty", "locked", "unlocked", "tpm-missing", "tpm-cleared", "damaged"]


class StoreError(Exception):
    """Base of every error this package raises."""


class SealError(StoreError):
    """The keys could not be unsealed, or a file failed its AEAD check.

    kind is "tpm-missing" (sealed with host+tpm2 and the TPM is gone - recoverable by turning
    PTT back on), "tpm-cleared" (a TPM is present but its SRK differs from the recorded one -
    unrecoverable), or "damaged" (unseal worked but a file does not decrypt; files are kept)."""

    def __init__(self, kind: SealKind, detail: str = ""):
        if kind not in ("tpm-missing", "tpm-cleared", "damaged"):
            raise ValueError(f"unknown seal error kind {kind!r}")
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


class StoreLocked(StoreError):
    """The call needs tier 1 (RK_list) and the store is locked."""


class EntryNotFound(StoreError, KeyError):
    """No live (non-tombstoned) entry has this id."""


class WrongPassphrase(StoreError):
    """A v1 key - PEEKed from the 1.3.2 agent or derived from the typed passphrase - does not
    open check.enc."""


class ImportMismatch(StoreError):
    """The converted v2 store did not re-open to the same counts and digest as the v1 read.
    The tmp directory has already been removed; v1 stays authoritative."""


@dataclass
class Meta:
    """The non-secret part of one entry, held under K_meta. This is all tier 1 releases.

    `id` is opaque to callers (at most 128 characters of [A-Za-z0-9._:-]) and stable across
    syncs for the same keychain item. `domain` is the primary site host, `sites` the extra
    sites Apple stores on the entry (s_as). `aliases` are inferred from metadata stubs and are
    for display only: autofill never matches on them. `mdat` is unix seconds, 0 if unknown.

    `tags` come from the final "Tags: #a #b" line of the notes (keychain/tagline.py): list
    metadata, not a secret. `has_notes` is about the notes body, without that line. `kind` is
    "passkey" for a row that is only a passkey (`has_password` false), `has_passkey` marks a
    login that also has one, and `recently_deleted` an item in Apple's Recently Deleted (an
    access group ending in -recently-deleted): read-only, and never a live entry.
    """

    id: str
    title: str
    domain: str
    sites: list[str]
    username: str
    nickname: str
    has_totp: bool
    has_notes: bool
    mdat: float
    history_count: int
    apple_title: str = ""
    aliases: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    has_passkey: bool = False
    kind: str = "login"
    has_password: bool = True
    recently_deleted: bool = False


@dataclass
class Secrets:
    """The secret part of one entry, sealed to PK_secret in entries/<id>.box.

    `totp_secret` is the raw seed (never base32 text) and `totp_params` its
    {digits, period, algorithm}, both None/empty when the entry has no code. `apple_history`
    is Apple's own password history for the item, newest first, as list of
    {"date": iso8601, "value": str}."""

    password: str
    notes: str
    totp_secret: bytes | None
    apple_history: list
    totp_params: dict = field(default_factory=dict)


@dataclass
class SyncItem:
    """One decrypted keychain item handed from the Apple pipeline to apply_sync. Plaintext and
    transient: the caller drops it as soon as apply_sync returns."""

    id: str
    meta: Meta
    secrets: Secrets


# The implementation modules import the exceptions and dataclasses above, so they come in only
# once those exist.
import datetime as _dt  # noqa: E402
import functools as _functools  # noqa: E402
import hmac as _hmac  # noqa: E402
import logging as _logging  # noqa: E402
import os as _os  # noqa: E402
import threading as _threading  # noqa: E402
import time as _time  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

from .. import paths as _paths  # noqa: E402
from ..daemon import paths as _system_paths  # noqa: E402
from . import entries as _entries  # noqa: E402
from . import format as _fmt  # noqa: E402
from . import keys as _keys  # noqa: E402
from . import meta as _meta  # noqa: E402
from . import seal as _seal  # noqa: E402
from . import session_store as _ss  # noqa: E402
from .ids import check_id as _check_id  # noqa: E402

_log = _logging.getLogger(__name__)
_TIERS = ("list", "secret")
_KEYS_FORMAT = 2


def _serialized(fn):
    """Run the method under the store's own mutex. The daemon calls the store from a worker
    thread (run_store) and the lock from the event loop; without this a lock landing mid-call
    wiped the keys under a running apply_sync, leaving a half-applied sync or an encrypted
    `null` written over meta.v2. lock() waits for the call in progress; try_lock() never
    waits: it asks for the wipe, and the call in progress carries it out the moment it
    returns, still holding the mutex. From then until the wipe has happened every new call is
    refused with StoreLocked - so a caller that strings several store calls together (one
    sync is a session save, a nickname read, apply_sync and a status write) cannot go on with
    the keys after the lock, whatever the daemon's run_store wrapper does."""
    @_functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._mx:
            outer = self._depth == 0
            if outer and self._wipe_req:
                self._wipe_now()
                raise StoreLocked("the store is being locked")
            self._depth += 1
            try:
                return fn(self, *args, **kwargs)
            finally:
                self._depth -= 1
                if outer and self._wipe_req:
                    self._wipe_now()          # the lock that landed during this call
    return wrapper


class UserStore:
    """One uid's v2 store. Every method that reads or writes keys or meta holds the store's
    mutex, so lock() never interleaves with a call in progress."""

    unseal_count: int
    """How many times SK_secret was unsealed by this object. A test hook: sync must leave it 0."""

    uid: int

    def __init__(self, uid: int, _root=None):
        self.uid = uid
        self.unseal_count = 0
        self._dir = _Path(_root) if _root is not None else _paths.user_dir(uid)
        self._rk: _keys.SecretBytes | None = None
        self._sub: dict | None = None
        self._pk: bytes | None = None
        self._doc: dict | None = None
        self._nick: dict | None = None
        self._fail: str | None = None
        self._mx = _threading.RLock()
        self._depth = 0               # nesting of serialized calls, read and written under _mx
        self._wipe_req = False        # a lock is waiting for the call in progress (no mutex)

    def __repr__(self) -> str:
        return f"<UserStore u{self.uid} {self.state()}>"

    # --- lifecycle ---------------------------------------------------------------------------
    @classmethod
    def open(cls, uid: int) -> "UserStore":
        """Bind to /var/lib/pear-passwords/u<uid>/ without touching any key. state() and
        status() work on the result; nothing secret is read."""
        return cls(uid)

    @classmethod
    def create(cls, uid: int) -> "UserStore":
        """Make a new store: random RK_list and an X25519 SK/PK pair, sealed with
        systemd-creds --with-key=auto, plus an empty meta. The result is unlocked.

        Refuses (StoreError) if u<uid> already holds a store; reset() is the way over one."""
        store = cls(uid)
        if store._has_keys():
            raise StoreError(f"u{uid} already holds a store")
        backend = _seal.get_backend()
        _fmt.ensure_dir(_Path(_paths.STATE_ROOT))
        fresh_dir = not _os.path.lexists(store._dir)
        kd = _fmt.ensure_dir(store._keys_dir())
        _entries.EntryFiles(store._dir).ensure()

        rk = _keys.new_root()
        sk, pk = _keys.new_keypair()
        written: list = []
        try:
            blobs = {"list": backend.encrypt(store._cred_name("list"), bytes(rk)),
                     "secret": backend.encrypt(store._cred_name("secret"), bytes(sk))}
            # Read both back before anything depends on them: a blob that does not open now
            # would be a store that can never be unlocked.
            # (Not counted in unseal_count: SK_secret was generated here, nothing is released.)
            store._verify_blob(backend, "list", blobs["list"], rk)
            store._verify_blob(backend, "secret", blobs["secret"], sk)
            # What the blobs are bound to, read from their headers - not a guess from a probe.
            sealed_with = backend.key_type(blobs["list"])
            if backend.key_type(blobs["secret"]) != sealed_with:
                raise _seal.SealUnavailable("the two key blobs were sealed differently")
            srk = backend.srk_fingerprint() if sealed_with == "host+tpm2" else None
            sub = _keys.derive(rk)
            for tier in _TIERS:
                written.append(kd / store._cred_file(tier))
                _fmt.atomic_write(written[-1], blobs[tier])
            written.append(kd / _paths.SECRET_PUB)
            _fmt.atomic_write(written[-1], _keys.pk_record(sub["meta"], pk))
            store._rk, store._sub, store._pk = rk, sub, pk
            store._doc, store._nick = _meta.empty(), {}
            written.append(store._dir / _paths.META_FILE)
            store._write_meta()
            # keys.json last: until it exists the directory is not a store anyone relies on.
            store._write_keys_json({"format": _KEYS_FORMAT, "sealed_with": sealed_with,
                                    **({"tpm_srk_fp": srk} if srk else {}),
                                    "created": _time.time()})
        except BaseException:
            store.lock()
            rk.wipe()
            # Fresh keys that never became a store guard nothing; leaving them would make the
            # directory look like a store that can never be unlocked.
            for f in written:
                try:
                    _os.unlink(f)
                except FileNotFoundError:
                    pass
            if fresh_dir:
                # Nothing was saved, so nothing is left: not even the empty skeleton.
                for d in (kd, store._dir / _paths.ENTRIES_DIR, store._dir / _paths.HISTORY_DIR,
                          store._dir):
                    try:
                        _os.rmdir(d)
                    except OSError:
                        pass
            raise
        finally:
            sk.wipe()
        return store

    @classmethod
    def create_blocked(cls) -> str | None:
        """Why create() (and so reset()) would certainly be refused, known before anything is
        sealed: "pcr-policy" when a TPM is present and sealing through this backend would bind
        the keys to a signed PCR policy (see SealRefused). None when nothing is known to stop
        it. Reads no key; the daemon asks before it raises a dialog."""
        backend = _seal.get_backend()
        blocked = _seal.tpm_sealing_blocked(backend)     # cheap: the backend and a file
        if blocked and backend.tpm_present():
            return blocked
        return None

    @classmethod
    def reset(cls, uid: int, discard_empty: bool = False) -> "UserStore":
        """The "Start over" button after tpm-cleared or damaged: rename u<uid> to
        u<uid>.broken-<unix time> (never delete - the files are kept for diagnosis), then
        create() a fresh store. Returns it unlocked.

        With discard_empty (the daemon passes it only for a store that opens normally, never
        after tpm-cleared or damaged), a store that keeps nothing (_keeps_nothing: only key
        wrappers and settings, as an abandoned 1.x import or a store never signed in leaves)
        is deleted once it has been renamed: there is nothing in it to diagnose, and every
        "start over" of an import used to leave another copy behind (round 2 gate, bug 3)."""
        d = _paths.user_dir(uid)
        if _os.path.lexists(d):
            empty = discard_empty and not _os.path.islink(d) and _keeps_nothing(d)
            aside = _paths.user_aside_dir(uid, "broken", _time.time())
            n = 1
            while _os.path.lexists(aside):
                aside = _paths.user_aside_dir(uid, "broken", _time.time() + n)
                n += 1
            _os.rename(d, aside)
            _fmt.fsync_dir(d.parent)
            if empty:
                try:
                    _remove_tree(aside)
                    _log.info("u%d: the old store held nothing; removed", uid)
                except (OSError, StoreError):
                    _log.warning("u%d: could not remove %s; kept", uid, aside.name)
            else:
                _log.warning("u%d: store moved aside to %s for diagnosis", uid, aside.name)
        return cls.create(uid)

    def state(self) -> StoreState:
        """Cheap, no unseal: "empty" with no keys, "unlocked" while RK_list is in memory,
        otherwise "locked" - or the SealError kind recorded by the last failed unlock()."""
        if self._rk is not None:
            return "unlocked"
        if self._fail is not None:
            return self._fail
        return "locked" if self._has_keys() else "empty"

    def holds_nothing(self) -> bool:
        """Whether this store keeps nothing anyone could lose, read without a key: no entry
        or history box, no iCloud session, no aliases and no nicknames. True with no store
        at all. A store left like that (an abandoned or reset 1.x import, a fresh store
        never signed in) may be replaced by a migrate-begin without a dead end."""
        if not self._has_keys():
            return True
        return _keeps_nothing(self._dir)

    def status(self) -> dict:
        """What hello reports: {state, signed_in, sealed_with, synced_at, needs_login}.

        signed_in is whether session.v2 exists (no key needed). sealed_with comes from the
        plaintext keys.json ("host" | "host+tpm2", None when empty). synced_at (unix seconds)
        and needs_login live under K_meta, so they are None while locked."""
        doc = self._doc                # one read: a lock may wipe it from another thread
        state = self.state()
        try:
            kj = self._read_keys_json()
        except SealError:
            kj = None
        sealed = kj.get("sealed_with") if kj else None
        unlocked = state == "unlocked" and doc is not None
        return {"state": state,
                "signed_in": state != "empty" and _ss.signed_in(self._dir),
                "sealed_with": sealed if sealed in ("host", "host+tpm2") else None,
                "synced_at": doc.get("synced_at") if unlocked else None,
                "needs_login": bool(doc.get("needs_login")) if unlocked else None}

    @_serialized
    def unlock(self) -> None:
        """Unseal RK_list, derive the subkeys, load meta. Raises SealError. Deletes any
        keys/*.prev left by an earlier re-seal once this unlock has succeeded."""
        if self._rk is not None:
            return
        if not self._has_keys():
            raise StoreError("empty: there is no store to unlock")
        # A rotation interrupted before its swap left the unverified new tree here, one
        # interrupted after it left the old (host-only) tree: either way, not the store.
        try:
            _remove_tree(self._rotate_dir())
        except (OSError, StoreError):
            _log.warning("u%d: could not remove a leftover %s", self.uid,
                         self._rotate_dir().name)
        try:
            rk = self._unseal_list()
        except SealError as e:
            self._fail = e.kind
            raise
        sub: dict = {}
        try:
            sub = _keys.derive(rk)
            pk = _keys.pk_from_record(sub["meta"],
                                      _fmt.read_file(self._keys_dir() / _paths.SECRET_PUB))
            doc = _fmt.read_sealed(self._dir, _paths.META_FILE, bytes(sub["meta"]),
                                   _fmt.KIND_META, self.uid)
            if doc is None:
                raise SealError("damaged", "meta.v2 is missing")
            doc = _meta.check(doc)
            nick = _ss.load_nicknames(self._dir, sub["nicknames"], self.uid)
        except SealError as e:
            rk.wipe()
            _keys.wipe_all(sub)
            self._fail = e.kind
            raise
        self._rk, self._sub, self._pk, self._doc, self._nick = rk, sub, pk, doc, nick
        self._fail = None
        self._drop_prev()

    def lock(self) -> None:
        """Wipe RK_list, every subkey, the plaintext meta and any cached session. Idempotent.
        There is no partial lock: 2.0 has no sync lease. Waits for a store call in progress;
        the daemon's event loop uses try_lock() instead."""
        self._wipe_req = True
        with self._mx:
            self._wipe_now()
            if self._depth == 0:
                self._wipe_req = False

    def try_lock(self) -> bool:
        """lock() if no store call is running right now, without waiting. Returns whether the
        keys were wiped. False means a call holds the store (a systemd-creds call can take up
        to a minute on a slow TPM): the wipe is then requested, that call wipes the keys as
        soon as it returns, and every store call after it is refused until a try_lock() or
        lock() finds the store free again (Registry.run_store calls it on the way out)."""
        self._wipe_req = True                 # set first: the call in progress reads it
        if not self._mx.acquire(blocking=False):
            return False
        try:
            if self._depth:                   # this thread is inside a call: let it finish
                return False
            self._wipe_now()
            self._wipe_req = False
        finally:
            self._mx.release()
        return True

    def lock_pending(self) -> bool:
        """True when the keys are gone or a lock is waiting to wipe them. Long Apple work
        checks it between network steps and stops (StoreLocked) rather than carry on after
        the user locked."""
        return self._wipe_req or self._rk is None

    def _wipe_now(self) -> None:
        if self._rk is not None:
            self._rk.wipe()
        _keys.wipe_all(self._sub or {})
        self._rk = self._sub = self._pk = None
        self._doc = self._nick = None

    @_serialized
    def tpm_move_state(self) -> str:
        """Whether reseal_if_tpm_available() can run, without touching a key: "available" (a
        TPM2 is usable and keys.json says "host"), "sealed" (already host+tpm2), "no-tpm", or
        "pcr-policy" (it would bind the keys to a signed PCR policy, so it is refused)."""
        kj = self._read_keys_json() or {}
        if kj.get("sealed_with") == "host+tpm2":
            return "sealed"
        backend = _seal.get_backend()
        if not backend.tpm_present():
            return "no-tpm"
        return _seal.tpm_sealing_blocked(backend) or "available"

    @_serialized
    def reseal_if_tpm_available(self) -> bool:
        """Only after the user asked for it (op tpm-move, behind its own .manage dialog): if a
        TPM2 is present and keys.json says "host", move the store to NEW keys sealed with
        host+tpm2. Returns True if it did.

        This is the one step that opens every box with SK_secret outside a per-entry grant:
        each entry and history box is opened inside the daemon, re-sealed to the new PK at once
        and its plaintext dropped before the next one; nothing of it leaves the daemon, and it
        happens once per store. That is why it is never automatic (docs/security.md 2).

        A re-wrap of the same RK_list and SK_secret would leave every backup or snapshot taken
        before (host-key-only blobs plus /var/lib/systemd/credential.secret) able to decrypt
        everything written afterwards, so this is a rotation: a fresh RK_list and SK/PK pair;
        meta, session, aliases and nicknames re-encrypted under the new subkeys; every entry
        and history box opened once with the old SK_secret and sealed to the new PK. The new
        store is built beside the old one (u<uid>.rotate), opened again from scratch through a
        real unseal with every box checked against the old plaintext, and only then swapped
        in with one renameat2(RENAME_EXCHANGE). The old tree is deleted at once; a crash
        leaves at most a u<uid>.rotate that the next unlock removes. No host-only copy of a
        key that opens current data is kept anywhere."""
        self._need_unlocked()
        kj = self._read_keys_json() or {}
        if kj.get("sealed_with") == "host+tpm2":
            return False
        backend = _seal.get_backend()
        if not backend.tpm_present():
            return False
        rot = self._rotate_dir()
        try:
            _remove_tree(rot)
            sk_old = self._unseal_sk()
        except (SealError, _seal.SealUnavailable, OSError, StoreError) as e:
            _log.warning("u%d: cannot re-seal, the entry key did not unseal (%s)", self.uid,
                         type(e).__name__)
            return False
        rk = _keys.new_root()
        sk, pk = _keys.new_keypair()
        sub = _keys.derive(rk)
        try:
            try:
                doc = self._build_rotated(rot, backend, kj, sk_old, rk, sk, pk, sub)
            finally:
                sk_old.wipe()
                sk.wipe()
            _fmt.exchange(rot, self._dir)
        except (SealError, _seal.SealUnavailable, OSError, StoreError, ValueError) as e:
            rk.wipe()
            _keys.wipe_all(sub)
            try:
                _remove_tree(rot)
            except (OSError, StoreError):
                pass
            _log.warning("u%d: moving to TPM-sealed keys did not verify (%s); kept host sealing",
                         self.uid, type(e).__name__)
            return False
        _fmt.fsync_dir(self._dir.parent)
        # u<uid>.rotate now holds the old tree, whose host-only keys open the old data: gone.
        try:
            _remove_tree(rot)
        except (OSError, StoreError):
            _log.warning("u%d: the pre-TPM tree could not be removed yet; the next unlock "
                         "removes it", self.uid)
        old_rk, old_sub = self._rk, self._sub
        self._rk, self._sub, self._pk, self._doc = rk, sub, pk, doc
        old_rk.wipe()
        _keys.wipe_all(old_sub)
        _log.info("u%d: keys rotated and sealed with host+tpm2", self.uid)
        return True

    def _rotate_dir(self) -> _Path:
        return self._dir.with_name(self._dir.name + ".rotate")

    def _build_rotated(self, rot, backend, kj, sk_old, rk, sk, pk, sub) -> dict:
        """Write the whole store under new keys into `rot` and prove it reads back."""
        import copy
        uid = self.uid
        _fmt.ensure_dir(rot)
        kd = _fmt.ensure_dir(rot / _paths.KEYS_DIR)
        blobs = {"list": backend.encrypt(self._cred_name("list"), bytes(rk)),
                 "secret": backend.encrypt(self._cred_name("secret"), bytes(sk))}
        self._verify_blob(backend, "list", blobs["list"], rk)
        self._verify_blob(backend, "secret", blobs["secret"], sk)
        for t in _TIERS:
            if backend.key_type(blobs[t]) != "host+tpm2":
                raise _seal.SealUnavailable("the new blobs are not bound to the TPM")
        srk = backend.srk_fingerprint()
        for t in _TIERS:
            _fmt.atomic_write(kd / self._cred_file(t), blobs[t])
        _fmt.atomic_write(kd / _paths.SECRET_PUB, _keys.pk_record(sub["meta"], pk))

        # Every box on disk, current and history, referenced by meta or not.
        old_files, new_files = _entries.EntryFiles(self._dir), _entries.EntryFiles(rot)
        new_files.ensure()
        want: dict = {}                    # (id, n or None) -> sha256 of the payload
        doc = copy.deepcopy(self._doc)
        import hashlib
        for name in sorted(_os.listdir(old_files.entries)) if old_files.entries.is_dir() else []:
            if not name.endswith(_paths.BOX_SUFFIX):
                continue
            id = name[:-len(_paths.BOX_SUFFIX)]
            payload = _entries.open_box(bytes(sk_old), old_files.read(id), id)
            new_files.write(id, _entries.seal(pk, payload))
            want[(id, None)] = hashlib.sha256(_fmt.dumps(payload)).hexdigest()
            rec = doc["entries"].get(id)
            if rec is not None:
                s = _entries.from_payload(payload)
                rec["pwmac"] = _keys.pwmac(sub["pwmac"], s.password)
                rec["smac"] = _keys.smac(sub["pwmac"], _entries.rest_canonical(s))
        for rec_id, rec in doc["entries"].items():
            if (rec_id, None) not in want:
                rec.pop("pwmac", None)     # a MAC under the old key means nothing now
                rec.pop("smac", None)
        hist_root = old_files.history
        for id in sorted(_os.listdir(hist_root)) if hist_root.is_dir() else []:
            for n in old_files.numbers(id):
                payload = _entries.open_box(bytes(sk_old), old_files.read_history(id, n), id)
                new_files.write_history(id, n, _entries.seal(pk, payload))
                want[(id, n)] = hashlib.sha256(_fmt.dumps(payload)).hexdigest()

        _fmt.write_sealed(rot, _paths.META_FILE, bytes(sub["meta"]), _fmt.KIND_META, uid, doc)
        sess = _ss.load_session(self._dir, self._sub["session"], uid)
        if sess:
            _ss.save_session(rot, sub["session"], uid, sess)
        if (self._dir / _paths.ALIASES_FILE).exists():
            _ss.save_aliases(rot, sub["aliases"], uid,
                             _ss.load_aliases(self._dir, self._sub["aliases"], uid))
        if (self._dir / _paths.NICKNAMES_FILE).exists():
            _ss.save_nicknames(rot, sub["nicknames"], uid, dict(self._nick or {}))
        for plain in (_paths.DEVICE_FILE, _paths.STATE_FILE):
            data = _fmt.read_file(self._dir / plain)
            if data is not None:
                _fmt.atomic_write(rot / plain, data)
        # keys.json last, as in create().
        _fmt.atomic_write(kd / _paths.KEYS_JSON, _fmt.dumps(
            {**{k: v for k, v in kj.items() if k != "tpm_srk_fp"}, "format": _KEYS_FORMAT,
             "sealed_with": "host+tpm2", **({"tpm_srk_fp": srk} if srk else {}),
             "rotated": _time.time()}))

        # Read it all back through a fresh unlock (a real unseal of the new blobs).
        reader = UserStore(uid, _root=rot)
        reader.unlock()
        try:
            got: dict = {}
            sk2 = reader._unseal_sk()
            try:
                for (id, n) in want:
                    blob = new_files.read(id) if n is None else new_files.read_history(id, n)
                    got[(id, n)] = hashlib.sha256(_fmt.dumps(
                        _entries.open_box(bytes(sk2), blob, id))).hexdigest()
            finally:
                sk2.wipe()
            if got != want or reader._doc != doc \
                    or reader.load_session() != sess \
                    or reader.load_nicknames() != dict(self._nick or {}):
                raise StoreError("the TPM-sealed copy does not read back as the store")
        finally:
            reader.lock()
        return doc

    # --- tier 1: metadata ---------------------------------------------------------------------
    @_serialized
    def list_meta(self) -> list[Meta]:
        """Every live entry's Meta. Raises StoreLocked."""
        self._need_unlocked()
        out = [_meta.to_meta(i, r, self._nick.get(i, "")) for i, r in _meta.live(self._doc)]
        out.sort(key=lambda m: (m.title.lower(), m.username.lower(), m.id))
        return out

    @_serialized
    def get_meta(self, id: str) -> Meta:
        """One live entry's Meta. Raises StoreLocked or EntryNotFound."""
        self._need_unlocked()
        return _meta.to_meta(id, self._live(id), self._nick.get(id, ""))

    @_serialized
    def set_sync_status(self, *, synced_at: float | None = None,
                        needs_login: bool | None = None) -> None:
        """Record the outcome of a sync (fields left None are unchanged). Raises StoreLocked."""
        self._need_unlocked()
        if synced_at is not None:
            self._doc["synced_at"] = float(synced_at)
        if needs_login is not None:
            self._doc["needs_login"] = bool(needs_login)
        self._write_meta()

    # --- tier 2: one entry ---------------------------------------------------------------------
    @_serialized
    def open_entry(self, id: str) -> Secrets:
        """Unseal SK_secret, open entries/<id>.box, check the id inside it, wipe SK_secret at
        once, and return the plaintext. Increments unseal_count. The caller owns the result
        and must drop it when the grant ends. Raises StoreLocked, EntryNotFound, SealError."""
        self._need_unlocked()
        rec = self._live(id)
        files = _entries.EntryFiles(self._dir)
        blob = files.read(id)
        if blob is None:
            raise SealError("damaged", "entry box is missing")
        sk = self._unseal_sk()
        try:
            payload = _entries.open_box(bytes(sk), blob, id, int(rec.get("v", 0)))
        finally:
            sk.wipe()
        return _entries.from_payload(payload)

    @_serialized
    def history(self, id: str) -> list[tuple[str, str]]:
        """Earlier values of the entry's password, newest first, as (iso8601 date, value):
        the local history boxes merged with Apple's own history. Unseals SK_secret like
        open_entry. Raises StoreLocked, EntryNotFound, SealError."""
        self._need_unlocked()
        rec = self._live(id)
        files = _entries.EntryFiles(self._dir)
        blob = files.read(id)
        hist = list(rec.get("hist") or [])
        blobs = [(h, files.read_history(id, h["n"])) for h in hist]
        if blob is None or any(b is None for _, b in blobs):
            raise SealError("damaged", "an entry or history box is missing")
        sk = self._unseal_sk()
        try:
            current = _entries.open_box(bytes(sk), blob, id, int(rec.get("v", 0)))
            local = [(float(h.get("at") or 0.0), _entries.open_box(bytes(sk), b, id)["password"],
                      h.get("source") or "local") for h, b in blobs]
        finally:
            sk.wipe()
        return _merge_history(local, current.get("apple_history") or [])

    @_serialized
    def set_secrets(self, id: str, s: Secrets) -> None:
        """Replace one entry's secrets after a successful iCloud push: move the old box into
        history/<id>/ without decrypting it, seal the new one to PK_secret, update pwmac and
        mdat in meta. Never unseals SK_secret."""
        self._need_unlocked()
        rec = self._live(id)
        _entries.check_secrets(s)
        self._replace_secrets(id, rec, s, source="local", when=_time.time())
        rec["mdat"] = _time.time()
        self._write_meta()

    # --- sync ----------------------------------------------------------------------------------
    @_serialized
    def apply_sync(self, items: Iterable[SyncItem], deleted: set[str]) -> dict:
        """Upsert what iCloud returned, using PK_secret and pwmac only.

        For each item: write its Meta; if pwmac(password) differs from the stored one, move
        the old box to history and seal the new secrets; if only non-password secrets changed,
        re-seal the box (the old one is not history). Ids in `deleted` are tombstoned in meta.
        Returns {"added": n, "changed": n, "deleted": n, "unchanged": n}.
        Must never unseal SK_secret (unseal_count stays unchanged)."""
        self._need_unlocked()
        items = list(items)
        for it in items:
            if not isinstance(it, SyncItem) or not isinstance(it.meta, Meta):
                raise ValueError("apply_sync takes SyncItems")
            _check_id(it.id)
            if it.meta.id != it.id:
                raise ValueError("SyncItem.meta.id differs from SyncItem.id")
            _entries.check_secrets(it.secrets)
        gone = set(deleted or ())
        counts = {"added": 0, "changed": 0, "deleted": 0, "unchanged": 0}
        entries = self._doc["entries"]
        now = _time.time()
        for it in items:
            fields = _meta.fields_from(it.meta)
            fields["has_totp"] = bool(it.secrets.totp_secret)
            # The tag line is read from the plaintext this sync already holds (no SK); the box
            # keeps the whole raw notes, so the smac and byte fidelity are unchanged.
            fields.update(_meta.notes_fields(it.secrets.notes))
            rec = entries.get(it.id)
            if rec is None or rec.get("deleted"):
                if rec is None:
                    rec = entries[it.id] = {"v": 0, "hist": []}
                rec.pop("deleted", None)
                rec.pop("deleted_at", None)
                rec.update(fields)
                self._replace_secrets(it.id, rec, it.secrets, source="local", when=now)
                counts["added"] += 1
                continue
            hist_before = tuple(h.get("n") for h in rec.get("hist") or [])
            touched = self._replace_secrets(it.id, rec, it.secrets, source="local", when=now)
            if touched or not _meta.same_fields(rec, fields):
                rec.update(fields)
                counts["changed"] += 1
            else:
                counts["unchanged"] += 1
            if tuple(h.get("n") for h in rec.get("hist") or []) != hist_before:
                # A box moved into history: record it now, so a crash before the end of the
                # sync cannot leave a history box meta does not know (and a stale pwmac that
                # would file the current password as history on the next sync).
                self._write_meta()
        for id in gone:
            rec = entries.get(id) if isinstance(id, str) else None
            if rec is not None and not rec.get("deleted"):
                rec["deleted"], rec["deleted_at"] = True, now
                counts["deleted"] += 1
        self._write_meta()
        return counts

    @_serialized
    def pwmac_matches(self, texts: list[str]) -> list[int]:
        """Indexes of `texts` whose HMAC(K_pwmac, text) equals some entry's current pwmac.
        Used by clip-history-check; compares MACs only, no SK. Raises StoreLocked."""
        self._need_unlocked()
        known = {r.get("pwmac") for _, r in _meta.live(self._doc)}
        k = self._sub["pwmac"]
        return [i for i, t in enumerate(texts)
                if isinstance(t, str) and _keys.pwmac(k, t) in known]

    # --- session, aliases, nicknames (tier 1 subkeys) -------------------------------------------
    @_serialized
    def load_session(self) -> dict:
        """The former session.enc contents ({} when signed out). Raises StoreLocked."""
        self._need_unlocked()
        return _ss.load_session(self._dir, self._sub["session"], self.uid)

    @_serialized
    def save_session(self, d: dict) -> None:
        """Replace session.v2. An empty dict removes it (sign-out). Raises StoreLocked."""
        self._need_unlocked()
        _ss.save_session(self._dir, self._sub["session"], self.uid, d)

    @_serialized
    def load_aliases(self) -> list[dict]:
        """Hide My Email aliases as plain dicts. Raises StoreLocked."""
        self._need_unlocked()
        return _ss.load_aliases(self._dir, self._sub["aliases"], self.uid)

    @_serialized
    def save_aliases(self, aliases: list[dict]) -> None:
        self._need_unlocked()
        _ss.save_aliases(self._dir, self._sub["aliases"], self.uid, aliases)

    @_serialized
    def load_nicknames(self) -> dict[str, str]:
        """Local nicknames by entry id. Raises StoreLocked."""
        self._need_unlocked()
        return dict(self._nick)

    @_serialized
    def save_nicknames(self, names: dict[str, str]) -> None:
        self._need_unlocked()
        _ss.save_nicknames(self._dir, self._sub["nicknames"], self.uid, names)
        self._nick = dict(names)

    def load_device(self) -> dict:
        """device.json (plaintext 0600, the Apple device identity - not a key). {} if absent."""
        return _ss.load_device(self._dir)

    @_serialized
    def save_device(self, d: dict) -> None:
        _fmt.ensure_dir(self._dir)
        _ss.save_device(self._dir, d)

    # --- plaintext settings (state.json) -------------------------------------------------------
    def load_settings(self) -> dict:
        """{grant_s, idle_lock_s, clip_timeout_s} merged over protocol.DEFAULT_SETTINGS, plus
        "old_copy": {"dir", "files": [{"name", "sha256"}], "migrated_at"} once a migration
        recorded one, and "migration_pending": True between migrate-begin and import-commit.
        Works while locked."""
        return _ss.load_settings(self._dir)

    @_serialized
    def save_settings(self, d: dict) -> None:
        """Validated by the caller; written as given."""
        _fmt.ensure_dir(self._dir)
        _ss.save_settings(self._dir, d)

    # --- migration from 1.x --------------------------------------------------------------------
    @_serialized
    def import_v1(self, files: dict[str, bytes], key: bytes) -> dict:
        """Convert a v1 vault (protocol.IMPORT_FILES contents, keyed by file name) opened with
        the 32-byte v1 key into this store.

        Builds everything in u<uid>.tmp/, re-opens it through the v2 loaders, and compares
        counts and a SHA-256 over the canonical plaintext JSON with the figures from the v1
        read. On a match the tmp tree replaces the data files of u<uid>; on a mismatch it is
        removed and ImportMismatch is raised. Never unlinks or rewrites anything the caller
        passed in. Requires the store unlocked (it was just created by migrate-begin).

        Returns {"counts": {"credentials", "history", "nicknames", "aliases", "session_keys"},
        "digest": hex sha256}."""
        from . import importer
        return importer.import_v1(self, files, key)

    # --- internals -----------------------------------------------------------------------------
    def _keys_dir(self) -> _Path:
        return self._dir / _paths.KEYS_DIR

    def _has_keys(self) -> bool:
        kd = self._keys_dir()
        return _os.path.lexists(kd / _paths.KEYS_JSON) or _os.path.lexists(kd / _paths.LIST_CRED)

    def _cred_name(self, tier: str) -> str:
        return _system_paths.credential_name(tier, self.uid)

    @staticmethod
    def _cred_file(tier: str) -> str:
        return {"list": _paths.LIST_CRED, "secret": _paths.SECRET_CRED}[tier]

    def _need_unlocked(self) -> None:
        if self._rk is None:
            raise StoreLocked("the store is locked")

    def _live(self, id: str) -> dict:
        rec = _meta.live_record(self._doc, id)
        if rec is None:
            raise EntryNotFound(id)
        return rec

    def _read_keys_json(self) -> dict | None:
        raw = _fmt.read_file(self._keys_dir() / _paths.KEYS_JSON, 65536)
        if raw is None:
            return None
        doc = _fmt.loads(raw, _paths.KEYS_JSON)
        if not isinstance(doc, dict):
            raise SealError("damaged", "keys.json has the wrong shape")
        return doc

    def _write_keys_json(self, d: dict) -> None:
        _fmt.atomic_write(self._keys_dir() / _paths.KEYS_JSON, _fmt.dumps(d))

    def _write_meta(self) -> None:
        # Take both at once: never seal a None doc (an encrypted `null` would replace meta.v2).
        sub, doc = self._sub, self._doc
        if sub is None or doc is None:
            raise StoreLocked("the store was locked")
        _fmt.write_sealed(self._dir, _paths.META_FILE, bytes(sub["meta"]),
                          _fmt.KIND_META, self.uid, doc)

    def _verify_blob(self, backend, tier: str, blob, want) -> None:
        if blob is None:
            raise SealError("damaged", f"{tier} blob vanished")
        try:
            got = backend.decrypt(self._cred_name(tier), blob)
        except _seal.UnsealRefused:
            raise SealError("damaged", f"freshly sealed {tier} blob does not open") from None
        if not _hmac.compare_digest(bytes(got), bytes(want)):
            raise SealError("damaged", f"freshly sealed {tier} blob opens to something else")

    def _unseal(self, tier: str, blob: bytes, backend) -> _keys.SecretBytes:
        """UnsealRefused and SealUnavailable pass through; the caller decides what they mean."""
        plain = backend.decrypt(self._cred_name(tier), blob)
        try:
            if len(plain) != _keys.KEY_BYTES:
                raise SealError("damaged", f"{tier} key has the wrong length")
            return _keys.SecretBytes(plain)
        finally:
            del plain

    def _unseal_list(self) -> _keys.SecretBytes:
        """RK_list from list.cred, rolling back to list.cred.prev (the blobs from before the
        last re-seal) when the current blob is refused and the previous one still opens."""
        backend = _seal.get_backend()
        kd = self._keys_dir()
        kj = self._read_keys_json()
        blob = _fmt.read_file(kd / _paths.LIST_CRED, 65536)
        if kj is not None and blob is not None:
            try:
                return self._unseal("list", blob, backend)
            except _seal.UnsealRefused:
                pass
        rk = self._rollback(backend)
        if rk is not None:
            return rk
        if kj is None or blob is None:
            raise SealError("damaged", "keys.json or list.cred is missing")
        raise SealError(_seal.classify(backend, kj.get("sealed_with"), kj.get("tpm_srk_fp")),
                        "list.cred was refused")

    def _rollback(self, backend) -> _keys.SecretBytes | None:
        kd = self._keys_dir()
        prev = {n: kd / (n + _paths.PREV_SUFFIX)
                for n in (_paths.LIST_CRED, _paths.SECRET_CRED, _paths.KEYS_JSON)}
        if not all(p.exists() for p in prev.values()):
            return None
        try:
            rk = self._unseal("list", _fmt.read_file(prev[_paths.LIST_CRED], 65536), backend)
        except (_seal.UnsealRefused, SealError):
            return None
        for name, p in prev.items():
            _os.replace(p, kd / name)
        _fmt.fsync_dir(kd)
        _log.warning("u%d: re-sealed keys were refused; rolled back to the previous blobs",
                     self.uid)
        return rk

    def _drop_prev(self) -> None:
        """The rollback window of a re-seal from before key rotation closes at the first
        successful unlock - but only when the current set is complete: a .prev must never go
        while it is the only copy of a key."""
        kd = self._keys_dir()
        names = (_paths.LIST_CRED, _paths.SECRET_CRED, _paths.KEYS_JSON)
        if not all((kd / n).is_file() for n in names) \
                or any(_os.path.lexists(kd / (n + _paths.NEW_SUFFIX)) for n in names):
            return
        dropped = False
        for name in (_paths.LIST_CRED, _paths.SECRET_CRED, _paths.KEYS_JSON):
            try:
                _os.unlink(kd / (name + _paths.PREV_SUFFIX))
                dropped = True
            except FileNotFoundError:
                pass
        if dropped:
            _fmt.fsync_dir(kd)

    def _unseal_sk(self) -> _keys.SecretBytes:
        """SK_secret, briefly. The caller wipes it in a finally. Counted in unseal_count."""
        self._need_unlocked()
        backend = _seal.get_backend()
        blob = _fmt.read_file(self._keys_dir() / _paths.SECRET_CRED, 65536)
        if blob is None:
            raise SealError("damaged", "secret.cred is missing")
        self.unseal_count += 1
        try:
            sk = self._unseal("secret", blob, backend)
        except _seal.UnsealRefused:
            kj = self._read_keys_json() or {}
            raise SealError(_seal.classify(backend, kj.get("sealed_with"),
                                           kj.get("tpm_srk_fp")),
                            "secret.cred was refused") from None
        if not _keys.sk_matches_pk(bytes(sk), self._pk):
            sk.wipe()
            raise SealError("damaged", "secret.cred does not match secret.pub")
        return sk

    def _replace_secrets(self, id: str, rec: dict, s: Secrets, *, source: str,
                         when: float) -> bool:
        """Seal `s` as the entry's current box if it differs from what meta says the box
        holds. A different password moves the old box into history first; other changes
        re-seal in place. Returns whether a box was written. Meta is updated in `rec` and
        written by the caller. Uses PK_secret only.

        A box that held no password (a passkey-only row, which shares its id with a login for
        the same account) is never history: it would file a blank "previous password" and take
        a history slot from a real one. A password removed (the login gone, the passkey kept)
        is a real previous password and is kept as history."""
        k = self._sub["pwmac"]
        pwm = _keys.pwmac(k, s.password)
        sm = _keys.smac(k, _entries.rest_canonical(s))
        files = _entries.EntryFiles(self._dir)
        has_box = files.exists(id)
        if has_box and rec.get("pwmac") == pwm and rec.get("smac") == sm:
            return False
        no_password = rec.get("kind") == "passkey" or rec.get("pwmac") == _keys.pwmac(k, "")
        if has_box and rec.get("pwmac") not in (None, pwm) and not no_password:
            hist = rec.setdefault("hist", [])
            n = files.next_number(id, [h["n"] for h in hist])
            if files.move_to_history(id, n):
                hist.append({"n": n, "at": when, "source": source})
                while len(hist) > _entries.MAX_HISTORY:
                    files.drop_history(id, hist.pop(0)["n"])
        v = int(rec.get("v") or 0) + 1
        files.write(id, _entries.seal(self._pk, _entries.to_payload(id, v, s)))
        rec.update({"v": v, "pwmac": pwm, "smac": sm, "apple_n": len(s.apple_history or []),
                    "has_totp": bool(s.totp_secret), **_meta.notes_fields(s.notes)})
        return True


def _keeps_nothing(d) -> bool:
    """No entry or history box, no iCloud session, no aliases and no nicknames under the
    store directory d, read without a key. False when it cannot tell."""
    d = _Path(d)
    for name in (_paths.SESSION_FILE, _paths.ALIASES_FILE, _paths.NICKNAMES_FILE):
        if _os.path.lexists(d / name):
            return False
    for sub in (_paths.ENTRIES_DIR, _paths.HISTORY_DIR):
        try:
            with _os.scandir(d / sub) as it:
                if any(True for _ in it):
                    return False
        except FileNotFoundError:
            continue
        except OSError:
            return False                  # cannot tell: treat it as holding something
    return True


def _remove_tree(path) -> None:
    """Remove a directory the store created beside a user directory. Refuses a symlink."""
    import shutil
    p = _Path(path)
    if p.is_symlink():
        raise StoreError(f"{p} is a symlink")
    if p.exists():
        shutil.rmtree(p)
        _fmt.fsync_dir(p.parent)


def _ts(iso: str) -> float:
    try:
        return _dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _iso(ts: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return "1970-01-01T00:00:00Z"


def _merge_history(local: list, apple: list) -> list:
    """Local history (at, value, source) and Apple's [{date, value}], newest first. An Apple
    item with the same value in the same minute as a local one is the same change seen twice;
    the local one wins."""
    items = [(at, _entries.HistoryItem(_iso(at), value, "local")) for at, value, _ in local]
    known = {(value, round(at / 60)) for at, value, _ in local}
    for h in apple:
        if not isinstance(h, dict) or not isinstance(h.get("value"), str):
            continue
        at = _ts(h.get("date"))
        if (h["value"], round(at / 60)) in known:
            continue
        items.append((at, _entries.HistoryItem(str(h.get("date") or _iso(at)), h["value"],
                                               "apple")))
    items.sort(key=lambda p: p[0], reverse=True)
    return [item for _, item in items]


def v1_key_from_passphrase(kdf_json: bytes, passphrase: str) -> bytes:
    """Argon2id(passphrase) with the salt and limits from the v1 kdf.json (256 MiB at the
    moderate preset). Returns the 32-byte v1 key; does not check it."""
    from . import legacy
    return legacy.key_from_passphrase(kdf_json, passphrase)


def v1_key_opens(check_enc: bytes, key: bytes) -> bool:
    """True if `key` opens the v1 check.enc. Constant-time with respect to the key."""
    from . import legacy
    return legacy.key_opens(check_enc, key)


def v1_key_verifies(files: dict, key: bytes) -> bool:
    """True if `key` is the v1 vault's key: check.enc when present, else vault.enc (a vault
    1.x keyed by the login keyring has no check.enc)."""
    from . import legacy
    return legacy.key_verifies(files, key)


__all__ = [
    "EntryNotFound", "ImportMismatch", "Meta", "SealError", "SealKind", "Secrets",
    "StoreError", "StoreLocked", "StoreState", "SyncItem", "UserStore", "WrongPassphrase",
    "v1_key_from_passphrase", "v1_key_opens", "v1_key_verifies",
]
