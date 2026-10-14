"""Entry boxes: one sealed file per account, and its earlier versions kept unopened.

    entries/<id>.box        crypto_box_seal(PK_secret, pad256(json{id, v, password, notes,
                            totp_secret, totp_params, apple_history}))
    history/<id>/<n>.box    an earlier entries/<id>.box, moved here by rename, never opened

A sealed box needs only the public key to write, which is the point: sync and edits replace
boxes with PK_secret alone, and SK_secret is unsealed only when a person asked for one entry
(open_entry, history). Padding to 256 bytes keeps a box's size from telling a short password
from a long one.

The box carries its own id and version. Opening checks both, so a box copied over another
entry's file, or an old history box renamed back into entries/, is refused as damaged instead
of being served as that entry's current password. The version check is "at least the one in
meta", because a crash between writing a new box and writing meta leaves the box one ahead;
the next sync repairs meta.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import nacl.bindings
import nacl.exceptions
import nacl.public

from .. import paths
from . import Secrets, SealError
from . import format as fmt
from .ids import check_id

PAD_BLOCK = 256
MAX_BOX = 1024 * 1024
MAX_HISTORY = 50          # per entry, as 1.x: a runaway rotation must not grow without bound


class HistoryItem(tuple):
    """One earlier password: a plain `(date, value)` pair, as UserStore.history() promises,
    that also knows where it came from (`.source`: "local" for a change this machine saw,
    "apple" for Apple's own record), because the protocol's history reply reports it."""

    def __new__(cls, date: str, value: str, source: str):
        item = super().__new__(cls, (date, value))
        item.source = source
        return item


# --- payloads --------------------------------------------------------------------------------

def _rest(s: Secrets) -> dict:
    return {
        "notes": s.notes or "",
        "totp_secret": base64.b64encode(s.totp_secret).decode() if s.totp_secret else None,
        "totp_params": dict(s.totp_params or {}) if s.totp_secret else {},
        "apple_history": [dict(h) for h in (s.apple_history or [])],
    }


def rest_canonical(s: Secrets) -> bytes:
    """Canonical bytes of everything but the password, for the smac."""
    return fmt.dumps(_rest(s))


def to_payload(id: str, v: int, s: Secrets) -> dict:
    check_secrets(s)
    return {"id": id, "v": int(v), "password": s.password, **_rest(s)}


def from_payload(p: dict) -> Secrets:
    try:
        seed = p.get("totp_secret")
        return Secrets(password=str(p["password"]), notes=str(p.get("notes") or ""),
                       totp_secret=base64.b64decode(seed, validate=True) if seed else None,
                       apple_history=list(p.get("apple_history") or []),
                       totp_params=dict(p.get("totp_params") or {}))
    except (KeyError, TypeError, ValueError):
        raise SealError("damaged", "entry box has the wrong shape") from None


def check_secrets(s: Secrets) -> None:
    """Shape checks on what a caller hands in, before anything is sealed."""
    if not isinstance(s, Secrets) or not isinstance(s.password, str) \
            or not isinstance(s.notes, str):
        raise ValueError("Secrets needs str password and notes")
    if s.totp_secret is not None and not isinstance(s.totp_secret, (bytes, bytearray)):
        raise ValueError("totp_secret is raw bytes or None")
    if not isinstance(s.apple_history, list) or not isinstance(s.totp_params or {}, dict):
        raise ValueError("apple_history is a list, totp_params a dict")
    for h in s.apple_history:
        if not isinstance(h, dict):
            raise ValueError("apple_history items are dicts")


# --- sealing ---------------------------------------------------------------------------------

def seal(pk: bytes, payload: dict) -> bytes:
    data = nacl.bindings.sodium_pad(fmt.dumps(payload), PAD_BLOCK)
    return nacl.public.SealedBox(nacl.public.PublicKey(pk)).encrypt(data)


def open_box(sk: bytes, blob: bytes, expect_id: str, min_v: int | None = None) -> dict:
    """The payload of a box, checked to be `expect_id`'s (and, for a current box, at least
    version min_v). SealError("damaged") otherwise; the file is never touched."""
    try:
        data = nacl.public.SealedBox(nacl.public.PrivateKey(sk)).decrypt(blob)
        data = nacl.bindings.sodium_unpad(data, PAD_BLOCK)
    except (nacl.exceptions.CryptoError, ValueError, TypeError):
        raise SealError("damaged", "entry box does not open") from None
    p = fmt.loads(data, "entry box")
    if not isinstance(p, dict) or p.get("id") != expect_id:
        raise SealError("damaged", "entry box belongs to another entry")
    if min_v is not None and not (isinstance(p.get("v"), int) and p["v"] >= min_v):
        raise SealError("damaged", "entry box is older than its metadata")
    return p


# --- files -----------------------------------------------------------------------------------

class EntryFiles:
    """The entries/ and history/ trees of one user directory."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.entries = self.root / paths.ENTRIES_DIR
        self.history = self.root / paths.HISTORY_DIR

    def box_path(self, id: str) -> Path:
        return self.entries / (check_id(id) + paths.BOX_SUFFIX)

    def history_dir(self, id: str) -> Path:
        return self.history / check_id(id)

    def history_path(self, id: str, n: int) -> Path:
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ValueError("bad history number")
        return self.history_dir(id) / f"{n}{paths.BOX_SUFFIX}"

    def ensure(self) -> None:
        fmt.ensure_dir(self.entries)
        fmt.ensure_dir(self.history)

    def write(self, id: str, blob: bytes) -> None:
        fmt.ensure_dir(self.entries)
        fmt.atomic_write(self.box_path(id), blob)

    def read(self, id: str) -> bytes | None:
        return fmt.read_file(self.box_path(id), MAX_BOX)

    def exists(self, id: str) -> bool:
        return self.box_path(id).exists()

    def numbers(self, id: str) -> list[int]:
        """History numbers on disk for `id`, ascending (stray names are ignored)."""
        try:
            names = os.listdir(self.history_dir(id))
        except FileNotFoundError:
            return []
        out = []
        for name in names:
            stem = name[:-len(paths.BOX_SUFFIX)] if name.endswith(paths.BOX_SUFFIX) else ""
            if stem.isdigit() and str(int(stem)) == stem:
                out.append(int(stem))
        return sorted(out)

    def next_number(self, id: str, known: list[int]) -> int:
        """One past everything meta knows and everything on disk, so a box left by a crash is
        never overwritten."""
        return max([0, *known, *self.numbers(id)]) + 1

    def move_to_history(self, id: str, n: int) -> bool:
        """Rename the current box to history/<id>/<n>.box without opening it. False if there
        was no current box. Refuses to replace an existing history file."""
        src = self.box_path(id)
        if not src.exists():
            return False
        d = fmt.ensure_dir(self.history_dir(id))
        dst = self.history_path(id, n)
        os.link(src, dst)                 # fails rather than replace an existing file
        os.unlink(src)
        fmt.fsync_dir(d)
        fmt.fsync_dir(self.entries)
        return True

    def write_history(self, id: str, n: int, blob: bytes) -> None:
        """A history box written directly (the v1 import, which has old values but no old
        boxes to move)."""
        fmt.ensure_dir(self.history_dir(id))
        fmt.atomic_write(self.history_path(id, n), blob)

    def read_history(self, id: str, n: int) -> bytes | None:
        return fmt.read_file(self.history_path(id, n), MAX_BOX)

    def drop_history(self, id: str, n: int) -> None:
        """Remove one history box past MAX_HISTORY. The only unlink of entry data in the
        store, and it is a retention limit, never a reaction to a read error."""
        try:
            os.unlink(self.history_path(id, n))
        except FileNotFoundError:
            pass
