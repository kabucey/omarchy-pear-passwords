"""The key hierarchy under one user's two sealed blobs (spec section 3).

    RK_list   (32 random bytes, keys/list.cred)
      +-- HKDF-SHA256(RK_list, "pear/v2/meta")       K_meta      meta.v2, the PK MAC
      +-- HKDF-SHA256(RK_list, "pear/v2/session")    K_sess      session.v2
      +-- HKDF-SHA256(RK_list, "pear/v2/aliases")    K_alias     aliases.v2
      +-- HKDF-SHA256(RK_list, "pear/v2/nicknames")  K_nick      nicknames.v2
      +-- HKDF-SHA256(RK_list, "pear/v2/pwmac")      K_pwmac     pwmac / smac of each entry
    SK_secret (X25519 private, keys/secret.cred)   opens entries/<id>.box and history boxes
    PK_secret (keys/secret.pub, MACed with K_meta)  seals them: sync and edits need only this

secret.pub carries `HMAC-SHA256(K_meta, "pk" || PK)` so a planted public key cannot make the
daemon seal new passwords to a key someone else holds: the MAC is checked at every unlock and
before every seal, and only RK_list can produce it.

Python cannot promise that a key has no other copy in memory (bytes are immutable and get
copied by every call into libsodium). SecretBytes keeps the long-lived copy in an mlock'd
bytearray that is zeroed on wipe; that is the best this language offers, and the docs say
so. The real boundaries are the separate uid, the non-dumpable clients and the unit sandbox.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import secrets

import nacl.public
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import SealError

KEY_BYTES = 32
SUBKEYS = ("meta", "session", "aliases", "nicknames", "pwmac")
_INFO = {name: f"pear/v2/{name}".encode() for name in SUBKEYS}
_PK_LABEL = b"pk"
_PWMAC_LABEL = b"pw"
_SMAC_LABEL = b"s"


# --- memory ----------------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _libc():
    try:
        import ctypes
        return ctypes, ctypes.CDLL(None, use_errno=True)
    except Exception:                     # no ctypes, or a sandbox that refuses it
        return None, None


class SecretBytes:
    """A key held in an mlock'd bytearray (best effort) that wipe() zeroes in place."""

    __slots__ = ("_buf", "_addr", "_locked")

    def __init__(self, data):
        self._buf = bytearray(data)
        self._addr = None
        self._locked = False
        ctypes, libc = _libc()
        if ctypes is not None and self._buf:
            try:
                self._addr = ctypes.addressof((ctypes.c_char * len(self._buf))
                                              .from_buffer(self._buf))
                self._locked = libc.mlock(ctypes.c_void_p(self._addr),
                                          ctypes.c_size_t(len(self._buf))) == 0
            except Exception:
                self._addr = None

    def __bytes__(self) -> bytes:
        if not self._buf:
            raise SealError("damaged", "use of a wiped key")
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:
        return f"<SecretBytes {len(self._buf)} bytes>"

    def wipe(self) -> None:
        n = len(self._buf)
        for i in range(n):
            self._buf[i] = 0
        if self._locked:
            ctypes, libc = _libc()
            try:
                libc.munlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(n))
            except Exception:
                pass
            self._locked = False
        self._addr = None
        try:
            self._buf.clear()             # refused while a ctypes view is still alive
        except BufferError:
            self._buf = bytearray()


def wipe_all(*keys) -> None:
    for k in keys:
        if isinstance(k, SecretBytes):
            k.wipe()
        elif isinstance(k, dict):
            wipe_all(*k.values())


# --- generation and derivation ---------------------------------------------------------------

def new_root() -> SecretBytes:
    return SecretBytes(secrets.token_bytes(KEY_BYTES))


def new_keypair() -> tuple[SecretBytes, bytes]:
    """(SK_secret, PK_secret) for entry boxes."""
    sk = nacl.public.PrivateKey.generate()
    return SecretBytes(bytes(sk)), bytes(sk.public_key)


def derive(rk: SecretBytes) -> dict[str, SecretBytes]:
    """Every tier-1 subkey from RK_list."""
    if len(rk) != KEY_BYTES:
        raise SealError("damaged", "RK_list has the wrong length")
    raw = bytes(rk)
    try:
        return {name: SecretBytes(HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES,
                                       salt=None, info=_INFO[name]).derive(raw))
                for name in SUBKEYS}
    finally:
        del raw


# --- the public-key record -------------------------------------------------------------------

def pk_record(k_meta: SecretBytes, pk: bytes) -> bytes:
    """keys/secret.pub: PK_secret || HMAC-SHA256(K_meta, "pk" || PK_secret)."""
    if len(pk) != KEY_BYTES:
        raise ValueError("public key has the wrong length")
    return pk + hmac.new(bytes(k_meta), _PK_LABEL + pk, hashlib.sha256).digest()


def pk_from_record(k_meta: SecretBytes, record: bytes | None) -> bytes:
    """PK_secret, if its MAC verifies under K_meta; otherwise SealError("damaged")."""
    if record is None or len(record) != KEY_BYTES + 32:
        raise SealError("damaged", "secret.pub missing or the wrong size")
    pk, tag = record[:KEY_BYTES], record[KEY_BYTES:]
    want = hmac.new(bytes(k_meta), _PK_LABEL + pk, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, want):
        raise SealError("damaged", "secret.pub does not verify")
    return pk


def sk_matches_pk(sk: bytes, pk: bytes) -> bool:
    return hmac.compare_digest(bytes(nacl.public.PrivateKey(sk).public_key), pk)


# --- MACs that let sync work without SK_secret -----------------------------------------------

def pwmac(k_pwmac: SecretBytes, password: str) -> str:
    """HMAC(K_pwmac, password): how sync tells a changed password without opening the box,
    and how clip-history-check matches clipboard text without any entry key."""
    return hmac.new(bytes(k_pwmac), _PWMAC_LABEL + password.encode("utf-8", "surrogatepass"),
                    hashlib.sha256).hexdigest()


def smac(k_pwmac: SecretBytes, canonical_rest: bytes) -> str:
    """HMAC over the canonical JSON of an entry's other secrets (notes, TOTP, Apple history),
    so a sync can tell "only the notes changed" (re-seal, no history) from "nothing changed"
    without SK_secret. A separate label keeps it from ever equalling a pwmac."""
    return hmac.new(bytes(k_pwmac), _SMAC_LABEL + canonical_rest, hashlib.sha256).hexdigest()
