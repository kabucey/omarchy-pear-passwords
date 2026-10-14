"""The on-disk format of every `.v2` file, and the one way anything in the store is written.

A `.v2` file is

    "PPW2" | kind (1 byte) | nonce (24 bytes) | XChaCha20-Poly1305-IETF ciphertext

with associated data `"PPW2" | kind | uid (u32 big-endian) | file name`. The AAD is what makes
the files impossible to swap: meta.v2 cannot be passed off as session.v2 (kind and name), and
u1000's meta cannot be passed off as u1001's (uid), even though every file of one user is
under keys derived from the same RK_list.

Writes are always: a new temp file in the same directory created 0600 with O_EXCL, the data,
fsync, rename over the target, fsync of the directory. A reader therefore sees the old file or
the new one, never half of either, and after a crash the rename is either durable or not there.

Reads never repair anything. A file that fails its check raises SealError("damaged") and stays
exactly as it was, for diagnosis - 1.x's habit of deleting a vault it could not decrypt turned
a wrong key into lost data.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import struct
from pathlib import Path

import nacl.bindings
import nacl.exceptions

from . import SealError

MAGIC = b"PPW2"
NONCE_BYTES = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES     # 24
KEY_BYTES = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES        # 32
HEADER_BYTES = len(MAGIC) + 1 + NONCE_BYTES

KIND_META = 1
KIND_SESSION = 2
KIND_ALIASES = 3
KIND_NICKNAMES = 4
KINDS = (KIND_META, KIND_SESSION, KIND_ALIASES, KIND_NICKNAMES)

# Nothing the daemon reads back is anywhere near this; it bounds a read of a planted file.
MAX_FILE = 64 * 1024 * 1024


def aad(kind: int, uid: int, filename: str) -> bytes:
    if kind not in KINDS:
        raise ValueError(f"unknown file kind {kind}")
    if "/" in filename or not filename:
        raise ValueError("file name, not a path")
    return MAGIC + bytes([kind]) + struct.pack(">I", uid) + filename.encode("ascii")


def encrypt(key: bytes, kind: int, uid: int, filename: str, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad(kind, uid, filename), nonce, bytes(key))
    return MAGIC + bytes([kind]) + nonce + ct


def decrypt(key: bytes, kind: int, uid: int, filename: str, blob: bytes) -> bytes:
    """The plaintext, or SealError("damaged"). Never touches the file the blob came from."""
    if len(blob) < HEADER_BYTES + 16 or blob[:4] != MAGIC or blob[4] != kind:
        raise SealError("damaged", f"{filename}: bad header")
    nonce = blob[5:HEADER_BYTES]
    try:
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            blob[HEADER_BYTES:], aad(kind, uid, filename), nonce, bytes(key))
    except nacl.exceptions.CryptoError:
        raise SealError("damaged", f"{filename}: does not authenticate") from None


# --- JSON ------------------------------------------------------------------------------------

def dumps(obj) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8. Used for everything hashed or MACed
    as well as stored, so the same value always has the same bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def loads(data: bytes, what: str):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SealError("damaged", f"{what}: not JSON") from None


# --- files -----------------------------------------------------------------------------------

def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    """Create `path` (and missing parents) with `mode`; refuse a symlink or a non-directory."""
    path = Path(path)
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass
    except FileNotFoundError:
        ensure_dir(path.parent, mode)
        os.mkdir(path, mode)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(f"{path} is not a directory")
    if stat.S_IMODE(st.st_mode) != mode:
        os.chmod(path, mode)
    return path


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


_AT_FDCWD = -100
_RENAME_EXCHANGE = 2


def exchange(a: Path, b: Path) -> None:
    """Swap two paths in one step (renameat2 RENAME_EXCHANGE): at every moment each name
    holds one complete tree. OSError if the kernel or filesystem cannot."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    fn = getattr(libc, "renameat2", None)
    if fn is None:
        raise OSError(38, "renameat2 is not available")
    fn.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    fn.restype = ctypes.c_int
    if fn(_AT_FDCWD, os.fsencode(str(a)), _AT_FDCWD, os.fsencode(str(b)), _RENAME_EXCHANGE) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Replace `path` with `data`: O_EXCL temp file (0600 from creation), fsync, rename, fsync
    of the directory. The temp file is removed if anything fails before the rename."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            if mode != 0o600:
                os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(path.parent)


def read_file(path: Path, max_size: int = MAX_FILE) -> bytes | None:
    """The file's bytes, or None when it does not exist. Refuses a symlink, a non-regular file
    and anything over max_size (as damaged: the daemon never wrote such a file)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise SealError("damaged", f"{Path(path).name}: cannot open ({e.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_size:
            raise SealError("damaged", f"{Path(path).name}: not a regular file of sane size")
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_sealed(directory: Path, filename: str, key: bytes, kind: int, uid: int,
                 obj) -> None:
    atomic_write(Path(directory) / filename, encrypt(key, kind, uid, filename, dumps(obj)))


def read_sealed(directory: Path, filename: str, key: bytes, kind: int, uid: int):
    """The decoded JSON of a `.v2` file, None if the file does not exist, or SealError."""
    blob = read_file(Path(directory) / filename)
    if blob is None:
        return None
    return loads(decrypt(key, kind, uid, filename, blob), filename)
