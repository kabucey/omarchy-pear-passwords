"""Passphrase-derived master key.

The upstream master key lives in the login keyring, which is unlocked for your entire desktop
session - so anything running as you can ask the Secret Service for it and read the whole vault.
A gate in front of that is theatre. The key therefore has to be something you supply and we never
store: Argon2id over a passphrase, with only the (non-secret) salt and cost parameters on disk.

`check.enc` exists purely to tell "wrong passphrase" apart from "corrupt vault" - without it a
typo and a damaged file are the same CryptoError, and the caller would helpfully delete the vault.
"""

from __future__ import annotations

import json

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import nacl.utils

from .. import paths
from ..errors import AppleError

_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE
_CHECK_PLAINTEXT = b"icp-lockbox-v1"

# Interactive cost. SENSITIVE would be better against offline cracking but takes seconds and
# ~1GB per unlock; MODERATE is the usual password-manager tradeoff for a key you unlock often.
_OPS = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
_MEM = nacl.pwhash.argon2id.MEMLIMIT_MODERATE


class WrongPassphrase(AppleError):
    pass


class NotInitialised(AppleError):
    pass


def params_file():
    return paths.config_dir() / "kdf.json"


def check_file():
    return paths.config_dir() / "check.enc"


def is_initialised() -> bool:
    return params_file().exists() and check_file().exists()


def _write_private(path, data: bytes) -> None:
    paths.atomic_write_private(path, data)


def derive(passphrase: str) -> bytes:
    """Passphrase -> 32-byte key using the stored salt. Does not verify it is correct."""
    if not is_initialised():
        raise NotInitialised("No passphrase has been set; run `icp passphrase` first.")
    params = json.loads(params_file().read_text())
    salt = bytes.fromhex(params["salt"])
    return nacl.pwhash.argon2id.kdf(
        _KEY_SIZE, passphrase.encode("utf-8"), salt,
        opslimit=params.get("opslimit", _OPS), memlimit=params.get("memlimit", _MEM),
    )


def verify(key: bytes) -> bool:
    """True if `key` decrypts the check blob, i.e. the passphrase was right."""
    try:
        return nacl.secret.SecretBox(key).decrypt(check_file().read_bytes()) == _CHECK_PLAINTEXT
    except (nacl.exceptions.CryptoError, OSError):
        return False


def unlock(passphrase: str) -> bytes:
    key = derive(passphrase)
    if not verify(key):
        raise WrongPassphrase("Wrong passphrase.")
    return key


def initialise(passphrase: str) -> bytes:
    """Set (or reset) the passphrase. Returns the new key so the caller can re-encrypt."""
    key, params, check = prepare_initialisation(passphrase)
    _write_private(params_file(), params)
    _write_private(check_file(), check)
    return key


def prepare_initialisation(passphrase: str) -> tuple[bytes, bytes, bytes]:
    """Build new KDF metadata and its check blob without changing the active lockbox files.

    Passphrase migration stages these bytes beside the existing files and publishes them only in
    the same journal commit as the encrypted stores.  Keeping this separate from ``initialise``
    makes a process death before commit recoverable without the old key.
    """
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    params = json.dumps(
        {"salt": salt.hex(), "opslimit": _OPS, "memlimit": _MEM, "alg": "argon2id"}
    ).encode()
    key = nacl.pwhash.argon2id.kdf(
        _KEY_SIZE, passphrase.encode("utf-8"), salt, opslimit=_OPS, memlimit=_MEM,
    )
    return key, params, nacl.secret.SecretBox(key).encrypt(_CHECK_PLAINTEXT)
