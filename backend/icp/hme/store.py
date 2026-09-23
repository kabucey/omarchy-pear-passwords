"""Encrypted local cache of Hide My Email aliases (read by the native host). Same encryption as
`vault/store.py`; refreshed by `icp show`/`icp sync` so the host serves a snapshot, never live."""

from __future__ import annotations

import dataclasses
import json
import logging

import nacl.exceptions
import nacl.secret

from .. import paths
from ..auth.session import _master_key
from ..errors import EncryptedStoreError
from .client import HmeAlias


class AliasesError(EncryptedStoreError):
    """The local alias cache exists but its ciphertext or JSON cannot be trusted."""


@paths.mutation_lock
def save_aliases(aliases: list[HmeAlias], *, path=None) -> None:
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps({"aliases": [dataclasses.asdict(a) for a in aliases]}).encode())
    f = path or paths.aliases_file()
    paths.atomic_write_private(f, blob)


def load_aliases() -> list[HmeAlias]:
    f = paths.aliases_file()
    if not f.exists():
        return []
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
        if not isinstance(data, dict) or not isinstance(data.get("aliases"), list):
            raise ValueError("invalid aliases document")
        return [HmeAlias(**a) for a in data["aliases"]]
    except (nacl.exceptions.CryptoError, OSError, UnicodeError, ValueError, TypeError,
            AttributeError, KeyError) as e:
        logging.getLogger(__name__).warning(
            "cannot decrypt or parse %s; preserving the ciphertext and refusing to use it", f)
        raise AliasesError(
            f"cannot decrypt or parse {f}; ciphertext was preserved - refusing to use the "
            "alias cache until it is repaired or replaced"
        ) from e
