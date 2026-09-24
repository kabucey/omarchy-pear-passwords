"""Encrypted local vault of decrypted credentials (read by the app's backend). Persisted with the
same libsodium secret box + keyring master key as the auth session, file mode 0600."""

from __future__ import annotations

import json
import logging

import nacl.exceptions
import nacl.secret

from .. import paths
from ..errors import EncryptedStoreError
from .host import Credential, CredentialStore
from ..auth.session import _master_key


class VaultError(EncryptedStoreError):
    """The local vault exists but its ciphertext or JSON cannot be trusted."""


@paths.mutation_lock
def save_vault(store: CredentialStore, *, path=None) -> None:
    creds = [c.storage_dict() for c in store.all()]
    box = nacl.secret.SecretBox(_master_key())
    blob = box.encrypt(json.dumps({"credentials": creds}).encode())
    f = path or paths.vault_file()
    paths.atomic_write_private(f, blob)


def load_vault() -> CredentialStore:
    f = paths.vault_file()
    if not f.exists():
        return CredentialStore([])
    box = nacl.secret.SecretBox(_master_key())
    try:
        data = json.loads(box.decrypt(f.read_bytes()).decode())
        if not isinstance(data, dict) or not isinstance(data.get("credentials"), list):
            raise ValueError("invalid vault document")
        creds = [Credential(domain=c.get("domain", ""), username=c.get("username", ""),
                            password=c.get("password", ""), title=c.get("title", ""),
                            mdat=c.get("mdat", 0.0), totp=c.get("totp"),
                            notes=c.get("notes", ""),
                            aliases=tuple(c.get("aliases") or ()),
                            apple_history=tuple(c.get("apple_history") or ()),
                            apple_title=c.get("apple_title", ""),
                            sites=tuple(c.get("sites") or ()))
                 for c in data["credentials"]]
    except (nacl.exceptions.CryptoError, OSError, UnicodeError, ValueError, TypeError,
            AttributeError, KeyError) as e:
        logging.getLogger(__name__).warning(
            "cannot decrypt or parse %s; preserving the ciphertext and refusing to serve it",
            f)
        raise VaultError(
            f"cannot decrypt or parse {f}; ciphertext was preserved - refusing to use the "
            "vault until it is repaired or replaced") from e
    return CredentialStore(creds)
