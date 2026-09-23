"""Encrypted session store.

In the default mode the master key lives in the GNOME login keyring (Secret Service), or in a
0600 key file when the user explicitly opts into that fallback. Once passphrase mode is enabled,
the key exists only in the private runtime agent after a passphrase unlock; it is never recovered
from a persistent copy.
"""

import base64
import binascii
import json
import logging
import os
import re
import uuid

import nacl.exceptions
import nacl.secret
import nacl.utils

from .. import paths
from ..errors import AppleError, PassphraseMigrationError

logger = logging.getLogger(__name__)

_ATTRS = {"application": "icp", "type": "master-key"}
_LABEL = "ApplePasswords-Linux master key"
_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE
_MASTER_CLEAN_MARKER = b"icp-master-key-clean-v1\n"
_PASSPHRASE_MIGRATION_ACTIVE = False
_MIGRATION_VERSION = 1
_MIGRATION_STATES = frozenset(("preparing", "committing", "committed"))
_MIGRATION_NAMES = ("params", "check", "session", "vault", "aliases", "history", "nicknames")
_MIGRATION_ID = re.compile(r"^[0-9a-f]{32}$")
_PASSPHRASE_MIGRATION_KEY = None


class SessionError(AppleError):
    """The stored session exists but cannot be read with the current master key."""


class MasterKeyCleanupError(SessionError):
    """The pre-passphrase keyring/file copy could not be removed."""


def _decode_key(stored: bytes | str | None) -> bytes | None:
    if stored is None:
        return None
    raw = stored.encode() if isinstance(stored, str) else bytes(stored)
    if len(raw) == _KEY_SIZE:
        return raw
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return key if len(key) == _KEY_SIZE else None


def _key_from_secret_service() -> bytes | None:
    try:
        import secretstorage
    except Exception:
        return None
    try:
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked() and coll.unlock():
            logger.warning("keyring unlock dismissed; using key file fallback")
            return None
        unusable = 0
        for item in coll.search_items(_ATTRS):
            key = _decode_key(item.get_secret())
            if key is not None:
                return key
            unusable += 1
        if unusable:
            logger.warning("keyring holds %d unusable master-key item(s); replacing them", unusable)
        key = nacl.utils.random(_KEY_SIZE)
        coll.create_item(_LABEL, _ATTRS, base64.b64encode(key), replace=True)
        return key
    except Exception as e:  # dbus not running, no keyring, etc.
        logger.warning("Secret Service unavailable (%s); using key file fallback", e)
        return None


def _key_from_file() -> bytes:
    f = paths.fallback_key_file()
    if f.exists():
        key = _decode_key(f.read_bytes())
        if key is not None:
            return key
        logger.warning("master key file %s is unusable; writing a fresh key", f)
    key = nacl.utils.random(_KEY_SIZE)
    _write_private(f, base64.b64encode(key))
    logger.warning("Stored master key at %s (0600) - less safe than the keyring", f)
    return key


@paths.mutation_lock
def _master_key() -> bytes:
    # Once a passphrase is set, it is the only source of the key: nothing derived from it is
    # stored, so there is no copy for a same-user process to fetch behind our back. The agent
    # caches it and drops it after ICP_LOCK_TIMEOUT. In particular, do not add a file fallback
    # here: that would turn `icp lock` into a cosmetic gate.
    recover_passphrase_migration()
    if _PASSPHRASE_MIGRATION_ACTIVE and _PASSPHRASE_MIGRATION_KEY is not None:
        return _PASSPHRASE_MIGRATION_KEY
    from . import agent, held_key, lockbox, prompt
    if lockbox.is_initialised():
        key = agent.get_key()
        if key is None:
            agent.unlock(prompt.ask_passphrase())
            key = agent.get_key()
        if key is None:
            raise SessionError("keychain is locked")
        # Versions before passphrase mode was made an at-rest boundary left the raw derived
        # key in vault.key (and, briefly, in a Secret Service item). The first unlock after an
        # upgrade removes those copies and records only a non-secret completion marker. Once
        # that marker is verified, ordinary unlocks do not depend on a live keyring connection.
        if not _PASSPHRASE_MIGRATION_ACTIVE:
            held_key.ensure_clean()
            # The pre-passphrase session key is a separate Secret Service namespace. A failed
            # migration cleanup must be retried on ordinary unlock/use, not only by rerunning
            # `icp passphrase`.
            ensure_legacy_master_key_clean()
        return key

    key = _key_from_secret_service()
    if key is not None:
        return key
    # Falling back writes the vault key to disk in the clear, which silently drops this to
    # "any process running as you reads everything". A dismissed keyring prompt must not be
    # enough to trigger that, so require an explicit opt-in.
    if os.environ.get("ICP_ALLOW_KEYFILE") != "1":
        raise SessionError(
            "Keyring unavailable and the plaintext key-file fallback is disabled.\n"
            "Unlock your login keyring and retry, or set ICP_ALLOW_KEYFILE=1 to accept an "
            f"unprotected master key at {paths.fallback_key_file()}."
        )
    return _key_from_file()


def _set_passphrase_migration_active(active: bool) -> None:
    """Suppress legacy cleanup while a conversion is still rollbackable."""
    global _PASSPHRASE_MIGRATION_ACTIVE
    _PASSPHRASE_MIGRATION_ACTIVE = active


def _set_passphrase_migration_key(key: bytes | None) -> None:
    """Hold the newly derived key only in the migration process while staging ciphertext."""
    global _PASSPHRASE_MIGRATION_KEY
    _PASSPHRASE_MIGRATION_KEY = bytes(key) if key is not None else None


def _migration_targets() -> dict[str, object]:
    """The KDF and encrypted-store files committed as one durable transaction."""
    from . import lockbox
    return {
        "params": lockbox.params_file(),
        "check": lockbox.check_file(),
        "session": paths.session_file(),
        "vault": paths.vault_file(),
        "aliases": paths.aliases_file(),
        "history": paths.history_file(),
        "nicknames": paths.nicknames_file(),
    }


def _migration_stage(transaction: str, name: str):
    if not _MIGRATION_ID.fullmatch(transaction) or name not in _MIGRATION_NAMES:
        raise PassphraseMigrationError("invalid passphrase migration journal")
    return paths.passphrase_migration_stage_file(transaction, name)


def _read_migration_journal() -> dict | None:
    journal = paths.passphrase_migration_file()
    if not journal.exists():
        return None
    try:
        data = json.loads(journal.read_text())
        if (not isinstance(data, dict) or data.get("version") != _MIGRATION_VERSION
                or data.get("state") not in _MIGRATION_STATES
                or not _MIGRATION_ID.fullmatch(str(data.get("transaction", "")))):
            raise ValueError("invalid journal header")
        entries = data.get("entries")
        if not isinstance(entries, dict) or set(entries) != set(_MIGRATION_NAMES):
            raise ValueError("invalid journal entries")
        for name in _MIGRATION_NAMES:
            entry = entries[name]
            if not isinstance(entry, dict) or not isinstance(entry.get("present"), bool):
                raise ValueError(f"invalid journal entry: {name}")
            digest = entry.get("digest")
            if entry["present"]:
                # A preparing transaction records the intended presence before its stage is
                # written.  Once commit is durable every present entry must have a digest.
                if digest is None and data["state"] == "preparing":
                    continue
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError(f"invalid digest: {name}")
            elif digest is not None:
                raise ValueError(f"unexpected digest: {name}")
        return data
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as e:
        raise PassphraseMigrationError(
            f"cannot read the passphrase migration journal {journal}; manual recovery is required"
        ) from e


def _write_migration_journal(data: dict) -> None:
    paths.atomic_write_private(
        paths.passphrase_migration_file(), (json.dumps(data, sort_keys=True) + "\n").encode())


def begin_passphrase_migration(present: dict[str, bool]) -> dict:
    """Durably record a staged migration before any destination file can change."""
    transaction = uuid.uuid4().hex
    entries = {
        name: {"present": bool(present.get(name, False)), "digest": None}
        for name in _MIGRATION_NAMES
    }
    data = {"version": _MIGRATION_VERSION, "transaction": transaction,
            "state": "preparing", "entries": entries}
    _write_migration_journal(data)
    return data


def migration_stage(data: dict, name: str):
    return _migration_stage(data["transaction"], name)


def mark_migration_entry(data: dict, name: str, *, present: bool, digest: str | None) -> None:
    if name not in _MIGRATION_NAMES or name not in data["entries"]:
        raise PassphraseMigrationError("invalid passphrase migration entry")
    data["entries"][name] = {"present": present, "digest": digest}
    _write_migration_journal(data)


def mark_migration_committing(data: dict) -> None:
    for name in _MIGRATION_NAMES:
        entry = data["entries"][name]
        if entry["present"] and not isinstance(entry.get("digest"), str):
            raise PassphraseMigrationError(
                f"passphrase migration has no staged bytes for {name}")
    data["state"] = "committing"
    _write_migration_journal(data)


def _finish_migration_commit(data: dict) -> None:
    targets = _migration_targets()
    for name in _MIGRATION_NAMES:
        target = targets[name]
        entry = data["entries"][name]
        stage = migration_stage(data, name)
        if not entry["present"]:
            target.unlink(missing_ok=True)
            stage.unlink(missing_ok=True)
            continue
        expected = entry["digest"]
        if paths.private_digest(target) != expected:
            if paths.private_digest(stage) != expected:
                raise PassphraseMigrationError(
                    f"passphrase migration cannot recover {target}; staged bytes are missing")
            paths.replace_private(stage, target)
        else:
            stage.unlink(missing_ok=True)
        if paths.private_digest(target) != expected:
            raise PassphraseMigrationError(
                f"passphrase migration could not verify {target} after replacement")


def mark_migration_committed(data: dict) -> None:
    _finish_migration_commit(data)
    data["state"] = "committed"
    _write_migration_journal(data)


def _discard_migration(data: dict) -> None:
    for name in _MIGRATION_NAMES:
        migration_stage(data, name).unlink(missing_ok=True)
    paths.passphrase_migration_file().unlink(missing_ok=True)


@paths.mutation_lock
def recover_passphrase_migration() -> None:
    """Finish or abandon a journaled migration without opening any old ciphertext.

    A preparing transaction has not replaced a destination and is discarded.  A committing or
    committed transaction is completed from its durable staged ciphertext and KDF bytes.  The
    old key is never needed for either decision; legacy-key cleanup remains a later marker-driven
    step after the new files are verified.
    """
    if _PASSPHRASE_MIGRATION_ACTIVE:
        return
    data = _read_migration_journal()
    if data is None:
        return
    if data["state"] == "preparing":
        from . import agent
        try:
            # The migration may have installed the new key in the long-lived agent just before
            # power loss.  Invalidate it before deleting the journal: otherwise the old
            # ciphertext remains active while subsequent commands trust the new runtime key.
            agent.lock_strict()
        except BaseException as error:
            raise PassphraseMigrationError(
                "cannot discard a preparing passphrase migration; the runtime key could not be "
                "invalidated and the migration journal was retained"
            ) from error
        _discard_migration(data)
        return
    _finish_migration_commit(data)
    if data["state"] == "committing":
        data["state"] = "committed"
        _write_migration_journal(data)


@paths.mutation_lock
def finish_passphrase_migration() -> None:
    """Drop a completed journal and any leftover stage names after legacy cleanup succeeds."""
    data = _read_migration_journal()
    if data is None:
        return
    if data["state"] != "committed":
        raise PassphraseMigrationError("passphrase migration is not committed")
    _finish_migration_commit(data)
    _discard_migration(data)


@paths.mutation_lock
def abort_passphrase_migration(data: dict) -> None:
    """Discard a preparing transaction whose destinations were never published."""
    if data.get("state") != "preparing":
        raise PassphraseMigrationError("cannot abort a committed passphrase migration")
    _discard_migration(data)


def _master_keyring_collection(*, strict: bool):
    """Return the keyring collection, tolerating a transient bus outage in probe mode."""
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
    except Exception as e:
        if not strict:
            return None
        raise MasterKeyCleanupError(
            "could not inspect or remove the old Secret Service master key; "
            "passphrase migration stopped before claiming the at-rest boundary"
        ) from e
    try:
        if coll.is_locked():
            if not strict:
                return None
            raise MasterKeyCleanupError(
                "the Secret Service is locked; unlock it before setting a passphrase"
            )
    except MasterKeyCleanupError:
        raise
    except Exception as e:
        if not strict:
            return None
        raise MasterKeyCleanupError(
            "could not inspect the old Secret Service master key"
        ) from e
    return coll


def _delete_master_key_items(coll, *, strict: bool) -> None:
    try:
        items = list(coll.search_items(_ATTRS))
    except Exception as e:
        if not strict:
            return
        raise MasterKeyCleanupError(
            "could not inspect the old Secret Service master key"
        ) from e
    for item in items:
        try:
            item.delete()
        except Exception as e:
            # Once a persistent item is found, an inability to delete it is not a transient
            # keyring outage: fail closed, including during normal post-migration probes.
            raise MasterKeyCleanupError(
                "could not remove the old Secret Service master-key item"
            ) from e
    try:
        remaining = list(coll.search_items(_ATTRS))
    except Exception:
        if not strict:
            return
        raise MasterKeyCleanupError(
            "could not verify removal of the old Secret Service master key"
        )
    if remaining:
        raise MasterKeyCleanupError(
            "the Secret Service still contains the old master-key item"
        )


def _purge_master_keyring() -> None:
    """Strictly delete and verify the old default-mode Secret Service master-key item."""
    _delete_master_key_items(_master_keyring_collection(strict=True), strict=True)


def _probe_master_keyring() -> None:
    """Best-effort self-healing check for a master-key item recreated after migration."""
    coll = _master_keyring_collection(strict=False)
    if coll is not None:
        _delete_master_key_items(coll, strict=False)


def master_key_cleanup_complete() -> bool:
    marker = paths.master_key_cleanup_file()
    if paths.fallback_key_file().exists() or not marker.exists():
        return False
    try:
        return marker.read_bytes() == _MASTER_CLEAN_MARKER
    except OSError:
        return False


def ensure_legacy_master_key_clean() -> None:
    """Remove old key sources, retrying cleanup on every passphrase-mode key use."""
    if master_key_cleanup_complete():
        _probe_master_keyring()
        return
    _purge_master_keyring()
    try:
        paths.fallback_key_file().unlink(missing_ok=True)
        paths.atomic_write_private(paths.master_key_cleanup_file(), _MASTER_CLEAN_MARKER)
    except OSError as e:
        raise MasterKeyCleanupError(
            "could not remove or record cleanup of the old plaintext master-key file"
        ) from e


def _write_private(f, data: bytes) -> None:
    """Write a private ciphertext without exposing a partial replacement."""
    paths.atomic_write_private(f, data)


@paths.mutation_lock
def save(data: dict, *, path=None) -> None:
    box = nacl.secret.SecretBox(_master_key())
    _write_private(path or paths.session_file(), box.encrypt(json.dumps(data).encode()))


@paths.mutation_lock
def load() -> dict | None:
    f = paths.session_file()
    if not f.exists():
        return None
    box = nacl.secret.SecretBox(_master_key())
    try:
        return json.loads(box.decrypt(f.read_bytes()).decode())
    except nacl.exceptions.CryptoError as e:
        raise SessionError(
            f"cannot decrypt {f} - the master key no longer matches it (the keyring entry was "
            "lost or replaced). Run `icp logout`, then `icp login` to sign in again.") from e


@paths.mutation_lock
def clear() -> None:
    f = paths.session_file()
    if f.exists():
        f.unlink()
