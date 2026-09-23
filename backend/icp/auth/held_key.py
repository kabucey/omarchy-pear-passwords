"""Remove raw derived-key copies left by older passphrase-mode versions.

This module intentionally does not read, validate, migrate, or write the key. A legacy
``vault.key`` is already equivalent to an unlocked passphrase, so the safe migration is to
discard it after a real passphrase unlock and derive the key again into the runtime agent.
"""

from __future__ import annotations

from .. import paths
from ..errors import AppleError

_ATTRS = {"application": "icp", "type": "lockbox-key"}
_CLEAN_MARKER = b"icp-legacy-key-clean-v1\n"


class LegacyKeyCleanupError(AppleError):
    """A legacy raw-key copy could not be removed and the boundary is not complete."""


def _collection(*, strict: bool):
    """Return the keyring collection, distinguishing an unavailable bus from a deletion error."""
    try:
        import secretstorage
        conn = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(conn)
    except Exception as e:  # pragma: no cover - exercised with a real missing keyring
        if not strict:
            return None
        raise LegacyKeyCleanupError(
            "could not inspect the Secret Service for the legacy vault key; "
            "passphrase migration stopped before claiming the at-rest boundary"
        ) from e
    try:
        if coll.is_locked():
            if not strict:
                return None
            raise LegacyKeyCleanupError(
                "the Secret Service is locked; unlock it before setting a passphrase"
            )
    except LegacyKeyCleanupError:
        raise
    except Exception as e:
        if not strict:
            return None
        raise LegacyKeyCleanupError(
            "could not inspect the Secret Service for the legacy vault key"
        ) from e
    return coll


def _delete_items(coll, *, strict: bool) -> None:
    """Delete known items; only discovery/verification may be transient in best-effort mode."""
    try:
        items = list(coll.search_items(_ATTRS))
    except Exception as e:
        if not strict:
            return
        raise LegacyKeyCleanupError(
            "could not inspect the Secret Service for the legacy vault key"
        ) from e
    for item in items:
        try:
            item.delete()
        except Exception as e:
            # We found a persistent copy.  A failed delete is never a transient absence and
            # must fail closed even during a best-effort post-migration probe.
            raise LegacyKeyCleanupError(
                "could not remove the legacy vault key from the Secret Service"
            ) from e
    try:
        remaining = list(coll.search_items(_ATTRS))
    except Exception:
        if not strict:
            return
        raise LegacyKeyCleanupError(
            "could not verify removal of the legacy vault key from the Secret Service"
        )
    if remaining:
        raise LegacyKeyCleanupError(
            "the Secret Service still contains a legacy vault-key item"
        )


def _purge_keyring() -> None:
    """Strictly delete and verify every legacy Secret Service copy."""
    _delete_items(_collection(strict=True), strict=True)


def _probe_keyring() -> None:
    """Best-effort self-healing check for a keyring item recreated after migration.

    A transiently unavailable/locked bus is not a reason to break an already-clean vault. If
    an item is actually discovered, however, a failed deletion is fatal.
    """
    coll = _collection(strict=False)
    if coll is not None:
        _delete_items(coll, strict=False)


def clear() -> None:
    """Discard legacy raw-key copies after the caller has genuinely unlocked.

    The file is removed without reading it. Secret Service items are likewise deleted by
    metadata only, so this migration cannot accidentally reintroduce a key-loading path.
    """
    try:
        _purge_keyring()
    except LegacyKeyCleanupError:
        raise
    except Exception as e:
        raise LegacyKeyCleanupError(
            "could not remove the legacy vault key from the Secret Service"
        ) from e
    try:
        paths.vault_key_file().unlink(missing_ok=True)
    except OSError as e:
        raise LegacyKeyCleanupError(
            f"could not remove the legacy vault key {paths.vault_key_file()}"
        ) from e


def cleanup_complete() -> bool:
    """Whether this installation has completed strict legacy-key cleanup.

    The marker contains no key material.  A stale marker never suppresses cleanup when the
    legacy file is present, which keeps an upgrade from turning a partial migration into a
    claimed at-rest boundary.
    """
    marker = paths.legacy_key_cleanup_file()
    if paths.vault_key_file().exists() or not marker.exists():
        return False
    try:
        return marker.read_bytes() == _CLEAN_MARKER
    except OSError:
        return False


def mark_cleanup_complete() -> None:
    try:
        paths.atomic_write_private(paths.legacy_key_cleanup_file(), _CLEAN_MARKER)
    except OSError as e:
        raise LegacyKeyCleanupError(
            f"could not record legacy-key cleanup at {paths.legacy_key_cleanup_file()}"
        ) from e


def ensure_clean() -> None:
    """Inspect and remove legacy copies once, then remember the verified result."""
    if cleanup_complete():
        if paths.vault_key_file().exists():
            # A marker can survive a later recreation of the raw file; never let it hide one.
            clear()
            mark_cleanup_complete()
        else:
            _probe_keyring()
        return
    clear()
    mark_cleanup_complete()
