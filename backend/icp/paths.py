"""Filesystem locations. Everything lives under $XDG_CONFIG_HOME/icp."""

import contextlib
import fcntl
import hashlib
import os
import tempfile
import threading
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = Path(base) / "icp"
    d.mkdir(parents=True, exist_ok=True)
    # Tokens and identity are sensitive; keep the directory private.
    os.chmod(d, 0o700)
    return d


def atomic_write_private(path: Path, data: bytes) -> None:
    """Replace a private file without exposing a partial or world-readable write.

    The temporary file is created in the destination directory so ``os.replace`` is atomic
    on the same filesystem.  Flush both the file and its directory before returning; a
    process or machine failure during a store update must leave the previous ciphertext
    readable, not a truncated file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def replace_private(source: Path, destination: Path) -> None:
    """Atomically install an already fsynced private file and persist the directory entry."""
    source = Path(source)
    destination = Path(destination)
    os.replace(source, destination)
    directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def private_digest(path: Path) -> str | None:
    """Return the SHA-256 of a private file, or None when it is absent."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    return hashlib.sha256(data).hexdigest()


class _MutationLock(contextlib.ContextDecorator):
    """One re-entrant process-wide lock for every operation that rewrites local state.

    The file lock serialises separate CLI processes.  The thread-local depth makes nested calls
    (for example a push operation's final sync) safe without opening a second conflicting flock
    in the same process.
    """

    _local = threading.local()

    def __enter__(self):
        depth = getattr(self._local, "depth", 0)
        if depth:
            self._local.depth = depth + 1
            return self
        lock = open(mutation_lock_file(), "a+")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
        except BaseException:
            lock.close()
            raise
        self._local.lock = lock
        self._local.depth = 1
        return self

    def __exit__(self, exc_type, exc, tb):
        depth = getattr(self._local, "depth", 0)
        if depth > 1:
            self._local.depth = depth - 1
            return False
        lock = getattr(self._local, "lock", None)
        try:
            if lock is not None:
                fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            if lock is not None:
                lock.close()
            self._local.depth = 0
            self._local.lock = None
        return False


mutation_lock = _MutationLock()


def device_file() -> Path:
    return config_dir() / "device.json"


def session_file() -> Path:
    return config_dir() / "session.enc"


def fallback_key_file() -> Path:
    return config_dir() / "master.key"


def vault_key_file() -> Path:
    """Legacy raw derived-key path, retained only so passphrase migration can remove it."""
    return config_dir() / "vault.key"


def legacy_key_cleanup_file() -> Path:
    """Non-secret marker proving legacy passphrase-key cleanup completed."""
    return config_dir() / "legacy-key-clean"


def master_key_cleanup_file() -> Path:
    """Non-secret marker proving the pre-passphrase master-key stores were removed."""
    return config_dir() / "master-key-clean"


def needs_login_file() -> Path:
    """Set when Apple demanded 2FA during an unattended refresh, cleared on a good sync.

    While it exists, automated syncs stand down. Without it every retry re-triggers Apple's
    sign-in push, so a expired token turns into a code arriving on your phone every few
    minutes that nothing on this machine is able to accept."""
    return config_dir() / "needs-login"


def history_file() -> Path:
    """Encrypted password-change journal. Holds old passwords, so it is vault-grade."""
    return config_dir() / "history.enc"


def nicknames_file() -> Path:
    """User-chosen entry names. Encrypted - a list of nicknames against accounts is a map of
    someone's life even though no single nickname is a secret."""
    return config_dir() / "nicknames.enc"


def vault_file() -> Path:
    return config_dir() / "vault.enc"


def aliases_file() -> Path:
    return config_dir() / "aliases.enc"


def sync_lock_file() -> Path:
    return config_dir() / "sync.lock"


def mutation_lock_file() -> Path:
    return config_dir() / "mutation.lock"


def passphrase_migration_file() -> Path:
    """Private, non-secret transaction journal for passphrase conversion recovery."""
    return config_dir() / "passphrase-migration.json"


def passphrase_migration_stage_file(transaction: str, name: str) -> Path:
    """Private staging path for one encrypted/KDF artifact in a migration transaction."""
    return config_dir() / f".passphrase-migration-{transaction}-{name}"


def sync_attempt_file() -> Path:
    return config_dir() / "sync.attempt"
