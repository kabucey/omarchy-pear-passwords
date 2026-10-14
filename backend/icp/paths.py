"""Filesystem locations: the 2.0 per-user store, and the 1.x vault the migration reads.

Two worlds live here and must not be confused:

* **v2 store** - `/var/lib/pear-passwords/u<uid>/`, owned by the `pear-passwords` system user
  and written only by the daemon (icp.vstore). Nothing under $HOME decrypts anything in 2.0.
  The layout is spec section 3.2; the names below are the only place it is spelled out.
* **v1 vault** - `$XDG_CONFIG_HOME/icp`, the 1.x files. In 2.0 they are only ever *read*, by
  the importer running as the user (`pear-exec migrate`), and then renamed aside. The
  passphrase-derived key never had a file of its own; the keyring/keyfile master key
  (master.key) and the cached lockbox key (vault.key) are gone with the code that wrote them.
"""

from __future__ import annotations

import os
from pathlib import Path

from .daemon import paths as _system

# --- v2 store (daemon side) ------------------------------------------------------------------
# The root of every per-user store. A module attribute rather than a constant baked into each
# function, so tests can point it at a scratch directory; the daemon never changes it.
STATE_ROOT = _system.STATE_DIR

KEYS_DIR = "keys"
LIST_CRED = "list.cred"             # RK_list, sealed with systemd-creds
SECRET_CRED = "secret.cred"         # SK_secret (X25519), sealed with systemd-creds
SECRET_PUB = "secret.pub"           # PK_secret || HMAC(K_meta, "pk" || PK_secret)
KEYS_JSON = "keys.json"             # plaintext {format, sealed_with, tpm_srk_fp?, created}
PREV_SUFFIX = ".prev"               # pre-rotation re-seal rollback copies (read, never written now)
NEW_SUFFIX = ".new"                 # re-sealed blobs before they are verified

META_FILE = "meta.v2"
SESSION_FILE = "session.v2"
ALIASES_FILE = "aliases.v2"
NICKNAMES_FILE = "nicknames.v2"
DEVICE_FILE = "device.json"         # plaintext 0600: the Apple device identity, not a key
STATE_FILE = "state.json"           # plaintext settings, not secret
ENTRIES_DIR = "entries"             # entries/<id>.box
HISTORY_DIR = "history"             # history/<id>/<n>.box
BOX_SUFFIX = ".box"


def _uid(uid: int) -> int:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise ValueError(f"bad uid {uid!r}")
    return uid


def user_dir(uid: int) -> Path:
    """`<STATE_ROOT>/u<uid>`: the same path as icp.daemon.paths.user_dir under the default root."""
    return Path(STATE_ROOT) / f"u{_uid(uid)}"


def user_tmp_dir(uid: int) -> Path:
    """Where an import is built and verified before it replaces user_dir()."""
    return Path(STATE_ROOT) / f"u{_uid(uid)}.tmp"


def user_aside_dir(uid: int, tag: str, when: int) -> Path:
    """A directory a store is renamed to instead of being deleted (`reset`, a replaced
    pre-import store): `u<uid>.<tag>-<unix time>`."""
    if tag not in ("broken", "pre-import"):
        raise ValueError(f"bad tag {tag!r}")
    return Path(STATE_ROOT) / f"u{_uid(uid)}.{tag}-{int(when)}"


# --- v1 vault (user side, read-only in 2.0) --------------------------------------------------
V1_FILES = ("session.enc", "vault.enc", "history.enc", "nicknames.enc", "aliases.enc",
            "kdf.json", "check.enc", "device.json")


def legacy_dir() -> Path:
    """The 1.x vault directory, `$XDG_CONFIG_HOME/icp`. Never created: its absence means there
    is nothing to migrate, and the migration must not be the thing that makes it."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "icp"


def legacy_file(name: str) -> Path:
    """One of the v1 files the importer may read (V1_FILES); nothing else in that directory."""
    if name not in V1_FILES:
        raise ValueError(f"not a v1 vault file: {name!r}")
    return legacy_dir() / name


def config_dir() -> Path:
    """The 1.x directory, created 0700 if missing.

    Kept for the 1.x Apple pipeline's development commands; 2.0 code must use
    legacy_dir(), which never creates anything."""
    d = legacy_dir()
    d.mkdir(parents=True, exist_ok=True)
    # Tokens and identity are sensitive; keep the directory private.
    os.chmod(d, 0o700)
    return d


def device_file() -> Path:
    return config_dir() / "device.json"


def session_file() -> Path:
    return config_dir() / "session.enc"


def needs_login_file() -> Path:
    """Set when Apple demanded 2FA during an unattended refresh, cleared on a good sync (1.x).

    2.0 keeps the flag under the metadata key instead (UserStore.set_sync_status)."""
    return config_dir() / "needs-login"


def history_file() -> Path:
    """The 1.x encrypted password-change journal. Read once by the importer."""
    return config_dir() / "history.enc"


def nicknames_file() -> Path:
    """The 1.x encrypted nicknames. Read once by the importer."""
    return config_dir() / "nicknames.enc"


def vault_file() -> Path:
    return config_dir() / "vault.enc"


def aliases_file() -> Path:
    return config_dir() / "aliases.enc"


def kdf_file() -> Path:
    """The 1.x Argon2id salt and limits (not secret)."""
    return config_dir() / "kdf.json"


def check_file() -> Path:
    """The 1.x passphrase check blob: SecretBox(key, b"icp-lockbox-v1")."""
    return config_dir() / "check.enc"


def sync_lock_file() -> Path:
    return config_dir() / "sync.lock"


def sync_attempt_file() -> Path:
    return config_dir() / "sync.attempt"
