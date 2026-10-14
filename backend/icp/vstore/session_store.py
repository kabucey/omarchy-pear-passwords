"""The small tier-1 files and the two plaintext ones.

    session.v2     K_sess   the whole former session.enc: Apple ID password if saved, GSA sk,
                            PET, mme/CloudKit tokens, web cookies and trust token, Octagon peer
                            keys, escrow sponsor key
    aliases.v2     K_alias  Hide My Email aliases
    nicknames.v2   K_nick   local nicknames by entry id
    device.json    plain    the Apple device identity (stable ids, not a key), 0600
    state.json     plain    settings, and the record of the v1 copy left behind by a migration

Each sealed file holds one JSON object with a single top-level key, so a future field can be
added beside it without a format change.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import paths
from ..daemon import protocol
from . import SealError
from . import format as fmt

MAX_NICKNAME = 80


def _read(directory: Path, name: str, key, kind: int, uid: int, field: str, typ, default):
    doc = fmt.read_sealed(directory, name, bytes(key), kind, uid)
    if doc is None:
        return default
    if not isinstance(doc, dict) or not isinstance(doc.get(field), typ):
        raise SealError("damaged", f"{name} has the wrong shape")
    return doc[field]


# --- session ---------------------------------------------------------------------------------

def load_session(directory: Path, key, uid: int) -> dict:
    return _read(directory, paths.SESSION_FILE, key, fmt.KIND_SESSION, uid, "session", dict, {})


def save_session(directory: Path, key, uid: int, d: dict) -> None:
    if not isinstance(d, dict):
        raise ValueError("session is a dict")
    f = Path(directory) / paths.SESSION_FILE
    if not d:
        # Sign-out. The file goes; a stale copy would keep `signed_in` true.
        try:
            f.unlink()
            fmt.fsync_dir(f.parent)
        except FileNotFoundError:
            pass
        return
    fmt.write_sealed(directory, paths.SESSION_FILE, bytes(key), fmt.KIND_SESSION, uid,
                     {"session": d})


def signed_in(directory: Path) -> bool:
    return (Path(directory) / paths.SESSION_FILE).is_file()


# --- aliases and nicknames -------------------------------------------------------------------

def load_aliases(directory: Path, key, uid: int) -> list[dict]:
    out = _read(directory, paths.ALIASES_FILE, key, fmt.KIND_ALIASES, uid, "aliases", list, [])
    if not all(isinstance(a, dict) for a in out):
        raise SealError("damaged", "aliases.v2 has the wrong shape")
    return out


def save_aliases(directory: Path, key, uid: int, aliases: list[dict]) -> None:
    if not isinstance(aliases, list) or not all(isinstance(a, dict) for a in aliases):
        raise ValueError("aliases are a list of dicts")
    fmt.write_sealed(directory, paths.ALIASES_FILE, bytes(key), fmt.KIND_ALIASES, uid,
                     {"aliases": aliases})


def load_nicknames(directory: Path, key, uid: int) -> dict[str, str]:
    out = _read(directory, paths.NICKNAMES_FILE, key, fmt.KIND_NICKNAMES, uid, "names", dict,
                {})
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in out.items()):
        raise SealError("damaged", "nicknames.v2 has the wrong shape")
    return out


def save_nicknames(directory: Path, key, uid: int, names: dict[str, str]) -> None:
    if not isinstance(names, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in names.items()):
        raise ValueError("nicknames are a dict of str")
    fmt.write_sealed(directory, paths.NICKNAMES_FILE, bytes(key), fmt.KIND_NICKNAMES, uid,
                     {"names": names})


# --- plaintext -------------------------------------------------------------------------------

def _read_json(f: Path):
    raw = fmt.read_file(f, 1024 * 1024)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SealError("damaged", f"{f.name}: not JSON") from None


def load_device(directory: Path) -> dict:
    d = _read_json(Path(directory) / paths.DEVICE_FILE)
    if d is None:
        return {}
    if not isinstance(d, dict):
        raise SealError("damaged", "device.json has the wrong shape")
    return d


def save_device(directory: Path, d: dict) -> None:
    if not isinstance(d, dict):
        raise ValueError("device is a dict")
    fmt.atomic_write(Path(directory) / paths.DEVICE_FILE, fmt.dumps(d))


def _state_keys(src: dict, out: dict) -> None:
    """The daemon's bookkeeping beside the settings: the v1 backup record (old_copy) and the
    marker of a migrate-begin that has not committed yet (migration_pending, only ever True),
    browser autofill turned on in the window (autofill_enabled, only ever True), and the
    categories that wait for a check (features: the known flags, booleans, the rest off)."""
    if isinstance(src.get("old_copy"), dict):
        out["old_copy"] = src["old_copy"]
    if src.get("migration_pending") is True:
        out["migration_pending"] = True
    if src.get("autofill_enabled") is True:
        out["autofill_enabled"] = True
    if isinstance(src.get("features"), dict):
        out["features"] = {k: src["features"].get(k) is True for k in protocol.FEATURES}


def load_settings(directory: Path) -> dict:
    """DEFAULT_SETTINGS overlaid with what state.json holds for those keys, plus old_copy and
    migration_pending.

    Unknown keys are dropped on the way out - in particular a `sync_lease_h` left by a
    pre-release build never reaches the daemon. A state.json that is not JSON gives the
    defaults and is left alone: settings are not worth refusing to unlock over."""
    out = dict(protocol.DEFAULT_SETTINGS)
    try:
        stored = _read_json(Path(directory) / paths.STATE_FILE)
    except SealError:
        stored = None
    if isinstance(stored, dict):
        for k, default in protocol.DEFAULT_SETTINGS.items():
            v = stored.get(k)
            # Each value keeps its default's type: window_mode is a string, the rest ints.
            # Reading back only ints dropped "regular" on every daemon start.
            if isinstance(default, str):
                if isinstance(v, str) and (k != "window_mode" or v in protocol.WINDOW_MODES):
                    out[k] = v
            elif isinstance(v, int) and not isinstance(v, bool):
                out[k] = v
        _state_keys(stored, out)
    return out


def save_settings(directory: Path, d: dict) -> None:
    if not isinstance(d, dict):
        raise ValueError("settings are a dict")
    keep = {k: d[k] for k in protocol.DEFAULT_SETTINGS if k in d}
    _state_keys(d, keep)
    fmt.atomic_write(Path(directory) / paths.STATE_FILE, fmt.dumps(keep))
