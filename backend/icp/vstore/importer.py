"""The one-time move of a 1.x vault into a fresh 2.0 store (spec section 10, step 6).

    migrate-begin   UserStore.create(uid): new keys, empty meta, unlocked
    import-*        the importer streams the v1 files and the key to the daemon
    import-commit   UserStore.import_v1(files, key)  <- this module

import_v1 builds the whole converted store in u<uid>.tmp/ next to the real one, using the new
store's keys (hard links of keys/, so the tmp tree is a complete store of its own). It then
opens that tree again from scratch - a real unlock through systemd-creds, every box opened -
and computes the same canonical model from what it reads back. Only if the counts and the
SHA-256 over that model equal the figures taken from the v1 plaintext does the tmp tree become
u<uid>. Otherwise it is removed and ImportMismatch says so; the v1 files, which this code only
ever received as bytes, stay the authoritative copy.

The swap is two renames: u<uid> (fresh keys, no data) aside, u<uid>.tmp into place. A crash
between them leaves no u<uid>, which reads as "empty" - the migration can simply run again.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path

from .. import paths
from ..daemon import protocol
from . import (ImportMismatch, Secrets, StoreError, StoreLocked, UserStore, WrongPassphrase)
from . import entries as _entries
from . import format as fmt
from . import legacy
from . import meta as _meta

log = logging.getLogger(__name__)


def import_v1(store: UserStore, files: dict, key: bytes) -> dict:
    if store.state() != "unlocked":
        raise StoreLocked("import_v1 needs the store created by migrate-begin, unlocked")
    if store._doc["entries"]:
        raise StoreError("this store already holds entries; an import never merges")
    files = _check_files(files)
    if not legacy.key_verifies(files, key):
        raise WrongPassphrase("the key does not open check.enc (or vault.enc without one)")

    canon = legacy.to_canonical(legacy.read(files, key))
    want_counts, want_digest = legacy.counts(canon), legacy.digest(canon)

    uid = store.uid
    final = store._dir                      # paths.user_dir(uid); tmp is paths.user_tmp_dir(uid)
    tmp = final.with_name(final.name + ".tmp")
    _remove_tree(tmp)                       # a leftover of a crashed import: ours, rebuildable
    try:
        _build(store, tmp, canon)
        got = _read_back(store, tmp)
        got_counts, got_digest = legacy.counts(got), legacy.digest(got)
        if got_counts != want_counts or got_digest != want_digest:
            raise ImportMismatch("the converted store does not read back as the v1 vault")
    except BaseException:
        _remove_tree(tmp)
        raise

    aside = final.with_name(f"{final.name}.pre-import-{int(time.time())}")
    os.rename(final, aside)
    os.rename(tmp, final)
    fmt.fsync_dir(final.parent)
    _remove_tree(aside)                     # fresh keys (still linked from final) and no data

    store._doc = _meta.check(fmt.read_sealed(final, paths.META_FILE, bytes(store._sub["meta"]),
                                             fmt.KIND_META, uid))
    store._nick = dict(canon["nicknames"])
    log.info("u%d: imported %d credentials from 1.x", uid, want_counts["credentials"])
    return {"counts": want_counts, "digest": want_digest}


def _check_files(files) -> dict:
    if not isinstance(files, dict):
        raise StoreError("files is a dict of name to bytes")
    out = {}
    for name, data in files.items():
        if name not in protocol.IMPORT_FILES:
            raise StoreError(f"{name!r} is not a v1 vault file")
        if not isinstance(data, (bytes, bytearray)) or len(data) > protocol.IMPORT_FILE_MAX:
            raise StoreError(f"{name} is not bytes of at most {protocol.IMPORT_FILE_MAX}")
        out[name] = bytes(data)
    missing = [n for n in protocol.IMPORT_REQUIRED if n not in out]
    if missing:
        raise StoreError(f"missing v1 files: {', '.join(missing)}")
    return out


def _view(store: UserStore, root: Path) -> UserStore:
    """A UserStore over `root` that borrows `store`'s keys (never lock() it: that would wipe
    the keys it shares)."""
    v = UserStore(store.uid, _root=root)
    v._rk, v._sub, v._pk = store._rk, store._sub, store._pk
    v._doc, v._nick = _meta.empty(), {}
    return v


def _build(store: UserStore, tmp: Path, canon: dict) -> None:
    fmt.ensure_dir(tmp)
    kd = fmt.ensure_dir(tmp / paths.KEYS_DIR)
    src_keys = store._dir / paths.KEYS_DIR
    for name in (paths.LIST_CRED, paths.SECRET_CRED, paths.SECRET_PUB, paths.KEYS_JSON):
        os.link(src_keys / name, kd / name)
    state = store._dir / paths.STATE_FILE
    if state.exists():
        os.link(state, tmp / paths.STATE_FILE)
    fmt.fsync_dir(kd)

    view = _view(store, tmp)
    files = _entries.EntryFiles(tmp)
    files.ensure()
    now = time.time()
    for id, e in canon["entries"].items():
        rec = view._doc["entries"][id] = {**e["meta"], "v": 0, "hist": []}
        for n, (at, source, value) in enumerate(e["history"], 1):
            # 1.x kept old values, not old boxes: each becomes a box of its own, sealed like
            # any other and marked v=0 so it can never pass for a current box.
            old = Secrets(password=value, notes="", totp_secret=None, apple_history=[])
            files.write_history(id, n, _entries.seal(store._pk,
                                                     _entries.to_payload(id, 0, old)))
            rec["hist"].append({"n": n, "at": at, "source": source})
        if e["deleted"]:
            rec["deleted"], rec["deleted_at"] = True, now
        else:
            view._replace_secrets(id, rec, legacy.secrets_from_canonical(e["secrets"]),
                                  source="local", when=now)
    view._write_meta()
    view.save_nicknames(canon["nicknames"])
    if canon["aliases"]:
        view.save_aliases(canon["aliases"])
    view.save_session(canon["session"])
    if canon["device"]:
        view.save_device(canon["device"])


def _read_back(store: UserStore, tmp: Path) -> dict:
    """The canonical model of what is on disk in `tmp`, through a fresh unlock."""
    reader = UserStore(store.uid, _root=tmp)
    reader.unlock()
    try:
        doc = reader._doc
        files = _entries.EntryFiles(tmp)
        sk = reader._unseal_sk()
        try:
            out_entries = {}
            for id, rec in doc["entries"].items():
                hist = []
                for h in rec.get("hist") or []:
                    blob = files.read_history(id, h["n"])
                    if blob is None:
                        raise ImportMismatch("a history box is missing")
                    hist.append([h["at"], h["source"],
                                 _entries.open_box(bytes(sk), blob, id)["password"]])
                secrets = None
                if not rec.get("deleted"):
                    blob = files.read(id)
                    if blob is None:
                        raise ImportMismatch("an entry box is missing")
                    secrets = legacy.canonical_secrets(_entries.from_payload(
                        _entries.open_box(bytes(sk), blob, id, int(rec.get("v", 0)))))
                out_entries[id] = {"meta": {k: rec.get(k) for k in _META_KEYS},
                                   "secrets": secrets, "deleted": bool(rec.get("deleted")),
                                   "history": hist}
        finally:
            sk.wipe()
        return {"entries": out_entries, "nicknames": reader.load_nicknames(),
                "aliases": reader.load_aliases(), "session": reader.load_session(),
                "device": reader.load_device()}
    finally:
        reader.lock()


_META_KEYS = _meta._META_FIELDS        # every stored Meta field, as the v1 side computes it


def _remove_tree(path: Path) -> None:
    """Remove a directory this module created. Refuses a symlink (rmtree would refuse too)."""
    p = Path(path)
    if p.is_symlink():
        raise StoreError(f"{p} is a symlink")
    if p.exists():
        shutil.rmtree(p)
        fmt.fsync_dir(p.parent)
