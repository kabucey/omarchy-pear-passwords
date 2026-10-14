"""Shared test fixtures (owned by the store). Fake data only - nothing here was ever a real vault.

- `FakeSealBackend`: a stand-in for `systemd-creds --user` with a switchable TPM, so tests can
  seal, re-seal, pull the TPM and clear it without root or hardware.
- `vstore_env(tmp)`: points the v2 store at a scratch directory and installs a fake backend.
- `v1_files()`: the committed 1.x vault in `v1_vault/`, made by `make_v1_fixture.py` with the
  known test passphrase `V1_PASSPHRASE` and deliberately cheap Argon2id limits.
"""

from __future__ import annotations

import contextlib
import os

from .fake_seal import FakeSealBackend

HERE = os.path.dirname(os.path.abspath(__file__))
V1_DIR = os.path.join(HERE, "v1_vault")
V1_PASSPHRASE = "TEST passphrase - not a real one"

# What the committed fixture holds (see make_v1_fixture.py): 6 credentials (one pair shares a
# domain and username), 4 local history values (one of them for an account no longer in the
# vault), 2 nicknames, 2 aliases, 5 session keys. The shared pair becomes one entry, the newer
# item, with the older one's password as local history (vstore.ids.collapse): so 5 entries
# and 4 + 1 history values.
V1_COUNTS = {"credentials": 5, "history": 5, "nicknames": 2, "aliases": 2, "session_keys": 5}


def v1_files() -> dict:
    out = {}
    for name in sorted(os.listdir(V1_DIR)):
        with open(os.path.join(V1_DIR, name), "rb") as f:
            out[name] = f.read()
    return out


@contextlib.contextmanager
def vstore_env(root, backend: FakeSealBackend | None = None):
    """Run a block with icp.paths.STATE_ROOT at `root` and `backend` (default: a fresh
    FakeSealBackend without a TPM) as the seal backend. Yields the backend."""
    from icp import paths
    from icp.vstore import seal

    backend = backend or FakeSealBackend()
    old_root = paths.STATE_ROOT
    paths.STATE_ROOT = str(root)
    seal.set_backend(backend)
    try:
        yield backend
    finally:
        paths.STATE_ROOT = old_root
        seal.set_backend(None)


__all__ = ["FakeSealBackend", "V1_COUNTS", "V1_DIR", "V1_PASSPHRASE", "v1_files",
           "vstore_env"]
