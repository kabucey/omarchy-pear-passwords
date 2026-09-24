"""Password change history, kept locally and encrypted like the vault.

Apple keeps a history of its own - the `s_hi` list inside a Passwords *metadata* record - but
only for entries its Passwords app manages. Most keychain items have no metadata record at all,
so for them Apple remembers nothing. This journal covers every entry by diffing each sync
against the last one, which also catches changes made on any other device.

Old passwords are still passwords, so the file gets the same treatment as the vault: the same
libsodium box under the same master key, mode 0600. `icp logout`/`clear` removes it with
everything else.
"""

from __future__ import annotations

import json
import logging
import time

import nacl.exceptions
import nacl.secret

from .. import paths
from ..auth.session import _master_key
from ..errors import EncryptedStoreError

logger = logging.getLogger(__name__)

SOURCE_SYNC = "sync"      # observed by diffing two syncs - the change happened elsewhere
SOURCE_LOCAL = "local"    # written from this machine, through the app
SOURCE_APPLE = "apple"    # lifted from Apple's own s_hi history

MAX_PER_ACCOUNT = 50      # a runaway rotation must not grow the file without bound


class HistoryError(EncryptedStoreError):
    """The password history exists but its ciphertext or JSON cannot be trusted."""


def _key(domain: str, username: str) -> str:
    return f"{domain}\x1f{username}"


def load() -> dict:
    """{account_key: [entry, ...]} newest first.

    A corrupt journal is preserved and rejected rather than returned as an empty map, because
    the next save would otherwise overwrite the only copy of the ciphertext.
    """
    f = paths.history_file()
    if not f.exists():
        return {}
    try:
        box = nacl.secret.SecretBox(_master_key())
        data = json.loads(box.decrypt(f.read_bytes()).decode())
        if not isinstance(data, dict) or not isinstance(data.get("accounts"), dict):
            raise ValueError("invalid history document")
        return data["accounts"]
    except (nacl.exceptions.CryptoError, OSError, UnicodeError, ValueError, TypeError,
            AttributeError, KeyError) as e:
        logger.warning("cannot read the password history (%s); preserving it", e)
        raise HistoryError(
            f"cannot decrypt or parse {f}; ciphertext was preserved - refusing to use the "
            "password history until it is repaired or replaced"
        ) from e


@paths.mutation_lock
def save(accounts: dict, *, path=None) -> None:
    box = nacl.secret.SecretBox(_master_key())
    f = path or paths.history_file()
    paths.atomic_write_private(f, box.encrypt(json.dumps({"accounts": accounts}).encode()))


def record(accounts: dict, domain: str, username: str, *, old: str | None, new: str,
           source: str, when: float | None = None, title: str = "") -> dict:
    """Append one change. Returns the same dict so calls can be chained in a loop."""
    entries = accounts.setdefault(_key(domain, username), [])
    entry = {"at": when if when is not None else time.time(), "source": source,
             "old": old, "new": new, "title": title}
    entries.insert(0, entry)
    del entries[MAX_PER_ACCOUNT:]
    return accounts


def for_account(accounts: dict, domain: str, username: str) -> list:
    return accounts.get(_key(domain, username), [])


def diff_stores(before, after) -> list:
    """Changes between two credential stores: (domain, username, old, new, title).

    Only reports an account present in both with a different password. A new account is not a
    change, and a disappeared one is a deletion - neither is a rotation, and calling them one
    would make the history lie about what happened.
    """
    old_by = {_key(c.domain, c.username): c for c in before}
    changes = []
    for c in after:
        prev = old_by.get(_key(c.domain, c.username))
        if prev is not None and prev.password != c.password:
            changes.append((c.domain, c.username, prev.password, c.password, c.title))
    return changes


def observe_sync(before, after) -> int:
    """Journal every password that changed between two syncs. Returns how many."""
    changes = diff_stores(before, after)
    if not changes:
        return 0
    accounts = load()
    for domain, username, old, new, title in changes:
        record(accounts, domain, username, old=old, new=new, source=SOURCE_SYNC, title=title)
    save(accounts)
    logger.info("recorded %d password change(s) seen during sync", len(changes))
    return len(changes)


def merge_apple_history(entries: list, apple: list) -> list:
    """Fold Apple's own history in, newest first, without duplicating ours.

    `apple` is metadata.password_history()'s normalised [{at, password}]. An Apple entry whose
    password we already hold at roughly the same minute is the same event seen twice - ours
    wins because it also knows what the value changed *from*.
    """
    out = list(entries)
    known = {(e.get("new"), round(e.get("at", 0) / 60)) for e in out}
    for h in apple or []:
        pw, at = h.get("password"), h.get("at", 0.0)
        if pw is None or (pw, round(at / 60)) in known:
            continue
        out.append({"at": at, "source": SOURCE_APPLE, "old": None, "new": pw, "title": ""})
    return sorted(out, key=lambda e: e.get("at", 0), reverse=True)
