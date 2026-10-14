"""Entry ids: opaque, filesystem-safe, and the same for the same account before and after the
migration.

1.x named an entry `"<domain>\\x1f<username>"` - the key its history journal and nicknames
were filed under. That cannot be a file name (`/`, control characters, any length), so 2.0
hashes it. The hash keeps one property that matters more than readability: the importer, which
only ever sees 1.x credentials, and the Apple pipeline, which sees keychain items, compute the
same id for the same (domain, username). If they did not, the first sync after a migration
would add all 554 entries again under new ids and tombstone the imported ones, taking every
nickname and every local history entry with them.

So every producer of a SyncItem - the importer here, icp.octagon.items for a sync and the
icp.vault.store adapter - calls `entry_id(domain, username)`, and `collapse()` when one batch
can hold the same pair twice. A pair seen twice (a site saved over two protocols) keeps the
newest item, which is also the one an Apple device fills; the importer files the older
password into the kept entry's history so nothing 1.x showed is lost.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")

# What vstore.Meta promises callers ([A-Za-z0-9._:-], at most 128), minus a leading dot so an
# id can never be "." or ".." when it becomes entries/<id>.box or the directory history/<id>/.
_ID_RE = re.compile(r"^[A-Za-z0-9_:-][A-Za-z0-9._:-]{0,127}$")

PREFIX = "k1-"
HEX_CHARS = 40          # 160 bits of SHA-256: no accidental collision across one keychain


# Salt of a copy in Apple's Recently Deleted: the deleted and the live copy of one account are
# two entries, and must never collapse into one or take each other's id.
RECENTLY_DELETED = "rd:"


def entry_id(domain: str, username: str, salt: str = "") -> str:
    """The id of the account (domain, username), byte-exact: no case folding, no `www.`
    stripping, because 1.x did none either and two such entries really are two entries.

    The pair is hashed as a JSON array, not joined with a separator, so no choice of domain
    and username can collide with another pair that happens to contain the separator. A
    salted id hashes [salt, domain, username], which no unsalted pair can produce."""
    parts = [str(salt), str(domain), str(username)] if salt else [str(domain), str(username)]
    pair = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    h = hashlib.sha256(b"pear/v2/entry\x00" + pair.encode("utf-8", "surrogatepass"))
    return PREFIX + h.hexdigest()[:HEX_CHARS]


def collapse(items: Iterable[T], key: Callable[[T], str],
             mdat: Callable[[T], float]) -> tuple[dict[str, T], list[tuple[str, T]]]:
    """One item per id: ({id: kept}, [(id, dropped), ...]), both in first-seen order. The kept
    item is the one with the newest `mdat`; on a tie the first one seen stays."""
    kept: dict[str, T] = {}
    dropped: list[tuple[str, T]] = []
    for it in items:
        k = key(it)
        prev = kept.get(k)
        if prev is None:
            kept[k] = it
        elif mdat(it) > mdat(prev):
            kept[k] = it
            dropped.append((k, prev))
        else:
            dropped.append((k, it))
    return kept, dropped


def valid_id(value) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def check_id(value) -> str:
    """Return `value` if it is a usable entry id, else raise ValueError (never a path)."""
    if not valid_id(value):
        raise ValueError("bad entry id")
    return value
