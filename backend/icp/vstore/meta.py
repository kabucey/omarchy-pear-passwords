"""meta.v2: everything tier 1 releases, plus the bookkeeping that lets sync run without SK.

Plaintext shape (under K_meta, written whole on every change - 554 entries is ~200 KiB):

    {"format": 2, "synced_at": float|null, "needs_login": bool,
     "entries": {"<id>": {
         "title", "domain", "sites", "username", "apple_title", "aliases",
         "has_totp", "has_notes", "mdat", "tags", "has_passkey", "kind",
         "has_password", "recently_deleted",           -> vstore.Meta (nickname comes from
                                                          nicknames.v2, history_count is
                                                          derived)
         "v":      version of entries/<id>.box,
         "pwmac":  HMAC(K_pwmac, password),
         "smac":   HMAC(K_pwmac, the other secrets),
         "apple_n": how many Apple history items the box holds,
         "hist":   [{"n", "at", "source"}...] oldest first, one per history/<id>/<n>.box,
         "deleted": bool, "deleted_at": float}}}

A tombstoned entry keeps its record, box and history: if iCloud brings the account back, its
history and nickname are still there.

The last five Meta fields came after the first meta.v2 files were written. A record without
them reads as the defaults below (FORMAT stays 2), and compares equal to them, so loading an
older file changes nothing until the next sync fills them in.
"""

from __future__ import annotations

from ..keychain import tagline
from . import Meta, SealError

FORMAT = 2
_META_FIELDS = ("title", "domain", "sites", "username", "apple_title", "aliases", "has_totp",
                "has_notes", "mdat", "tags", "has_passkey", "kind", "has_password",
                "recently_deleted")
# What a record written before a field existed holds for it.
DEFAULTS = {"tags": [], "has_passkey": False, "kind": "login", "has_password": True,
            "recently_deleted": False}
KINDS = ("login", "passkey")


def empty() -> dict:
    return {"format": FORMAT, "synced_at": None, "needs_login": False, "entries": {}}


def check(doc) -> dict:
    """The document if it has the expected shape, else SealError("damaged"): a file that
    authenticates but is not ours is no less damaged than one that does not."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT \
            or not isinstance(doc.get("entries"), dict):
        raise SealError("damaged", "meta.v2 has the wrong shape")
    for rec in doc["entries"].values():
        if not isinstance(rec, dict) or not isinstance(rec.get("hist", []), list):
            raise SealError("damaged", "meta.v2 has the wrong shape")
    return doc


def fields_from(m: Meta) -> dict:
    """The stored, non-derived Meta fields, normalised."""
    if not isinstance(m, Meta):
        raise ValueError("Meta expected")
    return {
        "title": str(m.title or ""),
        "domain": str(m.domain or ""),
        "sites": [str(s) for s in (m.sites or [])],
        "username": str(m.username or ""),
        "apple_title": str(m.apple_title or ""),
        "aliases": [str(a) for a in (m.aliases or [])],
        "has_totp": bool(m.has_totp),
        "has_notes": bool(m.has_notes),
        "mdat": float(m.mdat or 0.0),
        "tags": [str(t) for t in (m.tags or [])][:tagline.MAX_TAGS],
        "has_passkey": bool(m.has_passkey),
        "kind": m.kind if m.kind in KINDS else "login",
        "has_password": bool(m.has_password),
        "recently_deleted": bool(m.recently_deleted),
    }


def notes_fields(notes: str) -> dict:
    """has_notes and tags from an entry's plaintext notes: the tag line's tags, and whether
    anything is left of the body without it."""
    body, tags = tagline.split(notes or "")
    return {"has_notes": bool(body.strip()), "tags": tags}


def same_fields(rec: dict, fields: dict) -> bool:
    return all(rec.get(k, DEFAULTS.get(k)) == fields[k] for k in _META_FIELDS)


def history_count(rec: dict) -> int:
    return len(rec.get("hist") or []) + int(rec.get("apple_n") or 0)


def to_meta(id: str, rec: dict, nickname: str = "") -> Meta:
    return Meta(id=id, title=rec.get("title", ""), domain=rec.get("domain", ""),
                sites=list(rec.get("sites") or []), username=rec.get("username", ""),
                nickname=nickname, has_totp=bool(rec.get("has_totp")),
                has_notes=bool(rec.get("has_notes")), mdat=float(rec.get("mdat") or 0.0),
                history_count=history_count(rec), apple_title=rec.get("apple_title", ""),
                aliases=list(rec.get("aliases") or []),
                tags=[str(t) for t in (rec.get("tags") or [])],
                has_passkey=bool(rec.get("has_passkey", False)),
                kind=rec.get("kind") if rec.get("kind") in KINDS else "login",
                has_password=bool(rec.get("has_password", True)),
                recently_deleted=bool(rec.get("recently_deleted", False)))


def live(doc: dict):
    """(id, record) of every entry that is not tombstoned."""
    return ((i, r) for i, r in doc["entries"].items() if not r.get("deleted"))


def live_record(doc: dict, id: str) -> dict | None:
    rec = doc["entries"].get(id) if isinstance(id, str) else None
    return rec if rec is not None and not rec.get("deleted") else None
