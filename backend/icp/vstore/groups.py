"""One account on several websites: which live entries are one listing.

Apple's Passwords app shows an account with several websites as one row, but the keychain keeps
one internet-password item per site, each with its own `srvr` and the same `acct` and password.
No field on the items points from one to another (the pipeline's comment on stubs says as much:
path, sha1, UUID and vwht were all checked), so the link is inferred: same username and same
password. The password is compared by `pwmac` (HMAC under K_pwmac, already in meta.v2), so
nothing is opened and no password leaves the daemon; the group id is derived from entry ids only.

Two entries that each carry a different name (Apple title or Pear nickname) are two accounts
that merely share a username and a password, and stay apart. Recently Deleted copies, passkey
rows, rows without a password, Wi-Fi networks and entries without a username are never grouped.
"""

from __future__ import annotations


def _eligible(rec: dict) -> bool:
    return (not rec.get("recently_deleted") and rec.get("kind", "login") == "login"
            and rec.get("has_password", True) and bool(rec.get("pwmac"))
            and bool((rec.get("username") or "").strip())
            and (rec.get("domain") or "") != "AirPort")


def _same(a: str, b: str) -> bool:
    return not a or not b or a == b


def compute(doc: dict, nicknames: dict | None = None) -> dict[str, str]:
    """{entry id: group id} for every live entry that shares an account with another. The group
    id is the smallest member id, so it is stable while the group's membership is."""
    nick = nicknames or {}
    buckets: dict[tuple, list] = {}
    for i, rec in doc["entries"].items():
        if rec.get("deleted") or not _eligible(rec):
            continue
        # Entries of a shared group are paired inside that group only: never with an entry of
        # the person's own keychain, nor with another group's.
        buckets.setdefault((rec.get("shared_group") or "", rec["username"].strip(),
                            rec["pwmac"]), []).append(i)
    out: dict[str, str] = {}
    for ids in buckets.values():
        if len(ids) < 2:
            continue
        clusters: list[dict] = []     # {"ids", "title", "nick"}
        for i in sorted(ids):
            title = (doc["entries"][i].get("apple_title") or "").strip().lower()
            nk = (nick.get(i) or "").strip().lower()
            for c in clusters:
                if _same(c["title"], title) and _same(c["nick"], nk):
                    c["ids"].append(i)
                    c["title"], c["nick"] = c["title"] or title, c["nick"] or nk
                    break
            else:
                clusters.append({"ids": [i], "title": title, "nick": nk})
        for c in clusters:
            if len(c["ids"]) > 1:
                for i in c["ids"]:
                    out[i] = c["ids"][0]
    return out
