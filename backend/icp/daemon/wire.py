"""Meta as the window receives it (docs/protocol.md 3.1), and the account label dialogs show.

The display fields are derived exactly as 1.3.2's `app-list` derived them, so the list looks the
same after the move: a nickname wins, then Apple's own title, then the keychain title with its
"(username)" suffix stripped; an entry with no real title leads with its account; Wi-Fi items
are those whose site is AirPort; rows that would look identical are flagged `ambiguous`.
`tags`, `has_passkey`, `kind`, `has_password` and `recently_deleted` are list metadata too.
"""

from __future__ import annotations

import re

_UUIDISH = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-")
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _display(title: str, username: str, domain: str) -> dict:
    title, user, domain = (title or "").strip(), (username or "").strip(), (domain or "").strip()
    if user and title.endswith(f"({user})"):
        title = title[: -len(f"({user})")].strip()
    if not title or _UUIDISH.match(title):
        return {"primary": user or domain or "(untitled)", "secondary": "", "no_site": True}
    return {"primary": title, "secondary": user, "no_site": False}


def visible(m, features: dict | None = None) -> bool:
    """Whether the window may list `m`. Recently Deleted copies and passkey-only rows wait for
    their feature flag (unlock reply `features`), which waits for a check on a real keychain."""
    f = features or {}
    if getattr(m, "recently_deleted", False) and not f.get("apple_deleted"):
        return False
    if getattr(m, "kind", "login") == "passkey" and not f.get("passkeys"):
        return False
    return True


def meta_to_wire(m, features: dict | None = None) -> dict:
    f = features or {}
    d = _display(m.title, m.username, m.domain)
    local = (m.nickname or "").strip()
    apple = (getattr(m, "apple_title", "") or "").strip()
    name = local or apple
    if d["no_site"] and name and m.username and not d["secondary"]:
        d["secondary"] = m.username
    return {
        "id": m.id, "title": m.title, "domain": m.domain, "sites": list(m.sites or ()),
        "username": m.username, "nickname": m.nickname, "apple_title": apple,
        "aliases": list(getattr(m, "aliases", ()) or ()),
        "has_totp": bool(m.has_totp), "has_notes": bool(m.has_notes),
        "mdat": float(m.mdat or 0), "history_count": int(m.history_count or 0),
        "primary": name or d["primary"], "secondary": d["secondary"],
        "no_site": d["no_site"], "is_wifi": (m.domain or "") == "AirPort",
        "ambiguous": False,
        "tags": [str(t) for t in (getattr(m, "tags", None) or ())],
        "has_passkey": bool(getattr(m, "has_passkey", False)) and bool(f.get("passkeys")),
        "kind": "passkey" if getattr(m, "kind", "login") == "passkey" else "login",
        "has_password": bool(getattr(m, "has_password", True)),
        "recently_deleted": bool(getattr(m, "recently_deleted", False)),
        "_real_title": d["primary"],
    }


def internal_reason(e: dict) -> str | None:
    """Why an item counts as one of Apple's own records (a short rule name, for the journal),
    or None for an entry a person logs in with.

    Anything a person named is theirs: an entry with a Passwords-app title, a Pear nickname or
    tags is never internal, whatever its username or site look like (an app password saved as
    "Mail API" with an API client id as its username was hidden by the username rules below)."""
    if (e.get("apple_title") or "").strip() or (e.get("nickname") or "").strip() or e.get("tags"):
        return None
    user, domain = e["username"] or "", e["domain"] or ""
    title = e.get("_real_title") or ""
    # Apple's own markers, wherever they appear.
    if user.startswith("PCSBoundaryKey") or user.startswith("com.apple."):
        return "apple-service-account"
    if "CHIPPlugin" in user or "CHIPPlugin" in title:
        return "chip-plugin"
    if user.startswith("_Apple") or title.startswith("_Apple"):
        return "apple-private"
    # Shape rules, only for an item with no real website: a login at a site may well have a
    # 70-character API client id or a numeric customer number as its username.
    real_site = domain == "AirPort" or ("." in domain and not _UUIDISH.match(domain))
    if not real_site:
        if len(user) > 60:
            return "long-username"
        if re.fullmatch(r"[0-9]{6,}", user) or re.fullmatch(r"[0-9]{6,}", title):
            return "numeric-id"
        if not domain and not (e["primary"] or ""):
            return "no-site-no-name"
    return None


def is_internal(e: dict) -> bool:
    """Keychain items that exist for Apple's own services, not for a person to log in with."""
    return internal_reason(e) is not None


def entries(metas, show_all: bool = False, features: dict | None = None) -> list[dict]:
    """The sorted wire list. Internal records are left out unless `show_all`, and rows whose
    feature is off are left out always (visible())."""
    out = [meta_to_wire(m, features) for m in metas if visible(m, features)]
    if not show_all:
        out = [e for e in out if not is_internal(e)]
    out.sort(key=lambda e: (e["primary"].lower(), e["secondary"].lower()))
    seen: dict[tuple, int] = {}
    for e in out:
        k = (e["primary"], e["secondary"])
        seen[k] = seen.get(k, 0) + 1
    for e in out:
        e["ambiguous"] = seen[(e["primary"], e["secondary"])] > 1
        del e["_real_title"]
    return out


def account_label(m) -> str:
    """"<name> — <username>" for the dialog's $(account): the nickname when set, else the
    title, else the domain. Unsanitized; polkit.sanitize() runs on every details value."""
    title = _display(m.title, m.username, m.domain)
    name = ((m.nickname or "").strip() or (getattr(m, "apple_title", "") or "").strip()
            or ("" if title["no_site"] else title["primary"]) or (m.domain or "").strip())
    user = (m.username or "").strip()
    if name and user and name != user:
        return f"{name} — {user}"
    return name or user or "(untitled)"


def valid_id(value) -> bool:
    return isinstance(value, str) and bool(ID_RE.match(value))
