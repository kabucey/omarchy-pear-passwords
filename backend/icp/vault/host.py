"""The credential model: one login (Credential) and the in-memory store the app reads
(CredentialStore), built from decrypted keychain items. Nothing here opens a socket or
listens for anyone - the app asks the backend CLI, one command at a time.
"""

from __future__ import annotations

import dataclasses
import datetime
import re


@dataclasses.dataclass(frozen=True)
class Credential:
    domain: str
    username: str
    password: str
    title: str = ""
    # Unix epoch seconds of the item's last change (keychain `mdat`, falling back to `cdat`);
    # 0 when unknown. Used to sort newest-first and to render a "last used N ago" line.
    mdat: float = 0.0
    # TOTP configuration lifted from the account's metadata item, or None. Kept as the raw
    # Apple form; icp.totp handles raw-vs-base32 and generates the code.
    totp: dict | None = None
    notes: str = ""
    # Apple's own password history from the entry's metadata record, newest first. Empty for
    # the many items Apple's Passwords app does not manage - those rely on our sync journal.
    apple_history: tuple = ()
    # The name given to this entry in Apple's Passwords app, synced from its metadata record.
    apple_title: str = ""
    # Extra domains this credential is offered on, inferred from metadata stubs that name the
    # same account but have no password item of their own. Apple stores no pointer we can
    # follow, so this is an inference, not a fact - see aliases_are_inferred in the picker.
    aliases: tuple = ()
    # Extra websites stored on the entry itself (metadata `s_as`). Unlike `aliases`, these are
    # a fact Apple records, and they are what the user edits.
    sites: tuple = ()
    # A copy in Apple's Recently Deleted (its access group ends in -recently-deleted). Shown
    # only as such, never as a live login, and never merged with the live copy.
    recently_deleted: bool = False
    # "passkey" for a row that is only a passkey (no password item for that account); a login
    # that also has one carries has_passkey. The passkey's private key is never kept.
    kind: str = "login"
    has_passkey: bool = False

    def storage_dict(self) -> dict:
        """Everything, for the on-disk vault (encrypted)."""
        d = {"domain": self.domain, "username": self.username, "password": self.password,
             "title": self.title, "mdat": self.mdat, "notes": self.notes,
             "aliases": list(self.aliases),
             "apple_history": [dict(h) for h in (self.apple_history or ())],
             "apple_title": self.apple_title, "sites": list(self.sites)}
        # Only when set, so a 1.x-shaped dict stays exactly what it was.
        if self.recently_deleted:
            d["recently_deleted"] = True
        if self.kind == "passkey":
            d["kind"] = "passkey"
        if self.has_passkey:
            d["has_passkey"] = True
        if self.totp:
            t = dict(self.totp)
            s = t.get("secret")
            # plist gives bytes; JSON cannot hold them, so store hex and mark it.
            if isinstance(s, (bytes, bytearray)):
                t["secret"] = bytes(s).hex()
                t["secret_hex"] = True
            d["totp"] = t
        return d

    def public_dict(self) -> dict:
        """What crosses the native-messaging socket to the browser.

        The TOTP *secret* deliberately never leaves this process - a compromised extension
        would otherwise walk away with a permanent second factor rather than one 30-second
        code. Only the fact that a code exists is exposed; the CLI generates it locally."""
        return {"domain": self.domain, "username": self.username,
                "password": self.password, "title": self.title, "mdat": self.mdat,
                "has_totp": bool(self.totp), "aliases": list(self.aliases)}

    def totp_code(self):
        """(code, seconds_remaining) or None."""
        if not self.totp:
            return None
        from .. import totp as _totp
        secret = self.totp.get("secret")
        if self.totp.get("secret_hex") and isinstance(secret, str):
            secret = bytes.fromhex(secret)
        return (_totp.code(secret, digits=self.totp.get("digits", 6),
                           period=self.totp.get("period", 30),
                           algorithm=self.totp.get("algorithm", 0)),
                _totp.seconds_remaining(self.totp.get("period", 30)))


_APPLE_EPOCH = 978307200  # 2001-01-01 UTC in unix seconds (Apple "absolute time" origin)


def _to_unix(value) -> float:
    """Best-effort convert a keychain date (`mdat`/`cdat`) to unix epoch seconds; 0 if unknown.
    plistlib yields a datetime for binary-plist <date>; a CKKS dateValue arrives as `CKDate`;
    a bare number is Apple absolute time (secs since 2001) when small, already-unix when large."""
    if isinstance(value, datetime.datetime):
        return value.timestamp()
    value = getattr(value, "time", value)  # ckks.CKDate -> its .time (unix seconds)
    if isinstance(value, (int, float)) and value > 0:
        return float(value) + _APPLE_EPOCH if value < 1e9 else float(value)
    return 0.0


def _normalize_host(value: str) -> str:
    """Reduce a URL or host to a bare lowercase hostname (strip scheme/port/path/leading www)."""
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split("?", 1)[0]
    v = v.split("@")[-1]          # strip userinfo
    v = v.split(":", 1)[0]        # strip port
    if v.startswith("www."):
        v = v[4:]
    return v


def domains_match(page: str, stored: str) -> bool:
    """True if a stored item's domain should autofill on `page`.

    Matches exact host, and either being a sub-domain of the other (so `example.com` fills on
    `login.example.com` and vice-versa). Conservative: requires a dotted-boundary suffix so
    `notexample.com` never matches `example.com`.
    """
    p, s = _normalize_host(page), _normalize_host(stored)
    if not p or not s:
        return False
    if p == s:
        return True
    return p.endswith("." + s) or s.endswith("." + p)


def match_aliases(page_domain: str, aliases: list) -> list:
    """Hide My Email aliases (icp.hme.client.HmeAlias) whose recorded domain matches the
    page, same domains_match() rule as Credential. Duck-typed on `.domain` rather than
    importing HmeAlias - vault/ stays free of any import from the hme/ extension."""
    return [a for a in aliases if a.domain and domains_match(page_domain, a.domain)]


def _is_credential(domain: str, title: str) -> bool:
    """False for the non-login records iCloud Keychain also syncs: Protected Cloud Storage service
    blobs (label "PCS com.apple.*", whose `acct` is a base64 key) and per-site "Website Metadata"
    records. Checks the final domain/title so the marker is caught wherever it lands; real web
    logins are reverse-DNS free and never carry these names."""
    for tag in (domain, title):
        t = (tag or "").strip().lower()
        if t.startswith(("pcs ", "pcs-", "website metadata")) or "com.apple." in t:
            return False
    return True


_GENERIC_NAME_TOKENS = {
    "account", "accounts", "admin", "app", "dashboard", "login", "password", "passwords",
    "signin", "sign", "web", "www",
}


def _name_matches_host(page: str, name: str) -> bool:
    """Fallback for Passwords entries that decrypt as generic items with only a saved label.

    The iOS Passwords app can show a useful account name (for example "Cloudflare") even when
    the decrypted item has no `srvr` host. Match only whole hostname labels so this stays much
    narrower than substring matching.
    """
    labels = {label for label in _normalize_host(page).split(".") if label}
    if not labels:
        return False
    tokens = {
        token for token in re.findall(r"[a-z0-9]+", name.lower())
        if len(token) >= 4 and token not in _GENERIC_NAME_TOKENS
    }
    return bool(labels & tokens)


# Apple keeps Recently Deleted items in the same CKKS view, under a parallel access group per
# live one (com.apple.cfnetwork-recently-deleted, com.apple.password-manager-recently-deleted,
# com.apple.webkit.webauthn-recently-deleted, ...: Apple's Passwords view policy).
RECENTLY_DELETED_SUFFIX = "-recently-deleted"
# Passkeys: class `keys` items in this access group (older spelling com.apple.WebKit.WebAuthn).
WEBAUTHN_AGRP = "com.apple.webkit.webauthn"

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def agrp_of(it) -> str:
    return str(it.get("agrp") or "")


def is_recently_deleted(it) -> bool:
    return agrp_of(it).endswith(RECENTLY_DELETED_SUFFIX)


def is_passkey(it) -> bool:
    base = agrp_of(it).removesuffix(RECENTLY_DELETED_SUFFIX)
    return str(it.get("class") or "") == "keys" and base.lower() == WEBAUTHN_AGRP


def _name(value) -> str:
    """An access group, class or attribute name as the diagnostic may show it, or "?"."""
    return value if isinstance(value, str) and _NAME_RE.match(value) else "?"


def strip_and_shape(items) -> dict:
    """Delete the private key (`v_Data`) of every class `keys` item, in place, before anything
    else reads it, and return what the items look like without a single value:
    {(class, agrp): {"count", "keys": {attribute names}, "inner_keys": {names}}}, where
    inner_keys are the top-level names inside a password-manager metadata blob.

    This is what op diag-items shows, once, to confirm the passkey and Recently Deleted
    attribute names on a real keychain. Names that are not plain identifiers show as "?"."""
    from ..keychain import metadata as _meta

    shape: dict = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        names = {_name(k) for k in it}
        if str(it.get("class") or "") == "keys":
            it.pop("v_Data", None)
        cls_, agrp = str(it.get("class") or ""), agrp_of(it)
        key = (_name(cls_) if cls_ else "", _name(agrp) if agrp else "")
        slot = shape.setdefault(key, {"count": 0, "keys": set(), "inner_keys": set()})
        slot["count"] += 1
        slot["keys"] |= names
        inner = _meta.parse(it.get("v_Data"))
        if inner is not None:
            slot["inner_keys"] |= {_name(k) for k in inner}
    return shape


def _holds(obj, needle: bytes, depth: int = 0) -> bool:
    """Whether a metadata blob holds `needle` (a passkey's credential id) as a value."""
    if depth > 4:
        return False
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj) == needle
    if isinstance(obj, dict):
        return any(_holds(v, needle, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_holds(v, needle, depth + 1) for v in obj)
    return False


class CredentialStore:
    """In-memory read-only store. The pipeline builds this from decrypted keychain items."""

    def __init__(self, credentials=None):
        self._creds: list[Credential] = list(credentials or [])
        # What from_items saw, as names and counts only (strip_and_shape).
        self.item_shape: dict = {}

    def __len__(self) -> int:
        return len(self._creds)

    def all(self) -> list["Credential"]:
        return list(self._creds)

    def match(self, page_domain: str) -> list[Credential]:
        def match_rank(c: Credential) -> int | None:
            if not _is_credential(c.domain, c.title):  # filters an older, unfiltered vault too
                return None
            if domains_match(page_domain, c.domain):
                return 0 if _normalize_host(page_domain) == _normalize_host(c.domain) else 1
            stored = _normalize_host(c.domain)
            if ("." not in stored) and _name_matches_host(page_domain, c.title or c.domain):
                return 2
            # Inferred aliases rank last: they come from a metadata stub naming this account at
            # that domain, not from a stored pointer, so a real match must always win.
            if any(domains_match(page_domain, a) for a in c.aliases):
                return 3
            return None

        ranked = [(rank, c) for c in self._creds
                  if not c.recently_deleted and c.kind != "passkey"
                  and (rank := match_rank(c)) is not None]
        # exact-host matches first, then parent/subdomain, then label-only fallbacks; within a
        # tier, most-recently-used first (newest `mdat`), then title for a stable order.
        ranked.sort(key=lambda rc: (rc[0], -rc[1].mdat, rc[1].title, rc[1].username))
        return [c for _, c in ranked]

    @classmethod
    def from_items(cls, items) -> "CredentialStore":
        """Build from decrypted keychain item dicts (plist form). Apple `inet` password items use
        `srvr` (server/domain), `acct` (username), `v_Data` (plaintext password), `labl` (title);
        tolerate the common variants.

        Two kinds of item are not plain logins. An item whose access group ends in
        -recently-deleted is in Apple's Recently Deleted: it becomes its own credential flagged
        `recently_deleted`, keyed apart from the live copy everywhere below, so it can neither
        merge into the live entry nor lend it notes, a code or aliases. A class `keys` item in
        the WebAuthn access group is a passkey: its `v_Data` (the private key) is deleted from
        the dict before anything reads it, and it either marks the login for the same (rp id,
        user) `has_passkey` or becomes a passkey-only row with no password."""
        from ..keychain import metadata as _meta

        items = list(items)
        shape = strip_and_shape(items)
        items = [it for it in items if isinstance(it, dict)]

        def _key(it):
            return (str(it.get("srvr") or it.get("server") or it.get("domain")
                        or it.get("url") or it.get("svce") or ""),
                    str(it.get("acct") or it.get("username") or it.get("user") or ""))

        def _rkey(it):
            return (is_recently_deleted(it), *_key(it))

        passkeys = [it for it in items if is_passkey(it)]
        rest = [it for it in items if not is_passkey(it)]

        # Pass 1. Apple stores per-account attributes in a sibling item whose v_Data is a
        # binary plist, not a password. Upstream treated those as logins, so a third of the
        # vault had "bplist00..." as its password and the extension would have typed it into
        # a form. Index them by (deleted, domain, account) and keep them out of the credential
        # list.
        extras = {}
        # (deleted, account) -> domains a metadata stub names but no password item occupies.
        stub_domains = {}
        # Every metadata record, for finding a passkey's account: (deleted, domain, account, blob).
        sidecars = []
        pw_keys = set()
        for it in rest:
            if not _meta.is_metadata(it.get("v_Data")):
                pw_keys.add(_rkey(it))
        for it in rest:
            meta = _meta.parse(it.get("v_Data"))
            if meta is None:
                continue
            rk = _rkey(it)
            sidecars.append((rk[0], rk[1], rk[2], meta))
            if rk not in pw_keys and rk[1] and rk[2] \
                    and _is_credential(rk[1], str(it.get("labl") or "")):
                stub_domains.setdefault((rk[0], rk[2]), set()).add(rk[1])
            cfg, note = _meta.totp_config(meta), _meta.notes(meta)
            apple_hist = _meta.password_history(meta)
            apple_name = _meta.title(meta)
            extra_sites = _meta.sites(meta)
            if cfg or note or apple_hist or apple_name or extra_sites:
                slot = extras.setdefault(rk, {})
                if extra_sites and not slot.get("sites"):
                    slot["sites"] = extra_sites
                if apple_name and not slot.get("apple_title"):
                    slot["apple_title"] = apple_name
                if cfg and not slot.get("totp"):
                    slot["totp"] = cfg
                if note and not slot.get("notes"):
                    slot["notes"] = note
                if apple_hist and not slot.get("apple_history"):
                    slot["apple_history"] = apple_hist

        creds = []
        for it in rest:
            if _meta.is_metadata(it.get("v_Data")):
                continue          # attributes, not a credential
            if str(it.get("class") or "") == "keys":
                continue          # a key item that is not a passkey: nothing to show
            deleted = is_recently_deleted(it)
            domain = (it.get("srvr") or it.get("server") or it.get("domain")
                      or it.get("url") or it.get("svce") or "")
            username = it.get("acct") or it.get("username") or it.get("user") or ""
            pw = it.get("v_Data") or it.get("password") or b""
            if isinstance(pw, (bytes, bytearray)):
                pw = pw.decode("utf-8", "replace")
            title = str(it.get("labl") or domain)
            if not _is_credential(str(domain), title):
                continue
            # Need a host/label to match against and at least a username or password to fill.
            if (not domain and not username) or not (username or pw):
                continue
            mdat = _to_unix(it.get("mdat") or it.get("cdat"))
            extra = extras.get(_rkey(it), {})
            # Apple stores no pointer from a stub to its credential (path, sha1, UUID, vwht and
            # bin0 were all checked and none resolves), so association is inferred from the
            # account name. Never alias onto the credential's own domain.
            alias = tuple(sorted(d for d in stub_domains.get((deleted, str(username)), ())
                                 if not domains_match(d, str(domain))))
            creds.append(Credential(domain=str(domain), username=str(username),
                                    password=str(pw), title=title, mdat=mdat,
                                    totp=extra.get("totp"), notes=extra.get("notes", ""),
                                    apple_history=tuple(extra.get("apple_history") or ()),
                                    apple_title=extra.get("apple_title", ""),
                                    aliases=alias, sites=tuple(extra.get("sites") or ()),
                                    recently_deleted=deleted))

        for it in passkeys:
            deleted = is_recently_deleted(it)
            rp, user, sidecar = _passkey_account(it, sidecars, deleted)
            if not rp or not _is_credential(rp, rp):
                continue
            hits = [i for i, c in enumerate(creds)
                    if c.kind == "login" and c.recently_deleted == deleted
                    and c.username == user and _normalize_host(c.domain) == _normalize_host(rp)]
            for i in hits:
                creds[i] = dataclasses.replace(creds[i], has_passkey=True)
            if hits:
                continue
            extra = extras.get((deleted, *sidecar), {}) if sidecar else {}
            creds.append(Credential(domain=rp, username=user, password="", title=rp,
                                    mdat=_to_unix(it.get("mdat") or it.get("cdat")),
                                    notes=extra.get("notes", ""),
                                    apple_title=extra.get("apple_title", ""),
                                    sites=tuple(extra.get("sites") or ()),
                                    recently_deleted=deleted, kind="passkey",
                                    has_passkey=True))
        store = cls(creds)
        store.item_shape = shape
        return store


def _passkey_account(it, sidecars, deleted: bool):
    """(rp id, user, sidecar key or None) for a passkey item.

    The key item carries the rp id in `labl` and the credential id in `klbl`, but no account
    name: that lives in the password-manager metadata record ("sidecar") Apple keeps for it.
    The sidecar is the one that holds this credential id; failing that, the only account any
    metadata record names at that rp id. UNVERIFIED on a real keychain (the Passkeys category
    stays off until op diag-items confirms the names); with no unique answer the user is ""."""
    rp = str(it.get("labl") or it.get("srvr") or "")
    user = str(it.get("acct") or "")
    same = [sc for sc in sidecars if sc[0] == deleted]
    cid = it.get("klbl")
    if isinstance(cid, (bytes, bytearray)) and len(cid) >= 16:
        for sc in same:
            if (not rp or _normalize_host(sc[1]) == _normalize_host(rp)) \
                    and _holds(sc[3], bytes(cid)):
                return rp or sc[1], user or sc[2], (sc[1], sc[2])
    if not rp:
        return "", "", None
    at = [sc for sc in same if sc[2] and _normalize_host(sc[1]) == _normalize_host(rp)]
    if user:
        mine = [sc for sc in at if sc[2] == user]
        return rp, user, ((mine[0][1], user) if mine else None)
    if len({sc[2] for sc in at}) == 1:
        return rp, at[0][2], (at[0][1], at[0][2])
    return rp, "", None
