"""Decryption pipeline: composes the primitives into the unwrap chain
tlkshare -> TLK -> class key -> item key -> item plist -> credential. See RESEARCH.md."""

from __future__ import annotations

import base64
import dataclasses
import plistlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec

from ..proto.codec import decode_fields, first, first_str
from ..transport import ckks
from . import crypto as kc, nska
from ..vault.host import CredentialStore

# item-record fields that are NOT part of the per-item authenticated data (everything else is)
_AAD_EXCLUDED = {"gen", "pcspublickey", "UUID", "data", "pcsservice", "pcspublicidentity",
                 "parentkeyref", "uploadver", "wrappedkey", "encver"}


@dataclasses.dataclass
class PipelineDiagnostics:
    """Evidence collected while turning one fetched CKKS snapshot into credentials.

    Foreign TLK shares are deliberately counted but are not failures: a Cuttlefish zone can
    contain shares for every trusted peer.  Failures in the chain needed by a fetched item are
    fatal, and callers must inspect :attr:`complete` before replacing a local vault.
    ``authoritative`` is set only by the caller that has completed every requested zone; it is
    intentionally separate from ``complete`` so an empty but authoritative account is valid.
    """

    authoritative: bool = False
    tlkshare_records: int = 0
    foreign_tlkshares: int = 0
    relevant_tlkshares: int = 0
    unwrapped_tlks: int = 0
    tlkshare_failures: list[str] = dataclasses.field(default_factory=list)
    class_key_records: int = 0
    unwrapped_class_keys: int = 0
    class_key_failures: dict[str, str] = dataclasses.field(default_factory=dict)
    item_records: int = 0
    decrypted_items: int = 0
    item_failures: dict[str, str] = dataclasses.field(default_factory=dict)
    missing_class_keys: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    credential_count: int = 0
    store_failure: str | None = None

    @property
    def errors(self) -> list[str]:
        """Human-readable fatal diagnostics for this snapshot."""
        errors = []
        if self.tlkshare_failures:
            errors.append(f"{len(self.tlkshare_failures)} relevant TLK share(s) failed")
        if self.item_failures:
            errors.append(f"{len(self.item_failures)} item(s) failed to decrypt or parse")
        if self.missing_class_keys:
            errors.append(f"{len(self.missing_class_keys)} class key(s) missing")
        needed_class_failures = set(self.missing_class_keys) & set(self.class_key_failures)
        if needed_class_failures:
            errors.append(f"{len(needed_class_failures)} required class key(s) failed to unwrap")
        if self.store_failure:
            errors.append(f"credential conversion failed: {self.store_failure}")
        return errors

    @property
    def complete(self) -> bool:
        """Whether no relevant decryption or conversion failure was observed."""
        return not self.errors

    @property
    def authoritative_empty(self) -> bool:
        """Whether an explicitly complete snapshot produced no credentials."""
        return self.authoritative and self.complete and self.credential_count == 0

    def summary(self) -> str:
        details = self.errors
        if details:
            return "; ".join(details)
        return (f"{self.decrypted_items} item(s) decrypted, {self.credential_count} credential(s)"
                + (" (authoritative empty result)" if self.authoritative_empty else ""))


@dataclasses.dataclass(frozen=True)
class PipelineResult:
    """Credential snapshot plus the evidence needed before committing it to disk."""

    store: CredentialStore
    diagnostics: PipelineDiagnostics


def _record_name(record, index: int) -> str:
    name = getattr(record, "record_name", None)
    return str(name) if name else f"<record-{index}>"


def _failure_text(exc: Exception) -> str:
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _le8(n: int) -> bytes:
    """64-bit two's-complement little-endian (Rust i64/u64 `.to_le_bytes`). Masks to 64 bits so
    proto int64 negatives (which arrive as large unsigned varints) don't raise OverflowError."""
    return (int(n) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def authenticated_data_v2(uuid: str, fields: dict, *, encver: int, gen: int,
                          parent_key_id: str) -> list[bytes]:
    """Build the AES-SIV associated-data values for an `item` record (encver 2): the item's
    authenticated metadata as a by-key-sorted map, values in key order (after the leading IV)."""
    aad = {
        "UUID": uuid.encode(),
        "encver": _le8(encver),
        "gen": _le8(gen),
        "wrappedkey": parent_key_id.encode(),  # the parent class key's id, not the wrappedkey field
    }
    # PCS fields are authenticated when present, with specific encodings, so are handled here
    # rather than in the generic loop below.
    if fields.get("pcsservice") is not None:
        aad["pcsservice"] = _le8(fields["pcsservice"])
    for _pcs in ("pcspublicidentity", "pcspublickey"):
        v = fields.get(_pcs)
        if isinstance(v, (bytes, bytearray)):
            aad[_pcs] = bytes(v)
    for name, val in fields.items():
        if name in _AAD_EXCLUDED or name.startswith("server_"):
            continue
        if isinstance(val, str):
            aad[name] = val.encode()
        elif isinstance(val, (bytes, bytearray)):
            aad[name] = bytes(val)
        elif isinstance(val, ckks.CKDate):               # RFC3339 seconds, 'Z' suffix
            dt = datetime.fromtimestamp(int(val.time), tz=timezone.utc)
            aad[name] = dt.strftime("%Y-%m-%dT%H:%M:%SZ").encode()
        elif isinstance(val, bool):                      # before int - bool is an int subclass
            aad[name] = _le8(1 if val else 0)
        elif isinstance(val, float):                     # (value as u64).to_le_bytes()
            aad[name] = (int(val) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        elif isinstance(val, int):                       # signedValue: i64 little-endian
            aad[name] = _le8(val)
    return [aad[k] for k in sorted(aad)]


def unwrap_tlkshares(tlkshares, our_peer_id: str,
                     our_encryption_key: ec.EllipticCurvePrivateKey,
                     diagnostics: PipelineDiagnostics | None = None) -> dict:
    """Return {tlkUuid: TLK key bytes} for every TLKShare addressed to us that we can decrypt.

    A TLKShare's `wrappedkey` ECIES-decrypts (with our peer encryption key) to a
    `CuttlefishSerializedKey` protobuf {uuid(1), zoneName(2), keyclass(3), key(4)} - NOT raw
    TLK bytes - so the TLK uuid comes from field 1 and the key material from field 4."""
    tlks: dict[str, bytes] = {}
    for index, share in enumerate(tlkshares):
        record_name = _record_name(share, index)
        if diagnostics is not None:
            diagnostics.tlkshare_records += 1
        try:
            receiver = share.get_str("receiver")
        except Exception as exc:
            if diagnostics is not None:
                diagnostics.relevant_tlkshares += 1
                diagnostics.tlkshare_failures.append(record_name)
            continue
        if receiver != our_peer_id:
            if diagnostics is not None:
                diagnostics.foreign_tlkshares += 1
            continue
        if diagnostics is not None:
            diagnostics.relevant_tlkshares += 1
        try:
            wrapped = share.get_str("wrappedkey")
        except Exception:
            wrapped = None
        if not wrapped:
            if diagnostics is not None:
                diagnostics.tlkshare_failures.append(record_name)
            continue
        try:
            ies = nska.expand(base64.b64decode(wrapped, validate=True))
            serialized = kc.ecies_decrypt_sf(our_encryption_key, ies)
            f = decode_fields(serialized)
            key_id, tlk = first_str(f, 1), first(f, 4)
            if not key_id or not tlk:
                raise ValueError("decrypted TLK share has no key id or key material")
        except Exception:
            if diagnostics is not None:
                diagnostics.tlkshare_failures.append(record_name)
            continue
        tlks[key_id] = tlk
        if diagnostics is not None:
            diagnostics.unwrapped_tlks += 1
    return tlks


def unwrap_class_keys(synckeys, tlks: dict,
                      diagnostics: PipelineDiagnostics | None = None) -> dict:
    """Return {keyId: class-key (64B SIV)} by unwrapping each synckey with its parent TLK."""
    keys: dict[str, bytes] = {}
    for index, sk in enumerate(synckeys):
        record_name = _record_name(sk, index)
        if diagnostics is not None:
            diagnostics.class_key_records += 1
        try:
            parent = sk.get_str("parentkeyref")
            wrapped = sk.get_str("wrappedkey")
        except Exception as exc:
            if diagnostics is not None:
                diagnostics.class_key_failures[record_name] = _failure_text(exc)
            continue
        if not parent:
            if diagnostics is not None:
                diagnostics.class_key_failures[record_name] = "missing parent TLK reference"
            continue
        tlk = tlks.get(parent)
        if tlk is None:
            if diagnostics is not None:
                diagnostics.class_key_failures[record_name] = f"missing TLK {parent}"
            continue
        if not wrapped:
            if diagnostics is not None:
                diagnostics.class_key_failures[record_name] = "missing wrapped class key"
            continue
        try:
            key = kc.siv_unwrap(tlk, base64.b64decode(wrapped, validate=True))
            if not key:
                raise ValueError("empty class key")
        except Exception as exc:
            if diagnostics is not None:
                diagnostics.class_key_failures[record_name] = _failure_text(exc)
            continue
        keys[record_name] = key
        if diagnostics is not None:
            diagnostics.unwrapped_class_keys += 1
    return keys


def decrypt_items(items, class_keys: dict,
                  diagnostics: PipelineDiagnostics | None = None) -> list[dict]:
    """Decrypt each `item` record whose parent class key we hold -> the item plist dict."""
    out = []
    for index, it in enumerate(items):
        record_name = _record_name(it, index)
        if diagnostics is not None:
            diagnostics.item_records += 1
        try:
            parent = it.get_str("parentkeyref")
            data = it.get_bytes("data")
            wrapped = it.get_str("wrappedkey")
        except Exception as exc:
            if diagnostics is not None:
                diagnostics.item_failures[record_name] = _failure_text(exc)
            continue
        if not parent or data is None or not wrapped:
            if diagnostics is not None:
                diagnostics.item_failures[record_name] = "missing item parent, data, or wrapped key"
            continue
        ck = class_keys.get(parent)
        if ck is None:
            if diagnostics is not None:
                diagnostics.missing_class_keys.setdefault(parent, []).append(record_name)
            continue
        try:
            item_key = kc.siv_unwrap(ck, base64.b64decode(wrapped, validate=True))
            encver = it.fields.get("encver", 2)
            gen = it.fields.get("gen", 0)
            aad = authenticated_data_v2(record_name, it.fields, encver=encver, gen=gen,
                                        parent_key_id=parent)
            plaintext = kc.decrypt_item(item_key, data, aad)
            parsed = plistlib.loads(plaintext)
            if not isinstance(parsed, dict):
                raise ValueError("decrypted item is not a plist dictionary")
        except Exception as exc:
            if diagnostics is not None:
                diagnostics.item_failures[record_name] = _failure_text(exc)
            continue
        out.append(parsed)
        if diagnostics is not None:
            diagnostics.decrypted_items += 1
    return out


def build_credential_store(records_by_type: dict, our_peer_id: str,
                           our_encryption_key: ec.EllipticCurvePrivateKey,
                           tlks: dict | None = None,
                           *, diagnostics: PipelineDiagnostics | None = None) -> CredentialStore:
    """Full pipeline: grouped CKKS records -> decrypted CredentialStore.

    TLKs come from two UNIONed sources: `tlks` supplied pre-computed (from
    `fetchRecoverableTLKShares`, the only source for user-controllable views like Passwords) and the
    plain `tlkshare` records in the fetched zones (always-on views like WiFi)."""
    diagnostics = diagnostics or PipelineDiagnostics()
    plain_tlks = unwrap_tlkshares(records_by_type.get("tlkshare", []), our_peer_id,
                                  our_encryption_key, diagnostics)
    merged_tlks = {**plain_tlks, **tlks} if tlks else plain_tlks
    class_keys = unwrap_class_keys(records_by_type.get("synckey", []), merged_tlks,
                                   diagnostics)
    items = decrypt_items(records_by_type.get("item", []), class_keys, diagnostics)
    try:
        store = CredentialStore.from_items(items)
    except Exception as exc:
        diagnostics.store_failure = _failure_text(exc)
        store = CredentialStore([])
    diagnostics.credential_count = len(store)
    return store


def build_credential_snapshot(records_by_type: dict, our_peer_id: str,
                              our_encryption_key: ec.EllipticCurvePrivateKey,
                              tlks: dict | None = None,
                              *, authoritative: bool = False) -> PipelineResult:
    """Build a credential snapshot and retain the evidence needed to commit it.

    ``authoritative`` must come from a caller that has completed every requested zone.  It is
    not inferred from how many credentials happened to decrypt: zero credentials can be a valid
    account, while a nonzero partial result can still have silently lost passwords.
    """
    diagnostics = PipelineDiagnostics(authoritative=authoritative)
    store = build_credential_store(records_by_type, our_peer_id, our_encryption_key, tlks,
                                   diagnostics=diagnostics)
    return PipelineResult(store=store, diagnostics=diagnostics)
