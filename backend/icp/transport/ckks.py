"""CKKS record fetch: pull the iCloud Keychain zone records (tlkshare / synckey / item /
currentitem) via a CloudKit RecordRetrieveChanges op per zone. See RESEARCH.md "transport/ckks.py"."""

from __future__ import annotations

import dataclasses
import struct

from ..proto.codec import Writer, decode_fields, first, first_str


@dataclasses.dataclass
class CKDate:
    """A CloudKit Date value - kept distinct from a plain double so the item AAD encodes it
    as RFC3339 rather than as a number."""
    time: float   # seconds (UNIX)


# Keychain CKKS zones (private DB). "Passwords" + "Manatee" hold web credentials.
KEYCHAIN_ZONES = (
    "Passwords", "Manatee", "Engram", "SecureObjectSync", "ProtectedCloudStorage",
    "CreditCards", "ApplePay", "WiFi", "Home", "Groups", "Contacts", "Mail",
    "LimitedPeersAllowed", "SE-PTC", "Photos",
)

# These are the zones from which the vault's credentials are built.  A successful sync must
# fetch every requested credential-bearing zone; accepting one zone while silently losing the
# other would turn a transient CloudKit error into a destructive local snapshot.
CREDENTIAL_ZONES = frozenset(("Passwords", "Manatee"))

ID_TYPE_RECORD = 1
ID_TYPE_RECORD_ZONE = 6
ID_TYPE_USER = 7

OP_TYPE_RECORD_RETRIEVE_CHANGES = 213
FIELD_RETRIEVE_CHANGES = 213

# RequestOperation.recordSaveRequest = 210 and Operation.Type.RECORD_SAVE_TYPE = 210: in this
# protocol the operation type and the request/response field number are the same number.
OP_TYPE_RECORD_SAVE = 210
FIELD_RECORD_SAVE = 210

# Record.Field.Value.Type - written explicitly on save. Reads ignore it (the populated value
# field is enough to tell them apart) but Apple's decoder is given the declared type.
VT_BYTES, VT_DATE, VT_STRING, VT_REFERENCE, VT_INT64, VT_DOUBLE = 1, 2, 3, 5, 7, 8

# RecordSaveRequest.saveSemantics. 2 creates, 3 updates an existing record; both are sent with
# merge=true. Values taken from rustpush's SaveRecordOperation, which is what these were
# reverse-engineered from and is known to be accepted by Apple.
SAVE_SEMANTICS_CREATE = 2
SAVE_SEMANTICS_UPDATE = 3


def _identifier(name: str, type_: int) -> bytes:
    return Writer().string(1, name).uint64(2, type_).finish()


def record_zone_identifier(zone: str, user_id: str) -> bytes:
    return (Writer()
            .message(1, _identifier(zone, ID_TYPE_RECORD_ZONE))
            .message(2, _identifier(user_id, ID_TYPE_USER))
            .finish())


def build_retrieve_changes_request(zone_identifier: bytes,
                                   continuation_token: bytes | None = None,
                                   max_changes: int = 500) -> bytes:
    return (Writer()
            .bytes(1, continuation_token)
            .message(2, zone_identifier)
            .uint64(4, max_changes)
            .finish())


@dataclasses.dataclass
class CloudKitRecord:
    record_name: str        # identifier value name (usually a UUID)
    type: str               # "item" / "synckey" / "tlkshare" / "currentitem" / ...
    fields: dict            # {field_name: python value}
    etag: str | None = None  # RecordChange.etag - the server's version of this record

    def get_bytes(self, name: str) -> bytes | None:
        v = self.fields.get(name)
        return v if isinstance(v, (bytes, bytearray)) else None

    def get_str(self, name: str) -> str | None:
        v = self.fields.get(name)
        return v if isinstance(v, str) else None


def _parse_value(raw: bytes):
    """Record.Field.Value -> python value. Types are preserved so the item AAD encodes each
    correctly: str, bytes, int, float, CKDate."""
    v = decode_fields(raw)
    if 2 in v:
        return first(v, 2)                     # bytesValue
    if 7 in v:
        return first_str(v, 7)                 # stringValue
    if 4 in v:
        return first(v, 4)                     # signedValue (int64)
    if 5 in v:                                 # doubleValue (fixed64, IEEE-754)
        return struct.unpack("<d", first(v, 5).to_bytes(8, "little"))[0]
    if 6 in v:                                 # dateValue: Date{ time(1): double }
        d = decode_fields(first(v, 6))
        if 1 in d:
            return CKDate(struct.unpack("<d", first(d, 1).to_bytes(8, "little"))[0])
    if 9 in v:                                 # referenceValue -> the target record's name,
        ref = decode_fields(first(v, 9))       # e.g. parentkeyref linking synckey->TLK / item->classkey
        rid = first(ref, 2)
        if rid is not None:
            idval = first(decode_fields(rid), 1)
            if idval is not None:
                return first_str(decode_fields(idval), 1)
    return None


def parse_record(raw: bytes) -> CloudKitRecord:
    f = decode_fields(raw)
    rec_id = first(f, 2)
    name = ""
    if rec_id is not None:
        idval = first(decode_fields(rec_id), 1)
        if idval is not None:
            name = first_str(decode_fields(idval), 1) or ""
    type_blob = first(f, 3)
    rtype = first_str(decode_fields(type_blob), 1) if type_blob is not None else ""
    fields = {}
    for fld in f.get(7, []):
        ff = decode_fields(fld)
        ident = first(ff, 1)
        fname = first_str(decode_fields(ident), 1) if ident is not None else None
        val = first(ff, 2)
        if fname is not None and val is not None:
            fields[fname] = _parse_value(val)
    return CloudKitRecord(record_name=name, type=rtype or "", fields=fields)


def _record_identifier(record_name: str, user_id: str, zone: str) -> bytes:
    """RecordIdentifier { value(1): Identifier{name,type}, zoneIdentifier(2): RecordZoneIdentifier }."""
    return (Writer()
            .message(1, _identifier(record_name, ID_TYPE_RECORD))
            .message(2, record_zone_identifier(zone, user_id))
            .finish())


def serialize_value(v) -> bytes:
    """Inverse of _parse_value. The type tag and the value field must agree; getting them out
    of step is the kind of thing Apple accepts and another device then cannot read."""
    if isinstance(v, (bytes, bytearray)):
        return Writer().uint64(1, VT_BYTES).bytes(2, bytes(v)).finish()
    if isinstance(v, CKDate):
        return (Writer().uint64(1, VT_DATE)
                .message(6, Writer().double(1, v.time))
                .finish())
    if isinstance(v, str):
        return Writer().uint64(1, VT_STRING).string(7, v).finish()
    if isinstance(v, bool):                      # before int - bool is an int subclass
        return Writer().uint64(1, VT_INT64).uint64(4, 1 if v else 0).finish()
    if isinstance(v, int):
        return Writer().uint64(1, VT_INT64).uint64(4, v).finish()
    if isinstance(v, float):
        return Writer().uint64(1, VT_DOUBLE).double(5, v).finish()
    raise TypeError(f"cannot serialize record value of type {type(v).__name__}")


def serialize_reference(target_record_name: str, user_id: str, zone: str) -> bytes:
    """A referenceValue, e.g. an item's parentkeyref pointing at its class key."""
    ref = Writer().message(2, _record_identifier(target_record_name, user_id, zone)).finish()
    return Writer().uint64(1, VT_REFERENCE).message(9, ref).finish()


def serialize_record(record_name: str, record_type: str, fields: dict, *,
                     user_id: str, zone: str, references: set | None = None) -> bytes:
    """Record { recordIdentifier(2), type(3), recordField(7)* }.

    etag(1) is deliberately not sent: the save carries saveSemantics=3 + merge=true, which is
    the form rustpush uses for an update, and Apple resolves the version server-side.
    `references` names the fields that must go out as referenceValue rather than a string -
    parentkeyref reads back as a plain record name, so the type is lost on the way in.
    """
    refs = references or set()
    w = (Writer()
         .message(2, _record_identifier(record_name, user_id, zone))
         .message(3, Writer().string(1, record_type)))
    for name in sorted(fields):                       # deterministic order for diffable output
        value = fields[name]
        if value is None:
            continue
        val = (serialize_reference(value, user_id, zone) if name in refs
               else serialize_value(value))
        w.message(7, Writer().message(1, Writer().string(1, name)).message(2, val))
    return w.finish()


def build_record_save_request(record: bytes, *, merge: bool = True,
                              save_semantics: int = SAVE_SEMANTICS_UPDATE) -> bytes:
    """RecordSaveRequest { record(1), merge(2), saveSemantics(6) }."""
    return (Writer()
            .message(1, record)
            .bool(2, merge)
            .uint64(6, save_semantics)
            .finish())


def parse_record_save_response(raw: bytes) -> CloudKitRecord | None:
    """RecordSaveResponse { serverFields(4): Record } - the record as the server now holds it."""
    rec = first(decode_fields(raw), 4)
    return parse_record(rec) if rec is not None else None


def parse_retrieve_changes_response(raw: bytes) -> dict:
    """Returns {records, continuation_token, status}. status 1 means another page is available;
    status 3 is the final state token for the zone."""
    f = decode_fields(raw)
    records = []
    for change in f.get(1, []):
        cf = decode_fields(change)
        rec = first(cf, 5)
        if rec is not None:
            parsed = parse_record(rec)
            parsed.etag = first_str(cf, 2)      # RecordChange.etag, for conflict detection
            records.append(parsed)
    return {"records": records, "continuation_token": first(f, 2), "status": first(f, 4)}
