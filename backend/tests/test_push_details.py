"""create_entry / push_details / push_nickname / push_password / delete_entry against a fake
zone: which records get written, and the guards."""
import os
import pytest

from icp.cli import push
from icp.keychain import metadata as md, tagline, update as up
from icp.transport import ckks
from icp.transport.ckks import CloudKitRecord

CK = os.urandom(64)
PARENT = "CLASS-KEY"


def _rec(name, plist):
    return CloudKitRecord(name, "item", up.new_item_fields(CK, PARENT, plist, record_name=name,
                                                          uploadver="test"))


class FakeTransport:
    def __init__(self):
        self.saves = []
        self.performed = []

    def save_record(self, req):
        self.saves.append(req)

    def _perform(self, url, op_type, field, body, *, bundle):
        self.performed.append((url, op_type, field, body))


class FakeClient:
    user_id = "_user"

    def __init__(self):
        self.transport = FakeTransport()


@pytest.fixture
def records():
    return {"item": [
        _rec("A-PW", up.new_password_plist("has-meta.example", "alex", "pw1")),
        _rec("A-META", up.new_metadata_plist("has-meta.example", "alex", notes="n")),
        _rec("B-PW", up.new_password_plist("bare.example", "sam", "pw2")),
    ]}


@pytest.fixture
def zone(monkeypatch, records):
    saved = []
    monkeypatch.setattr(push, "_save", lambda c, rec, fields, create=False, zone="Passwords":
                        saved.append((rec.record_name, create, up.decrypt_item_record(
                            CloudKitRecord(rec.record_name, "item", fields), CK))))
    z = push.Zone(FakeClient(), records, {PARENT: CK})
    z.saved = saved
    return z


def test_details_edit_touches_only_the_metadata_record(zone):
    push.push_details(zone, "has-meta.example", "alex", sites=["www.has-meta.example"])
    assert [(n, c) for n, c, _ in zone.saved] == [("A-META", False)]
    meta = md.parse(zone.saved[0][2]["v_Data"])
    assert md.sites(meta) == ["www.has-meta.example"] and md.notes(meta) == "n"


def test_details_on_entry_without_metadata_creates_one(zone):
    cfg = {"secret": b"12345678901234567890", "digits": 6, "period": 30, "algorithm": 0}
    push.push_details(zone, "bare.example", "sam", totp=cfg)
    (name, created, plist), = zone.saved
    assert created and name not in ("B-PW",)
    assert plist["agrp"] == up.AGRP_METADATA and plist["srvr"] == "bare.example"
    assert md.totp_config(md.parse(plist["v_Data"]))["secret"] == cfg["secret"]


def test_create_writes_password_and_metadata(zone):
    site = push.clean_site("https://new.example/login")
    assert push.create_entry(zone, site, "kim", "pw3", title="New") == 2
    kinds = [(c, p["agrp"], p["srvr"]) for _, c, p in zone.saved]
    assert kinds == [(True, up.AGRP_PASSWORD, "new.example"), (True, up.AGRP_METADATA, "new.example")]
    assert zone.saved[0][2]["v_Data"] == b"pw3"


def test_an_entry_without_a_site_gets_a_uuid_server_like_apples_own():
    site = push.clean_site("", title="Bank card PIN")
    assert len(site) == 36 and site.count("-") == 4
    with pytest.raises(push.PushError):
        push.clean_site("", title="   ")


def test_create_refuses_an_existing_account(zone):
    with pytest.raises(push.PushError, match="already exists"):
        push.create_entry(zone, "bare.example", "sam", "other")
    assert zone.saved == []


def test_create_needs_site_and_password(zone):
    with pytest.raises(push.PushError):
        push.create_entry(zone, "", "kim", "pw")
    with pytest.raises(push.PushError):
        push.create_entry(zone, "new.example", "kim", "")
    assert zone.saved == []


def test_password_change_moves_both_records(zone):
    assert push.push_password(zone, "has-meta.example", "alex", "new-pw") == 2
    names = [n for n, _, _ in zone.saved]
    assert names == ["A-PW", "A-META"]
    assert zone.saved[0][2]["v_Data"] == b"new-pw"
    hist = md.password_history(md.parse(zone.saved[1][2]["v_Data"]))
    assert hist and hist[0]["password"] == "new-pw"


def test_password_change_on_a_password_only_entry_writes_one_record(zone):
    assert push.push_password(zone, "bare.example", "sam", "x") == 1
    assert [n for n, _, _ in zone.saved] == ["B-PW"]


def test_nothing_is_written_for_an_account_that_is_not_there(zone):
    with pytest.raises(push.PushError):
        push.push_password(zone, "nowhere.example", "alex", "x")
    with pytest.raises(push.PushError):
        push.push_details(zone, "has-meta.example", "someone-else", notes="x")
    assert zone.saved == []


def test_rename_goes_to_the_metadata_record_or_reports_it_cannot(zone):
    assert push.push_nickname(zone, "bare.example", "sam", "Sam's") is False
    assert zone.saved == []
    assert push.push_nickname(zone, "has-meta.example", "alex", "Work") is True
    (name, created, plist), = zone.saved
    assert name == "A-META" and not created
    assert md.title(md.parse(plist["v_Data"])) == "Work"


def test_delete_sends_nothing_while_switched_off(monkeypatch, zone):
    monkeypatch.setattr(push, "RECORD_DELETE_VERIFIED", False)
    with pytest.raises(push.DeleteUnavailable):
        push.delete_entry(zone, "has-meta.example", "alex")
    assert zone.client.transport.performed == [] and zone.saved == []


def test_delete_when_enabled_names_exactly_the_two_records(monkeypatch, zone):
    monkeypatch.setattr(push, "RECORD_DELETE_VERIFIED", True)
    assert push.delete_entry(zone, "has-meta.example", "alex") == 2
    bodies = [p[3] for p in zone.client.transport.performed]
    assert [b"A-META" in b for b in bodies] == [True, False]
    assert [b"A-PW" in b for b in bodies] == [False, True]
    assert all(b"Passwords" in b for b in bodies)


def test_refetch_reads_one_zone_and_decrypts_with_the_held_keys(monkeypatch, zone, records):
    asked = []
    monkeypatch.setattr(ckks, "record_zone_identifier", lambda name, uid: asked.append(name) or b"z")
    monkeypatch.setattr(ckks, "build_retrieve_changes_request", lambda zid, cont=None: b"req")
    monkeypatch.setattr(zone.client.transport, "fetch_records", lambda req: b"raw", raising=False)
    monkeypatch.setattr(ckks, "parse_retrieve_changes_response",
                        lambda raw: {"records": records["item"], "continuation_token": None,
                                     "status": 3})
    monkeypatch.setattr(push, "decrypt_items",
                        lambda its, keys: [up.decrypt_item_record(r, CK) for r in its])
    store = push.refetch(zone, "Passwords")
    assert asked == ["Passwords"]
    c = push.find(store, "has-meta.example", "alex")
    assert c.password == "pw1" and c.notes == "n"
    assert push.find(store, "has-meta.example", "nobody") is None


# --- tags and the notes body (features spec 5b.5) and Recently Deleted copies (4.3) ----------

import plistlib  # noqa: E402

RD = "-recently-deleted"


def _meta_notes(site, acct, raw, agrp=up.AGRP_METADATA):
    """A details record whose notes are exactly `raw` (bytes), as an Apple device left them."""
    p = up.new_metadata_plist(site, acct)
    inner = plistlib.loads(p["v_Data"])
    if raw is None:
        inner.pop("notes", None)
    else:
        inner["notes"] = raw
    p["v_Data"] = plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)
    p["agrp"] = agrp
    return p


def _zone(monkeypatch, items):
    saved = []
    monkeypatch.setattr(push, "_save", lambda c, rec, fields, create=False, zone="Passwords":
                        saved.append((rec.record_name, create, up.decrypt_item_record(
                            CloudKitRecord(rec.record_name, "item", fields), CK))))
    z = push.Zone(FakeClient(), {"item": [_rec(n, p) for n, p in items]}, {PARENT: CK})
    z.saved = saved
    return z


def _notes_of(plist):
    return plistlib.loads(plist["v_Data"]).get("notes")


def test_pair_ignores_recently_deleted_copies(monkeypatch):
    z = _zone(monkeypatch, [
        ("RD-PW", {**up.new_password_plist("s.example", "u", "old"),
                   "agrp": up.AGRP_PASSWORD + RD}),
        ("RD-META", _meta_notes("s.example", "u", b"deleted", up.AGRP_METADATA + RD)),
        ("PW", up.new_password_plist("s.example", "u", "live")),
        ("META", _meta_notes("s.example", "u", b"live")),
    ])
    assert {a: r.record_name for a, (r, _, _) in
            push._pair(z.records, z.class_keys, "s.example", "u").items()} == \
        {up.AGRP_PASSWORD: "PW", up.AGRP_METADATA: "META"}
    push.push_details(z, "s.example", "u", tags=["x"])
    push.push_password(z, "s.example", "u", "new")
    assert [n for n, _, _ in z.saved] == ["META", "PW", "META"]


def test_a_tag_edit_splices_the_fetched_notes_byte_for_byte(monkeypatch):
    raw = "Recovery:\r\nabcd efgh\r\n\r\ntags:\t#Old  ".encode()
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u", raw))])
    expect = {}
    push.push_details(z, "s.example", "u", tags=["old", "new"], expect=expect)
    (_, _, plist), = z.saved
    written = _notes_of(plist)
    assert written == b"Recovery:\r\nabcd\xc2\xa0efgh\r\n\r\nTags: #old #new"
    assert expect["notes"] == written.decode()
    # Everything but the notes bytes and mdat is what was there.
    before = up.decrypt_item_record(z.records["item"][1], CK)
    assert set(up.diff_plists(before, plist)) == {"mdat", "v_Data"}
    inner_before, inner_after = (plistlib.loads(p["v_Data"]) for p in (before, plist))
    assert {k: v for k, v in inner_before.items() if k != "notes"} == \
        {k: v for k, v in inner_after.items() if k != "notes"}


def test_removing_every_tag_restores_the_body_exactly(monkeypatch):
    raw = b"\n  keep my leading newline and spaces  \nTags: #a"
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u", raw))])
    push.push_details(z, "s.example", "u", tags=[])
    assert _notes_of(z.saved[0][2]) == b"\n  keep my leading newline and spaces  "


def test_remove_all_tags_then_save_the_notes_unchanged(monkeypatch):
    # faudit-real #1: the body's own "Tags: #abc" line, held open by the removal, must not
    # become list metadata when the notes editor saves that body back unchanged.
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u",
                                                 b"pin 1234\nTags: #abc\n\nTags: #work"))])
    push.push_details(z, "s.example", "u", tags=[])
    held = _notes_of(z.saved[-1][2])
    assert held == b"pin 1234\nTags: #abc\n"
    body = tagline.split(held.decode())[0]             # what the notes editor is given
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u", held))])
    push.push_details(z, "s.example", "u", notes_body=body)
    assert _notes_of(z.saved[-1][2]) == held
    assert tagline.split(held.decode())[1] == []


def test_a_body_edit_keeps_the_tag_line(monkeypatch):
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u", b"old body\nTAGS: #Keep"))])
    expect = {}
    push.push_details(z, "s.example", "u", notes_body="\nnew body\n", expect=expect)
    assert _notes_of(z.saved[0][2]) == b"new body\nTAGS: #Keep"
    assert expect["notes"] == "new body\nTAGS: #Keep"


def test_tags_on_notes_that_are_not_utf8_are_refused_before_anything_is_written(monkeypatch):
    raw = b"\xff\xfe not utf-8\n\nTags: #a"
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u", raw))])
    assert push.notes_editable(z, "s.example", "u") is False
    with pytest.raises(up.NotesNotUtf8):
        push.push_details(z, "s.example", "u", tags=["b"])
    assert z.saved == []
    # A body edit replaces those bytes with what the person typed (the tag line, valid
    # UTF-8, stays); that is allowed.
    push.push_details(z, "s.example", "u", notes_body="fixed")
    assert _notes_of(z.saved[0][2]) == b"fixed\n\nTags: #a"


def test_notes_editable_for_entries_without_details_or_notes(monkeypatch):
    z = _zone(monkeypatch, [("PW", up.new_password_plist("s.example", "u", "pw")),
                            ("META", _meta_notes("s.example", "u", None)),
                            ("B-PW", up.new_password_plist("b.example", "u", "pw"))])
    assert push.notes_editable(z, "s.example", "u") and push.notes_editable(z, "b.example", "u")


def test_tags_on_an_entry_without_a_details_record(monkeypatch):
    z = _zone(monkeypatch, [("PW", up.new_password_plist("b.example", "u", "pw"))])
    expect = {}
    push.push_details(z, "b.example", "u", notes_body="body", tags=["x"], expect=expect)
    (_, created, plist), = z.saved
    assert created and _notes_of(plist) == b"body\n\nTags: #x"
    assert expect["notes"] == "body\n\nTags: #x"


@pytest.mark.parametrize("stored", [b"old body\n\nTags: #keep", b"old body", None])
def test_a_tag_line_typed_last_in_a_body_edit_joins_the_tags(monkeypatch, stored):
    # The same rule with or without tags already, with or without a details record, and with
    # tags sent in the same edit: the typed line joins them, as on create, never dropped.
    recs = [("PW", up.new_password_plist("s.example", "u", "pw"))]
    if stored is not None:
        recs.append(("META", _meta_notes("s.example", "u", stored)))
    keep = ["keep"] if stored and b"#keep" in stored else []
    z = _zone(monkeypatch, recs)
    push.push_details(z, "s.example", "u", notes_body="new\nTags: #typed")
    assert tagline.split(_notes_of(z.saved[-1][2]).decode()) == ("new", keep + ["typed"])
    z = _zone(monkeypatch, recs)
    push.push_details(z, "s.example", "u", notes_body="new\nTags: #typed", tags=["sent"])
    assert tagline.split(_notes_of(z.saved[-1][2]).decode()) == ("new", ["sent", "typed"])


def test_whole_notes_and_a_splice_are_not_mixed():
    with pytest.raises(up.ItemUpdateError):
        up.edit_details(up.new_metadata_plist("s.example", "u"), notes="x", tags=["a"])


def test_details_landed_compares_the_written_notes_exactly():
    from icp.vault.host import Credential
    c = Credential("s.example", "u", "pw", notes="\nlead\n\nTags: #a")
    assert push.details_landed(c, "s.example", notes_raw="\nlead\n\nTags: #a")
    assert not push.details_landed(c, "s.example", notes_raw="lead\n\nTags: #a")
