"""The device pick decides which escrow record a passcode is spent against, so the index
mapping is tested through the JSON frontend (0-based), and anything that is not a valid index
aborts instead of guessing."""

import pytest

from icp.cli import jsonui
from icp.octagon import bottles

from apple_fakes import ScriptedFrontend

BOTTLES = [
    {"id": "a", "meta": {"serial": "S1", "ClientMetadata": {"device_model": "MacBook Pro"}}},
    {"id": "b", "meta": {"serial": "S2", "ClientMetadata": {"device_model": "iPhone"}}},
]


def _json_frontend(monkeypatch, reply):
    fe = jsonui.JsonFrontend()
    sent = []
    monkeypatch.setattr(fe, "_send", lambda m: sent.append(m))
    monkeypatch.setattr(fe, "_await", lambda m: (sent.append(m), reply)[1])
    return fe, sent


@pytest.mark.parametrize("reply,expect", [("0", "a"), ("1", "b"), ("2", None), ("-1", None), ("x", None)])
def test_app_pick_is_zero_based_and_bad_input_aborts(monkeypatch, reply, expect):
    fe, sent = _json_frontend(monkeypatch, reply)
    got = bottles.select(fe, BOTTLES)
    assert (got["id"] if got else None) == expect
    q = [m for m in sent if m.get("need") == "choice"][0]
    assert q["kind"] == "device"
    assert q["options"] == ["MacBook Pro", "iPhone"]
    assert q["details"] == ["Mac login password · serial ending S1", "serial ending S2"]


@pytest.mark.parametrize("answer", [None, -1, 2, True, "1"])
def test_a_frontend_answer_that_is_not_an_index_aborts(answer):
    assert bottles.select(ScriptedFrontend({"device": answer}), BOTTLES) is None


def test_single_bottle_is_not_asked(monkeypatch):
    fe, sent = _json_frontend(monkeypatch, "0")
    assert bottles.select(fe, BOTTLES[:1])["id"] == "a"
    assert not [m for m in sent if m.get("need")]


def test_device_chosen_stage_can_include_device_name(monkeypatch):
    fe, sent = _json_frontend(monkeypatch, "0")
    fe.stage("device_chosen", name="Alex's iPhone", model="iPhone 16 Pro", secret="passcode")
    assert sent == [{"event": "stage", "stage": "device_chosen",
                     "name": "Alex's iPhone", "model": "iPhone 16 Pro",
                     "secret": "passcode"}]


def test_label_prefers_own_name_and_tells_similar_devices_apart():
    from datetime import datetime
    b = {"meta": {"serial": "F4GXXXXX7XQ2", "com.apple.securebackup.timestamp": "2026-09-03 10:22:31",
                  "ClientMetadata": {"device_name": "Alex's iPhone", "device_model": "iPhone 16 Pro",
                                     "SecureBackupUsesNumericPassphrase": True,
                                     "SecureBackupNumericPassphraseLength": 6}}}
    assert bottles.name(b) == "Alex's iPhone"
    assert bottles.details(b) == "iPhone 16 Pro · backed up 3 Sep 2026 · 6-digit passcode · serial ending 7XQ2"
    b["meta"]["com.apple.securebackup.timestamp"] = datetime(2026, 9, 3)
    assert "backed up 3 Sep 2026" in bottles.details(b)


def test_label_without_metadata_says_so():
    assert bottles.name({"meta": {}}) == "Unknown device"
    assert "can't tell which device" in bottles.details({})


def test_model_not_repeated_when_name_already_has_it():
    b = {"meta": {"ClientMetadata": {"device_name": "iPhone", "device_model": "iPhone"}}}
    assert bottles.name(b) == "iPhone"
    assert bottles.model(b) == ""


def test_mac_says_password_not_passcode():
    b = {"meta": {"ClientMetadata": {"device_name": "Work Mac", "device_model": "MacBook Pro",
                                     "SecureBackupUsesComplexPassphrase": True}}}
    assert "Mac login password" in bottles.details(b)
    assert "passcode" not in bottles.details(b)


def test_mac_detection_uses_model_not_owner_name():
    mac = {"meta": {"ClientMetadata": {"device_name": "Work", "device_model": "MacBook Air"}}}
    ipad = {"meta": {"ClientMetadata": {"device_name": "Mac's iPad", "device_model": "iPad Pro"}}}
    assert bottles.is_mac(mac) and not bottles.is_mac(ipad)
