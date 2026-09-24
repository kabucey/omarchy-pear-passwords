"""The device pick decides which escrow record a passcode is spent against, so the index
mapping is tested for both frontends: terminal (1-based) and the app's JSON (0-based)."""

import io
import json

import pytest

from icp.cli import app, jsonui, ui

BOTTLES = [
    {"id": "a", "meta": {"serial": "S1", "ClientMetadata": {"device_model": "MacBook Pro"}}},
    {"id": "b", "meta": {"serial": "S2", "ClientMetadata": {"device_model": "iPhone"}}},
]


@pytest.fixture(autouse=True)
def _no_frontend():
    saved = ui._frontend
    ui._frontend = None
    yield
    ui._frontend = saved


@pytest.mark.parametrize("typed,expect", [("1", "a"), ("2", "b"), ("", None)])
def test_terminal_pick_is_one_based(monkeypatch, typed, expect):
    monkeypatch.setattr(ui, "ask", lambda *a, **k: typed)
    got = app._select_bottle(BOTTLES)
    assert (got and got["id"]) == expect or (got is None and expect is None)


def test_terminal_rejects_out_of_range_then_accepts(monkeypatch):
    answers = iter(["3", "0", "x", "2"])
    monkeypatch.setattr(ui, "ask", lambda *a, **k: next(answers))
    assert app._select_bottle(BOTTLES)["id"] == "b"


def _json_frontend(monkeypatch, reply):
    fe = jsonui.JsonFrontend()
    sent = []
    monkeypatch.setattr(fe, "_send", lambda m: sent.append(m))
    monkeypatch.setattr(fe, "_await", lambda m: (sent.append(m), reply)[1])
    ui._frontend = fe
    return sent


@pytest.mark.parametrize("reply,expect", [("0", "a"), ("1", "b"), ("2", None), ("-1", None), ("x", None)])
def test_app_pick_is_zero_based_and_bad_input_aborts(monkeypatch, reply, expect):
    sent = _json_frontend(monkeypatch, reply)
    got = app._select_bottle(BOTTLES)
    assert (got["id"] if got else None) == expect
    q = [m for m in sent if m.get("need") == "choice"][0]
    assert q["kind"] == "device"
    assert q["options"] == ["MacBook Pro", "iPhone"]
    assert q["details"] == ["Mac login password · serial ending S1", "serial ending S2"]


def test_single_bottle_is_not_asked(monkeypatch):
    sent = _json_frontend(monkeypatch, "0")
    assert app._select_bottle(BOTTLES[:1])["id"] == "a"
    assert not [m for m in sent if m.get("need")]


def test_device_chosen_stage_can_include_device_name(monkeypatch):
    sent = _json_frontend(monkeypatch, "0")
    ui.stage("device_chosen", name="Alex's iPhone", model="iPhone 16 Pro",
             secret="passcode")
    assert sent == [{"event": "stage", "stage": "device_chosen",
                     "name": "Alex's iPhone", "model": "iPhone 16 Pro",
                     "secret": "passcode"}]


def test_label_prefers_own_name_and_tells_similar_devices_apart():
    from datetime import datetime
    b = {"meta": {"serial": "F4GXXXXX7XQ2", "com.apple.securebackup.timestamp": "2026-09-03 10:22:31",
                  "ClientMetadata": {"device_name": "Alex's iPhone", "device_model": "iPhone 16 Pro",
                                     "SecureBackupUsesNumericPassphrase": True,
                                     "SecureBackupNumericPassphraseLength": 6}}}
    assert app._bottle_name(b) == "Alex's iPhone"
    assert app._bottle_details(b) == "iPhone 16 Pro · backed up 3 Sep 2026 · 6-digit passcode · serial ending 7XQ2"
    b["meta"]["com.apple.securebackup.timestamp"] = datetime(2026, 9, 3)
    assert "backed up 3 Sep 2026" in app._bottle_details(b)


def test_label_without_metadata_says_so():
    assert app._bottle_name({"meta": {}}) == "Unknown device"
    assert "can't tell which device" in app._bottle_details({})


def test_model_not_repeated_when_name_already_has_it():
    b = {"meta": {"ClientMetadata": {"device_name": "iPhone", "device_model": "iPhone"}}}
    assert app._bottle_name(b) == "iPhone"


def test_mac_says_password_not_passcode():
    b = {"meta": {"ClientMetadata": {"device_name": "Work Mac", "device_model": "MacBook Pro",
                                     "SecureBackupUsesComplexPassphrase": True}}}
    assert "Mac login password" in app._bottle_details(b)
    assert "passcode" not in app._bottle_details(b)


def test_mac_detection_uses_model_not_owner_name():
    mac = {"meta": {"ClientMetadata": {"device_name": "Work", "device_model": "MacBook Air"}}}
    ipad = {"meta": {"ClientMetadata": {"device_name": "Mac's iPad", "device_model": "iPad Pro"}}}
    assert app._bottle_is_mac(mac) and not app._bottle_is_mac(ipad)
