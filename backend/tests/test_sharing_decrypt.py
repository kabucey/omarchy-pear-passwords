"""The shared-group decrypt diagnostic: read-only, counts only, nothing reaches the vault.

The PCS primitives are tested the way Sank6/iCloud-Keychain-for-Linux (MIT) tests them (the
primitive tests below are ported from its tests/test_sharing.py). The diagnostic may send
exactly op 201, 203 and 213 to the sharing container, never 200 (zone save), 202 (zone delete)
or 210 (record save), and the only store write is the refreshed session, as a sync does.
"""

import ast
import hashlib
import hmac as _hmac
import json
import os
import pathlib
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from icp.daemon import apple
from icp.keychain import pipeline
from icp.octagon import client as octagon
from icp.proto.codec import Writer
from icp.sharing import diagnose, groups, pcs
from icp.transport import ckks, cloudkit

ALLOWED_OPS = {201, 203, 213}
GROUP_UUID = "6F1C2B9A-0000-4D2E-9C11-ABCDEFABCDEF"
SECRETS = ("hunter2", "alice@example.com", "example.com", "Family passwords", GROUP_UUID)


def _wrap(pub_x: bytes, key: bytes) -> bytes:
    """Test-side inverse of pcs.rfc6637_unwrap."""
    eph = ec.generate_private_key(ec.SECP256R1())
    secret = eph.exchange(ec.ECDH(), pcs._public_from_x(pub_x))
    kek = hashlib.sha256(b"\x00\x00\x00\x01" + secret + pcs._P256_OID + bytes([18, 3, 1, 8, 7])
                         + b"Anonymous Sender    " + b"fingerprint".ljust(20, b"\x00")).digest()[:16]
    msg = bytearray(40)
    msg[0] = 1
    msg[1:1 + len(key)] = key
    msg[1 + len(key):3 + len(key)] = (sum(key) & 0xFFFF).to_bytes(2, "big")
    pad = 40 - (len(key) + 3)
    msg[3 + len(key):] = bytes([pad]) * pad
    blob = aes_key_wrap(kek, bytes(msg))
    return (256).to_bytes(2, "big") + pcs.compact_x(eph) + bytes([len(blob)]) + blob


def _encrypt(key: pcs.PCSKey, plain: bytes, aad: bytes) -> bytes:
    kid = key.key_id()
    header = b"\x03" + kid[0:2] + b"\x02" + kid[2:4]
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(key._derive(b"encryption key key m")), modes.GCM(iv)).encryptor()
    enc.authenticate_additional_data(header + aad)
    ct = enc.update(plain) + enc.finalize()
    return header + iv + enc.tag[:12] + ct


class PrimitiveTests(unittest.TestCase):
    def test_kdf_is_sp800_108_counter_hmac(self):
        block = lambda i: _hmac.new(b"k" * 16, struct.pack(">I", i) + b"label\x00ctx"
                                    + struct.pack(">I", 40 * 8), hashlib.sha256).digest()
        self.assertEqual(pcs.kdf_ctr_hmac(b"k" * 16, b"label", b"ctx", 40), (block(1) + block(2))[:40])

    def test_rfc6637_round_trip(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        key = os.urandom(16)
        self.assertEqual(pcs.rfc6637_unwrap(priv, _wrap(pcs.compact_x(priv), key)), key)
        wrapped = bytearray(_wrap(pcs.compact_x(priv), key))
        wrapped[-1] ^= 1
        with self.assertRaises(pcs.PCSError):
            pcs.rfc6637_unwrap(priv, bytes(wrapped))

    def test_compact_private_key_forms(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        d = priv.private_numbers().private_value.to_bytes(32, "big")
        for raw in (pcs.compact_x(priv) + d, d):
            self.assertEqual(pcs.compact_x(pcs.private_from_compact(raw)), pcs.compact_x(priv))

    def test_pcs_key_decrypt_round_trip_and_aad(self):
        key = pcs.PCSKey(os.urandom(16))
        ct = _encrypt(key, b"secret", b"group-x-item-1-payload")
        self.assertEqual(key.decrypt(ct, b"group-x-item-1-payload"), b"secret")
        with self.assertRaises(pcs.PCSError):
            key.decrypt(ct, b"group-x-item-2-payload")
        with self.assertRaises(pcs.PCSError):
            pcs.PCSKey(os.urandom(16)).decrypt(ct, b"")

    def test_v2_private_key_der(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        compact = pcs.compact_x(priv) + priv.private_numbers().private_value.to_bytes(32, "big")
        pb = Writer().message(1, Writer().bytes(1, compact)).finish()
        octet = b"\x04" + bytes([len(pb)]) + pb
        der = b"\x65" + bytes([len(octet)]) + octet  # [APPLICATION 5]
        self.assertEqual(pcs.compact_x(pcs.private_key_from_der(der)), pcs.compact_x(priv))


class SharingItemTests(unittest.TestCase):
    def test_internet_password_maps_to_keychain_item(self):
        ip = (Writer().string(1, "com.apple.cfnetwork")
              .bytes(2, None).string(4, "bastian").string(6, "example.com")
              .bytes(9, b"pw").string(12, "Example").finish())
        ip = ip + b"\x11" + struct.pack("<d", 700000000.0)  # Field 2, fixed64.
        item = groups.sharing_item_to_keychain(Writer().bytes(3, ip).finish())
        self.assertEqual((item["agrp"], item["acct"], item["srvr"], item["v_Data"], item["labl"]),
                         ("com.apple.cfnetwork", "bastian", "example.com", b"pw", "Example"))
        self.assertEqual(item["mdat"], 700000000.0)

    def test_other_payload_kinds_are_skipped(self):
        self.assertIsNone(groups.sharing_item_to_keychain(Writer().bytes(2, b"\x0a\x00").finish()))


# --------------------------------------------------------------------------- fixtures

def _ip_payload(srvr, acct, pw, agrp="com.apple.cfnetwork") -> bytes:
    ip = Writer().string(1, agrp).string(4, acct).string(6, srvr).bytes(9, pw).finish()
    return Writer().bytes(3, ip).finish()


def _record(name, rtype, fields: dict) -> bytes:
    w = (Writer().message(2, Writer().message(1, Writer().string(1, name)))
         .message(3, Writer().string(1, rtype)))
    for fname, val in fields.items():
        v = Writer().bytes(2, val) if isinstance(val, bytes) else Writer().uint64(4, val)
        w.message(7, Writer().message(1, Writer().string(1, fname)).message(2, v))
    return w.finish()


def _change(record: bytes | None) -> bytes:
    return Writer().bytes(5, record).finish() if record is not None else Writer().uint64(2, 1).finish()


def _page(changes, status, token=b"t"):
    w = Writer()
    for c in changes:
        w.message(1, c)
    return w.bytes(2, token).uint64(4, status).finish()


class AnalyseTests(unittest.TestCase):
    def setUp(self):
        self.key = pcs.PCSKey(os.urandom(16))
        self.zone = f"group-{GROUP_UUID}"
        salt = os.urandom(16)
        self.distinct = {"accounts": diagnose._Distinct(salt), "with_password": diagnose._Distinct(salt)}

    def _rec(self, name, payload=None, rtype="item", type_field=1):
        fields = {"type": type_field}
        if payload is not None:
            fname = "displayName" if rtype == "cloudkit.share" else "payload"
            fields[fname] = _encrypt(self.key, payload, f"{self.zone}-{name}-{fname}".encode())
        return groups.parse_record(_record(name, rtype, fields))

    def _analyse(self, records, opened=True):
        prot = {"protection": b"x", "record_protection": None}
        with mock.patch.object(groups, "has_service_key", return_value=opened), \
                mock.patch.object(groups, "open_zone",
                                  return_value=([], [self.key])) as op:
            if not opened:
                op.side_effect = pcs.PCSError("no service key")
            return diagnose.analyse_group(self.zone, records, prot, {}, self.distinct)

    def test_counts_explain_items_without_values(self):
        recs = [
            self._rec("share", Writer().string(6, "Family passwords").finish(), "cloudkit.share"),
            self._rec("a", _ip_payload("example.com", "alice@example.com", b"hunter2")),
            self._rec("b", _ip_payload("example.com", "alice@example.com", b"hunter3")),  # history
            self._rec("c", _ip_payload("example.com", "bob", b"")),                       # empty
            self._rec("d", Writer().bytes(2, b"\x0a\x00").finish()),                      # other kind
            self._rec("e", None),                                                          # no payload
            self._rec("a", _ip_payload("example.com", "alice@example.com", b"hunter2")),  # repeated name
        ]
        recs.append(groups.parse_record(_record("bad", "item", {"payload": b"\x03garbage" * 8})))
        st = self._analyse(recs)
        self.assertTrue(st["name_decrypted"])
        self.assertTrue(st["service_key_found"])
        self.assertEqual((st["records"], st["items"], st["decrypted"]), (8, 7, 5))
        self.assertEqual(st["items_without_payload"], 1)
        self.assertEqual(st["failed"], {"decrypt:PCSError": 1})
        self.assertEqual(st["payload_kinds"], {"3": 4, "2": 1})
        self.assertEqual(st["internet_passwords"], 4)
        self.assertEqual(st["empty_password"], 1)
        self.assertEqual(st["duplicate_record_names"], 1)
        self.assertEqual(st["distinct_server_account"], 2)
        self.assertEqual(st["distinct_server_account_password"], 3)
        self.assertEqual(st["agrp"], {"com.apple.cfnetwork": 4})
        text = json.dumps(st)
        for s in SECRETS:
            self.assertNotIn(s, text)

    def test_unopened_zone_counts_failures_by_class(self):
        st = self._analyse([self._rec("a", _ip_payload("s", "a", b"p"))], opened=False)
        self.assertFalse(st["zone_opened"])
        self.assertEqual(st["open_error"], "PCSError")
        self.assertEqual(st["failed"], {"zone:PCSError": 1})
        self.assertEqual(st["decrypted"], 0)


class PcsKeysTests(unittest.TestCase):
    def test_only_pcs_items_are_kept_and_a_bad_item_is_counted(self):
        import base64
        x = b"\x07" * 32
        plists = {
            "k": {"agrp": "com.apple.ProtectedCloudStorage-x", "acct": base64.b64encode(x).decode(),
                  "v_Data": b"der"},
            "p": {"agrp": "com.apple.cfnetwork", "acct": "a", "v_Data": b"pw"},
        }

        def decrypt(items, class_keys):
            name = items[0].record_name
            if name == "bad":
                raise pipeline.PipelineError("x")
            return [plists[name]]
        recs = {"item": [ckks.CloudKitRecord(n, "item", {}) for n in ("k", "p", "bad")]}
        with mock.patch.object(pipeline, "decrypt_items", decrypt), \
                mock.patch.object(pipeline, "unwrap_class_keys", return_value={}):
            keys, stats = pcs.pcs_keys_from_records(recs, {})
        self.assertEqual(keys, {x: b"der"})
        self.assertEqual(stats, {"items": 3, "undecryptable": 1, "pcs_keys": 1})


# --------------------------------------------------------------------------- the ops sent

class _Result:
    def __init__(self, payload: bytes, field: int):
        self.payload, self.num = payload, field

    def field(self, n):
        return self.payload if n == self.num else None


class DiagnosticOpsTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.key = pcs.PCSKey(os.urandom(16))
        zone = f"group-{GROUP_UUID}"
        records = [
            _record("share", "cloudkit.share", {"displayName": _encrypt(
                self.key, Writer().string(6, "Family passwords").finish(),
                f"{zone}-share-displayName".encode())}),
            _record("i1", "item", {"type": 1, "payload": _encrypt(
                self.key, _ip_payload("example.com", "alice@example.com", b"hunter2"),
                f"{zone}-i1-payload".encode())}),
        ]
        sent = self.sent
        page1 = _page([_change(records[0]), _change(None)], 1)
        page2 = _page([_change(records[1])], 3)

        def perform(transport, url, op, field, req, **kw):
            sent.append({"op": op, "container": transport.container, **kw})
            if op == cloudkit.OP_TYPE_ZONE_RETRIEVE_CHANGES:
                zid = ckks.record_zone_identifier(zone, "kcuser")
                change = Writer().message(1, zid).uint64(2, 1).finish()
                return _Result(Writer().message(1, change).uint64(3, 2).finish(), field)
            if op == cloudkit.OP_TYPE_ZONE_RETRIEVE:
                return _Result(Writer().message(1, Writer().message(1, Writer().message(
                    3, Writer().bytes(1, b"prot")))).finish(), field)
            if op == ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES:
                again = any(s["op"] == 213 for s in sent[:-1])
                return _Result(page2 if again else page1, field)
            raise AssertionError(f"unexpected op {op}")

        self.patches = [
            mock.patch.object(cloudkit, "ck_app_init", return_value="kcuser"),
            mock.patch.object(cloudkit.CloudKitTransport, "_perform", perform),
            mock.patch.object(groups, "has_service_key", return_value=True),
            mock.patch.object(groups, "open_zone", return_value=([], [self.key])),
            mock.patch.object(octagon, "load_peer_keys",
                              return_value=SimpleNamespace(encryption=SimpleNamespace(private_key=None))),
            mock.patch.object(pipeline, "unwrap_tlkshares", return_value={}),
            mock.patch.object(pcs, "pcs_keys_from_records",
                              return_value=({b"x": b"der"}, {"items": 3, "undecryptable": 0,
                                                             "pcs_keys": 1})),
            mock.patch.object(diagnose.time, "sleep"),
        ]
        for p in self.patches:
            p.start()
        c = octagon.OctagonClient.__new__(octagon.OctagonClient)
        c.mme_dsid, c.mme_token, c.ck_token, c.anisette = "1", "t", "ck", None
        c.record = {"octagon": {"peer_id": "me"}}
        c.transport = mock.Mock(device=cloudkit.DeviceConfig(device_uuid="d", serial="s", name="n"))
        c.fetch_recoverable_tlks = mock.Mock(return_value=({}, []))
        c.sync_keychain = mock.Mock(return_value={"item": [], "tlkshare": []})
        self.client = c

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_only_fetches_are_sent_to_the_sharing_container(self):
        self.client.probe_sharing()
        self.assertTrue(self.sent)
        for s in self.sent:
            self.assertIn(s["op"], ALLOWED_OPS)
            self.assertNotIn(s["op"], (200, 202, 210))
            self.assertEqual(s["container"], cloudkit.KCSHARING_CONTAINER)
            self.assertEqual(s["bundle"], cloudkit.KCSHARING_BUNDLE)
            self.assertEqual((s["database"], s["scope"]), (cloudkit.DB_PRIVATE, "Private"))
        self.assertEqual({s["op"] for s in self.sent}, ALLOWED_OPS)
        # No Cuttlefish call of its own: the keychain side is the normal sync's two fetches.
        self.client.transport.invoke.assert_not_called()
        self.client.fetch_recoverable_tlks.assert_called_once()
        self.client.sync_keychain.assert_called_once_with()

    def test_report_is_counts_and_follows_every_page(self):
        rep = self.client.probe_sharing()
        self.assertEqual(rep["groups_owned"], 1)
        g = rep["groups"][0]
        self.assertEqual(g["paging"], {"pages": 2, "statuses": {"1": 1, "3": 1}, "complete": True,
                                       "changes_without_record": 1})
        self.assertEqual((g["records"], g["items"], g["decrypted"]), (2, 1, 1))
        self.assertTrue(g["name_decrypted"])
        self.assertEqual(rep["keychain"]["pcs_keys"], 1)
        self.assertEqual(rep["totals"]["distinct_server_account"], 1)
        text = json.dumps(rep)
        for s in SECRETS:
            self.assertNotIn(s, text)

    def test_a_failing_keychain_fetch_reports_and_sends_nothing_to_the_sharing_container(self):
        self.client.sync_keychain.side_effect = octagon.OctagonError("incomplete")
        rep = self.client.probe_sharing()
        self.assertEqual(rep["error"]["type"], "OctagonError")
        self.assertEqual(self.sent, [])


# --------------------------------------------------------------------------- nothing reaches the vault

class _RecordingStore:
    """A store that fails the test on any use but the unlock probe _still_unlocked makes."""

    def __init__(self):
        self.touched = []

    def lock_pending(self):
        return False

    def __getattr__(self, name):
        self.touched.append(name)
        raise AssertionError(f"the diagnostic touched the store: {name}")


class NoVaultTests(unittest.TestCase):
    def test_only_the_session_save_touches_the_store(self):
        store = _RecordingStore()
        ctx = SimpleNamespace(store=store, ui=mock.Mock(), interactive=True, anisette_url="u")
        client = mock.Mock()
        client.probe_sharing.return_value = {"mode": "decrypt"}
        s = {"mme": {}}
        with mock.patch.object(apple.session_store, "load", return_value=s), \
                mock.patch.object(apple.session_store, "save") as save, \
                mock.patch.object(apple, "_device", return_value=(object(), object())), \
                mock.patch.object(apple.signin, "ensure_fresh_tokens"), \
                mock.patch("icp.octagon.client.is_joined", return_value=True), \
                mock.patch("icp.octagon.client.OctagonClient", return_value=client):
            self.assertEqual(apple.probe_sharing(ctx), {"mode": "decrypt"})
        self.assertEqual(store.touched, [])
        # ensure_fresh_tokens saves once; the call itself saves once more, after the client
        # is built, like a sync. Both go through session_store, never a store method.
        self.assertTrue(all(c.args[0] is store for c in save.call_args_list))

    FORBIDDEN = {"apply_sync", "save_session", "save_record", "save_sync_token", "save_nicknames",
                 "set_sync_status", "OP_TYPE_RECORD_SAVE", "FIELD_RECORD_SAVE", "CKDATABASE_SAVE_URL",
                 "invoke", "join_via_escrow", "_recover_sponsor", "joinWithVoucher", "updateTrust",
                 "establish", "UserStore", "ctx"}

    def test_the_sharing_package_has_no_write_or_store_reference(self):
        pkg = pathlib.Path(pcs.__file__).parent
        for path in sorted(pkg.glob("*.py")):
            tree = ast.parse(path.read_text())
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    names.add(node.attr)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    mods = [getattr(node, "module", None) or ""] + [a.name for a in node.names]
                    for m in mods:
                        for bad in ("vstore", "vault", "daemon", "auth.session"):
                            self.assertNotIn(bad, m, f"{path.name} imports {m}")
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    names.add(node.value)
            self.assertEqual(names & self.FORBIDDEN, set(), path.name)

    def test_zone_retrieve_is_a_fetch_and_the_write_ops_are_not_named_here(self):
        self.assertEqual(cloudkit.OP_TYPE_ZONE_RETRIEVE, 201)
        self.assertEqual(cloudkit.OP_TYPE_ZONE_RETRIEVE_CHANGES, 203)
        self.assertEqual(ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES, 213)
        src = pathlib.Path(diagnose.__file__).read_text() + pathlib.Path(groups.__file__).read_text()
        for bad in ("OP_TYPE_RECORD_SAVE", "save_record", "_perform("):
            self.assertNotIn(bad, src)


if __name__ == "__main__":
    unittest.main()
