"""Offline tests for the decryption pipeline's live building blocks: item AAD
construction, and CKKS value parsing."""

import plistlib
import unittest
from unittest import mock

from icp.keychain import pipeline


class _Record:
    def __init__(self, name, fields):
        self.record_name = name
        self.fields = fields

    def get_str(self, name):
        value = self.fields.get(name)
        return value if isinstance(value, str) else None

    def get_bytes(self, name):
        value = self.fields.get(name)
        return value if isinstance(value, (bytes, bytearray)) else None


def _item(name, *, parent="CLASS-1", data=b"cipher", wrapped="d3JhcA=="):
    return _Record(name, {"parentkeyref": parent, "data": data, "wrappedkey": wrapped,
                          "encver": 2, "gen": 0})


class AadTests(unittest.TestCase):
    def test_aad_includes_pcs_fields(self):
        fields = {"parentkeyref": "CLASSC", "encver": 2, "gen": 0,
                  "pcsservice": 5, "pcspublicidentity": b"ident", "pcspublickey": b"pub",
                  "wrappedkey": "ignored", "data": b"ignored"}
        aad = pipeline.authenticated_data_v2("UUID-x", fields, encver=2, gen=0,
                                             parent_key_id="CLASSC")
        self.assertIn(b"ident", aad)
        self.assertIn(b"pub", aad)
        self.assertIn((5).to_bytes(8, "little", signed=True), aad)

    def test_le8_two_complement_no_overflow(self):
        # proto int64 negatives arrive as large unsigned varints; must give the 64-bit
        # two's-complement LE, not raise OverflowError.
        self.assertEqual(pipeline._le8(0xFFFFFFFFFFFFFFFF), b"\xff" * 8)   # -1 as i64
        self.assertEqual(pipeline._le8(2), b"\x02" + b"\x00" * 7)
        aad = pipeline.authenticated_data_v2(
            "U", {"n": 0xFFFFFFFFFFFFFFFF, "parentkeyref": "C"}, encver=2, gen=0, parent_key_id="C")
        self.assertIn(b"\xff" * 8, aad)

    def test_aad_encodes_date_and_double(self):
        from icp.transport.ckks import CKDate
        fields = {"parentkeyref": "C", "cdat": CKDate(1687305600.0), "score": 3.9}
        aad = pipeline.authenticated_data_v2("U", fields, encver=2, gen=0, parent_key_id="C")
        self.assertIn(b"2023-06-21T00:00:00Z", aad)       # RFC3339 seconds Z
        self.assertIn((3).to_bytes(8, "little"), aad)     # double truncated -> (u64) LE


class ParseValueTests(unittest.TestCase):
    def test_parse_value_decodes_double_and_date(self):
        import struct
        from icp.transport.ckks import CKDate, _parse_value
        raw_double = bytes([(5 << 3) | 1]) + struct.pack("<d", 2.5)
        self.assertEqual(_parse_value(raw_double), 2.5)
        date_inner = bytes([(1 << 3) | 1]) + struct.pack("<d", 1687305600.0)
        raw_date = bytes([(6 << 3) | 2, len(date_inner)]) + date_inner
        self.assertEqual(_parse_value(raw_date), CKDate(1687305600.0))


class UnionTlkTests(unittest.TestCase):
    def test_plain_and_recoverable_tlks_are_unioned(self):
        # The recoverable TLKs (user-controllable views like Passwords) are UNIONed with the
        # plain-zone tlkshare TLKs (always-on views like WiFi), not substituted.
        seen = {}
        orig = (pipeline.unwrap_tlkshares, pipeline.unwrap_class_keys, pipeline.decrypt_items)
        pipeline.unwrap_tlkshares = lambda *a, **k: {"TLK-WIFI": b"w" * 64}
        pipeline.unwrap_class_keys = (
            lambda synckeys, tlks, access_key=None: seen.update(tlks=dict(tlks)) or {})
        pipeline.decrypt_items = lambda items, class_keys, *args, **kwargs: []
        try:
            pipeline.build_credential_store({}, "SHA256:me", None, tlks={"TLK-PW": b"p" * 64})
        finally:
            (pipeline.unwrap_tlkshares, pipeline.unwrap_class_keys,
             pipeline.decrypt_items) = orig
        self.assertEqual(seen["tlks"], {"TLK-WIFI": b"w" * 64, "TLK-PW": b"p" * 64})


class CompletenessDiagnosticsTests(unittest.TestCase):
    def test_foreign_tlk_share_is_ignored_without_marking_snapshot_incomplete(self):
        share = _Record("foreign-share", {"receiver": "SHA256:someone-else",
                                           "wrappedkey": "not-base64"})
        diagnostics = pipeline.PipelineDiagnostics(authoritative=True)
        out = pipeline.unwrap_tlkshares([share], "SHA256:me", None, diagnostics)

        self.assertEqual(out, {})
        self.assertEqual(diagnostics.foreign_tlkshares, 1)
        self.assertEqual(diagnostics.tlkshare_failures, [])
        self.assertTrue(diagnostics.complete)

    def test_partial_item_failure_is_reported_instead_of_dropped(self):
        good = _item("good", data=b"good")
        bad = _item("bad", data=b"bad")
        diagnostics = pipeline.PipelineDiagnostics(authoritative=True)
        good_plist = {"srvr": "example.com", "acct": "alice", "v_Data": b"secret"}

        with mock.patch.object(pipeline.kc, "siv_unwrap", return_value=b"item-key"), \
                mock.patch.object(pipeline.kc, "decrypt_item",
                                  side_effect=[plistlib.dumps(good_plist), ValueError("tampered")]):
            items = pipeline.decrypt_items([good, bad], {"CLASS-1": b"class-key"}, diagnostics)

        self.assertEqual(items, [good_plist])
        self.assertEqual(diagnostics.decrypted_items, 1)
        self.assertEqual(set(diagnostics.item_failures), {"bad"})
        self.assertFalse(diagnostics.complete)

    def test_missing_class_key_is_reported(self):
        diagnostics = pipeline.PipelineDiagnostics(authoritative=True)
        items = pipeline.decrypt_items([_item("needs-key")], {}, diagnostics)

        self.assertEqual(items, [])
        self.assertEqual(diagnostics.missing_class_keys, {"CLASS-1": ["needs-key"]})
        self.assertFalse(diagnostics.complete)

    def test_malformed_item_is_reported(self):
        diagnostics = pipeline.PipelineDiagnostics(authoritative=True)
        malformed = _item("malformed", data=None, wrapped=None)

        items = pipeline.decrypt_items([malformed], {"CLASS-1": b"class-key"}, diagnostics)

        self.assertEqual(items, [])
        self.assertIn("malformed", diagnostics.item_failures)
        self.assertFalse(diagnostics.complete)

    def test_authoritative_empty_result_is_explicitly_valid(self):
        result = pipeline.build_credential_snapshot(
            {}, "SHA256:me", None, authoritative=True)

        self.assertEqual(len(result.store), 0)
        self.assertTrue(result.diagnostics.complete)
        self.assertTrue(result.diagnostics.authoritative_empty)


if __name__ == "__main__":
    unittest.main()
