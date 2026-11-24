"""The shared-group probe is read-only, never feeds the vault, and reports no values or group ids.

It may send exactly two CloudKit operations, both fetches: 203 (list a database's zones) and
213 (a zone's records, the fetch every sync makes). Never 200 (zone save), 202 (zone delete) or
210 (record save)."""

import unittest
from unittest import mock

from icp.octagon import client as octagon
from icp.proto.codec import Writer
from icp.transport import ckks, cloudkit

READ_ONLY_OPS = {cloudkit.OP_TYPE_ZONE_RETRIEVE_CHANGES, ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES}
GROUP_UUID = "6F1C2B9A-0000-4D2E-9C11-ABCDEFABCDEF"


def _zone_change(name: str, owner: str, change_type: int = 1) -> bytes:
    zid = ckks.record_zone_identifier(name, owner)
    return Writer().message(1, zid).uint64(2, change_type).finish()


def _zone_page(*changes: bytes) -> bytes:
    w = Writer()
    for c in changes:
        w.message(1, c)
    return w.uint64(3, 2).finish()


class _Result:
    def __init__(self, payload: bytes, field: int):
        self.payload, self.num = payload, field

    def field(self, n):
        return self.payload if n == self.num else None


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        sent = self.sent

        def perform(transport, url, op, field, req, **kw):
            sent.append({"op": op, "container": transport.container, **kw})
            if op == cloudkit.OP_TYPE_ZONE_RETRIEVE_CHANGES:
                if kw["database"] == cloudkit.DB_PRIVATE:
                    return _Result(_zone_page(_zone_change(f"group-{GROUP_UUID}", "kcuser"),
                                              _zone_change("group-gone", "kcuser", 2),
                                              _zone_change("_defaultZone", "kcuser")), field)
                return _Result(_zone_page(_zone_change("group-joined", "someone-else")), field)
            return _Result(b"records", field)

        self.patches = [
            mock.patch.object(cloudkit, "ck_app_init", return_value="kcuser"),
            mock.patch.object(cloudkit.CloudKitTransport, "_perform", perform),
            mock.patch.object(ckks, "parse_retrieve_changes_response", return_value={
                "records": [ckks.CloudKitRecord("r1", "item", {"payload": b"secret"}),
                            ckks.CloudKitRecord("s", "cloudkit.share", {"displayName": b"x"})],
                "continuation_token": None, "status": 3}),
        ]
        for p in self.patches:
            p.start()
        c = octagon.OctagonClient.__new__(octagon.OctagonClient)
        c.mme_dsid, c.mme_token, c.ck_token, c.anisette = "1", "t", "ck", None
        c.transport = mock.Mock(device=cloudkit.DeviceConfig(device_uuid="d", serial="s", name="n"))
        self.client = c

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_summarize_has_no_values(self):
        r = ckks.CloudKitRecord("n", "item", {"data": b"secret", "gen": 1})
        out = ckks.summarize_records([r])
        self.assertEqual(out, {"records": 1, "types": {"item": 1}, "fields": ["data", "gen"]})
        self.assertNotIn("secret", repr(out))

    def test_only_fetches_are_sent_and_only_to_the_sharing_container(self):
        self.client.probe_sharing()
        self.assertTrue(self.sent)
        for s in self.sent:
            self.assertIn(s["op"], READ_ONLY_OPS)
            self.assertEqual(s["container"], cloudkit.KCSHARING_CONTAINER)
            self.assertEqual(s["bundle"], cloudkit.KCSHARING_BUNDLE)
        scopes = {(s["database"], s["scope"]) for s in self.sent}
        self.assertEqual(scopes, {(cloudkit.DB_PRIVATE, "Private"), (cloudkit.DB_SHARED, "Shared")})

    def test_report_counts_groups_and_records_without_ids_or_values(self):
        rep = self.client.probe_sharing()
        priv, shared = rep["databases"]["private"], rep["databases"]["shared"]
        self.assertEqual(priv["zones"], 2)                    # the deleted group is left out
        self.assertEqual(priv["other_zone_names"], ["_defaultZone"])
        self.assertEqual(len(priv["groups"]), 1)
        self.assertTrue(priv["groups"][0]["owned_by_you"])
        self.assertEqual(priv["groups"][0]["types"], {"item": 1, "cloudkit.share": 1})
        self.assertFalse(shared["groups"][0]["owned_by_you"])
        self.assertNotIn(GROUP_UUID, repr(rep))
        self.assertNotIn("secret", repr(rep))
        self.assertNotIn("someone-else", repr(rep))

    def test_a_failing_database_does_not_stop_the_other(self):
        def boom(*a, **kw):
            raise cloudkit.CloudKitError("no", code=3, description="nope")
        with mock.patch.object(cloudkit.CloudKitTransport, "probe_zone_changes", boom):
            rep = self.client.probe_sharing()
        self.assertEqual(rep["databases"]["private"]["error"]["code"], 3)
        self.assertEqual(rep["databases"]["shared"]["error"]["code"], 3)


if __name__ == "__main__":
    unittest.main()
