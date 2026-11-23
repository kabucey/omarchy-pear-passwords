"""The shared-group probe is read-only, never feeds the vault, and logs no values."""

import unittest

from icp.octagon import client as octagon
from icp.transport import ckks, cloudkit


class _T:
    def __init__(self):
        self.private, self.shared = [], []

    def fetch_records(self, req):
        self.private.append(req)
        return b"priv"

    def probe_shared_records(self, req, db):
        self.shared.append(db)
        if db == 2:
            raise cloudkit.CloudKitError("nope", code=26, description="ZONE_NOT_FOUND")
        return b"shared"


class ProbeTests(unittest.TestCase):
    def test_summarize_has_no_values(self):
        r = ckks.CloudKitRecord("n", "item", {"data": b"secret", "gen": 1})
        out = ckks.summarize_records([r])
        self.assertEqual(out, {"records": 1, "types": {"item": 1}, "fields": ["data", "gen"]})
        self.assertNotIn("secret", repr(out))

    def test_probe_reports_each_scope_and_errors(self):
        c = octagon.OctagonClient.__new__(octagon.OctagonClient)
        c.user_id = "u"
        c.transport = _T()
        orig = ckks.parse_retrieve_changes_response
        ckks.parse_retrieve_changes_response = lambda raw: {
            "records": [ckks.CloudKitRecord("n", "item", {"data": b"x"})],
            "continuation_token": None, "status": 3}
        try:
            rep = c.probe_sharing(candidate_zones=("Sharing",))
        finally:
            ckks.parse_retrieve_changes_response = orig
        self.assertEqual(rep["private_zones"]["Sharing"]["types"], {"item": 1})
        self.assertEqual(rep["shared"]["Sharing@db2"]["error"]["code"], 26)
        self.assertEqual(rep["shared"]["Sharing@db3"]["records"], 1)
        self.assertEqual(c.transport.shared, [2, 3])

    def test_shared_scope_only_sends_a_fetch(self):
        sent = {}

        class T(cloudkit.CloudKitTransport):
            def __init__(self):
                pass

            def _perform(self, url, op, field, req, **kw):
                sent.update(op=op, kw=kw)

                class R:
                    def field(self, n):
                        return b""
                return R()

        T().probe_shared_records(b"r", 3)
        self.assertEqual(sent["op"], ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES)
        self.assertEqual(sent["kw"]["scope"], "Shared")
