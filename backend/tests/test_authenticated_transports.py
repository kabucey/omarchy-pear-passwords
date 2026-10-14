"""Regression tests for the credential-bearing Apple HTTP transports.

These tests use Requests' adapter boundary, so they exercise Session environment merging and
redirect behavior without contacting Apple or an attacker-controlled endpoint.
"""

import json
import os
import plistlib
import unittest
from unittest import mock

import requests
from requests.adapters import BaseAdapter

from icp.auth import gsa, icloud
from icp.auth.gsa import GSAError, GSAClient
from icp.auth.http import secure_session
from icp.auth.icloud import ICloudError
from icp.escrow.srp import EscrowGateError, EscrowRecovery
from icp.transport import cloudkit


class _ResponseAdapter(BaseAdapter):
    def __init__(self, *, status=200, body=b"", headers=None):
        self.status = status
        self.body = body
        self.response_headers = headers or {}
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append((request, kwargs))
        response = requests.Response()
        response.status_code = self.status
        response.headers.update(self.response_headers)
        response.url = request.url
        response.request = request
        response._content = self.body
        return response

    def close(self):
        pass


class _Anisette:
    def headers(self):
        return {"X-Apple-I-MD": "machine"}


class AuthenticatedTransportTests(unittest.TestCase):
    ENV = {
        "REQUESTS_CA_BUNDLE": "/tmp/attacker-ca.pem",
        "CURL_CA_BUNDLE": "/tmp/attacker-ca.pem",
        "HTTP_PROXY": "http://attacker-proxy.invalid:8080",
        "HTTPS_PROXY": "http://attacker-proxy.invalid:8080",
        "ALL_PROXY": "http://attacker-proxy.invalid:8080",
    }

    def _session(self, adapter):
        session = requests.Session()
        session.mount("https://", adapter)
        return session

    def _assert_clean_request(self, adapter, *, verify):
        self.assertEqual(len(adapter.calls), 1)
        _, kwargs = adapter.calls[0]
        self.assertEqual(kwargs["proxies"], {})
        self.assertEqual(kwargs["verify"], verify)

    @mock.patch.dict(os.environ, ENV)
    def test_each_transport_ignores_environment_ca_and_proxy(self):
        # iCloud setup POST: explicit Apple bundle and no environment route.
        icloud_adapter = _ResponseAdapter(body=plistlib.dumps({}))
        icloud._post_service(
            "https://setup.icloud.com", headers={"Authorization": "Basic PET"}, data=b"",
            operation="test", session=self._session(icloud_adapter))
        self._assert_clean_request(icloud_adapter, verify=icloud.ca.bundle())

        # Escrow POST: the PET-bearing request uses the public system trust store explicitly.
        escrow_adapter = _ResponseAdapter(body=plistlib.dumps({}))
        EscrowRecovery(
            "https://p99-escrowproxy.icloud.com", "person@icloud.com", "PET", _Anisette(),
            session=self._session(escrow_adapter),
        )._invoke("get_records", {})
        self._assert_clean_request(escrow_adapter, verify=True)

        # CloudKit ckAppInit: Basic(dsid, mmeAuthToken) is protected from both settings.
        cloudkit_adapter = _ResponseAdapter(body=json.dumps({"cloudKitUserId": "user"}).encode())
        cloudkit.ck_app_init(
            cloudkit.CUTTLEFISH_CONTAINER, cloudkit.CUTTLEFISH_BUNDLE,
            "123", "MME-TOKEN", _Anisette(), session=self._session(cloudkit_adapter),
        )
        self._assert_clean_request(cloudkit_adapter, verify=cloudkit.VERIFY_TLS)

        # GSA client: the SRP and 2FA requests share the isolated client session.
        gsa_adapter = _ResponseAdapter(body=plistlib.dumps({"Response": {}}))
        client = GSAClient(object(), _Anisette(), session=self._session(gsa_adapter))
        client._request_http("POST", gsa.const.GSA_ENDPOINT, headers={}, data=b"", timeout=1)
        self._assert_clean_request(gsa_adapter, verify=gsa.ca.bundle())

    def test_redirects_are_rejected_before_any_second_request(self):
        location = "https://evil.example/collect"

        icloud_adapter = _ResponseAdapter(status=307, headers={"Location": location})
        with self.assertRaisesRegex(ICloudError, "redirect"):
            icloud._post_service(
                "https://setup.icloud.com", headers={"Authorization": "Basic PET"}, data=b"",
                operation="test", session=self._session(icloud_adapter))
        self.assertEqual(len(icloud_adapter.calls), 1)
        self.assertEqual(icloud_adapter.calls[0][0].headers["Authorization"], "Basic PET")

        escrow_adapter = _ResponseAdapter(status=307, headers={"Location": location})
        with self.assertRaisesRegex(EscrowGateError, "redirect"):
            EscrowRecovery(
                "https://p99-escrowproxy.icloud.com", "person@icloud.com", "PET", _Anisette(),
                session=self._session(escrow_adapter),
            )._invoke("get_records", {})
        self.assertEqual(len(escrow_adapter.calls), 1)
        self.assertTrue(escrow_adapter.calls[0][0].headers["Authorization"].startswith("Basic "))

        cloudkit_adapter = _ResponseAdapter(status=307, headers={"Location": location})
        transport = cloudkit.CloudKitTransport(
            "CLOUDKIT-TOKEN", "USER", cloudkit.DeviceConfig("device", "serial"), _Anisette(),
            session=self._session(cloudkit_adapter),
        )
        with self.assertRaisesRegex(cloudkit.CloudKitError, "redirect"):
            transport.invoke("fetchChanges", b"")
        self.assertEqual(len(cloudkit_adapter.calls), 1)
        self.assertEqual(
            cloudkit_adapter.calls[0][0].headers["x-cloudkit-authtoken"], "CLOUDKIT-TOKEN")

        gsa_adapter = _ResponseAdapter(status=307, headers={"Location": location})
        client = GSAClient(object(), _Anisette(), session=self._session(gsa_adapter))
        with self.assertRaisesRegex(GSAError, "redirect"):
            client._request_http(
                "GET", "https://gsa.apple.com/auth",
                headers={"X-Apple-Identity-Token": "DSID:TOKEN"}, timeout=1)
        self.assertEqual(len(gsa_adapter.calls), 1)
        self.assertEqual(
            gsa_adapter.calls[0][0].headers["X-Apple-Identity-Token"], "DSID:TOKEN")

    def test_secure_session_configures_injected_session(self):
        session = requests.Session()
        configured = secure_session(verify="/trusted-ca.pem", session=session)
        self.assertIs(configured, session)
        self.assertFalse(session.trust_env)
        self.assertEqual(session.verify, "/trusted-ca.pem")


if __name__ == "__main__":
    unittest.main()
