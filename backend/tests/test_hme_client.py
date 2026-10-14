"""Offline tests for the Hide My Email REST client (icp.hme.client). No network: `http` is
a fake object standing in for the authenticated `requests.Session` from webauth.

Run: .venv/bin/python -m unittest tests.test_hme_client
"""

import unittest

from icp.hme.client import HmeAlias, HmeClient, HmeError


class _FakeResponse:
    def __init__(self, status_code=200, json_body=None, headers=None):
        self.status_code = status_code
        self._json = json_body
        self.headers = headers or {}
        self.ok = 200 <= status_code < 300
        self.reason = "error" if not self.ok else "OK"

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


class _FakeHttp:
    def __init__(self, response):
        self.response = response
        self.requested_urls = []
        self.requested_kwargs = []

    def get(self, url, **kwargs):
        self.requested_urls.append(url)
        self.requested_kwargs.append(kwargs)
        return self.response


class ListTests(unittest.TestCase):
    def test_parses_aliases(self):
        http = _FakeHttp(_FakeResponse(200, {
            "success": True,
            "result": {
                "hmeEmails": [
                    {"anonymousId": "abc-123", "hme": "quiet-otter@icloud.com",
                     "label": "Claude", "note": "signed up on claude.ai",
                     "forwardToEmail": "me@example.com", "isActive": True,
                     "domain": "claude.ai", "createTimestamp": 1700000000000},
                ],
                "selectedForwardTo": "me@example.com",
                "forwardToEmails": ["me@example.com"],
            },
        }))
        aliases = HmeClient("https://p1-maildomainws.icloud.com", http).list()
        self.assertEqual(aliases, [HmeAlias(
            anonymous_id="abc-123", address="quiet-otter@icloud.com", label="Claude",
            note="signed up on claude.ai", forward_to="me@example.com", is_active=True,
            domain="claude.ai", created_at=1700000000.0)])
        self.assertEqual(http.requested_urls, ["https://p1-maildomainws.icloud.com/v2/hme/list"])

    def test_empty_list(self):
        http = _FakeHttp(_FakeResponse(200, {"success": True, "result": {"hmeEmails": []}}))
        self.assertEqual(HmeClient("https://p1-maildomainws.icloud.com", http).list(), [])

    def test_success_false_raises(self):
        http = _FakeHttp(_FakeResponse(200, {
            "success": False, "error": {"errorMessage": "not entitled"}}))
        with self.assertRaisesRegex(HmeError, "not entitled"):
            HmeClient("https://p1-maildomainws.icloud.com", http).list()

    def test_success_false_with_non_dict_error_does_not_crash(self):
        """Apple's `error` field is sometimes a bare int code, not the {errorMessage: ...}
        dict the browser extension's types assume."""
        http = _FakeHttp(_FakeResponse(200, {"success": False, "error": -1}))
        with self.assertRaisesRegex(HmeError, "-1"):
            HmeClient("https://p1-maildomainws.icloud.com", http).list()

    def test_success_false_with_no_error_field_shows_raw_body(self):
        http = _FakeHttp(_FakeResponse(200, {"success": False}))
        with self.assertRaisesRegex(HmeError, "success"):
            HmeClient("https://p1-maildomainws.icloud.com", http).list()

    def test_non_json_raises(self):
        http = _FakeHttp(_FakeResponse(200, json_body=None))
        with self.assertRaises(HmeError):
            HmeClient("https://p1-maildomainws.icloud.com", http).list()

    def test_http_error_raises(self):
        http = _FakeHttp(_FakeResponse(500, {"success": False}))
        with self.assertRaises(HmeError):
            HmeClient("https://p1-maildomainws.icloud.com", http).list()

    def test_base_url_trailing_slash_tolerated(self):
        http = _FakeHttp(_FakeResponse(200, {"success": True, "result": {"hmeEmails": []}}))
        HmeClient("https://p1-maildomainws.icloud.com/", http).list()
        self.assertEqual(http.requested_urls, ["https://p1-maildomainws.icloud.com/v2/hme/list"])
        self.assertFalse(http.requested_kwargs[0]["allow_redirects"])

    def test_rejects_redirects_including_method_preserving_307_and_308(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                http = _FakeHttp(_FakeResponse(
                    status, {"success": True},
                    headers={"Location": "https://evil.example/collect"}))
                with self.assertRaisesRegex(HmeError, "redirect"):
                    HmeClient("https://p1-maildomainws.icloud.com", http).list()
                self.assertFalse(http.requested_kwargs[0]["allow_redirects"])

    def test_rejects_invalid_service_url_at_use_boundary(self):
        for url in (
                "http://p1-maildomainws.icloud.com",
                "https://evil.example",
                "https://evil.example@p1-maildomainws.icloud.com",
                "https://p1-maildomainws.icloud.com:8443",
                "https://p1-maildomainws.icloud.com?next=evil",
                "https://p1-maildomainws.icloud.com#fragment"):
            with self.subTest(url=url), self.assertRaises(HmeError):
                HmeClient(url, _FakeHttp(_FakeResponse()))


if __name__ == "__main__":
    unittest.main()
