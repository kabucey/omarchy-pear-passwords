"""Strict validation of server-provided device-auth service endpoints."""

import unittest
from unittest import mock

from icp.auth import icloud
from icp.auth.icloud import ICloudError, extract_webservices


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class ExtractWebservicesTests(unittest.TestCase):
    def test_keeps_only_strict_icloud_https_urls(self):
        settings = {"webservices": {
            "keychainsync": {"url": "https://p99-keychainsync.icloud.com", "status": 0},
            "http": {"url": "http://p99-keychainsync.icloud.com", "status": 0},
            "wrong_host": {"url": "https://evil.example", "status": 0},
            "userinfo": {"url": "https://evil.example@p99-keychainsync.icloud.com", "status": 0},
            "wrong_port": {"url": "https://p99-keychainsync.icloud.com:8443", "status": 0},
            "query": {"url": "https://p99-keychainsync.icloud.com?next=evil", "status": 0},
            "fragment": {"url": "https://p99-keychainsync.icloud.com#evil", "status": 0},
        }}
        self.assertEqual(extract_webservices(settings), {
            "keychainsync": {"url": "https://p99-keychainsync.icloud.com", "status": 0},
        })

    def test_classic_escrow_proxy_url_is_validated_too(self):
        settings = {"com.apple.mobileme": {
            "com.apple.Dataclass.KeychainSync": {
                "escrowProxyUrl": "https://p99-escrowproxy.icloud.com",
            },
            "com.apple.Dataclass.Bad": {
                "escrowProxyUrl": "http://evil.example",
            },
        }}
        self.assertEqual(extract_webservices(settings), {
            "com.apple.Dataclass.KeychainSync": {
                "url": "https://p99-escrowproxy.icloud.com",
                "status": None,
                "escrowProxyUrl": "https://p99-escrowproxy.icloud.com",
            },
            "keychainsync": {
                "url": "https://p99-escrowproxy.icloud.com",
                "status": None,
                "escrowProxyUrl": "https://p99-escrowproxy.icloud.com",
            },
        })

    def test_classic_optional_escrow_url_is_not_propagated_when_invalid(self):
        settings = {"com.apple.mobileme": {
            "com.apple.Dataclass.KeychainSync": {
                "url": "https://p99-keychainsync.icloud.com",
                "escrowProxyUrl": "https://evil.example/collect",
            },
        }}
        self.assertEqual(extract_webservices(settings), {
            "com.apple.Dataclass.KeychainSync": {
                "url": "https://p99-keychainsync.icloud.com",
                "status": None,
            },
            "keychainsync": {
                "url": "https://p99-keychainsync.icloud.com",
                "status": None,
            },
        })


class AuthenticatedServicePostTests(unittest.TestCase):
    def test_invalid_service_url_is_rejected_before_post(self):
        session = mock.Mock()
        with self.assertRaises(ICloudError):
            icloud._post_service("http://evil.example", headers={}, data=b"PET",
                                 operation="loginDelegates", session=session)
        session.post.assert_not_called()

    def test_method_preserving_redirects_are_not_followed(self):
        for status in (302, 307, 308):
            with self.subTest(status=status):
                response = mock.Mock(status_code=status,
                                     headers={"Location": "https://evil.example/collect"})
                session = _FakeSession(response)
                with self.assertRaisesRegex(ICloudError, "redirect"):
                    icloud._post_service("https://setup.icloud.com/setup/ws/1",
                                         headers={}, data=b"PET", operation="loginDelegates",
                                         session=session)
                self.assertFalse(session.calls[0][1]["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
