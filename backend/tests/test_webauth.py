"""Offline tests for the idmsa web-session auth (icp.auth.webauth).

No network: `WebAuthSession.http` is a real `requests.Session`, but its `get`/`post`
methods are monkeypatched per-test with fakes returning canned responses. `signin()`
itself is exercised via its private steps (`_auth_start`/`_federate`/`_srp_init`) mocked
out, since a full run needs a real SRP server on the other end.

Run: .venv/bin/python -m unittest tests.test_webauth
"""

import base64
import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import requests

from icp.auth import webauth
from icp.auth.webauth import WebAuthError, WebAuthSession, _derive_password_key


class _FakeResponse:
    def __init__(self, status_code=200, json_body=None, headers=None, ok=None):
        self.status_code = status_code
        self._json = json_body
        self.headers = headers or {}
        self.ok = ok if ok is not None else 200 <= status_code < 300
        self.reason = "error" if not self.ok else "OK"
        self.text = ""

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


def _session(**kw) -> WebAuthSession:
    return WebAuthSession("auth-test-frame", **kw)


class TransportSecurityTests(unittest.TestCase):
    def test_web_session_uses_verified_tls(self):
        self.assertIs(_session().http.verify, True)

    @mock.patch.dict(os.environ, {
        "REQUESTS_CA_BUNDLE": "/tmp/attacker-ca.pem",
        "CURL_CA_BUNDLE": "/tmp/attacker-ca.pem",
        "HTTP_PROXY": "http://attacker-proxy.invalid:8080",
        "HTTPS_PROXY": "http://attacker-proxy.invalid:8080",
        "ALL_PROXY": "http://attacker-proxy.invalid:8080",
    })
    def test_environment_ca_and_proxy_settings_are_ignored(self):
        sess = _session()
        settings = sess.http.merge_environment_settings(
            "https://idmsa.apple.com", {}, None, None, None)

        self.assertFalse(sess.http.trust_env)
        self.assertIs(settings["verify"], True)
        self.assertEqual(settings["proxies"], {})

    def test_cookie_export_preserves_scope_and_expiry(self):
        sess = _session()
        sess.http.cookies.set("aasp", "secret", domain="idmsa.apple.com", path="/",
                             secure=True, expires=2000000000)
        sess.http.cookies.set("hme", "alias", domain=".icloud.com", path="/v2",
                             secure=True, expires=None)

        restored = WebAuthSession("auth-test-frame", cookies=sess.export()["cookies"])
        self.assertFalse(restored.cookies_need_reauth)
        self.assertEqual(restored.http.cookies.get("aasp", domain="idmsa.apple.com", path="/"),
                         "secret")
        self.assertEqual(restored.http.cookies.get("hme", domain=".icloud.com", path="/v2"),
                         "alias")
        aasp = next(c for c in restored.http.cookies if c.name == "aasp")
        self.assertEqual(aasp.expires, 2000000000)
        self.assertTrue(aasp.secure)

        request = requests.Request("GET", "https://evil.example/").prepare()
        request.prepare_cookies(restored.http.cookies)
        self.assertIsNone(request.headers.get("Cookie"))

    def test_legacy_unscoped_cookie_dict_is_discarded(self):
        sess = _session(session_data={"session_token": "stale"},
                        cookies={"aasp": "secret"})
        self.assertTrue(sess.cookies_need_reauth)
        self.assertEqual(list(sess.http.cookies), [])
        with self.assertRaisesRegex(WebAuthError, "reauthentication"):
            sess.account_login()

    def test_malformed_scoped_cookie_list_is_discarded(self):
        sess = _session(cookies=[{"name": "aasp", "value": "secret"}])
        self.assertTrue(sess.cookies_need_reauth)
        self.assertEqual(list(sess.http.cookies), [])


class RedirectTests(unittest.TestCase):
    def test_auth_redirects_are_rejected_without_capturing_headers(self):
        for status in (300, 301, 302, 303, 307, 308):
            with self.subTest(status=status):
                sess = _session()
                seen = {}

                def fake_post(url, **kwargs):
                    seen.update(kwargs)
                    return _FakeResponse(
                        status, json_body={"ignored": True},
                        headers={"Location": "https://evil.example/collect",
                                 "X-Apple-Session-Token": "attacker-token"})

                sess.http.post = fake_post
                with self.assertRaises(WebAuthError):
                    sess._post("https://idmsa.apple.com/appleauth/auth/federate",
                               headers={}, body={"securityCode": {"code": "123456"}})
                self.assertFalse(seen["allow_redirects"])
                self.assertNotIn("session_token", sess.session_data)


class DerivePasswordKeyTests(unittest.TestCase):
    """Must match gsa.py's `_encrypt_password` exactly - same KDF, different transport."""

    def test_matches_gsa_encrypt_password(self):
        from icp.auth.gsa import _encrypt_password
        salt, iterations = b"some-salt", 20000
        for protocol in ("s2k", "s2k_fo"):
            self.assertEqual(
                _derive_password_key("hunter2", salt, iterations, protocol),
                _encrypt_password("hunter2", salt, iterations, protocol))

    def test_unknown_protocol_falls_back_to_s2k(self):
        """No protocol validation, deliberately - matches gsa.py's `_encrypt_password`,
        which treats anything other than "s2k_fo" as plain "s2k"."""
        from icp.auth.gsa import _encrypt_password
        self.assertEqual(_derive_password_key("hunter2", b"salt", 1000, "bogus"),
                         _encrypt_password("hunter2", b"salt", 1000, "bogus"))


class AuthStartTests(unittest.TestCase):
    def test_failure_raises(self):
        sess = _session()
        sess.http.get = lambda *a, **k: _FakeResponse(503, json_body=None)
        with self.assertRaises(WebAuthError):
            sess._auth_start()

    def test_success_captures_cookies_no_raise(self):
        sess = _session()
        sess.http.get = lambda *a, **k: _FakeResponse(200, json_body=None)
        sess._auth_start()  # must not raise


class FederateTests(unittest.TestCase):
    def test_failure_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(400, json_body=None)
        with self.assertRaises(WebAuthError):
            sess._federate("user@example.com")


class SrpInitTests(unittest.TestCase):
    def test_success_returns_parsed_body(self):
        sess = _session()
        body = {"iteration": 20000, "salt": base64.b64encode(b"salt").decode(),
                "protocol": "s2k", "b": base64.b64encode(b"B" * 32).decode(), "c": "chal-1"}
        sess.http.post = lambda *a, **k: _FakeResponse(200, json_body=body)
        self.assertEqual(sess._srp_init("user@example.com", b"A"), body)

    def test_error_body_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(
            200, json_body={"errorMessage": "Invalid ID or password."})
        with self.assertRaisesRegex(WebAuthError, "Invalid ID or password"):
            sess._srp_init("user@example.com", b"A")


class SigninTests(unittest.TestCase):
    """The multi-step signin() orchestration, with the network steps mocked out."""

    def _patched(self, sess, *, complete_status):
        init_resp = {"iteration": 1000, "salt": base64.b64encode(b"some-salt").decode(),
                    "protocol": "s2k", "b": base64.b64encode((7).to_bytes(256, "big")).decode(),
                    "c": "chal-1"}
        patches = [
            mock.patch.object(sess, "_auth_start"),
            mock.patch.object(sess, "_federate"),
            mock.patch.object(sess, "_srp_init", return_value=init_resp),
            mock.patch.object(sess, "_post",
                              return_value=_FakeResponse(complete_status, json_body={})),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_success_clears_needs_2fa(self):
        sess = _session()
        self._patched(sess, complete_status=200)
        sess.signin("user@example.com", "hunter2")
        self.assertFalse(sess.needs_2fa)

    def test_409_sets_needs_2fa_without_raising(self):
        sess = _session()
        self._patched(sess, complete_status=409)
        sess.signin("user@example.com", "hunter2")
        self.assertTrue(sess.needs_2fa)

    def test_other_failure_raises(self):
        sess = _session()
        self._patched(sess, complete_status=403)
        with self.assertRaises(WebAuthError):
            sess.signin("user@example.com", "wrongpassword")

    def test_username_is_lowercased_for_the_srp_proof(self):
        sess = _session()
        seen = {}

        def fake_federate(username):
            seen["username"] = username

        init_resp = {"iteration": 1000, "salt": base64.b64encode(b"some-salt").decode(),
                    "protocol": "s2k", "b": base64.b64encode((7).to_bytes(256, "big")).decode(),
                    "c": "chal-1"}
        with mock.patch.object(sess, "_auth_start"), \
             mock.patch.object(sess, "_federate", side_effect=fake_federate), \
             mock.patch.object(sess, "_srp_init", return_value=init_resp), \
             mock.patch.object(sess, "_post", return_value=_FakeResponse(200, json_body={})):
            sess.signin("User@Example.COM", "hunter2")
        self.assertEqual(seen["username"], "user@example.com")


class RequestPushNotificationTests(unittest.TestCase):
    def test_success(self):
        sess = _session()
        calls = []

        def fake_put(url, **k):
            calls.append(url)
            return _FakeResponse(200, json_body=None)

        sess.http.put = fake_put
        sess.request_push_notification()  # must not raise
        self.assertTrue(calls[0].endswith("/verify/trusteddevice/securitycode"))

    def test_failure_raises(self):
        sess = _session()
        sess.http.put = lambda *a, **k: _FakeResponse(500, json_body=None)
        with self.assertRaises(WebAuthError):
            sess.request_push_notification()


class TwoFactorTests(unittest.TestCase):
    def test_submit_2fa_then_trusts_session(self):
        sess = _session(session_data={"session_id": "sid-1", "scnt": "scnt-1"})
        calls = []

        def fake_post(url, **k):
            calls.append(("post", url))
            return _FakeResponse(204, json_body=None)

        def fake_get(url, **k):
            calls.append(("get", url))
            return _FakeResponse(200, json_body={},
                                 headers={"X-Apple-TwoSV-Trust-Token": "trust-1"})

        sess.http.post = fake_post
        sess.http.get = fake_get
        sess.needs_2fa = True
        sess.submit_2fa("123456")
        self.assertEqual(sess.session_data["trust_token"], "trust-1")
        self.assertFalse(sess.needs_2fa)
        self.assertTrue(calls[0][1].endswith("/verify/trusteddevice/securitycode"))
        self.assertTrue(calls[1][1].endswith("/2sv/trust"))

    def test_wrong_code_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(
            400, json_body={"errorMessage": "Incorrect verification code."})
        with self.assertRaisesRegex(WebAuthError, "Incorrect verification code"):
            sess.submit_2fa("000000")

    def test_trust_call_failure_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(204, json_body=None)
        sess.http.get = lambda *a, **k: _FakeResponse(500, json_body=None)
        with self.assertRaises(WebAuthError):
            sess.submit_2fa("123456")


class AccountLoginTests(unittest.TestCase):
    def test_returns_parsed_data(self):
        sess = _session(session_data={"session_token": "tok-1"})
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": True, "webservices": {}}
        sess.http.post = lambda *a, **k: _FakeResponse(200, json_body=data)
        self.assertEqual(sess.account_login(), data)

    def test_non_json_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(200, json_body=None)
        with self.assertRaises(WebAuthError):
            sess.account_login()

    def test_error_body_raises(self):
        sess = _session()
        sess.http.post = lambda *a, **k: _FakeResponse(
            200, json_body={"errorMessage": "Authentication required for Account."})
        with self.assertRaises(WebAuthError):
            sess.account_login()


class HsaChallengeTests(unittest.TestCase):
    def test_hsa1_never_challenges(self):
        self.assertFalse(webauth.hsa_challenge_required({"dsInfo": {"hsaVersion": 1}}))

    def test_trusted_browser_no_challenge(self):
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": True}
        self.assertFalse(webauth.hsa_challenge_required(data))

    def test_untrusted_browser_challenges(self):
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": False}
        self.assertTrue(webauth.hsa_challenge_required(data))

    def test_explicit_challenge_flag_wins(self):
        data = {"dsInfo": {"hsaVersion": 2}, "hsaTrustedBrowser": True,
                "hsaChallengeRequired": True}
        self.assertTrue(webauth.hsa_challenge_required(data))


class ExtractWebservicesTests(unittest.TestCase):
    def test_flattens_url_and_drops_off_services(self):
        data = {"webservices": {
            "premiummailsettings": {"url": "https://p1-maildomainws.icloud.com", "status": "active"},
            "drivews": {"url": "https://p1-drivews.icloud.com", "status": "off"},
            "noturl": {"status": "active"},
        }}
        self.assertEqual(webauth.extract_webservices(data),
                         {"premiummailsettings": "https://p1-maildomainws.icloud.com"})

    def test_drops_untrusted_webservice_urls(self):
        data = {"webservices": {
            "valid": {"url": "https://P1-MAILDOMAINWS.ICLOUD.COM", "status": "active"},
            "plain_http": {"url": "http://p1-maildomainws.icloud.com", "status": "active"},
            "wrong_domain": {"url": "https://icloud.com.attacker.test", "status": "active"},
            "user_info": {"url": "https://attacker.test@p1-maildomainws.icloud.com",
                           "status": "active"},
            "wrong_port": {"url": "https://p1-maildomainws.icloud.com:8443", "status": "active"},
        }}
        self.assertEqual(webauth.extract_webservices(data),
                         {"valid": "https://P1-MAILDOMAINWS.ICLOUD.COM"})


class ExportTests(unittest.TestCase):
    def test_export_round_trips_frame_tag_and_session_data(self):
        sess = _session(session_data={"session_token": "tok-1"})
        exported = sess.export()
        self.assertEqual(exported["frame_tag"], "auth-test-frame")
        self.assertEqual(exported["session_data"]["session_token"], "tok-1")
        self.assertIn("cookies", exported)

        restored = WebAuthSession(exported["frame_tag"], session_data=exported["session_data"],
                                  cookies=exported["cookies"])
        self.assertEqual(restored.session_data["session_token"], "tok-1")


class TlsVerificationTests(unittest.TestCase):
    """The session carries session/trust tokens, cookies and 2FA codes. It verified nothing at
    all until 1.0.2, which also silently disabled verification for Hide My Email, since
    HmeClient is handed this very session."""

    def test_session_verifies_certificates(self):
        self.assertIs(_session().http.verify, True)

    def test_hme_client_inherits_a_verifying_session(self):
        from icp.hme.client import HmeClient
        sess = _session()
        client = HmeClient("https://p1-maildomainws.icloud.com", sess.http)
        self.assertIs(client.http.verify, True)

    def test_module_does_not_silence_tls_warnings(self):
        """`urllib3.disable_warnings()` at import time hides InsecureRequestWarning for the
        whole process, so a future accidental bypass anywhere would fail silently."""
        import inspect
        for mod in (webauth, __import__("icp.auth.icloud", fromlist=["x"])):
            src = inspect.getsource(mod)
            self.assertNotIn("disable_warnings", src, f"{mod.__name__} silences urllib3 warnings")


class QmlTextFormatTests(unittest.TestCase):
    """Vault entry titles, usernames, domains and field values are rendered in QML labels. A
    label left on the default Text.AutoText parses them as markup, so an entry whose title or
    notes contain an <img> would make Qt fetch that URL when the vault is opened: an outbound
    request against README.md's "Requests go to Apple only", and a signal that the vault was
    opened and which entry was viewed. Entries can come from a shared iCloud group or be
    authored by a website through autofill, so their text is not all the owner's own."""

    QML = [os.path.join(os.path.dirname(__file__), "..", "..", d)
           for d in ("app", "plugin")]
    # A word boundary, not a line anchor: `delegate: Text {` and `component Foo: Text {` are
    # elements too. A ^ anchor skipped them, this test still passed, and the reviewer then
    # found one of them. TextInput has no textFormat property, so it is excluded by name.
    ELEMENT = re.compile(r"(?<![A-Za-z0-9_])(TextEdit|TextArea|TextInput|Text)\s*\{")

    def _files(self):
        for folder in self.QML:
            for name in sorted(os.listdir(folder)):
                if name.endswith(".qml"):
                    with open(os.path.join(folder, name)) as fh:
                        yield name, fh.read().split("\n")

    def test_every_text_element_declares_a_format(self):
        missing = []
        for name, lines in self._files():
            for i, line in enumerate(lines):
                found = self.ELEMENT.search(line)
                if (found and found.group(1) != "TextInput"
                        and "textFormat" not in " ".join(lines[i:i + 16])):
                    missing.append(f"{name}:{i + 1} {line.strip()[:50]}")
        self.assertEqual(missing, [], "on the AutoText default:\n" + "\n".join(missing))

    def test_markup_is_only_rendered_for_fixed_text(self):
        """StyledText and RichText fetch remote <img> just as AutoText does. 2.0 has no markup
        element at all: the one fixed escrow warning that used StyledText is plain text now
        (test_qml_text_plain.py holds the full rule)."""
        rich = []
        for name, lines in self._files():
            for i, line in enumerate(lines):
                if re.search(r"textFormat:\s*\w+\.(RichText|StyledText|AutoText)", line):
                    rich.append((name, i + 1))
        self.assertEqual(rich, [], "a markup element came back")

    def test_secret_word_is_clamped(self):
        """secretWord() is interpolated into that one markup element and takes its value from
        an Apple API response, so it must only ever return a word this file branches on."""
        shell = dict(self._files())["shell.qml"]
        start = next(i for i, l in enumerate(shell) if "function secretWord()" in l)
        body = "\n".join(shell[start:start + 12])
        self.assertIn("indexOf(root.signinDevice.secret)", body,
                      "secretWord() returns signinDevice.secret unchecked")


class OneCommandInstallTest(unittest.TestCase):
    """`omarchy plugin add` used to leave a plugin that did nothing but post a notification
    telling you to find a terminal. The plugin now lays the window down itself and the window
    asks before building the backend, so the install is one command plus one button."""

    ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

    def _read(self, *parts):
        with open(os.path.join(self.ROOT, *parts)) as fh:
            return fh.read()

    def test_installer_has_an_app_only_mode(self):
        body = self._read("install.sh")
        self.assertIn("--app-only", body, "the window-only install mode is gone")
        self.assertRegex(body, r'app_only=1', "the flag is not set anywhere")
        # app-only must not build the venv or install services
        after = body[body.index("if [ \"$app_only\" -eq 1 ]; then"):]
        self.assertIn("exit 0", after, "app-only no longer stops before the services")

    def test_app_only_does_not_need_the_heavy_dependencies(self):
        body = self._read("install.sh")
        self.assertRegex(body, r'\[ "\$app_only" -eq 1 \] && needed="quickshell"',
                         "app-only still demands podman/systemctl it does not use")

    def test_the_plugin_provisions_the_window(self):
        # 2.0: the window is installed root-owned by the system step, so the plugin copies
        # nothing; it checks that pear-exec is installed set-gid and says what to run.
        qml = self._read("plugin", "Service.qml")
        self.assertNotIn("--app-only", qml, "the plugin still lays a user copy of the window down")
        self.assertIn('"0 pear-client 2755"', qml, "the plugin no longer checks pear-exec")
        self.assertNotIn("venv", qml,
                         "the plugin must not build the backend")

    def test_the_plugin_compares_the_installed_snapshot_not_just_shell_qml(self):
        # installer-plugin-update-detection-ignores-version: a backend-only update (same
        # shell.qml, new SHA256SUMS) must be reported as outdated.
        import re
        import subprocess
        import tempfile
        qml = self._read("plugin", "Service.qml")
        block = qml[qml.index("property Process compare"):]
        m = re.search(r"command: (\[.*?\])\n\s*running:", block, re.S)
        self.assertIsNotNone(m, "the compare Process has no command")
        with tempfile.TemporaryDirectory() as d:
            checkout, prefix = os.path.join(d, "checkout"), os.path.join(d, "prefix")
            os.makedirs(os.path.join(checkout, "app"))
            os.makedirs(os.path.join(prefix, "app"))
            for base in (checkout, prefix):
                with open(os.path.join(base, "app", "shell.qml"), "w") as f:
                    f.write("// same window\n")
            with open(os.path.join(checkout, "manifest.json"), "w") as f:
                f.write('{\n  "version": "2.0.1"\n}\n')
            with open(os.path.join(checkout, "SHA256SUMS"), "w") as f:
                f.write("a" * 64 + "  backend/icp/daemon/peer.py\n")
            argv = eval(m.group(1), {}, {"root": type("R", (), {"checkout": checkout,
                                                                 "prefix": prefix})})
            run = lambda: subprocess.run(argv, capture_output=True, timeout=10).returncode
            self.assertNotEqual(run(), 0, "no VERSION installed reads as current")
            with open(os.path.join(checkout, "SHA256SUMS"), "rb") as f:
                sums = __import__("hashlib").sha256(f.read()).hexdigest()
            with open(os.path.join(prefix, "VERSION"), "w") as f:
                f.write(f"version=2.0.1\nsums={sums}\n")
            self.assertEqual(run(), 0, "the installed snapshot is this checkout's")
            with open(os.path.join(checkout, "SHA256SUMS"), "w") as f:
                f.write("b" * 64 + "  backend/icp/daemon/peer.py\n")   # backend-only change
            self.assertNotEqual(run(), 0, "a backend-only update was not noticed")

    def test_the_window_gates_on_the_backend(self):
        # 2.0: the window gates on reaching the daemon, and says what is missing.
        qml = self._read("app", "shell.qml")
        for state in ('"not-installed"', '"daemon-failed"', '"abi-mismatch"'):
            self.assertIn(state, qml, f"the {state} screen is gone")
        self.assertNotIn("root.icp", qml, "the window still runs the 1.x backend")

    def test_installer_output_is_stripped_before_display(self):
        """2.0: the window never runs the installer (it needs sudo), so no installer output
        can reach a Text; it only shows the command to run."""
        qml = self._read("app", "shell.qml")
        self.assertNotIn("install.sh\"", qml, "the window runs the installer again")
        self.assertNotIn("setupProc", qml)


class AnisetteProvenanceTest(unittest.TestCase):
    """The reviewer could not authenticate what source produced the published anisette image
    or where its Apple libraries come from. The image is now built here from one pinned
    upstream commit, and the chain is written down."""

    ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

    def _read(self, *parts):
        with open(os.path.join(self.ROOT, *parts)) as fh:
            return fh.read()

    def test_the_revision_is_a_full_sha_and_appears_once(self):
        """An abbreviated SHA is not a pin, and a second copy of it is a thing that drifts."""
        body = self._read("anisette", "Containerfile")
        found = re.search(r"^ARG ANISETTE_REV=([0-9a-f]{40})$", body, re.M)
        self.assertIsNotNone(found, "the pinned revision is gone or is not a full 40-char SHA")
        rev = found.group(1)
        # the unit must run exactly what the Containerfile pins
        unit = self._read("systemd", "pear-passwords-anisette.service")
        self.assertIn(f"localhost/pear-passwords-anisette:{rev}", unit,
                      "the service runs an image the Containerfile does not build")
        # build.sh must not carry its own copy of the revision
        self.assertNotIn(rev, self._read("anisette", "build.sh"),
                         "build.sh hardcodes the revision instead of reading the Containerfile")

    def test_the_published_image_is_no_longer_run(self):
        """It is still named in a comment, explaining why it is not used - which is fine. What
        matters is that no line the unit executes mentions it."""
        unit = self._read("systemd", "pear-passwords-anisette.service")
        for n, line in enumerate(unit.split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue
            self.assertNotIn("docker.io/dadoum", line,
                             f"line {n} still runs the unattested Docker Hub image: {line.strip()}")

    def test_build_refuses_a_revision_that_is_not_a_full_sha(self):
        self.assertIn("[0-9a-f]{40}", self._read("anisette", "build.sh"),
                      "build.sh no longer validates the revision it is given")

    def test_the_provenance_document_states_the_apple_library_source(self):
        doc = self._read("docs", "anisette-provenance.md")
        for needed in ("apps.mzstatic.com", "libCoreADI.so", "libstoreservicescore.so"):
            self.assertIn(needed, doc, f"the provenance doc no longer mentions {needed}")
        # and must not oversell: the APK is not pinned
        self.assertRegex(doc, r"(?i)not .{0,24}pinned|no digest",
                         "the doc does not say the Apple APK is unpinned")

    # --- Provision's session with Apple is TLS-verified (#10755) ------------------

    def _patch_id(self):
        """What anisette/patch-id.sh prints: sha256 of the sha256sum lines, first 12 digits."""
        lines = ""
        names = ["apple-root-ca.pem"] + sorted(
            "patches/" + n for n in os.listdir(os.path.join(self.ROOT, "anisette", "patches"))
            if n.endswith(".patch"))
        for name in names:
            with open(os.path.join(self.ROOT, "anisette", name), "rb") as fh:
                lines += f"{hashlib.sha256(fh.read()).hexdigest()}  {name}\n"
        return hashlib.sha256(lines.encode()).hexdigest()[:12]

    def test_the_unit_runs_the_image_with_the_current_patches(self):
        rev = re.search(r"^ARG ANISETTE_REV=([0-9a-f]{40})$",
                        self._read("anisette", "Containerfile"), re.M).group(1)
        script = subprocess.run([os.path.join(self.ROOT, "anisette", "patch-id.sh")],
                                capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(script, self._patch_id())
        self.assertIn(f"localhost/pear-passwords-anisette:{rev}-{script}\n",
                      self._read("systemd", "pear-passwords-anisette.service"),
                      "the unit runs an image built with other patches (or none)")

    def test_the_provision_patch_restores_verified_tls_to_apple(self):
        patch = self._read("anisette", "patches", "provision-apple-tls.patch")
        removed = [l[1:].strip() for l in patch.splitlines()
                   if l.startswith("-") and not l.startswith("---")]
        added = [l[1:].strip() for l in patch.splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        self.assertIn("request.sslSetVerifyPeer(false);", removed)
        for line in ('enum appleRootCA = "/opt/apple-root-ca.pem";',
                     "http.caInfo = appleRootCA;", "http.verifyPeer = true;",
                     "http.verifyHost = true;", "http.maxRedirects = 0;",
                     "http.url = appleURL(url);"):
            self.assertIn(line, added)
        self.assertFalse([l for l in added if "VerifyPeer(false" in l or "verifyHost = false" in l])
        # every request in the session goes through appleFetch, the URL bag's two included
        self.assertIn('string startProvisioningPlist = appleFetch(urlBag["midStartProvisioning"],',
                      added)
        self.assertIn('string endProvisioningPlist = appleFetch(urlBag["midFinishProvisioning"], '
                      'format!"<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>', added)

    def test_the_image_carries_the_one_root_the_patch_trusts(self):
        with open(os.path.join(self.ROOT, "anisette", "apple-root-ca.pem"), "rb") as a, \
                open(os.path.join(self.ROOT, "backend", "icp", "certs", "apple-root-ca.pem"),
                     "rb") as b:
            self.assertEqual(a.read(), b.read())
        body = self._read("anisette", "Containerfile")
        self.assertIn("COPY apple-root-ca.pem /opt/apple-root-ca.pem", body)
        self.assertRegex(body, r"ARG PROVISION_REV=[0-9a-f]{40}\n")
        self.assertIn("git -C provision apply /patches/provision-apple-tls.patch", body)
        self.assertIn("! grep -n 'sslSetVerifyPeer(false)' provision/lib/provision/adi.d", body)

    def test_the_installer_reuses_an_image_only_with_the_same_patches(self):
        body = self._read("install.sh")
        self.assertIn('anisette_patches="$("$here/anisette/patch-id.sh")"', body)
        self.assertIn('anisette_image="localhost/pear-passwords-anisette:$anisette_rev-$anisette_patches"',
                      body)
        self.assertIn('= "$anisette_rev $anisette_patches" ]', body)
        self.assertIn("systemctl --user try-restart pear-passwords-anisette.service", body)

    def test_the_installer_builds_before_enabling_the_unit(self):
        body = self._read("install.sh")
        self.assertLess(body.index("anisette/build.sh"),
                        body.index("enable --now pear-passwords-anisette.service"),
                        "the unit is enabled before the image it runs exists")

    # --- the libraries are gated at startup, not merely recorded ---------------

    def _entrypoint_harness(self, tmp, core, ssc, preexisting=None):
        """Run anisette/entrypoint.sh with its download stubbed out.

        LIBDIR and DIGESTS are deliberately hardcoded in the real script, so that
        an argument cannot point the gate at a directory the server does not read.
        That also means they have to be rewritten to exercise it. The sed-like
        replacements below are asserted to have applied: if the script changes
        shape, this fails loudly rather than testing nothing.
        """
        libdir = os.path.join(tmp, "lib")
        digests = os.path.join(tmp, "digests")
        script = os.path.join(tmp, "entrypoint.sh")

        with open(digests, "w") as fh:
            fh.write("# comment the checker must skip\n\n")
            fh.write(hashlib.sha256(b"REAL-CORE").hexdigest() + "  libCoreADI.so\n")
            fh.write(hashlib.sha256(b"REAL-SSC").hexdigest() + "  libstoreservicescore.so\n")

        body = self._read("anisette", "entrypoint.sh")
        swaps = [
            ("LIBDIR=/home/Alcoholic/.config/anisette-v3/lib", "LIBDIR=%s" % libdir),
            ("DIGESTS=/opt/apple-libs.sha256", "DIGESTS=%s" % digests),
            ('curl -fsSL "$APK_URL" -o "$tmp/applemusic.apk"', ":"),
            ('unzip -p "$tmp/applemusic.apk" lib/x86_64/libCoreADI.so > "$tmp/libCoreADI.so"',
             'printf "%s" "$FAKE_CORE" > "$tmp/libCoreADI.so"'),
            ('unzip -p "$tmp/applemusic.apk" lib/x86_64/libstoreservicescore.so'
             ' > "$tmp/libstoreservicescore.so"',
             'printf "%s" "$FAKE_SSC" > "$tmp/libstoreservicescore.so"'),
            ('exec /opt/anisette-v3-server "$@"', 'echo STARTED'),
        ]
        for old, repl in swaps:
            self.assertIn(old, body, "entrypoint.sh no longer contains %r" % old)
            body = body.replace(old, repl)
        with open(script, "w") as fh:
            fh.write(body)
        os.chmod(script, 0o755)

        if preexisting is not None:
            os.makedirs(libdir, exist_ok=True)
            for name, data in preexisting.items():
                with open(os.path.join(libdir, name), "wb") as fh:
                    fh.write(data)

        env = dict(os.environ, FAKE_CORE=core, FAKE_SSC=ssc)
        run = subprocess.run(["/bin/sh", script], env=env,
                             capture_output=True, text=True)
        return run, libdir

    def test_matching_libraries_start_the_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, libdir = self._entrypoint_harness(tmp, "REAL-CORE", "REAL-SSC")
            self.assertEqual(0, run.returncode, run.stderr)
            self.assertIn("STARTED", run.stdout)
            self.assertTrue(os.path.exists(os.path.join(libdir, "libCoreADI.so")))

    def test_a_substituted_library_stops_the_server_and_is_not_installed(self):
        """The finding: Apple's APK is mutable and the libraries were loaded unchecked."""
        with tempfile.TemporaryDirectory() as tmp:
            run, libdir = self._entrypoint_harness(tmp, "REAL-CORE", "TAMPERED")
            self.assertNotEqual(0, run.returncode, "a substituted library still started the server")
            self.assertNotIn("STARTED", run.stdout)
            self.assertIn("REFUSING TO START", run.stderr)
            self.assertFalse(os.path.exists(os.path.join(libdir, "libCoreADI.so")),
                             "libraries were installed despite the digest mismatch")

    def test_libraries_already_in_the_volume_are_checked_too(self):
        """The volume outlives the image and is writable, so a previous start is not evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = self._entrypoint_harness(
                tmp, "REAL-CORE", "REAL-SSC",
                preexisting={"libCoreADI.so": b"REAL-CORE",
                             "libstoreservicescore.so": b"SWAPPED-LATER"})
            self.assertNotEqual(0, run.returncode,
                                "a swapped library in the volume still started the server")
            self.assertIn("REFUSING TO START", run.stderr)

    def test_the_container_runs_the_gate_and_not_the_server_directly(self):
        cf = self._read("anisette", "Containerfile")
        self.assertRegex(cf, r'ENTRYPOINT \[ "/opt/entrypoint\.sh" \]',
                         "the image starts the server directly, bypassing the digest gate")
        self.assertIn("COPY apple-libs.sha256 /opt/apple-libs.sha256", cf,
                      "the digests are not in the image, so the gate has nothing to check against")
        for tool in ("curl", "unzip"):
            self.assertIn(tool, cf, "the runtime image cannot fetch and unpack the APK itself")

    def test_the_gate_keeps_the_library_directory_out_of_argv(self):
        """--adi-path moves where the server loads libraries from; the gate would
        then be checking a directory nothing reads."""
        body = self._read("anisette", "entrypoint.sh")
        self.assertIn("--adi-path", body, "the gate no longer refuses to be pointed elsewhere")

    def test_build_output_is_not_shown_as_an_error(self):
        """podman writes build progress to stderr. 2.0's window never runs the build, so none
        of it can be painted as an error there."""
        qml = self._read("app", "shell.qml")
        self.assertNotIn("setupError", qml, "the window shows installer output again")
        self.assertNotRegex(qml, r"onRead: function \(line\) \{ if \(line\.trim\(\)\) root\.setupError",
                            "a single stderr line still becomes an error")


if __name__ == "__main__":
    unittest.main()
