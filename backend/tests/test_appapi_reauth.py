"""Every app reauthentication path preserves the custom gate's verdict."""

import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from icp.cli import appapi
from icp.ui import reauth


class AppApiReauthTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "app-session.json")
        patch = mock.patch.object(appapi, "_app_session_path", return_value=self.path)
        patch.start()
        self.addCleanup(patch.stop)

    def write_session(self, *, full_until=None):
        now = time.time()
        with open(self.path, "w") as fh:
            json.dump({
                "pid": os.getppid(),
                "expires": now + appapi.SESSION_TTL,
                "full_until": now + (full_until if full_until is not None else appapi.FULL_TTL),
            }, fh)

    def run_command(self, command, **kwargs):
        output = io.StringIO()
        with redirect_stdout(output):
            code = command(mock.Mock(**kwargs))
        return code, json.loads(output.getvalue())

    def test_unlock_missing_policy_uses_pkexec(self):
        self.write_session(full_until=-1)
        with mock.patch.object(reauth, "available", return_value=False), \
             mock.patch.object(reauth, "pkexec_challenge", return_value="authed") as fallback:
            code, result = self.run_command(appapi.cmd_app_unlock)

        self.assertEqual(code, 0)
        self.assertTrue(result["ok"])
        fallback.assert_called_once_with()

    def test_elevate_broken_gate_uses_pkexec(self):
        self.write_session(full_until=-1)
        with mock.patch.object(reauth, "challenge_status", return_value="error"), \
             mock.patch.object(reauth, "pkexec_challenge", return_value="authed") as fallback:
            self.assertTrue(appapi._elevate())

        fallback.assert_called_once_with()
        self.assertTrue(appapi._full_access())

    def test_elevate_denial_never_uses_pkexec(self):
        self.write_session(full_until=-1)
        with mock.patch.object(reauth, "challenge_status", return_value="denied"), \
             mock.patch.object(reauth, "pkexec_challenge", return_value="authed") as fallback:
            self.assertFalse(appapi._elevate())

        fallback.assert_not_called()
        self.assertFalse(appapi._full_access())

    def test_unlock_denial_never_uses_pkexec(self):
        self.write_session(full_until=-1)
        with mock.patch.object(reauth, "challenge_status", return_value="denied"), \
             mock.patch.object(reauth, "pkexec_challenge", return_value="authed") as fallback:
            code, result = self.run_command(appapi.cmd_app_unlock)

        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "authentication cancelled")
        fallback.assert_not_called()

    def test_create_broken_gate_falls_back_successfully(self):
        self.write_session()
        payload = {"site": "example.com", "username": "alice", "password": "secret"}
        with mock.patch.object(appapi, "_payload_json", return_value=payload), \
             mock.patch.object(reauth, "challenge_status", return_value="error"), \
             mock.patch.object(reauth, "pkexec_challenge", return_value="authed") as fallback, \
             mock.patch("icp.cli.push.create_entry") as create_entry, \
             mock.patch.object(appapi, "load_vault", return_value=mock.Mock(all=lambda: [])):
            code, result = self.run_command(appapi.cmd_app_create, anisette=None)

        self.assertEqual(code, 0)
        self.assertTrue(result["ok"])
        fallback.assert_called_once_with()
        create_entry.assert_called_once()

    def test_create_denial_never_falls_back(self):
        self.write_session()
        payload = {"site": "example.com", "username": "alice", "password": "secret"}
        with mock.patch.object(appapi, "_payload_json", return_value=payload), \
             mock.patch.object(reauth, "challenge_status", return_value="denied"), \
             mock.patch.object(reauth, "pkexec_challenge", return_value="authed") as fallback, \
             mock.patch("icp.cli.push.create_entry") as create_entry:
            code, result = self.run_command(appapi.cmd_app_create, anisette=None)

        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "not authorised")
        fallback.assert_not_called()
        create_entry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
