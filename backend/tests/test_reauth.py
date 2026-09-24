"""The unlock gate's verdicts, and when pkexec may stand in for it.

The rule under test: a person saying no is an answer and is respected; only the gate itself
breaking falls back to pkexec. Getting that backwards either locks people out of their own
passwords, or quietly routes around a refusal.
"""

import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from icp.cli import appapi
from icp.ui import reauth


class ChallengeStatusTests(unittest.TestCase):
    def status(self, rc, available=True):
        with mock.patch.object(reauth, "available", return_value=available), \
             mock.patch.object(reauth, "_run", return_value=(rc, "")):
            return reauth.challenge_status()

    def test_verdicts(self):
        self.assertEqual(self.status(0), "authed")
        self.assertEqual(self.status(1), "denied")
        self.assertEqual(self.status(2), "error")       # gate broke
        self.assertEqual(self.status(None), "error")    # never finished: spawn fail / timeout

    def test_missing_gate_is_an_error_not_a_refusal(self):
        self.assertEqual(self.status(0, available=False), "error")

    def test_uses_pinned_system_python_even_when_environment_overrides_it(self):
        with mock.patch.dict(os.environ, {"ICP_SYSTEM_PYTHON": "/tmp/fake-python"}), \
             mock.patch.object(reauth, "available", return_value=True), \
             mock.patch.object(reauth, "_run", return_value=(0, "")) as run:
            self.assertEqual(reauth.challenge_status(), "authed")

        self.assertEqual(run.call_args.args[0], ["/usr/bin/python3", "-I", reauth.GATE])

    def test_untrusted_system_python_cannot_open_the_gate(self):
        with mock.patch.object(reauth, "policy_installed", return_value=True), \
             mock.patch.object(reauth.os.path, "isfile", return_value=True), \
             mock.patch.object(reauth, "_trusted_system_executable", return_value=False), \
             mock.patch.object(reauth, "_run") as run:
            self.assertEqual(reauth.challenge_status(), "error")
        run.assert_not_called()

    def test_bool_wrapper_still_means_authed(self):
        with mock.patch.object(reauth, "challenge_status", return_value="denied"):
            self.assertFalse(reauth.challenge())


class PkexecTests(unittest.TestCase):
    def verdict(self, rc, err=""):
        with mock.patch.object(reauth, "_trusted_system_executable", return_value=True), \
             mock.patch.object(reauth, "_run", return_value=(rc, err)):
            return reauth.pkexec_challenge()

    def test_success(self):
        self.assertEqual(self.verdict(0), "authed")

    def test_dismissed_dialog_is_a_refusal(self):
        self.assertEqual(self.verdict(126), "denied")

    def test_wrong_password_is_a_refusal(self):
        self.assertEqual(self.verdict(127, "Error executing command: Not authorized"), "denied")

    def test_no_agent_is_an_error(self):
        self.assertEqual(self.verdict(127, "Error: No authentication agent found."), "error")

    def test_untrusted_system_binary_is_an_error(self):
        with mock.patch.object(reauth, "_trusted_system_executable", return_value=False), \
             mock.patch.object(reauth, "_run") as run:
            self.assertEqual(reauth.pkexec_challenge(), "error")
        run.assert_not_called()

    def test_uses_fixed_paths_and_allowlisted_environment(self):
        with mock.patch.object(reauth, "_trusted_system_executable", return_value=True), \
             mock.patch.object(reauth, "_run", return_value=(0, "")) as run, \
             mock.patch.dict(os.environ, {
                 "PATH": "/tmp/attacker-bin",
                 "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                 "DISPLAY": ":99",
                 "XDG_RUNTIME_DIR": "/run/user/1000",
                 "HOME": "/tmp/attacker-home",
                 "LD_PRELOAD": "/tmp/attacker.so",
                 "PYTHONPATH": "/tmp/attacker-python",
                 "GCONV_PATH": "/tmp/attacker-gconv",
             }, clear=True):
            self.assertEqual(reauth.pkexec_challenge(), "authed")

        argv, timeout = run.call_args.args
        env = run.call_args.kwargs["env"]
        self.assertEqual(argv, [reauth.PKEXEC_PATH, reauth.TRUE_PATH])
        self.assertEqual(timeout, 90)
        self.assertEqual(env, {
            "PATH": "/usr/bin:/bin",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
            "DISPLAY": ":99",
            "XDG_RUNTIME_DIR": "/run/user/1000",
        })
        self.assertNotIn("LD_PRELOAD", env)
        self.assertNotIn("PYTHONPATH", env)

    def test_system_binary_validation_requires_root_and_no_group_writes(self):
        regular = stat.S_IFREG | stat.S_IXUSR
        with mock.patch.object(reauth.os, "stat", return_value=mock.Mock(
                st_mode=regular, st_uid=0)), \
             mock.patch.object(reauth.os, "access", return_value=True):
            self.assertTrue(reauth._trusted_system_executable("/usr/bin/true"))

        for mode, uid in ((regular | stat.S_IWGRP, 0), (regular, 1000)):
            with self.subTest(mode=mode, uid=uid), \
                 mock.patch.object(reauth.os, "stat", return_value=mock.Mock(
                     st_mode=mode, st_uid=uid)), \
                 mock.patch.object(reauth.os, "access", return_value=True):
                self.assertFalse(reauth._trusted_system_executable("/usr/bin/true"))

    def test_pkexec_validation_requires_setuid(self):
        mode = stat.S_IFREG | stat.S_IXUSR
        with mock.patch.object(reauth.os, "stat", return_value=mock.Mock(
                st_mode=mode, st_uid=0)), \
             mock.patch.object(reauth.os, "access", return_value=True):
            self.assertFalse(reauth._trusted_system_executable(
                reauth.PKEXEC_PATH, require_setuid=True))


class AppAuthFallbackTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "app-session.json")
        for target, value in ((appapi, "_app_session_path"), (appapi, "_app_session_ok")):
            pass
        p1 = mock.patch.object(appapi, "_app_session_path", return_value=self.path)
        p2 = mock.patch.object(appapi, "_app_session_ok", return_value=False)
        p3 = mock.patch("signal.signal")                # don't rebind the test runner's SIGTERM
        for p in (p1, p2, p3):
            p.start(); self.addCleanup(p.stop)

    def run_auth(self, polkit, pk):
        pk_mock = mock.Mock(return_value=pk)
        with mock.patch.object(reauth, "challenge_status", return_value=polkit), \
             mock.patch.object(reauth, "pkexec_challenge", pk_mock):
            out = io.StringIO()
            with redirect_stdout(out):
                appapi.cmd_app_auth(mock.Mock())
        return json.loads(out.getvalue()), pk_mock

    def test_a_refusal_is_never_routed_around(self):
        d, pk = self.run_auth(polkit="denied", pk="authed")
        self.assertFalse(d["authed"])
        pk.assert_not_called()
        self.assertFalse(os.path.exists(self.path))

    def test_broken_gate_falls_back_to_pkexec(self):
        d, pk = self.run_auth(polkit="error", pk="authed")
        pk.assert_called_once()
        self.assertTrue(d["authed"])
        self.assertEqual(d["via"], "pkexec")
        self.assertTrue(os.path.exists(self.path))

    def test_refusal_at_the_fallback_is_respected_too(self):
        d, _ = self.run_auth(polkit="error", pk="denied")
        self.assertFalse(d["authed"])
        self.assertFalse(os.path.exists(self.path))

    def test_healthy_gate_never_touches_pkexec(self):
        d, pk = self.run_auth(polkit="authed", pk="authed")
        pk.assert_not_called()
        self.assertEqual(d["via"], "polkit")


if __name__ == "__main__":
    unittest.main()
