"""The two clocks: one scan buys full access for a while, browsing for longer, then nothing.

The point of the model is that a scan is app-wide and time-bounded, so these tests pin both:
elevation must not ask again inside the window, and must ask again outside it - whatever entry
it is asked about.
"""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from icp.cli import appapi


class ClockTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "app-session.json")
        p = mock.patch.object(appapi, "_app_session_path", return_value=self.path)
        p.start(); self.addCleanup(p.stop)

    def write(self, *, age_full=0.0, age_session=0.0, pid=None):
        now = time.time()
        with open(self.path, "w") as fh:
            json.dump({"pid": os.getppid() if pid is None else pid,
                       "full_until": now + appapi.FULL_TTL - age_full,
                       "expires": now + appapi.SESSION_TTL - age_session}, fh)

    def test_a_scan_starts_both_clocks(self):
        s = appapi._write_session()
        self.assertAlmostEqual(s["full_until"] - time.time(), appapi.FULL_TTL, delta=2)
        self.assertAlmostEqual(s["expires"] - time.time(), appapi.SESSION_TTL, delta=2)
        self.assertTrue(appapi._app_session_ok() and appapi._full_access())

    def test_between_the_clocks_the_app_is_open_but_not_privileged(self):
        self.write(age_full=appapi.FULL_TTL + 1)          # full window gone, session alive
        self.assertTrue(appapi._app_session_ok())
        self.assertFalse(appapi._full_access())

    def test_after_the_session_clock_everything_is_locked(self):
        self.write(age_full=appapi.FULL_TTL + 1, age_session=appapi.SESSION_TTL + 1)
        self.assertFalse(appapi._app_session_ok())
        self.assertFalse(appapi._full_access())

    def test_elevate_inside_the_window_never_prompts(self):
        self.write()
        with mock.patch("icp.ui.reauth.challenge_status", side_effect=AssertionError("prompted")):
            self.assertTrue(appapi._elevate())

    def test_elevate_outside_the_window_prompts_and_restarts_both_clocks(self):
        self.write(age_full=appapi.FULL_TTL + 1, age_session=appapi.SESSION_TTL - 30)
        with mock.patch("icp.ui.reauth.challenge_status", return_value="authed") as ch:
            self.assertTrue(appapi._elevate())
            self.assertEqual(ch.call_count, 1)
        self.assertTrue(appapi._full_access())
        state = appapi._session_state()
        self.assertAlmostEqual(state["expires"] - time.time(), appapi.SESSION_TTL, delta=2)

    def test_a_refused_scan_leaves_the_window_shut(self):
        self.write(age_full=appapi.FULL_TTL + 1)
        with mock.patch("icp.ui.reauth.challenge_status", return_value="denied"):
            self.assertFalse(appapi._elevate())
        self.assertFalse(appapi._full_access())

    def test_lock_ends_full_access_but_leaves_the_app_open(self):
        self.write()
        import argparse
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            appapi.cmd_app_lock(argparse.Namespace())
        self.assertTrue(json.loads(out.getvalue())["unlocked"])
        self.assertFalse(appapi._full_access())
        self.assertTrue(appapi._app_session_ok())

    def test_another_app_instance_cannot_use_this_session(self):
        self.write(pid=os.getppid() + 12345)
        self.assertFalse(appapi._app_session_ok())
        self.assertFalse(appapi._full_access())


if __name__ == "__main__":
    unittest.main()
