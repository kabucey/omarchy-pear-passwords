"""Runtime-independent tests for Pear's ownership-aware clipboard cleanup."""

import io
import json
import os
import stat
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

from icp.cli import appapi
from icp.vault.host import Credential


class ClipboardOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "clipboard-owner.json")
        self.path_patch = mock.patch.object(appapi, "_clipboard_owner_path", return_value=self.path)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.lock_path_patch = mock.patch.object(
            appapi, "_clipboard_owner_lock_path", return_value=self.path + ".lock")
        self.lock_path_patch.start()
        self.addCleanup(self.lock_path_patch.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, **state):
        with open(self.path, "w") as fh:
            json.dump(state, fh)

    def test_token_from_old_timer_cannot_release_newer_copy(self):
        self.write_state(token="new", pid=42, start_time="7", tool="wl-copy")
        with mock.patch.object(appapi, "_clipboard_owner_is_alive", return_value=True), \
             mock.patch.object(appapi.os, "kill") as kill:
            self.assertTrue(appapi._clear_clipboard_owner("old"))
        kill.assert_not_called()
        self.assertTrue(os.path.exists(self.path))

    def test_current_owner_is_signalled_and_marker_removed(self):
        self.write_state(token="current", pid=42, start_time="7", tool="wl-copy")
        with mock.patch.object(appapi, "_clipboard_owner_is_alive", return_value=True), \
             mock.patch.object(appapi.os, "kill") as kill:
            self.assertTrue(appapi._clear_clipboard_owner("current"))
        kill.assert_called_once()
        self.assertFalse(os.path.exists(self.path))

    def test_replaced_clipboard_is_a_safe_noop_without_wl_copy_clear(self):
        self.write_state(token="current", pid=42, start_time="7", tool="wl-copy")
        with mock.patch.object(appapi, "_clipboard_owner_is_alive", return_value=False), \
             mock.patch.object(appapi.os, "kill") as kill:
            self.assertTrue(appapi._clear_clipboard_owner())
        kill.assert_not_called()
        self.assertFalse(os.path.exists(self.path))

    def test_owner_marker_is_private_and_has_no_secret(self):
        with mock.patch.object(appapi, "_process_start_time", return_value="7"):
            self.assertTrue(appapi._write_clipboard_owner("token", 42, "/usr/bin/wl-copy"))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        with open(self.path) as fh:
            state = json.load(fh)
        self.assertEqual(state, {"token": "token", "pid": 42,
                                 "start_time": "7", "tool": "wl-copy"})

    def test_old_clear_cannot_unlink_marker_written_while_it_is_reading(self):
        self.write_state(token="old", pid=42, start_time="7", tool="wl-copy")
        read_marker = threading.Event()
        release_clear = threading.Event()
        writer_done = threading.Event()
        results = []

        def paused_owner_check(_state):
            read_marker.set()
            release_clear.wait(2)
            return False

        def clear_old():
            results.append(appapi._clear_clipboard_owner("old"))

        def write_new():
            results.append(appapi._write_clipboard_owner("new", 43, "/usr/bin/wl-copy"))
            writer_done.set()

        with mock.patch.object(appapi, "_clipboard_owner_is_alive", side_effect=paused_owner_check), \
             mock.patch.object(appapi, "_process_start_time", return_value="8"):
            clear_thread = threading.Thread(target=clear_old)
            clear_thread.start()
            self.assertTrue(read_marker.wait(2))

            writer_thread = threading.Thread(target=write_new)
            writer_thread.start()
            self.assertFalse(writer_done.wait(0.15))
            release_clear.set()
            clear_thread.join(2)
            writer_thread.join(2)

        self.assertFalse(clear_thread.is_alive())
        self.assertFalse(writer_thread.is_alive())
        self.assertEqual(results, [True, True])
        with open(self.path) as fh:
            self.assertEqual(json.load(fh)["token"], "new")

    def test_copy_uses_foreground_owner_and_tokenized_timer(self):
        class Stdin(io.BytesIO):
            def close(self):
                self.closed_by_app = True

        owner_stdin = Stdin()
        owner_stdin.closed_by_app = False

        class Owner:
            pid = 42
            stdin = owner_stdin

            @staticmethod
            def poll():
                return None

            @staticmethod
            def terminate():
                pass

        calls = []

        def popen(*args, **kwargs):
            calls.append((args, kwargs))
            return Owner()

        class Store:
            @staticmethod
            def all():
                return [Credential("example.com", "alice", "secret")]

        args = mock.Mock(id="example.com\x1falice", field="password", seconds=30)
        with mock.patch.object(appapi, "_app_session_ok", return_value=True), \
             mock.patch.object(appapi, "_elevate", return_value=True), \
             mock.patch.object(appapi, "load_vault", return_value=Store()), \
             mock.patch("shutil.which", return_value="/usr/bin/wl-copy"), \
             mock.patch.object(appapi, "_clear_clipboard_owner", return_value=True), \
             mock.patch.object(appapi, "_write_clipboard_owner", return_value=True), \
             mock.patch("subprocess.Popen", side_effect=popen):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(appapi.cmd_app_copy(args), 0)
        result = json.loads(out.getvalue())
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 2)
        owner_args, owner_kwargs = calls[0]
        self.assertEqual(owner_args[0], ["/usr/bin/wl-copy", "--foreground"])
        self.assertTrue(owner_kwargs["start_new_session"])
        self.assertEqual(owner_stdin.getvalue(), b"secret")
        self.assertTrue(owner_stdin.closed_by_app)
        timer_args, _ = calls[1]
        self.assertNotIn("sh", timer_args[0])
        self.assertEqual(timer_args[0][2:5], ["icp", "app-clipboard-clear", "--token"])
        self.assertEqual(timer_args[0][6:], ["--delay", "30"])

    def test_delayed_clear_passes_ownership_token(self):
        with mock.patch.object(appapi.time, "sleep") as sleep, \
             mock.patch.object(appapi, "_clear_clipboard_owner", return_value=True) as clear:
            self.assertEqual(appapi.cmd_app_clipboard_clear(
                mock.Mock(token="token", delay=30)), 0)
        sleep.assert_called_once_with(30)
        clear.assert_called_once_with("token")


if __name__ == "__main__":
    unittest.main()
