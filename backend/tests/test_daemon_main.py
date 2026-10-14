"""Startup checks of pear-passwordsd (daemon/__main__.py): the pear-client group must have no
members, the socket must come from systemd, and sd_notify reaches $NOTIFY_SOCKET."""

import os
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from icp.daemon import __main__ as main


class StartupTests(unittest.TestCase):
    def test_client_group_must_have_no_members(self):
        ok = lambda name: SimpleNamespace(gr_gid=966, gr_mem=[])          # noqa: E731
        self.assertEqual(main.client_group_gid(ok), 966)
        with self.assertRaises(SystemExit) as cm:
            main.client_group_gid(lambda name: SimpleNamespace(gr_gid=966, gr_mem=["eve"]))
        self.assertIn("eve", str(cm.exception))

        def missing(name):
            raise KeyError(name)
        with self.assertRaises(SystemExit):
            main.client_group_gid(missing)

    def test_listen_socket_only_for_this_pid(self):
        self.assertIsNone(main.listen_socket({}))
        self.assertIsNone(main.listen_socket({"LISTEN_PID": str(os.getpid() + 1),
                                              "LISTEN_FDS": "1"}))
        self.assertIsNone(main.listen_socket({"LISTEN_PID": str(os.getpid()),
                                              "LISTEN_FDS": "0"}))
        self.assertIsNone(main.listen_socket({"LISTEN_PID": "x", "LISTEN_FDS": "1"}))

    def test_sd_notify(self):
        d = tempfile.mkdtemp(prefix="pearnotify-")
        path = os.path.join(d, "n")
        rx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        rx.bind(path)
        try:
            with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
                self.assertTrue(main.sd_notify("READY=1"))
            self.assertEqual(rx.recv(64), b"READY=1")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertFalse(main.sd_notify("READY=1"))
        finally:
            rx.close()
            os.unlink(path)
            os.rmdir(d)

    def test_watchdog_interval(self):
        with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "60000000",
                                          "WATCHDOG_PID": str(os.getpid())}):
            self.assertEqual(main._watchdog_interval(), 30.0)
        with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "1"}):
            self.assertIsNone(main._watchdog_interval())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(main._watchdog_interval())

    def test_main_refuses_without_systemd_socket(self):
        with mock.patch.object(main, "client_group_gid", lambda: 966), \
                mock.patch.object(main, "_harden_process", lambda: None), \
                mock.patch.dict(os.environ, {}, clear=True), \
                self.assertLogs("pear-passwordsd", "ERROR"):
            self.assertEqual(main.main([]), 1)


if __name__ == "__main__":
    unittest.main()


class ServerSocketTests(unittest.TestCase):
    def test_closing_the_server_leaves_systemds_socket_file(self):
        # Gate bug 4: on Python 3.13+ start_unix_server(sock=...) unlinks the path on close.
        # The file is systemd's (socket activation); the daemon must never remove it.
        import asyncio
        from icp.daemon.server import Server
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "client.sock")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(path)
            sock.listen()

            async def run():
                srv = await Server(object(), verify_peer=lambda s: None).start(sock)
                srv.close()
                await srv.wait_closed()
            asyncio.run(run())
            self.assertTrue(os.path.exists(path), "the server unlinked the activation socket")
