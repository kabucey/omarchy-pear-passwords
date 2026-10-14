"""The native-messaging host (client/autofill.py): framing, translation, and what it refuses.

The host sits between an extension nobody reviewed and the daemon. These tests check that it
frames messages the way browsers do, rebuilds every request from the two fields the daemon
needs (so no other op or field can be smuggled through), forwards only the state event, and
fails closed: an oversized frame ends the session, a lost daemon fails every pending request.
"""

import json
import os
import socket
import struct
import tempfile
import threading
import unittest

from icp.client import autofill as host
from icp.daemon import protocol


def frame(obj) -> bytes:
    data = json.dumps(obj).encode()
    return struct.pack("=I", len(data)) + data


def read_exact(fd, n, timeout=5.0):
    import select
    buf = b""
    while len(buf) < n:
        r, _, _ = select.select([fd], [], [], timeout)
        if not r:
            raise TimeoutError("host did not answer")
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def read_msg(fd):
    (n,) = struct.unpack("=I", read_exact(fd, 4))
    return json.loads(read_exact(fd, n))


class FramingTests(unittest.TestCase):
    def test_round_trip_native_order(self):
        msg = {"rid": 1, "op": "query", "origin": "https://github.com", "ü": "ok"}
        data = host.encode_message(msg)
        self.assertEqual(struct.unpack("=I", data[:4])[0], len(data) - 4)
        self.assertEqual(host.NativeReader().feed(data), [msg])

    def test_reader_handles_any_split(self):
        data = frame({"a": 1}) + frame({"b": 2}) + frame({"c": 3})
        r, out = host.NativeReader(), []
        for i in range(len(data)):
            out += r.feed(data[i:i + 1])
        self.assertEqual(out, [{"a": 1}, {"b": 2}, {"c": 3}])

    def test_non_objects_are_bad(self):
        bad = [b"[1,2]", b"\"x\"", b"nul", b"\xff\xfe", b"{\"a\":"]
        out = host.NativeReader().feed(b"".join(struct.pack("=I", len(b)) + b for b in bad))
        self.assertEqual(out, [host._BAD] * len(bad))

    def test_oversized_frame_is_fatal(self):
        with self.assertRaises(host.FrameError):
            host.NativeReader().feed(struct.pack("=I", host.NATIVE_IN_MAX + 1) + b"{}")
        with self.assertRaises(host.FrameError):
            host.NativeReader().feed(struct.pack("=I", 0xFFFFFFFF))

    def test_outgoing_limit(self):
        with self.assertRaises(host.FrameError):
            host.encode_message({"x": "a" * host.NATIVE_OUT_MAX})

    def test_daemon_lines(self):
        r = host.LineReader(limit=64)
        self.assertEqual(r.feed(b'{"rid":1}\n{"ev'), [{"rid": 1}])
        self.assertEqual(r.feed(b'ent":"state"}\n[1]\n'), [{"event": "state"}])
        with self.assertRaises(host.FrameError):
            r.feed(b"x" * 80)
        with self.assertRaises(host.FrameError):
            host.LineReader().feed(b"not json\n")


class HostHarness(unittest.TestCase):
    """A Host on pipes, with the daemon end of a socketpair in the test's hand."""

    hello_state = "unlocked"
    refuse = None

    def setUp(self):
        self.in_r, self.in_w = os.pipe()
        self.out_r, self.out_w = os.pipe()
        self.daemon = None
        self.connects = 0

        def connect():
            self.connects += 1
            if self.refuse:
                raise host.DaemonUnavailable(self.refuse)
            a, b = socket.socketpair()
            self.daemon = b
            self.daemon_reader = host.LineReader()
            return a, {"rid": 0, "proto": 2, "version": "2.0.0", "state": self.hello_state}

        self.host = host.Host(self.in_r, self.out_w, connect=connect)
        self.rc = None

        def run():
            self.rc = self.host.run()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def tearDown(self):
        for fd in (self.in_w, self.out_r):
            try:
                os.close(fd)
            except OSError:
                pass
        self.thread.join(5)
        for fd in (self.in_r, self.out_w):
            try:
                os.close(fd)
            except OSError:
                pass
        if self.daemon:
            self.daemon.close()

    def send(self, obj):
        os.write(self.in_w, frame(obj) if isinstance(obj, dict) else obj)

    def recv(self):
        return read_msg(self.out_r)

    def daemon_recv(self):
        self.daemon.settimeout(5)
        while True:
            got = self.daemon_reader.feed(self.daemon.recv(65536))
            if got:
                self.assertEqual(len(got), 1)
                return got[0]

    def daemon_send(self, obj):
        self.daemon.sendall(json.dumps(obj).encode() + b"\n")

    def finish(self):
        os.close(self.in_w)
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())
        return self.rc


class TranslationTests(HostHarness):
    def test_query_is_rebuilt_from_scratch(self):
        self.send({"op": "query", "rid": 7, "origin": "https://github.com",
                   "id": "smuggled", "role": "ui", "all": True, "ticket": "x"})
        self.assertEqual(self.recv(), {"event": "state", "state": "unlocked"})
        req = self.daemon_recv()
        self.assertEqual(set(req), {"op", "rid", "origin"})
        self.assertEqual(req["op"], "autofill-query")
        self.assertEqual(req["origin"], "https://github.com")
        self.daemon_send({"rid": req["rid"], "state": "unlocked", "host": "github.com",
                          "accounts": []})
        self.assertEqual(self.recv(), {"rid": 7, "state": "unlocked", "host": "github.com",
                                       "accounts": []})

    def test_names_carries_the_origin_only(self):
        self.send({"op": "names", "rid": 4, "origin": "https://github.com", "id": "gh1",
                   "all": True})
        self.recv()                                              # state event
        req = self.daemon_recv()
        self.assertEqual({k: v for k, v in req.items() if k != "rid"},
                         {"op": "autofill-names", "origin": "https://github.com"})
        self.daemon_send({"rid": req["rid"], "error": "dismissed"})
        self.assertEqual(self.recv(), {"rid": 4, "error": "dismissed"})

    def test_fill_carries_origin_and_id_only(self):
        self.send({"op": "fill", "rid": 3, "origin": "https://github.com", "id": "gh1",
                   "password": "x", "op2": "unlock"})
        self.recv()                                              # state event
        req = self.daemon_recv()
        self.assertEqual({k: v for k, v in req.items() if k != "rid"},
                         {"op": "autofill-fill", "origin": "https://github.com", "id": "gh1"})
        self.daemon_send({"rid": req["rid"], "error": "dismissed"})
        self.assertEqual(self.recv(), {"rid": 3, "error": "dismissed"})

    def test_no_other_daemon_op_is_reachable(self):
        for op in ("unlock", "grant", "reveal", "copy", "autofill-fill", "autofill-query",
                   "autofill-names", "hello", "redeem", "import-key", None, 5):
            self.send({"op": op, "rid": 1, "origin": "https://github.com", "id": "gh1"})
            self.assertEqual(self.recv(), {"rid": 1, "error": "unknown-op"}, op)
        self.assertIsNone(self.daemon)                           # never even connected

    def test_malformed_requests(self):
        cases = [({"op": "fill", "rid": 1, "origin": "https://github.com"}, "id"),
                 ({"op": "fill", "rid": 1, "origin": "https://a.b", "id": 5}, "id"),
                 ({"op": "fill", "rid": 1, "origin": "https://a.b", "id": "x" * 200}, "id"),
                 ({"op": "query", "rid": 1}, "origin"),
                 ({"op": "query", "rid": 1, "origin": ""}, "origin"),
                 ({"op": "query", "rid": 1, "origin": "x" * 5000}, "origin")]
        for msg, field in cases:
            self.send(msg)
            self.assertEqual(self.recv(), {"rid": 1, "error": "bad-request", "field": field})
        for rid in (True, -1, "1", 1.5, None, 2**53):
            self.send({"op": "query", "rid": rid, "origin": "https://a.b"})
            self.assertEqual(self.recv(), {"rid": None, "error": "bad-request", "field": "rid"})
        self.send(struct.pack("=I", 3) + b"[1]")
        self.assertEqual(self.recv(), {"rid": None, "error": "bad-request"})
        self.assertIsNone(self.daemon)

    def test_only_state_events_reach_the_browser(self):
        self.send({"op": "status", "rid": 1})
        self.assertEqual(self.recv(), {"event": "state", "state": "unlocked"})
        self.assertEqual(self.recv(), {"rid": 1, "state": "unlocked", "version": host.VERSION})
        self.daemon_send({"event": "withdraw"})
        self.daemon_send({"event": "autofill", "id": "gh1", "outcome": "filled"})
        self.daemon_send({"event": "state", "state": "bogus"})
        self.daemon_send({"rid": 999, "password": "stray"})       # unknown rid: dropped
        self.daemon_send({"event": "state", "state": "locked"})
        self.assertEqual(self.recv(), {"event": "state", "state": "locked"})
        self.send({"op": "status", "rid": 2})
        self.assertEqual(self.recv(), {"rid": 2, "state": "locked", "version": host.VERSION})

    def test_daemon_loss_fails_pending_requests(self):
        self.send({"op": "fill", "rid": 4, "origin": "https://github.com", "id": "gh1"})
        self.recv()
        self.daemon_recv()
        self.daemon.close()
        self.daemon = None
        self.assertEqual(self.recv(), {"rid": 4, "error": "no-daemon"})
        self.assertEqual(self.recv(), {"event": "state", "state": "unavailable"})

    def test_pending_cap(self):
        for i in range(host.MAX_PENDING + 1):
            self.send({"op": "query", "rid": i, "origin": "https://github.com"})
        self.recv()                                              # state event
        self.assertEqual(self.recv(), {"rid": host.MAX_PENDING, "error": "too-many"})

    def test_eof_ends_the_session(self):
        self.send({"op": "status", "rid": 1})
        self.recv(), self.recv()
        self.assertEqual(self.finish(), 0)
        self.daemon.settimeout(5)
        self.assertEqual(self.daemon.recv(10), b"")              # the host hung up too

    def test_oversized_frame_ends_the_session(self):
        self.send(struct.pack("=I", host.NATIVE_IN_MAX + 1) + b"{")
        self.assertEqual(self.recv(), {"rid": None, "error": "too-large"})
        self.thread.join(5)
        self.assertEqual(self.rc, 2)

    def test_oversized_reply_becomes_an_error(self):
        self.send({"op": "query", "rid": 9, "origin": "https://github.com"})
        self.recv()
        req = self.daemon_recv()
        self.daemon_send({"rid": req["rid"], "state": "unlocked", "pad": "a" * (2 << 20)})
        self.assertEqual(self.recv(), {"rid": 9, "error": "too-large"})


class NoDaemonTests(HostHarness):
    refuse = "connect"

    def test_requests_answer_no_daemon(self):
        self.send({"op": "status", "rid": 1})
        self.assertEqual(self.recv(), {"rid": 1, "error": "no-daemon"})
        self.send({"op": "query", "rid": 2, "origin": "https://github.com"})
        self.assertEqual(self.recv(), {"rid": 2, "error": "no-daemon"})
        self.assertEqual(self.connects, 1)                       # reconnects are spaced out


class TooManyTests(HostHarness):
    refuse = "too-many"

    def test_the_daemon_refusal_is_passed_on(self):
        self.send({"op": "query", "rid": 2, "origin": "https://github.com"})
        self.assertEqual(self.recv(), {"rid": 2, "error": "too-many"})


class DisabledTests(HostHarness):
    refuse = "forbidden"

    def test_autofill_switched_off_in_the_window_says_so(self):
        # escape-autofill-role-ungated: the daemon refuses the role until it is turned on.
        self.send({"op": "query", "rid": 2, "origin": "https://github.com"})
        self.assertEqual(self.recv(), {"rid": 2, "error": "disabled"})
        self.assertIn("disabled", host.HOST_ERRORS)


class ConnectTests(unittest.TestCase):
    def serve(self, reply):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, "s")
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(path)
        srv.listen(1)
        seen = {}

        def accept():
            c, _ = srv.accept()
            seen["hello"] = json.loads(c.makefile().readline())
            c.sendall(json.dumps(reply).encode() + b"\n")
            seen["conn"] = c
        t = threading.Thread(target=accept, daemon=True)
        t.start()
        self.addCleanup(srv.close)
        return path, seen, t

    def test_hello_as_autofill(self):
        path, seen, t = self.serve({"rid": 0, "proto": 2, "state": "locked"})
        s, hello = host.connect_daemon(path)
        t.join(5)
        s.close()
        seen["conn"].close()
        self.assertEqual(seen["hello"], {"op": "hello", "rid": 0, "role": "autofill",
                                         "proto": protocol.PROTO})
        self.assertEqual(hello["state"], "locked")

    def test_refused_hello(self):
        path, seen, t = self.serve({"rid": 0, "error": "too-many"})
        with self.assertRaises(host.DaemonUnavailable) as cm:
            host.connect_daemon(path)
        t.join(5)
        seen["conn"].close()
        self.assertEqual(cm.exception.args[0], "too-many")

    def test_no_socket(self):
        with self.assertRaises(host.DaemonUnavailable):
            host.connect_daemon("/nonexistent/pear/client.sock")


class ImportTests(unittest.TestCase):
    def test_host_imports_nothing_heavy(self):
        import subprocess
        import sys
        backend = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = ("import sys, icp.client.autofill; "
                "bad = [m for m in ('jeepney', 'icp.vstore', 'icp.daemon.apple', "
                "'icp.daemon.autofill', 'nacl', 'requests') if m in sys.modules]; "
                "print(','.join(bad))")
        env = dict(os.environ, PYTHONPATH=backend, PYTHONDONTWRITEBYTECODE="1")
        out = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, "
                              + repr(backend) + "); " + code], env=env, capture_output=True,
                             text=True, check=True)
        self.assertEqual(out.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
