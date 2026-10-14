"""A malformed message from another client, on a real dbus-broker (the bus Omarchy runs).

Any client may send any connection a signal, and dbus-broker passes on header fields it does not
know, as the spec allows. jeepney 0.9 raises ValueError on them, which ended the thread that
receives for a router: one signal from any local user, and the daemon stopped hearing logind
lock the screen or announce sleep. Here an attacker sends the receiving connection a signal with
header field 10, then a well-formed one. jeepney's own router stops; dbus_safe.Router drops the
bad message, still receives the next one and still completes a call.
"""

import os
import queue
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from jeepney import HeaderFields, MatchRule
from jeepney.bus_messages import message_bus

BROKER_LAUNCH = shutil.which("dbus-broker-launch")
SOCKET_ACTIVATE = shutil.which("systemd-socket-activate")
DBUS_DAEMON = shutil.which("dbus-daemon")

POLICY = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow send_type="method_call" send_destination="org.freedesktop.DBus"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
</busconfig>
"""


def raw_signal(fields, serial):
    """A little-endian signal built by hand, so it can carry a header field jeepney would not
    send: `fields` is [(code, (signature, value))]."""
    from jeepney.low_level import Endianness, _header_fields_type, padding
    head = struct.pack("<cBBBII", b"l", 4, 0, 1, 0, serial)
    head += _header_fields_type.serialise(fields, 12, Endianness.little)
    return head + b"\0" * padding(len(head), 8)


class Attacker:
    """A hand-rolled client: authenticate, say Hello, then write raw bytes."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.sock.sendall(b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode()
                          + b"\r\n")
        if not self.sock.recv(4096).startswith(b"OK"):
            raise ConnectionError("the bus refused EXTERNAL")
        self.sock.sendall(b"BEGIN\r\n" + message_bus.Hello().serialise(serial=1))
        self.serial = 1

    def signal(self, dest, path, extra=()):
        self.serial += 1
        fields = [(1, ("o", path)), (2, ("s", "org.example.Test")), (3, ("s", "Ping")),
                  (6, ("s", dest)), *extra]
        self.sock.sendall(raw_signal(fields, self.serial))

    def close(self):
        self.sock.close()


@unittest.skipUnless(BROKER_LAUNCH and SOCKET_ACTIVATE and DBUS_DAEMON,
                     "dbus-broker-launch, systemd-socket-activate or dbus-daemon is missing")
class MalformedMessageOnDbusBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        conf = os.path.join(d, "bus.conf")
        with open(conf, "w") as f:
            f.write(POLICY)
        # dbus-broker-launch --scope user wants a session bus of its own to talk to.
        parent = os.path.join(d, "parent")
        self.parent = subprocess.Popen([DBUS_DAEMON, "--session", "--nofork", "--nopidfile",
                                        f"--address=unix:path={parent}"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (self.parent.kill(), self.parent.wait(5)))
        self.wait_for(parent)
        self.path = os.path.join(d, "bus")
        self.broker = subprocess.Popen(
            [SOCKET_ACTIVATE, "-E", f"DBUS_SESSION_BUS_ADDRESS=unix:path={parent}",
             "-E", f"XDG_RUNTIME_DIR={d}", "-l", self.path,
             BROKER_LAUNCH, "--scope", "user", "--config-file", conf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(self.stop_broker)
        self.wait_for(self.path)

    def stop_broker(self):
        try:
            os.killpg(self.broker.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.broker.wait(5)

    @staticmethod
    def wait_for(path):
        deadline = time.monotonic() + 5
        while not os.path.exists(path) and time.monotonic() < deadline:
            time.sleep(0.02)

    def connect(self):
        from jeepney.io.threading import open_dbus_connection
        conn = open_dbus_connection(f"unix:path={self.path}", enable_fds=True)
        self.addCleanup(conn.close)
        return conn

    def attack(self, conn):
        """Header field 10 on a directed signal, then a well-formed one."""
        attacker = Attacker(self.path)
        self.addCleanup(attacker.close)
        attacker.signal(conn.unique_name, "/bad", extra=[(10, ("s", "boo"))])
        attacker.signal(conn.unique_name, "/ok")

    def test_jeepneys_router_stops_receiving(self):
        # The attack is real: this is what logind's watcher ran on in 2.0.0.
        from jeepney.io.threading import DBusRouter
        crashed = []
        old_hook = threading.excepthook
        threading.excepthook = lambda args: crashed.append(args.exc_type)
        self.addCleanup(setattr, threading, "excepthook", old_hook)
        router = DBusRouter(self.connect())
        self.addCleanup(router.close)
        q = queue.Queue()
        router.filter(MatchRule(type="signal", member="Ping"), queue=q)
        self.attack(router.conn)
        with self.assertRaises(queue.Empty):
            q.get(timeout=2)
        self.assertEqual(crashed, [ValueError])        # "10 is not a valid HeaderFields"
        with self.assertRaises(Exception):
            router.send_and_get_reply(message_bus.GetId(), timeout=2)

    def test_the_safe_router_drops_it_and_carries_on(self):
        from icp.dbus_safe import Router
        router = Router(self.connect())
        self.addCleanup(router.close)
        q = queue.Queue()
        router.filter(MatchRule(type="signal", member="Ping"), queue=q)
        with self.assertLogs("icp.dbus_safe", "WARNING") as logs:
            self.attack(router.conn)
            got = q.get(timeout=5)
        self.assertIn("dropped a D-Bus message that could not be parsed", "\n".join(logs.output))
        self.assertEqual(got.header.fields[HeaderFields.path], "/ok")
        self.assertTrue(router.call(message_bus.GetId(), timeout=5).body[0])


if __name__ == "__main__":
    unittest.main()
