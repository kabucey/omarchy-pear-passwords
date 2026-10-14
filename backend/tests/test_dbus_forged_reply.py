"""A forged polkit approval on a real D-Bus bus (HANCORE-linux, #10755).

jeepney 0.9 hands a waiting call any message whose REPLY_SERIAL matches, a directed signal from
any client included, and serials count up from 1. Here, on a private dbus-daemon: a fake polkitd
takes half a second and answers "denied", while an attacker connection sprays directed signals
with every small reply serial and an "authorized" body at the checking connection.

Two layers stop it, and each is tested on its own. jeepney's own router hands the check the
forged signal (the attack is real: 2.0.0 read it as "authorized"), and the polkit check now
refuses anything but a method return. dbus_safe.Router never hands it over at all and returns
polkitd's real "denied".
"""

import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

from jeepney import HeaderFields, MessageType

from icp.daemon import polkit

DBUS_DAEMON = shutil.which("dbus-daemon")
CHECK_REPLY = "(bba{ss})"


def _connect(address):
    from jeepney.io.threading import open_dbus_connection
    return open_dbus_connection(address, enable_fds=True)


class FakePolkitd(threading.Thread):
    """Owns org.freedesktop.PolicyKit1 and answers every CheckAuthorization "denied" after a
    delay, from its own connection."""

    def __init__(self, address, delay=0.5):
        super().__init__(daemon=True)
        from jeepney.bus_messages import message_bus
        from jeepney.io.blocking import open_dbus_connection
        self.conn = open_dbus_connection(address)
        self.conn.send_and_get_reply(message_bus.RequestName(polkit.AUTHORITY_BUS_NAME))
        self.delay = delay
        self.stop = False

    def run(self):
        from jeepney import MessageType, new_method_return
        while not self.stop:
            try:
                msg = self.conn.receive(timeout=0.2)
            except TimeoutError:
                continue
            except Exception:
                return
            if msg.header.message_type != MessageType.method_call:
                continue
            time.sleep(self.delay)
            self.conn.send(new_method_return(msg, CHECK_REPLY, ((False, True, {}),)))


def spray(address, victim, stop_at):
    """Directed signals to `victim` with REPLY_SERIAL 1..60, each claiming "authorized"."""
    from jeepney import HeaderFields, new_signal, DBusAddress
    from jeepney.io.blocking import open_dbus_connection
    conn = open_dbus_connection(address)
    src = DBusAddress("/forged", interface="org.example.Forged")
    while time.monotonic() < stop_at:
        for serial in range(1, 61):
            sig = new_signal(src, "Approved", CHECK_REPLY, ((True, False, {}),))
            sig.header.fields[HeaderFields.destination] = victim
            sig.header.fields[HeaderFields.reply_serial] = serial
            try:
                conn.send(sig)
            except Exception:
                return
        time.sleep(0.02)
    conn.close()


class _Bus:
    def __init__(self, router):
        self.router = router
        self.replies = []

    def call(self, msg, timeout=None):
        reply = self.router.send_and_get_reply(msg, timeout=timeout)
        self.replies.append(reply)
        return reply


@unittest.skipUnless(DBUS_DAEMON, "dbus-daemon is not installed")
class ForgedReplyOnARealBusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        sock = os.path.join(self.tmp.name, "bus")
        self.address = f"unix:path={sock}"
        self.bus = subprocess.Popen([DBUS_DAEMON, "--session", "--nofork", "--nopidfile",
                                     f"--address={self.address}"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (self.bus.kill(), self.bus.wait(5)))
        deadline = time.monotonic() + 5
        while not os.path.exists(sock) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.polkitd = FakePolkitd(self.address)
        self.polkitd.start()
        self.addCleanup(setattr, self.polkitd, "stop", True)

    def check_through(self, router):
        """(outcome, the one reply the check was handed)."""
        subject = polkit.Subject(pid=os.getpid(), pidfd=-1, uid=os.getuid(), start_time=1)
        bus = _Bus(router)
        auth = polkit.Authority(bus=bus, mode=polkit.SUBJECT_PID_START_TIME)
        attacker = threading.Thread(target=spray, args=(self.address, router.conn.unique_name,
                                                         time.monotonic() + 0.9), daemon=True)
        attacker.start()
        try:
            outcome = auth.check(subject, "io.github.dragosol.pearpasswords.autofill", {},
                                 "pear-test")
        finally:
            attacker.join(5)
        self.assertEqual(len(bus.replies), 1)
        return outcome, bus.replies[0]

    def test_jeepneys_router_hands_over_the_forgery_and_the_check_refuses_it(self):
        from jeepney.io.threading import DBusRouter
        conn = _connect(self.address)
        router = DBusRouter(conn)
        self.addCleanup(conn.close)
        self.addCleanup(router.close)
        with self.assertLogs("icp.daemon.polkit", "ERROR"):
            outcome, reply = self.check_through(router)
        # The attack is real: the check is handed the attacker's signal as its reply, which
        # 2.0.0 at 30ec0f1 read as "authorized".
        self.assertEqual(reply.header.message_type, MessageType.signal)
        self.assertEqual(reply.body, ((True, False, {}),))
        # The second layer: only a method return is an answer.
        self.assertEqual(outcome, polkit.INTERNAL)

    def test_the_safe_router_ignores_it_and_returns_polkitds_answer(self):
        from icp.dbus_safe import Router
        conn = _connect(self.address)
        router = Router(conn)
        self.addCleanup(conn.close)
        self.addCleanup(router.close)
        outcome, reply = self.check_through(router)
        self.assertEqual(reply.header.message_type, MessageType.method_return)
        self.assertEqual(reply.header.fields[HeaderFields.sender],
                         router.owner(polkit.AUTHORITY_BUS_NAME))
        self.assertEqual(outcome, polkit.DENIED)


if __name__ == "__main__":
    unittest.main()
