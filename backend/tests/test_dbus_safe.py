"""dbus_safe: a reply counts only if it is a METHOD_RETURN or ERROR, answers our serial, and
comes from the unique name that owns the destination (#10755). These cover what a real bus
rarely lets a client produce; test_dbus_forged_reply.py runs the signal attack on a real bus."""

import itertools
import os
import queue
import struct
import threading
import unittest
from unittest import mock

from jeepney import DBusAddress, HeaderFields, MessageType, new_method_call

from icp import dbus_safe

POLKIT = ":1.7"
ATTACKER = ":1.66"
ADDR = DBusAddress("/org/freedesktop/PolicyKit1/Authority", bus_name="org.freedesktop.PolicyKit1",
                   interface="org.freedesktop.PolicyKit1.Authority")


def message(mtype, *, serial, sender, body=()):
    m = mock.Mock()
    m.header.message_type = mtype
    m.header.fields = {HeaderFields.reply_serial: serial, HeaderFields.sender: sender}
    m.body = body
    return m


class FakeConn:
    """A blocking connection whose incoming messages are scripted per sent serial."""

    def __init__(self, script):
        self.outgoing_serial = itertools.count(1)
        self.script = script          # f(serial, msg) -> list of messages to deliver
        self.inbox = []

    def send(self, msg, serial=None):
        self.inbox.extend(self.script(serial, msg))

    def receive(self, timeout=None):
        if not self.inbox:
            raise TimeoutError
        return self.inbox.pop(0)


def owner_then(answers):
    """The driver names POLKIT as the owner; then `answers(serial)` follow the real call."""
    def script(serial, msg):
        if msg.header.fields.get(HeaderFields.member) == "GetNameOwner":
            return [message(MessageType.method_return, serial=serial, sender=dbus_safe.DRIVER,
                            body=(POLKIT,))]
        return answers(serial)
    return script


class CallBlockingTests(unittest.TestCase):
    def call(self, script):
        return dbus_safe.call_blocking(FakeConn(script),
                                       new_method_call(ADDR, "CheckAuthorization"), timeout=1)

    def test_a_forged_signal_and_a_stranger_s_reply_are_skipped(self):
        real = message(MessageType.method_return, serial=2, sender=POLKIT, body=("denied",))
        reply = self.call(owner_then(lambda s: [
            message(MessageType.signal, serial=s, sender=ATTACKER, body=("authorized",)),
            message(MessageType.method_return, serial=s, sender=ATTACKER, body=("authorized",)),
            message(MessageType.method_return, serial=s + 7, sender=POLKIT, body=("other",)),
            real]))
        self.assertIs(reply, real)

    def test_an_error_from_the_owner_is_the_reply(self):
        err = message(MessageType.error, serial=2, sender=POLKIT)
        self.assertIs(self.call(owner_then(lambda s: [err])), err)

    def test_only_forgeries_mean_no_reply(self):
        with self.assertRaises(TimeoutError):
            self.call(owner_then(lambda s: [
                message(MessageType.signal, serial=s, sender=ATTACKER, body=("authorized",))]))

    def test_a_signal_from_the_owner_itself_is_not_the_reply(self):
        # The type rule on its own: right sender, right serial, but a signal.
        real = message(MessageType.method_return, serial=2, sender=POLKIT, body=("denied",))
        reply = self.call(owner_then(lambda s: [
            message(MessageType.signal, serial=s, sender=POLKIT, body=("authorized",)),
            real]))
        self.assertIs(reply, real)

    def test_the_owner_lookup_itself_comes_only_from_the_driver(self):
        # An attacker answering GetNameOwner with its own name would then be "the owner".
        def script(serial, msg):
            if msg.header.fields.get(HeaderFields.member) == "GetNameOwner":
                return [message(MessageType.signal, serial=serial, sender=ATTACKER,
                                body=(ATTACKER,)),
                        message(MessageType.method_return, serial=serial,
                                sender=dbus_safe.DRIVER, body=(POLKIT,))]
            return [message(MessageType.method_return, serial=serial, sender=ATTACKER,
                            body=("authorized",)),
                    message(MessageType.method_return, serial=serial, sender=POLKIT,
                            body=("denied",))]
        reply = self.call(script)
        self.assertEqual(reply.body, ("denied",))


class RouterDispatchTests(unittest.TestCase):
    def test_dispatch_resolves_only_the_right_reply(self):
        router = dbus_safe.Router.__new__(dbus_safe.Router)
        from concurrent.futures import Future
        router._lock = threading.Lock()
        router._filters = []
        fut = Future()
        router._pending = {5: (POLKIT, fut)}
        router._dispatch(message(MessageType.signal, serial=5, sender=ATTACKER))
        router._dispatch(message(MessageType.method_return, serial=5, sender=ATTACKER))
        router._dispatch(message(MessageType.signal, serial=5, sender=POLKIT))
        self.assertFalse(fut.done())
        real = message(MessageType.method_return, serial=5, sender=POLKIT)
        router._dispatch(real)
        self.assertIs(fut.result(timeout=0), real)


def raw(mtype, fields, *, sig="", body=b"", serial=1):
    """A little-endian message built by hand, so it can carry what jeepney would not send:
    `fields` is [(code, (signature, value))]."""
    from jeepney.low_level import Endianness, _header_fields_type, padding
    if sig:
        fields = [*fields, (8, ("g", sig))]
    head = struct.pack("<cBBBII", b"l", mtype, 0, 1, len(body), serial)
    head += _header_fields_type.serialise(fields, 12, Endianness.little)
    return head + b"\0" * padding(len(head), 8) + body


SIGNAL_FIELDS = [(1, ("o", "/x")), (2, ("s", "org.example.T")), (3, ("s", "Ping")),
                 (7, ("s", ATTACKER))]
UNKNOWN_FIELD = raw(4, [*SIGNAL_FIELDS, (10, ("s", "boo"))])
NOT_UTF8 = raw(4, SIGNAL_FIELDS, sig="s", body=struct.pack("<I", 3) + b"\xff\xfe\xfd\0")
GOOD = raw(4, [(1, ("o", "/ok")), (2, ("s", "org.example.T")), (3, ("s", "Ping"))], serial=2)


class TolerantParserTests(unittest.TestCase):
    def parse_all(self, parser, chunks, fds=()):
        out = []
        for i, chunk in enumerate(chunks):
            parser.add_data(chunk, fds=fds if i == 0 else ())
            out.extend(iter(parser.get_next_message, None))
        return out

    def test_jeepneys_parser_breaks_on_these(self):
        # What the tolerant parser is for: jeepney raises, and stays misaligned after.
        from jeepney.low_level import Parser
        for bad in (UNKNOWN_FIELD, NOT_UTF8):
            parser = Parser()
            parser.add_data(bad + GOOD)
            with self.assertRaises(ValueError):
                parser.get_next_message()
            self.assertIsNotNone(parser.next_msg_size)

    def test_a_message_it_cannot_parse_is_dropped_and_the_next_one_arrives(self):
        for bad in (UNKNOWN_FIELD, NOT_UTF8):
            stream = bad + GOOD + bad + GOOD
            for chunks in ([stream], [stream[i:i + 1] for i in range(len(stream))]):
                with self.assertLogs("icp.dbus_safe", "WARNING"):
                    msgs = self.parse_all(dbus_safe._TolerantParser(), chunks)
                self.assertEqual([m.header.fields[HeaderFields.path] for m in msgs],
                                 ["/ok", "/ok"])

    def test_the_bad_message_s_file_descriptors_are_closed(self):
        from jeepney.fds import FileDescriptor
        r, w = os.pipe()
        self.addCleanup(os.close, w)
        fd = FileDescriptor(r)
        bad = raw(4, [*SIGNAL_FIELDS, (9, ("u", 1)), (10, ("s", "boo"))])
        parser = dbus_safe._TolerantParser()
        with self.assertLogs("icp.dbus_safe", "WARNING"):
            msgs = self.parse_all(parser, [bad, GOOD], fds=[fd])
        self.assertEqual(len(msgs), 1)
        self.assertEqual(parser.fds, [])
        self.assertEqual(repr(fd), "<FileDescriptor (closed)>")

    def test_tolerant_carries_on_from_what_the_connection_already_buffered(self):
        from jeepney.low_level import Parser
        conn = mock.Mock()
        conn.parser = Parser()
        conn.parser.add_data(GOOD[:20])
        conn.parser.get_next_message()                 # sizes the message, keeps 20 bytes
        dbus_safe.tolerant(conn)
        dbus_safe.tolerant(conn)                       # a second call changes nothing
        self.assertIsInstance(conn.parser, dbus_safe._TolerantParser)
        conn.parser.add_data(GOOD[20:] + UNKNOWN_FIELD + GOOD)
        with self.assertLogs("icp.dbus_safe", "WARNING"):
            msgs = list(iter(conn.parser.get_next_message, None))
        self.assertEqual(len(msgs), 2)


class RouterReceiverTests(unittest.TestCase):
    def test_a_message_that_breaks_handling_does_not_stop_the_receiver(self):
        from jeepney import MatchRule, Parser
        from jeepney.io.threading import ReceiveStopped
        inbox = queue.Queue()

        class Conn:
            unique_name = ":1.9"
            outgoing_serial = itertools.count(1)

            def receive(self):
                msg = inbox.get(timeout=10)
                if msg is None:
                    raise ReceiveStopped
                return msg

            def interrupt(self):
                inbox.put(None)

            def reset_interrupt(self):
                pass

        class Exploding:
            calls = 0

            def matches(self, msg):
                Exploding.calls += 1
                if Exploding.calls == 1:
                    raise ValueError("odd message")
                return False

        parser = Parser()
        parser.add_data(GOOD)
        good = parser.get_next_message()
        router = dbus_safe.Router(Conn())
        q = queue.Queue()
        router.filter(Exploding(), queue=queue.Queue())
        router.filter(MatchRule(type="signal", member="Ping"), queue=q)
        with self.assertLogs("icp.dbus_safe", "ERROR"):
            inbox.put(good)                            # breaks the first filter
            inbox.put(good)                            # still handled
            got = q.get(timeout=5)
        self.assertEqual(got.header.fields[HeaderFields.path], "/ok")
        self.assertTrue(router._thread.is_alive())
        router.close()
        self.assertFalse(router._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
