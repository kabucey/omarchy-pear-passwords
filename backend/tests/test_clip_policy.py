"""pear-clip against a fake data-control compositor.

The compositor here is a real Wayland wire-protocol peer on a socketpair: it advertises a seat
and a data-control manager, records every request, and can ask the offer for its data the way
a paste does (a `send` event with a pipe passed as SCM_RIGHTS). Who holds the other end of that
pipe is injected per request, so the reader rules are tested without real wl-paste processes;
the /proc scan that answers that question in production is tested separately against a real
child process.
"""

import array
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from icp.client import clip, watchers, wayland
from icp.client.channel import Channel
from icp.client.clip import HINT_MIME, Offer, Readers

EXT = "ext_data_control_manager_v1"
WLR = "zwlr_data_control_manager_v1"


def _pad(n):
    return (n + 3) & ~3


def _string(s):
    raw = s.encode() + b"\0"
    return struct.pack("=I", len(raw)) + raw + b"\0" * (_pad(len(raw)) - len(raw))


class FakeCompositor:
    """Server side of the socketpair. Records requests as (interface, request, args)."""

    def __init__(self, managers=(EXT,)):
        self.server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.client_sock = client
        self.managers = managers
        self.objects = {1: "wl_display"}
        self.requests = []
        self.source = None
        self.device = None
        self.mimes = []
        self.hold_sync = False
        self.held = []
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self._next_server_id = 0xFF000000
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    # events to the client
    def _event(self, obj, opcode, args=b"", fd=None):
        msg = struct.pack("=II", obj, ((8 + len(args)) << 16) | opcode) + args
        with self.lock:
            if fd is None:
                self.server.sendall(msg)
            else:
                self.server.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                             array.array("i", [fd]))])

    def _loop(self):
        buf = b""
        while True:
            try:
                data = self.server.recv(65536)
            except OSError:
                return
            if not data:
                return
            buf += data
            while len(buf) >= 8:
                obj, word = struct.unpack_from("=II", buf, 0)
                size, op = word >> 16, word & 0xFFFF
                if len(buf) < size:
                    break
                args, buf = buf[8:size], buf[size:]
                self._handle(obj, op, args)

    def _handle(self, obj, op, args):
        iface = self.objects.get(obj, "?")
        r = wayland.Reader(args)
        if iface == "wl_display" and op == 1:            # get_registry
            reg = r.uint()
            self.objects[reg] = "wl_registry"
            globs = [(1, "wl_seat", 7)] + [(10 + i, m, 1) for i, m in enumerate(self.managers)]
            for name, gi, ver in globs:
                self._event(reg, 0, struct.pack("=I", name) + _string(gi) + struct.pack("=I", ver))
            return
        if iface == "wl_display" and op == 0:            # sync
            cb = r.uint()
            if self.hold_sync and self.source is not None:
                self.held.append(cb)                     # a compositor slow to answer
                return
            self._event(cb, 0, struct.pack("=I", 1))
            self._event(1, 1, struct.pack("=I", cb))
            return
        if iface == "wl_registry" and op == 0:           # bind
            r.uint()
            gi = r.string()
            r.uint()
            self.objects[r.uint()] = gi
            self._record(gi, "bind", gi)
            return
        if iface.endswith("_manager_v1"):
            prefix = iface.rsplit("_manager_v1", 1)[0]
            if op == 0:
                self.source = r.uint()
                self.objects[self.source] = prefix + "_source_v1"
                self._record(iface, "create_data_source", self.source)
            elif op == 1:
                self.device = r.uint()
                self.objects[self.device] = prefix + "_device_v1"
                self._record(iface, "get_data_device", self.device)
            elif op == 2:
                self._record(iface, "destroy", None)
            return
        if iface.endswith("_source_v1"):
            if op == 0:
                m = r.string()
                self.mimes.append(m)
                self._record(iface, "offer", m)
            elif op == 1:
                self._record(iface, "destroy", obj)
            return
        if iface.endswith("_device_v1"):
            if op == 0:
                src = r.uint()
                self._record(iface, "set_selection", src)
                if src:
                    # A real compositor echoes the new selection as an offer to the device.
                    prefix = iface.rsplit("_device_v1", 1)[0]
                    oid = self._next_server_id
                    self._next_server_id += 1
                    self.objects[oid] = prefix + "_offer_v1"
                    self._event(self.device, 0, struct.pack("=I", oid))
                    self._event(oid, 0, _string("text/plain"))
                    self._event(self.device, 1, struct.pack("=I", oid))
            elif op == 1:
                self._record(iface, "destroy", obj)
            return
        if iface.endswith("_offer_v1"):
            self._record(iface, "destroy" if op == 1 else f"op{op}", obj)
            return
        self._record(iface, f"op{op}", None)

    def _record(self, iface, name, arg):
        with self.cond:
            self.requests.append((iface, name, arg))
            self.cond.notify_all()

    # test controls
    def wait_for(self, pred, timeout=3.0):
        deadline = time.monotonic() + timeout
        with self.cond:
            while not pred():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise AssertionError(f"timed out; requests: {self.requests}")
                self.cond.wait(left)

    def wait_selected(self):
        self.wait_for(lambda: any(n == "set_selection" for _, n, _ in self.requests))

    def paste(self, mime="text/plain;charset=utf-8"):
        """Ask the offer for its data like a paste would. Returns the pipe's read end."""
        r, w = os.pipe()
        self._event(self.source, 0, _string(mime), fd=w)
        os.close(w)
        return r

    def cancel(self):
        self._event(self.source, 1)

    def answer_held_syncs(self):
        for cb in self.held:
            self._event(cb, 0, struct.pack("=I", 1))
            self._event(1, 1, struct.pack("=I", cb))
        self.held = []

    def names(self):
        with self.lock:
            return [(i.split("_")[0], n, a) for i, n, a in self.requests]

    def close(self):
        for s in (self.server, self.client_sock):
            try:
                s.close()
            except OSError:
                pass


def read_all(fd, timeout=3.0):
    """Read a pipe to EOF. Returns the bytes."""
    out = b""
    deadline = time.monotonic() + timeout
    import select
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise AssertionError("pipe never closed")
        ready, _, _ = select.select([fd], [], [], left)
        if not ready:
            continue
        b = os.read(fd, 4096)
        if not b:
            os.close(fd)
            return out
        out += b


class HolderTable:
    """Injected identify(): which pids hold the pipe, keyed by the pipe's inode."""

    def __init__(self):
        self.by_inode = {}
        self.default = Readers(frozenset({4242}), frozenset())

    def set(self, read_fd, pids, watchers_=()):
        self.by_inode[os.fstat(read_fd).st_ino] = Readers(frozenset(pids), frozenset(watchers_))

    def __call__(self, fd):
        return self.by_inode.get(os.fstat(fd).st_ino, self.default)


class ClipHarness:
    def __init__(self, test, value=b"hunter2-secret", sensitive=True, timeout=1.5, grace=0.4,
                 managers=(EXT,), daemon=None, hold_sync=False):
        self.fc = FakeCompositor(managers)
        self.fc.hold_sync = hold_sync
        self.offered = []
        test.addCleanup(self.fc.close)
        self.holders = HolderTable()
        conn = wayland.Connection(self.fc.client_sock)
        self.dc = wayland.DataControl(conn)
        self.value = bytearray(value)
        self.offer = Offer(self.value, sensitive, timeout, self.holders, grace=grace)
        self.result = None
        self.thread = threading.Thread(target=self._run, args=(daemon,), daemon=True)
        self.thread.start()
        self.fc.wait_selected()

    def _run(self, daemon):
        self.result = clip.serve(self.dc, self.offer, daemon,
                                 on_offered=lambda: self.offered.append(time.monotonic()))

    def finish(self, timeout=5.0):
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise AssertionError("pear-clip did not finish")
        return self.result

    def request_with_no_reader(self, pids, mime="text/plain;charset=utf-8"):
        """A request whose reader is already gone: the read end closed before pear-clip sees
        it (a history watcher's capture.sh that exited without reading)."""
        r, w = os.pipe()
        self.holders.set(r, pids)
        os.close(r)
        n = len(self.offer.log)
        self.fc._event(self.fc.source, 0, _string(mime), fd=w)
        os.close(w)
        deadline = time.monotonic() + 5
        while len(self.offer.log) == n:
            if time.monotonic() > deadline:
                raise AssertionError("the request was never handled")
            time.sleep(0.01)
        return self.offer.log[-1][1]

    def paste(self, pids, watchers_=(), mime="text/plain;charset=utf-8"):
        r, w = os.pipe()
        self.holders.set(r, pids, watchers_)
        self.fc._event(self.fc.source, 0, _string(mime), fd=w)
        os.close(w)
        return read_all(r)


class ReaderRuleTests(unittest.TestCase):
    def test_watcher_is_refused_and_not_counted(self):
        h = ClipHarness(self)
        self.assertEqual(h.paste({101, 102}, watchers_={101, 102}), b"")
        self.assertEqual(h.offer.refused_watchers, 1)
        self.assertIsNone(h.offer.pasted_at)
        # The offer is still live: a real paste afterwards gets the value.
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(h.offer.served, 1)

    def test_mixed_holders_count_as_a_paste(self):
        # A watcher sharing the pipe with an unknown process is not "only watchers".
        h = ClipHarness(self)
        self.assertEqual(h.paste({101, 300}, watchers_={101}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")

    def test_first_other_reader_is_the_one_paste(self):
        h = ClipHarness(self, grace=0.5)
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        # Someone else, inside the grace window: nothing.
        self.assertEqual(h.paste({201}), b"")
        # The same holder asking again (XWayland reads twice): served.
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(h.offer.served, 2)
        self.assertEqual(h.offer.refused_others, 1)
        self.assertIn(("ext", "destroy", h.fc.source), h.fc.names())

    def test_burst_ends_with_the_grace_window(self):
        h = ClipHarness(self, grace=0.2, timeout=5)
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        # After the source is destroyed nothing more is served, even to the same holder.
        self.assertGreaterEqual(h.offer.served, 1)
        self.assertEqual([n for _, n, a in h.fc.names() if n == "destroy" and a == h.fc.source],
                         ["destroy"])

    def test_unidentified_reader_is_refused_and_not_counted(self):
        # c-vm: Pear's own window (non-dumpable, so its fds cannot be listed) reads the offer
        # through Qt's "can paste" check. A live reader nobody can identify gets nothing, and
        # the offer stays up for the real paste.
        h = ClipHarness(self)
        self.assertEqual(h.paste(set()), b"")
        self.assertEqual(h.offer.log[-1][1], "unidentified")
        self.assertEqual(h.offer.refused_unknown, 1)
        self.assertIsNone(h.offer.pasted_at)
        self.assertEqual(h.offer.served, 0)
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.paste(set()), b"")                  # not even inside the grace
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(h.offer.served, 1)

    def test_a_request_with_no_reader_left_is_not_the_paste(self):
        # clipboard_ui-1: the watcher's child exited before the /proc scan found it.
        h = ClipHarness(self)
        self.assertEqual(h.request_with_no_reader(set()), "gone")
        self.assertIsNone(h.offer.pasted_at)
        self.assertEqual(h.offer.served, 0)
        self.assertEqual(h.paste({200}), b"hunter2-secret")      # the real paste still works
        self.assertEqual(h.finish(), "pasted")

    def test_an_undelivered_write_is_not_the_paste(self):
        # A holder was seen, but its read end was closed by the time of the write (EPIPE).
        h = ClipHarness(self)
        self.assertEqual(h.request_with_no_reader({300}), "undelivered")
        self.assertIsNone(h.offer.pasted_at)
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(h.offer.served, 1)

    def test_a_partly_delivered_write_is_the_paste(self):
        # audit: a reader that shrinks its pipe to 4096 bytes and stalls got part of a long
        # value without using up the copy, again and again. Any byte written is the paste.
        import fcntl
        value = bytes(range(256)) * 64                      # 16 KiB, a long note
        h = ClipHarness(self, value=value, timeout=5, grace=0.2)
        r, w = os.pipe()
        fcntl.fcntl(w, fcntl.F_SETPIPE_SZ, 4096)
        h.holders.set(r, {300})
        n = len(h.offer.log)
        with mock.patch.object(clip, "WRITE_DEADLINE_S", 0.2):
            h.fc._event(h.fc.source, 0, _string("text/plain;charset=utf-8"), fd=w)
            os.close(w)
            deadline = time.monotonic() + 5
            while len(h.offer.log) == n:                    # never read while it writes
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
        got = read_all(r)
        self.assertTrue(0 < len(got) < len(value))
        self.assertEqual(h.offer.log[-1][1], "pasted-partly")
        self.assertIsNotNone(h.offer.pasted_at)
        self.assertEqual(h.paste({200}), b"")                # nobody else gets it now
        self.assertEqual(h.finish(), "pasted")

    def test_a_vanished_holder_is_dropped_by_the_identifier(self):
        ident = clip.make_identifier(set(), describe=lambda pid: None)
        r, w = os.pipe()
        try:
            self.assertEqual(ident(w).pids, frozenset())     # held by us, but "gone" to describe
        finally:
            os.close(r)
            os.close(w)

    def test_unknown_mime_gets_nothing(self):
        h = ClipHarness(self)
        self.assertEqual(h.paste({200}, mime="image/png"), b"")
        self.assertIsNone(h.offer.pasted_at)
        h.fc.cancel()
        h.finish()


class TimingFallbackTests(unittest.TestCase):
    """Gate G5's fallback (READER_POLICY = "timing"): no reader is identified; whoever asks in
    the first WATCHER_WINDOW_S is taken for the history watcher and gets nothing."""

    def test_the_shipped_policy_identifies_readers(self):
        self.assertEqual(clip.READER_POLICY, "proc")
        factory, window = clip.policy()
        self.assertIs(factory, clip.make_identifier)
        self.assertEqual(window, 0.0)
        with self.assertRaises(ValueError):
            clip.policy("guess")

    def harness(self, window):
        factory, w = clip.policy("timing")
        self.assertEqual(w, clip.WATCHER_WINDOW_S)
        h = ClipHarness(self, grace=0.4, timeout=3)
        h.offer.identify = factory(set())
        h.offer.watcher_window = window
        return h

    def test_an_early_reader_is_refused_and_not_counted(self):
        h = self.harness(0.3)
        self.assertEqual(h.paste({101}, watchers_={101}), b"")       # ids are ignored here
        self.assertEqual(h.offer.refused_watchers, 1)
        self.assertIsNone(h.offer.pasted_at)
        time.sleep(0.35)
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")

    def test_a_later_reader_is_the_paste_even_if_it_is_the_watcher(self):
        # The documented weakness: after the window, nothing tells a watcher from a paste.
        h = self.harness(0.05)
        time.sleep(0.1)
        self.assertEqual(h.paste({101}, watchers_={101}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")


class LifetimeTests(unittest.TestCase):
    def test_timeout_destroys_the_source_and_never_clears_the_selection(self):
        h = ClipHarness(self, timeout=0.4)
        self.assertEqual(h.finish(), "expired")
        names = h.fc.names()
        self.assertIn(("ext", "destroy", h.fc.source), names)
        sel = [a for _, n, a in names if n == "set_selection"]
        self.assertEqual(sel, [h.fc.source], "set_selection(null) would clear a newer copy")

    def test_cancelled_leaves_the_clipboard_alone(self):
        h = ClipHarness(self, timeout=5)
        h.fc.cancel()
        self.assertEqual(h.finish(), "replaced")
        sel = [a for _, n, a in h.fc.names() if n == "set_selection"]
        self.assertEqual(sel, [h.fc.source])
        self.assertEqual(h.offer.served, 0)

    def test_regular_selection_only(self):
        h = ClipHarness(self, timeout=0.3)
        h.finish()
        self.assertNotIn("set_primary_selection", [n for _, n, _ in h.fc.names()])

    def test_offer_echo_is_released(self):
        h = ClipHarness(self, timeout=0.3)
        h.finish()
        # the compositor's own offer object (0xff...) was destroyed, not leaked
        self.assertTrue(any(n == "destroy" and a and a >= 0xFF000000
                            for _, n, a in h.fc.names()))

    def test_withdraw_from_the_daemon_ends_it(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        daemon = Channel(b)
        self.addCleanup(daemon.close)
        h = ClipHarness(self, timeout=5, daemon=daemon)
        a.sendall(b'{"event":"withdraw"}\n')
        self.assertEqual(h.finish(), "withdrawn")
        self.assertIn(("ext", "destroy", h.fc.source), h.fc.names())

    def test_daemon_eof_withdraws(self):
        a, b = socket.socketpair()
        daemon = Channel(b)
        self.addCleanup(daemon.close)
        h = ClipHarness(self, timeout=5, daemon=daemon)
        a.close()
        self.assertEqual(h.finish(), "withdrawn")

    def test_value_is_zeroed_by_wipe(self):
        o = Offer(bytearray(b"abc"), True, 5, HolderTable())
        o.wipe()
        self.assertEqual(bytes(o.value), b"\0\0\0")


class OfferedReportTests(unittest.TestCase):
    """The window says "copied" only on pear-clip's {"event": "offered"}: that waits for the
    compositor to answer a sync sent after set_selection."""

    def wait(self, pred, timeout=5.0):
        deadline = time.monotonic() + timeout
        while not pred():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)

    def test_offered_waits_for_the_compositor(self):
        h = ClipHarness(self, timeout=5, hold_sync=True)
        self.wait(lambda: h.fc.held)
        time.sleep(0.2)
        self.assertEqual(h.offered, [])                 # set_selection sent, not yet answered
        self.assertFalse(h.offer.offered)
        h.fc.answer_held_syncs()
        self.wait(lambda: h.offered)
        self.assertEqual(len(h.offered), 1)
        self.assertEqual(h.paste({4242}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(len(h.offered), 1)

    def test_a_paste_right_behind_the_answer_is_not_dropped(self):
        h = ClipHarness(self, timeout=5, hold_sync=True)
        self.wait(lambda: h.fc.held)
        r, w = os.pipe()
        h.holders.set(r, {4242})
        with h.fc.lock:                                  # one write: answer and paste together
            cb = h.fc.held.pop()
            msg = (struct.pack("=II", cb, (12 << 16) | 0) + struct.pack("=I", 1)
                   + struct.pack("=II", 1, (12 << 16) | 1) + struct.pack("=I", cb))
            send = _string("text/plain;charset=utf-8")
            msg += struct.pack("=II", h.fc.source, ((8 + len(send)) << 16) | 0) + send
            h.fc.server.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                         array.array("i", [w]))])
        os.close(w)
        self.assertEqual(read_all(r), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(len(h.offered), 1)

    def test_no_answer_is_a_failure_never_offered(self):
        with mock.patch.object(clip, "OFFER_CONFIRM_S", 0.3):
            h = ClipHarness(self, timeout=5, hold_sync=True)
            self.assertEqual(h.finish(), "failed")
        self.assertEqual(h.offered, [])
        self.assertEqual(h.offer.error, "the compositor did not answer")

    def test_no_data_control_is_never_offered(self):
        fc = FakeCompositor(managers=())
        self.addCleanup(fc.close)
        dc = wayland.DataControl(wayland.Connection(fc.client_sock))
        offer = Offer(bytearray(b"x"), True, 5, HolderTable())
        seen = []
        self.assertEqual(clip.serve(dc, offer, None, on_offered=lambda: seen.append(1)), "failed")
        self.assertEqual(seen, [])
        self.assertIn("data-control", offer.error)


class HintTests(unittest.TestCase):
    def test_sensitive_offers_the_hint_and_serves_secret(self):
        h = ClipHarness(self, sensitive=True, timeout=5)
        self.assertIn(HINT_MIME, h.fc.mimes)
        self.assertEqual(h.paste({101}, watchers_={101}, mime=HINT_MIME), b"secret")
        self.assertIsNone(h.offer.pasted_at)        # reading the hint is not the paste
        h.fc.cancel()
        h.finish()

    def test_username_copy_has_no_hint(self):
        h = ClipHarness(self, sensitive=False, timeout=0.3)
        self.assertNotIn(HINT_MIME, h.fc.mimes)
        for m in clip.TEXT_MIMES:
            self.assertIn(m, h.fc.mimes)
        h.finish()


class ManagerChoiceTests(unittest.TestCase):
    def test_ext_preferred(self):
        h = ClipHarness(self, managers=(WLR, EXT), timeout=0.3)
        h.finish()
        self.assertTrue(all(i != "zwlr" for i, _, _ in h.fc.names()))

    def test_wlr_fallback(self):
        h = ClipHarness(self, managers=(WLR,), timeout=5)
        self.assertEqual(h.paste({200}), b"hunter2-secret")
        self.assertEqual(h.finish(), "pasted")
        self.assertIn(("zwlr", "destroy", h.fc.source), h.fc.names())

    def test_no_data_control_fails(self):
        fc = FakeCompositor(managers=())
        self.addCleanup(fc.close)
        dc = wayland.DataControl(wayland.Connection(fc.client_sock))
        offer = Offer(bytearray(b"x"), True, 1, HolderTable())
        self.assertEqual(clip.serve(dc, offer, None), "failed")


class InputMethodHistoryTests(unittest.TestCase):
    """On the owner's XPS, fcitx5 (its clipboard addon keeps a history) read a Pear copy 50 ms
    after the offer went up and was served as the one paste, so the user's own paste got
    nothing and the toast said "pasted" at once. It must get nothing and not count."""

    def test_fcitx5_gets_nothing_and_the_user_still_pastes_once(self):
        infos = {
            4001: watchers.ProcInfo(4001, 1321, ("/usr/bin/fcitx5", "--disable", "notificationitem")),
            4002: watchers.ProcInfo(4002, 1321, ("foot",)),
        }
        holder = {"pid": 4001}
        offer = clip.Offer(bytearray(b"dummy-value"), True, 30.0,
                           lambda fd: clip.Readers(frozenset({holder["pid"]}),
                                                   frozenset(p for p in {holder["pid"]}
                                                             if watchers.is_watcher(p, infos.get))))
        offer.start()
        r, w = os.pipe()
        offer.on_send("text/plain;charset=utf-8", w)
        self.assertEqual(offer.log[-1][1], "watcher")
        self.assertIsNone(offer.pasted_at)
        self.assertEqual(read_all(r), b"")
        holder["pid"] = 4002                    # then the user pastes into a terminal
        r2, w2 = os.pipe()
        offer.on_send("text/plain;charset=utf-8", w2)
        self.assertEqual(offer.log[-1][1], "pasted")
        self.assertEqual(read_all(r2), b"dummy-value")


class WatcherListTests(unittest.TestCase):
    def test_known_watchers(self):
        cap = watchers.OMARCHY_CAPTURE
        for argv in (["wl-paste", "--type", "text", "--watch", cap, "text"],
                     ["/usr/bin/wl-paste", "--type", "image/png", "--watch", cap, "image/png"],
                     ["wl-paste", "--watch", "cliphist", "store"],
                     ["wl-paste", "-t", "text", "-w", "/usr/bin/cliphist", "store"],
                     ["wl-paste", "-t", "text", "--watch", "clipman", "store", "--no-persist"],
                     # Programs that read every new entry themselves. fcitx5's clipboard addon
                     # read a live copy on the owner's XPS and took the one paste.
                     ["/usr/bin/fcitx5", "--disable", "notificationitem"], ["fcitx5"],
                     ["copyq"], ["/usr/bin/clipse", "-listen"], ["wl-clip-persist",
                     "--clipboard", "regular"], ["/usr/lib/kdeconnectd"], ["elephant"]):
            self.assertTrue(watchers.is_watcher_argv(argv), argv)

    def test_not_watchers(self):
        cap = watchers.OMARCHY_CAPTURE
        for argv in (["wl-paste"], ["wl-paste", "--no-newline"],
                     ["wl-paste", "--primary", "--watch", cap, "text"],
                     ["wl-paste", "--watch", "sh", "-c", "cat > /tmp/x"],
                     ["wl-pastex", "--watch", cap], ["bash", cap, "text"],
                     ["wl-paste", "--watch", "cliphist", "store", "--extra"],
                     ["wl-paste", "--watch", "clipman", "store", "evil"],
                     ["foot"], ["/usr/bin/zen-browser"], ["fcitx5-config-qt-x"], []):
            self.assertFalse(watchers.is_watcher_argv(argv), argv)

    def test_descendants_of_a_watcher_count(self):
        cap = watchers.OMARCHY_CAPTURE
        table = {10: watchers.ProcInfo(10, 1, ("wl-paste", "--type", "text", "--watch", cap,
                                               "text")),
                 11: watchers.ProcInfo(11, 10, ("/bin/bash", cap, "text")),
                 12: watchers.ProcInfo(12, 11, ("perl", "-MEncode")),
                 20: watchers.ProcInfo(20, 1, ("foot",)),
                 21: watchers.ProcInfo(21, 20, ("perl", "-MEncode"))}
        d = table.get
        self.assertTrue(watchers.is_watcher(11, d))
        self.assertTrue(watchers.is_watcher(12, d))
        self.assertFalse(watchers.is_watcher(21, d))
        self.assertFalse(watchers.is_watcher(99, d))

    def test_describe_reads_proc(self):
        info = watchers.describe_proc(os.getpid())
        self.assertEqual(info.ppid, os.getppid())
        self.assertTrue(info.argv)


class ProcScanTests(unittest.TestCase):
    def test_finds_the_child_holding_the_pipe(self):
        r, w = os.pipe()
        child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
                                 stdin=r, pass_fds=())
        os.close(r)
        try:
            deadline = time.monotonic() + 3
            while True:
                found = clip.pipe_holders(w, exclude={os.getpid()})
                if child.pid in found or time.monotonic() > deadline:
                    break
                time.sleep(0.05)
            self.assertIn(child.pid, found)
            self.assertNotIn(os.getpid(), found)
        finally:
            os.close(w)
            child.wait(5)

    def test_identifier_marks_watchers(self):
        r, w = os.pipe()
        child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
                                 stdin=r)
        os.close(r)
        try:
            fake = {child.pid: watchers.ProcInfo(child.pid, 1, (
                "wl-paste", "--watch", "cliphist", "store"))}
            ident = clip.make_identifier({os.getpid()}, describe=fake.get)
            deadline = time.monotonic() + 3
            while True:
                readers = ident(w)
                if readers.pids or time.monotonic() > deadline:
                    break
                time.sleep(0.05)
            self.assertEqual(readers.pids, frozenset({child.pid}))
            self.assertTrue(readers.only_watchers)
        finally:
            os.close(w)
            child.wait(5)


PR_SET_DUMPABLE = 4
BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(clip.__file__))))

# A reader that makes itself non-dumpable (like Pear's set-gid window), says so, then reads its
# stdin (the paste pipe) to EOF and prints how many bytes it got.
NON_DUMPABLE_READER = f"""
import ctypes, sys
assert ctypes.CDLL(None, use_errno=True).prctl({PR_SET_DUMPABLE}, 0, 0, 0, 0) == 0
print("ready", flush=True)
print(len(sys.stdin.buffer.read()), flush=True)
"""
ECHO_READER = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"

# pear-clip's Offer with the real identifier, excluding only itself (as in production, where
# the compositor is excluded too but the window, its parent, is not). One request per fd in
# argv, each when a line arrives on stdin; prints [verdict, counted as the paste].
CLIP_CHILD = """
import json, os, sys
from icp.client import clip
offer = clip.Offer(bytearray(b"hunter2-secret"), True, 30.0, clip.make_identifier({os.getpid()}))
offer.start()
for fd in sys.argv[1:]:
    sys.stdin.readline()
    offer.on_send("text/plain;charset=utf-8", int(fd))
    print(json.dumps([offer.log[-1][1], offer.pasted_at is not None]), flush=True)
"""

# The window-like process: non-dumpable, it starts the clip as its own child and holds the read
# end of the first request itself. Then an ordinary process pastes, then another. Prints JSON.
WINDOW = f"""
import ctypes, json, os, subprocess, sys
assert ctypes.CDLL(None, use_errno=True).prctl({PR_SET_DUMPABLE}, 0, 0, 0, 0) == 0
pipes = [os.pipe() for _ in range(3)]
clip = subprocess.Popen([sys.executable, "-c", sys.argv[1]] + [str(w) for _, w in pipes],
                        pass_fds=[w for _, w in pipes], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, text=True)
for _, w in pipes:
    os.close(w)

def step():
    clip.stdin.write("go\\n")
    clip.stdin.flush()
    return json.loads(clip.stdout.readline())

out = {{"window": step()}}
got = b""
while True:
    b = os.read(pipes[0][0], 4096)
    if not b:
        break
    got += b
out["window_got"] = len(got)
for name, (r, _) in (("paste", pipes[1]), ("second", pipes[2])):
    reader = subprocess.Popen([sys.executable, "-c", {ECHO_READER!r}], stdin=r,
                              stdout=subprocess.PIPE)
    os.close(r)
    out[name] = step()
    out[name + "_got"] = reader.communicate(timeout=10)[0].decode()
clip.stdin.close()
clip.wait(10)
print(json.dumps(out))
"""


class NonDumpableReaderTests(unittest.TestCase):
    """c-vm "the window takes the one paste itself": real processes and the real /proc scan.
    A non-dumpable holder's fds cannot be listed, so it is never identified."""

    def reader(self, src, r):
        p = subprocess.Popen([sys.executable, "-c", src], stdin=r, stdout=subprocess.PIPE)
        os.close(r)
        self.addCleanup(lambda: p.poll() is None and p.kill())
        return p

    def send(self, h, w):
        n = len(h.offer.log)
        h.fc._event(h.fc.source, 0, _string("text/plain;charset=utf-8"), fd=w)
        os.close(w)
        deadline = time.monotonic() + 5
        while len(h.offer.log) == n:
            self.assertLess(time.monotonic(), deadline, "the request was never handled")
            time.sleep(0.01)
        return h.offer.log[-1][1]

    def test_a_non_dumpable_child_gets_nothing_and_does_not_use_the_paste(self):
        h = ClipHarness(self, timeout=10, grace=0.5)
        h.offer.identify = clip.make_identifier({os.getpid()})
        r, w = os.pipe()
        hidden = self.reader(NON_DUMPABLE_READER, r)
        self.assertEqual(hidden.stdout.readline().strip(), b"ready")
        self.assertEqual(self.send(h, w), "unidentified")
        self.assertEqual(hidden.communicate(timeout=10)[0].strip(), b"0")
        self.assertIsNone(h.offer.pasted_at)
        self.assertEqual(h.offer.served, 0)
        # An ordinary process pasting afterwards gets the value...
        r, w = os.pipe()
        paste = self.reader(ECHO_READER, r)
        self.assertEqual(self.send(h, w), "pasted")
        self.assertEqual(paste.communicate(timeout=10)[0], b"hunter2-secret")
        # ...and a second paste gets nothing.
        r, w = os.pipe()
        second = self.reader(ECHO_READER, r)
        self.assertEqual(self.send(h, w), "refused")
        self.assertEqual(second.communicate(timeout=10)[0], b"")
        self.assertEqual(h.finish(), "pasted")
        self.assertEqual(h.offer.served, 1)
        self.assertEqual(h.offer.refused_unknown, 1)

    def test_the_non_dumpable_parent_of_the_clip_gets_nothing(self):
        env = dict(os.environ, PYTHONPATH=BACKEND, PYTHONDONTWRITEBYTECODE="1")
        done = subprocess.run([sys.executable, "-c", WINDOW, CLIP_CHILD], env=env,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = json.loads(done.stdout)
        self.assertEqual(out["window"], ["unidentified", False])
        self.assertEqual(out["window_got"], 0)
        self.assertEqual(out["paste"], ["pasted", True])
        self.assertEqual(out["paste_got"], "hunter2-secret")
        self.assertEqual(out["second"], ["refused", True])
        self.assertEqual(out["second_got"], "")


class XWaylandBridgeTests(unittest.TestCase):
    """s-audit #1: Hyprland's XWM (and wlroots' xwm in sway) bridges the clipboard to X11 apps
    inside the compositor: pipe(p), p[1] goes to our source, the compositor reads p[0]. The
    compositor is excluded from the general scan, so it is identified by holding the READ end
    (inode plus an O_RDONLY/O_RDWR access mode in fdinfo)."""

    def test_compositor_holding_the_read_end_is_the_paste(self):
        # The audit's xwl_sim.py: this process stands in for the compositor.
        comp = os.getpid()
        offer = clip.Offer(bytearray(b"dummy-value"), True, 30.0,
                           clip.make_identifier({comp}, compositor=comp))
        offer.start()
        r, w = os.pipe()                      # XWM.cpp: pipe(p); wlFD = p[0]; send(mime, p[1])
        offer.on_send("text/plain;charset=utf-8", w)              # closes w
        self.assertEqual(offer.log[-1][1], "pasted")
        self.assertIsNotNone(offer.pasted_at)
        self.assertEqual(offer.paste_holders, frozenset({comp}))
        self.assertEqual(offer.served, 1)
        self.assertEqual(read_all(r), b"dummy-value")             # delivered once, then EOF
        # Another reader that is not the bridge gets nothing afterwards.
        r2, w2 = os.pipe()
        child = subprocess.Popen([sys.executable, "-c", ECHO_READER], stdin=r2,
                                 stdout=subprocess.PIPE)
        os.close(r2)
        offer.identify = clip.make_identifier({comp}, compositor=None)
        offer.pasted_at -= 10                                     # past the grace window
        offer.on_send("text/plain;charset=utf-8", w2)
        self.assertEqual(offer.log[-1][1], "refused")
        self.assertEqual(child.communicate(timeout=10)[0], b"")
        self.assertEqual(offer.served, 1)

    def test_the_bridge_is_never_served_a_second_time(self):
        # x-vm (a): within the grace a second X11 paste got the value again, because the bridge
        # is the same holder for every X11 app. It must get nothing, and nobody else either.
        comp = os.getpid()
        offer = clip.Offer(bytearray(b"dummy-value"), True, 30.0,
                           clip.make_identifier({comp}, compositor=comp), bridge=comp)
        offer.start()
        r, w = os.pipe()
        offer.on_send("text/plain;charset=utf-8", w)
        self.assertEqual(offer.log[-1][1], "pasted")
        self.assertEqual(read_all(r), b"dummy-value")
        r2, w2 = os.pipe()                    # a second X11 app asks 0.1 s later
        offer.on_send("text/plain;charset=utf-8", w2)
        self.assertEqual(offer.log[-1][1], "refused")
        self.assertEqual(read_all(r2), b"")
        self.assertEqual(offer.served, 1)

    def test_compositor_holding_only_the_write_end_is_not_served(self):
        # An ordinary Wayland paste passes through the compositor as the WRITE end only.
        r, w = os.pipe()
        comp = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                pass_fds=[w])
        self.addCleanup(lambda: comp.poll() is None and comp.kill())
        offer = clip.Offer(bytearray(b"hunter2-secret"), True, 30.0,
                           clip.make_identifier({os.getpid(), comp.pid}, compositor=comp.pid))
        offer.start()
        try:
            self.assertFalse(clip.holds_read_end(comp.pid, w))
            offer.on_send("text/plain;charset=utf-8", w)          # closes our w
            self.assertEqual(offer.log[-1][1], "unidentified")
            self.assertIsNone(offer.pasted_at)
            self.assertEqual(offer.served, 0)
        finally:
            comp.kill()
            comp.wait(5)
        self.assertEqual(read_all(r), b"")                        # closes r

    def test_compositor_whose_fds_cannot_be_read_is_refused(self):
        # A non-dumpable compositor holding the read end: its fds cannot be listed, so the
        # reader is not identified and the refusal stays.
        r, w = os.pipe()
        comp = subprocess.Popen([sys.executable, "-c", NON_DUMPABLE_READER], stdin=r,
                                stdout=subprocess.PIPE)
        os.close(r)
        self.addCleanup(lambda: comp.poll() is None and comp.kill())
        self.assertEqual(comp.stdout.readline().strip(), b"ready")
        offer = clip.Offer(bytearray(b"hunter2-secret"), True, 30.0,
                           clip.make_identifier({os.getpid(), comp.pid}, compositor=comp.pid))
        offer.start()
        self.assertFalse(clip.holds_read_end(comp.pid, w))
        offer.on_send("text/plain;charset=utf-8", w)
        self.assertEqual(offer.log[-1][1], "unidentified")
        self.assertEqual(comp.communicate(timeout=10)[0].strip(), b"0")
        self.assertIsNone(offer.pasted_at)
        self.assertEqual(offer.served, 0)
        self.assertEqual(offer.refused_unknown, 1)

    def test_access_mode_comes_from_fdinfo_flags(self):
        # A fake /proc: same inode on three fds, told apart only by their fdinfo flags.
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        link = f"pipe:[{os.fstat(w).st_ino}]"
        with tempfile.TemporaryDirectory() as proc:
            for pid, flags in ((10, "01"), (11, "02000000"), (12, "0102"), (13, None)):
                os.makedirs(f"{proc}/{pid}/fd")
                os.makedirs(f"{proc}/{pid}/fdinfo")
                os.symlink(link, f"{proc}/{pid}/fd/7")
                if flags is not None:
                    with open(f"{proc}/{pid}/fdinfo/7", "w") as f:
                        f.write(f"pos:\t0\nflags:\t{flags}\nmnt_id:\t15\n")
            self.assertFalse(clip.holds_read_end(10, w, proc))    # O_WRONLY
            self.assertTrue(clip.holds_read_end(11, w, proc))     # O_RDONLY|O_CLOEXEC
            self.assertTrue(clip.holds_read_end(12, w, proc))     # O_RDWR
            self.assertFalse(clip.holds_read_end(13, w, proc))    # no fdinfo: unreadable
            self.assertFalse(clip.holds_read_end(99, w, proc))    # gone
            self.assertFalse(clip.holds_read_end(None, w, proc))
            ident = clip.make_identifier({10, 11}, describe=lambda p: None, compositor=11,
                                         proc=proc)
            self.assertEqual(ident(w), Readers(frozenset({11}), frozenset()))
            ident = clip.make_identifier({10, 11}, describe=lambda p: None, compositor=10,
                                         proc=proc)
            self.assertEqual(ident(w).pids, frozenset())

    def test_run_names_the_compositor(self):
        seen = {}

        def factory(exclude, describe=None, compositor=None):
            seen.update(exclude=exclude, compositor=compositor)
            return HolderTable()
        policy = clip.policy
        with mock.patch.object(clip, "policy", lambda: (factory, policy()[1])):
            import io
            d = FakeDaemon(self, timeout=5)
            fc = FakeCompositor()
            self.addCleanup(fc.close)
            t, result = RunTests.start_run(self, d, fc, io.StringIO(), identify=None)
            fc.wait_selected()
            self.assertEqual(read_all(fc.paste()), b"hunter2-secret")
            t.join(10)
        self.assertEqual(result.get("rc"), 0)
        # The fake compositor is this process (the peer of the socket run() connected to).
        self.assertEqual(seen["compositor"], os.getpid())
        self.assertIn(os.getpid(), seen["exclude"])


class FakeDaemon:
    """A daemon socket for one clip connection: hello, redeem, clip-result."""

    def __init__(self, test, value="hunter2-secret", sensitive=True, timeout=5):
        self.dir = tempfile.TemporaryDirectory()
        test.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "client.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(1)
        test.addCleanup(self.srv.close)
        self.value, self.sensitive, self.timeout = value, sensitive, timeout
        self.seen = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self.srv.accept()
        f = conn.makefile("rwb")
        for line in f:
            req = json.loads(line)
            self.seen.append(req)
            op, rid = req["op"], req["rid"]
            if op == "hello":
                rep = {"rid": rid, "proto": 2, "version": "2.0.0", "purpose": "copy"}
            elif op == "redeem":
                rep = {"rid": rid, "value": self.value, "sensitive": self.sensitive,
                       "timeout": self.timeout}
            else:
                rep = {"rid": rid, "ok": True}
            f.write(json.dumps(rep).encode() + b"\n")
            f.flush()
        conn.close()


class RunTests(unittest.TestCase):
    def start_run(self, d, fc, out, ticket="A" * 43, identify="table"):
        """clip.run() against FakeDaemon `d` and FakeCompositor `fc`, in a thread."""
        import io
        wl_path = os.path.join(d.dir.name, "wayland-9")
        lsn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        lsn.bind(wl_path)
        lsn.listen(1)
        self.addCleanup(lsn.close)

        def bridge():
            s, _ = lsn.accept()
            fc.client_sock.close()
            fc.server.close()
            fc.server = s
            fc.thread = threading.Thread(target=fc._loop, daemon=True)
            fc.thread.start()
        threading.Thread(target=bridge, daemon=True).start()
        result = {}
        t = threading.Thread(target=lambda: result.setdefault(
            "rc", clip.run(io.StringIO(ticket + "\n"), d.path, wl_path,
                           identify=HolderTable() if identify == "table" else identify,
                           out=out)))
        t.start()
        return t, result

    @staticmethod
    def lines(out):
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_stdout_says_offered_before_the_paste_then_the_outcome(self):
        import io
        d = FakeDaemon(self, timeout=5)
        fc = FakeCompositor()
        self.addCleanup(fc.close)
        out = io.StringIO()
        t, result = self.start_run(d, fc, out)
        deadline = time.monotonic() + 5
        while '"offered"' not in out.getvalue():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        self.assertEqual(self.lines(out), [{"event": "offered"}])     # nothing pasted yet
        self.assertEqual(read_all(fc.paste()), b"hunter2-secret")
        t.join(10)
        self.assertEqual(result.get("rc"), 0)
        self.assertEqual(self.lines(out), [{"event": "offered"},
                                           {"event": "done", "outcome": "pasted"}])
        self.assertNotIn("hunter2", out.getvalue())

    def test_stdout_says_why_when_never_offered(self):
        import io
        d = FakeDaemon(self, timeout=5)
        fc = FakeCompositor(managers=())
        self.addCleanup(fc.close)
        out = io.StringIO()
        t, result = self.start_run(d, fc, out)
        t.join(10)
        self.assertEqual(result.get("rc"), 0)
        lines = self.lines(out)
        self.assertEqual([x["event"] for x in lines], ["error", "done"])
        self.assertIn("data-control", lines[0]["reason"])
        self.assertEqual(lines[1]["outcome"], "failed")
        self.assertEqual([q["op"] for q in d.seen], ["hello", "redeem", "clip-result"])
        self.assertNotIn("hunter2", out.getvalue())

    def test_stdout_says_why_before_the_clipboard(self):
        import io
        out = io.StringIO()
        self.assertEqual(clip.run(io.StringIO("bad\n"), "/nonexistent", "/x", out=out), 2)
        out2 = io.StringIO()
        self.assertEqual(clip.run(io.StringIO("A" * 43 + "\n"), "/nonexistent/sock", "/x",
                                  out=out2), 3)
        for o in (out, out2):
            lines = self.lines(o)
            self.assertEqual([x["event"] for x in lines], ["error"])
            self.assertTrue(lines[0]["reason"])

    def test_end_to_end_with_ticket_on_stdin(self):
        import io
        d = FakeDaemon(self, timeout=5)
        fc = FakeCompositor()
        self.addCleanup(fc.close)
        # run() connects by path; hand it the fake compositor through a listening socket.
        wl_path = os.path.join(d.dir.name, "wayland-9")
        lsn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        lsn.bind(wl_path)
        lsn.listen(1)
        self.addCleanup(lsn.close)

        def bridge():
            s, _ = lsn.accept()
            # splice the accepted socket onto the fake compositor's client end
            fc.client_sock.close()
            fc.server.close()
            fc.server = s
            fc.thread = threading.Thread(target=fc._loop, daemon=True)
            fc.thread.start()
        threading.Thread(target=bridge, daemon=True).start()

        holders = HolderTable()
        ticket = "A" * 43
        result = {}
        t = threading.Thread(target=lambda: result.setdefault(
            "rc", clip.run(io.StringIO(ticket + "\n"), d.path, wl_path, identify=holders)))
        t.start()
        deadline = time.monotonic() + 5
        while fc.source is None or not any(n == "set_selection" for _, n, _ in fc.requests):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        r = fc.paste()
        self.assertEqual(read_all(r), b"hunter2-secret")
        t.join(10)
        self.assertEqual(result.get("rc"), 0)
        ops = [q["op"] for q in d.seen]
        self.assertEqual(ops, ["hello", "redeem", "clip-result"])
        self.assertEqual(d.seen[0]["ticket"], ticket)
        self.assertEqual(d.seen[0]["role"], "clip")
        self.assertEqual(d.seen[2]["outcome"], "pasted")

    def test_bad_ticket_never_connects(self):
        import io
        self.assertEqual(clip.run(io.StringIO("not a ticket\n"), "/nonexistent", "/x"), 2)
        self.assertEqual(clip.run(io.StringIO(""), "/nonexistent", "/x"), 2)


if __name__ == "__main__":
    unittest.main()
