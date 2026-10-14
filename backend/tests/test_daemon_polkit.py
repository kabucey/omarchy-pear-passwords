"""The daemon's polkit client against a fake system bus, and the registry's prompt rules
(docs/protocol.md 5): subject, flags, details, outcome classification, cancel, rate limits."""

import array
import asyncio
import os
import threading
import unittest

from daemon_fakes import FakeAuthority, FakeClock, Harness
from jeepney import HeaderFields, Message, MessageType, new_error, new_method_return

from icp.daemon import paths, polkit, protocol
from icp.daemon.polkit import Authority, Subject, classify, sanitize

# How long a step may take before a test gives up. Generous: the gate VM runs the suite
# under load, where 5 s waits for a worker thread timed out (round 1 gate finding 4).
WAIT = 30


class FakeBus:
    """Answers CheckAuthorization with a scripted (result, seconds) and records every message
    after a real serialise/parse round trip, so fd passing is exercised."""

    def __init__(self, clock, script):
        self.clock = clock
        self.script = script
        self.sent: list[tuple[Message, list]] = []

    def call(self, msg, timeout=None):
        fds = array.array("i")
        data = msg.serialise(serial=len(self.sent) + 1, fds=fds)
        parsed = Message.from_buffer(data, fds=[int(fd) for fd in fds])
        self.sent.append((parsed, list(fds)))
        member = msg.header.fields[HeaderFields.member]
        if member == "CancelCheckAuthorization":
            return new_method_return(parsed)
        reply, seconds = self.script(parsed)
        self.clock.advance(seconds)
        if isinstance(reply, str):
            return new_error(parsed, reply)
        return new_method_return(parsed, "(bba{ss})", (reply,))


SUBJECT = Subject(pid=4321, pidfd=0, uid=1000, start_time=99)


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.pidfd = os.pidfd_open(os.getpid())
        self.subject = Subject(pid=os.getpid(), pidfd=self.pidfd, uid=1000, start_time=99)

    def tearDown(self):
        os.close(self.pidfd)

    def run_check(self, reply, seconds=2.0, action=paths.ACTION_UNLOCK, details=None,
                  mode=polkit.SUBJECT_PIDFD):
        bus = FakeBus(self.clock, lambda m: (reply, seconds))
        auth = Authority(bus=bus, clock=self.clock, mode=mode)
        out = auth.check(self.subject, action, details or {}, "pear-1")
        return out, bus

    def test_message_shape_with_pidfd_subject(self):
        out, bus = self.run_check((True, False, {}), details={"account": "GitHub\n— me"})
        self.assertEqual(out, polkit.AUTHORIZED)
        msg, fds = bus.sent[0]
        f = msg.header.fields
        self.assertEqual((f[HeaderFields.destination], f[HeaderFields.path],
                          f[HeaderFields.interface], f[HeaderFields.member]),
                         ("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                          "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization"))
        (kind, props), action, details, flags, cancel_id = msg.body
        self.assertEqual(kind, "unix-process")
        self.assertEqual(set(props), {"pidfd", "uid"})
        self.assertEqual(props["pidfd"][0], "h")
        self.assertEqual(fds, [self.pidfd])                # the fd itself went over the bus
        self.assertEqual(props["uid"], ("i", 1000))
        self.assertEqual(action, paths.ACTION_UNLOCK)
        self.assertEqual(details, {"account": "GitHub — me"})
        self.assertEqual(flags, polkit.ALLOW_USER_INTERACTION)
        self.assertEqual(cancel_id, "pear-1")

    def test_fallback_subject(self):
        out, bus = self.run_check((True, False, {}), mode=polkit.SUBJECT_PID_START_TIME)
        msg, fds = bus.sent[0]
        _, props = msg.body[0]
        self.assertEqual(props, {"pid": ("u", os.getpid()), "start-time": ("t", 99),
                                 "uid": ("i", 1000)})
        self.assertEqual(fds, [])

    def test_mode_from_environment(self):
        old = os.environ.get(polkit.SUBJECT_ENV)
        try:
            os.environ[polkit.SUBJECT_ENV] = "pid-start-time"
            self.assertEqual(polkit.subject_mode(), polkit.SUBJECT_PID_START_TIME)
            os.environ[polkit.SUBJECT_ENV] = "anything else"
            self.assertEqual(polkit.subject_mode(), polkit.SUBJECT_PIDFD)
        finally:
            if old is None:
                os.environ.pop(polkit.SUBJECT_ENV, None)
            else:
                os.environ[polkit.SUBJECT_ENV] = old

    def test_outcomes(self):
        cases = [
            ((True, False, {}), 3.0, polkit.AUTHORIZED),
            ((False, True, {"polkit.dismissed": "true"}), 3.0, polkit.DISMISSED),
            ((False, True, {}), 3.0, polkit.DENIED),
            ((False, False, {}), 0.01, polkit.DENIED_UNANSWERED),  # not a challenge: policy
            ((False, True, {}), 0.01, polkit.NO_AGENT),           # G7: nobody saw a dialog
            ((False, True, {"polkit.dismissed": "true"}), 0.01, polkit.BUSY),
            ("org.freedesktop.PolicyKit1.Error.Failed", 0.01, polkit.INTERNAL),
            ("org.freedesktop.DBus.Error.ServiceUnknown", 0.01, polkit.NO_AGENT),
            ("org.freedesktop.PolicyKit1.Error.Cancelled", 0.01, polkit.BUSY),
        ]
        for reply, seconds, expected in cases:
            self.assertEqual(self.run_check(reply, seconds)[0], expected, (reply, seconds))

    def test_no_bus_means_no_agent(self):
        class Dead:
            def call(self, msg, timeout=None):
                raise ConnectionRefusedError()
        auth = Authority(bus=Dead(), clock=self.clock)
        with self.assertLogs("icp.daemon.polkit", "WARNING"):
            self.assertEqual(auth.check(self.subject, paths.ACTION_UNLOCK, {}, "x"),
                             polkit.NO_AGENT)

    def test_cancel_uses_the_same_id_and_wins(self):
        release = threading.Event()

        def script(msg):
            release.wait(5)
            return (False, True, {"polkit.dismissed": "true"}), 1.0
        bus = FakeBus(self.clock, script)
        auth = Authority(bus=bus, clock=self.clock)
        result = []
        t = threading.Thread(target=lambda: result.append(
            auth.check(self.subject, paths.ACTION_REVEAL, {}, "pear-7")))
        t.start()
        auth.cancel("pear-7")
        release.set()
        t.join(5)
        self.assertEqual(result, [polkit.CANCELLED])
        cancel = [m for m, _ in bus.sent
                  if m.header.fields[HeaderFields.member] == "CancelCheckAuthorization"]
        self.assertEqual(cancel[0].body, ("pear-7",))

    def test_only_pear_actions(self):
        auth = Authority(bus=FakeBus(self.clock, lambda m: ((True, False, {}), 0)),
                         clock=self.clock)
        with self.assertRaises(ValueError):
            auth.check(self.subject, "org.freedesktop.systemd1.manage-units", {}, "x")

    def test_a_polkit_refusal_of_the_call_is_internal_not_no_agent(self):
        # Gate bug 7: NotAuthorized (no owner annotation) looked like "shell restarting".
        for err in ("org.freedesktop.PolicyKit1.Error.NotAuthorized",
                    "org.freedesktop.DBus.Error.InvalidArgs",
                    "org.freedesktop.PolicyKit1.Error.Failed"):
            self.assertEqual(classify(None, error=err, elapsed=0.01, cancelled=False),
                             polkit.INTERNAL, err)
        for err in ("transport", "org.freedesktop.DBus.Error.ServiceUnknown",
                    "org.freedesktop.DBus.Error.NoReply"):
            self.assertEqual(classify(None, error=err, elapsed=0.01, cancelled=False),
                             polkit.NO_AGENT, err)
        self.assertEqual(classify(None, error="org.freedesktop.PolicyKit1.Error.Cancelled",
                                  elapsed=1, cancelled=False), polkit.BUSY)

    def test_only_a_method_return_can_authorize(self):
        # #10755: a signal carrying an "authorized" body must never be read as polkitd's answer,
        # even if a transport hands one over.
        class Hands:
            def __init__(self, mtype):
                self.mtype = mtype

            def call(self, msg, timeout=None):
                reply = new_method_return(msg, "(bba{ss})", ((True, False, {}),))
                reply.header.message_type = self.mtype
                return reply
        for mtype in (MessageType.signal, MessageType.method_call):
            auth = Authority(bus=Hands(mtype), clock=self.clock)
            with self.assertLogs("icp.daemon.polkit", "ERROR"):
                self.assertEqual(auth.check(self.subject, paths.ACTION_AUTOFILL, {}, "x"),
                                 polkit.INTERNAL, mtype)
        auth = Authority(bus=Hands(MessageType.method_return), clock=self.clock)
        self.assertEqual(auth.check(self.subject, paths.ACTION_AUTOFILL, {}, "x"),
                         polkit.AUTHORIZED)

    def test_a_denial_without_a_challenge_is_unanswered(self):
        self.assertEqual(classify((False, False, {}), error=None, elapsed=0.2, cancelled=False),
                         polkit.DENIED_UNANSWERED)
        self.assertEqual(classify((False, True, {}), error=None, elapsed=2.3, cancelled=False),
                         polkit.DENIED)

    def test_classify_error_and_cancel(self):
        self.assertEqual(classify(None, error="x", elapsed=9, cancelled=True), polkit.CANCELLED)
        self.assertEqual(classify((True, False, {}), error=None, elapsed=0, cancelled=True),
                         polkit.CANCELLED)


class SanitizeTests(unittest.TestCase):
    def test_strips_controls_bidi_and_zero_width(self):
        self.assertEqual(sanitize("Bank‮ lanoitaN​ — me\x00\x1b[31m"),
                         "Bank lanoitaN — me[31m")
        self.assertEqual(sanitize("a\nb\tc d"), "a b c d")
        self.assertEqual(sanitize("  many    spaces  "), "many spaces")

    def test_length(self):
        out = sanitize("x" * 500)
        self.assertEqual(len(out), protocol.DETAIL_MAX_CHARS)
        self.assertTrue(out.endswith("…"))
        self.assertEqual(sanitize("é" * 64), "é" * 64)

    def test_non_strings(self):
        self.assertEqual(sanitize(12), "12")


class PromptRuleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = FakeClock()
        self.auth = FakeAuthority()
        self.h = await Harness(authority=self.auth, clock=self.clock).start()
        self.st = self.h.seed()
        self.ui, self.peer = await self.h.ui()

    async def asyncTearDown(self):
        self.auth.release()
        await self.h.stop()

    async def test_subject_is_the_connections_pidfd(self):
        await self.h.unlock(self.ui)
        subject, action, details, cancel_id = self.auth.calls[0]
        self.assertEqual((subject.pid, subject.pidfd, subject.uid, subject.start_time),
                         (self.peer.pid, self.peer.pidfd, self.peer.uid, self.peer.start_time))
        self.assertEqual((action, details), (paths.ACTION_UNLOCK, {}))
        self.assertTrue(cancel_id.startswith("pear-"))

    async def test_three_answered_per_minute(self):
        self.auth.outcome = polkit.DENIED
        for _ in range(3):
            r = await self.ui.call("unlock")
            self.assertEqual(r["reason"], "denied")
        r = await self.ui.call("unlock")
        self.assertEqual((r["locked"], r["reason"]), (True, "rate-limited"))
        self.assertTrue(1 <= r["retry_after"] <= 60)
        self.assertEqual(len(self.auth.calls), 3)          # no fourth dialog
        self.clock.advance(60)
        self.auth.outcome = polkit.AUTHORIZED
        self.assertIn("entries", await self.ui.call("unlock"))

    async def test_no_agent_and_busy_are_not_counted(self):
        for outcome in (polkit.NO_AGENT, polkit.BUSY) * 3:
            self.auth.outcome = outcome
            self.assertEqual((await self.ui.call("unlock"))["reason"], outcome)
        self.auth.outcome = polkit.AUTHORIZED
        self.assertIn("entries", await self.ui.call("unlock"))

    async def test_rate_limit_error_shape_for_other_ops(self):
        await self.h.unlock(self.ui)
        self.auth.outcome = polkit.DISMISSED
        for _ in range(3):
            self.assertEqual((await self.ui.call("grant", id="e.0"))["error"], "dismissed")
        r = await self.ui.call("grant", id="e.0")
        self.assertEqual(r["error"], "rate-limited")
        self.assertIn("retry_after", r)

    async def test_approvals_never_hold_up_the_next_dialog(self):
        # Gate bug 6: unlock plus two accounts used up the minute; the third account (or a
        # reopened window) got rate-limited with no dialog.
        await self.h.unlock(self.ui)
        for i in range(6):
            r = await self.ui.call("grant", id=f"e.{i % 2}")
            self.assertNotIn("error", r, i)
        self.assertEqual(len(self.auth.calls), 7)

    async def test_refusals_count_per_action(self):
        await self.h.unlock(self.ui)
        self.auth.outcome = polkit.DISMISSED
        for _ in range(3):
            await self.ui.call("grant", id="e.0")
        self.assertEqual((await self.ui.call("grant", id="e.0"))["error"], "rate-limited")
        self.assertEqual((await self.ui.call("delete", id="e.1"))["error"], "dismissed")

    async def test_an_unanswered_denial_is_not_counted(self):
        # Gate bug 8: an agent that dies mid-dialog (or a policy "no") is denied, not counted.
        await self.h.unlock(self.ui)
        self.auth.outcome = polkit.DENIED_UNANSWERED
        for _ in range(5):
            self.assertEqual((await self.ui.call("grant", id="e.0"))["error"], "denied")
        self.auth.outcome = polkit.AUTHORIZED
        self.assertNotIn("error", await self.ui.call("grant", id="e.0"))

    async def test_unlock_waits_out_the_sync_it_starts(self):
        # Round 2 gate finding 4: the sync an unlock starts made the next dialog op busy-sync
        # now and then. A slow sync makes that certain without the harness's wait.
        orig = self.h.apple.sync
        started = threading.Event()

        def slow_sync(ctx):
            started.set()
            threading.Event().wait(0.3)
            return orig(ctx)
        self.h.apple.sync = slow_sync
        await self.h.unlock(self.ui)
        self.assertTrue(started.is_set())
        self.assertIsNone(self.h.reg.get(4242).busy)
        r = await self.ui.call("create", fields={"domain": "a.example", "password": "p"})
        self.assertNotEqual(r.get("error"), "busy-sync", r)
        self.assertEqual(self.auth.calls[-1][1], paths.ACTION_MANAGE)

    async def test_one_outstanding_dialog_per_bucket(self):
        await self.h.unlock(self.ui)
        self.auth.block = True
        self.auth.started.clear()
        pending = self.ui.send("create", fields={"domain": "a.example", "password": "p"})
        self.assertTrue(await asyncio.to_thread(self.auth.started.wait, WAIT))
        self.assertEqual((await self.ui.call("delete", id="e.1"))["error"], "prompt-pending")
        self.assertEqual((await self.ui.call("cancel", target=self.ui.rid - 1))["cancelled"],
                         True)
        self.assertEqual((await asyncio.wait_for(pending, WAIT))["error"], "cancelled")
        self.assertEqual(len(self.auth.cancels), 1)

    async def test_new_grant_supersedes_a_pending_one(self):
        await self.h.unlock(self.ui)
        self.auth.block = True
        self.auth.started.clear()
        first = self.ui.send("grant", id="e.0")
        self.assertTrue(await asyncio.to_thread(self.auth.started.wait, WAIT))
        self.auth.block = False
        second = await self.ui.call("grant", id="e.1")
        self.assertEqual(second["id"], "e.1")
        self.assertEqual((await asyncio.wait_for(first, WAIT))["error"], "cancelled")

    async def test_release_cancels_a_pending_grant(self):
        await self.h.unlock(self.ui)
        self.auth.block = True
        self.auth.started.clear()
        pending = self.ui.send("grant", id="e.0")
        self.assertTrue(await asyncio.to_thread(self.auth.started.wait, WAIT))
        await self.ui.call("release")
        self.assertEqual((await asyncio.wait_for(pending, WAIT))["error"], "cancelled")

    async def test_eof_cancels_the_dialog(self):
        self.auth.block = True
        self.auth.started.clear()
        self.ui.send("unlock")
        self.assertTrue(await asyncio.to_thread(self.auth.started.wait, WAIT))
        self.ui.close()
        for _ in range(50):
            if self.auth.cancels:
                break
            await asyncio.sleep(0.05)
        self.assertEqual(len(self.auth.cancels), 1)
        self.assertFalse(self.st.keys)

    async def test_buckets_are_separate(self):
        await self.h.unlock(self.ui)
        self.auth.block = True
        self.auth.started.clear()
        pending = self.ui.send("delete", id="e.1")
        self.assertTrue(await asyncio.to_thread(self.auth.started.wait, WAIT))
        await self.h.enable_autofill(4242)
        af, _ = await self.h.hello("autofill")
        reg = self.h.reg
        self.assertTrue(reg.prompt_pending(4242, "ui"))
        self.assertFalse(reg.prompt_pending(4242, "autofill"))
        conn = reg.connections(4242, "autofill")[0]
        self.auth.block = False
        await reg.authorize(conn, paths.ACTION_AUTOFILL, {"account": "a", "origin": "b.c"})
        self.assertEqual(self.auth.calls[-1][1], paths.ACTION_AUTOFILL)
        self.auth.release()
        await asyncio.wait_for(pending, WAIT)

    async def test_lock_cancels_pending_dialogs(self):
        await self.h.unlock(self.ui)
        self.auth.block = True
        self.auth.started.clear()
        pending = self.ui.send("grant", id="e.0")
        self.assertTrue(await asyncio.to_thread(self.auth.started.wait, WAIT))
        self.h.reg.lock(4242, "screen-locked")
        self.assertEqual((await asyncio.wait_for(pending, WAIT))["error"], "cancelled")

    async def test_only_prompt_ops_raise_dialogs(self):
        await self.h.unlock(self.ui)
        n = len(self.auth.calls)
        for op, extra in (("lock", {}), ("unlock", {}), ("sync", {}), ("settings", {"get": True}),
                          ("release", {}), ("copy", {"id": "e.1", "field": "username"}),
                          ("totp-preview", {"setup": "JBSWY3DPEHPK3PXP"})):
            await self.ui.call(op, **extra)
            if op == "lock":
                n += 1                                # the unlock after it prompts again
        self.assertEqual(len(self.auth.calls), n)
        for _, action, _, _ in self.auth.calls:
            self.assertIn(action, paths.ACTIONS)


if __name__ == "__main__":
    unittest.main()
