"""Single-use tickets binding clip and migrate processes to the window (docs/protocol.md 2.3)."""

import asyncio
import re
import unittest

from daemon_fakes import UID, FakeClock, Harness

from icp.daemon import protocol
from icp.daemon.tickets import TicketBook, TicketError


class _Ui:
    def __init__(self, pid=500, start_time=5000):
        self.pid = pid
        self.start_time = start_time
        self.closed = False


class TicketBookTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.book = TicketBook(self.clock)
        self.ui = _Ui()
        self.starts = {500: 5000}

    def issue(self, **kw):
        args = dict(uid=UID, role="clip", purpose="copy", ui_conn=self.ui, id="e.0",
                    field="password", value="v", sensitive=True)
        args.update(kw)
        return self.book.issue(**args)

    def redeem(self, token, **kw):
        args = dict(uid=UID, role="clip", ppid=500, parent_start_time=self.starts.get)
        args.update(kw)
        return self.book.redeem(token, **args)

    def test_token_shape(self):
        t = self.issue()
        self.assertRegex(t, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotEqual(t, self.issue())

    def test_redeem_once(self):
        t = self.issue()
        ticket = self.redeem(t)
        self.assertEqual((ticket.id, ticket.field, ticket.value), ("e.0", "password", "v"))
        with self.assertRaises(TicketError):
            self.redeem(t)

    def test_failed_redeem_still_consumes(self):
        t = self.issue()
        with self.assertRaises(TicketError):
            self.redeem(t, ppid=501)
        with self.assertRaises(TicketError):
            self.redeem(t)

    def test_expires_after_ttl(self):
        t = self.issue()
        self.clock.advance(protocol.TICKET_TTL_S + 0.01)
        with self.assertRaises(TicketError):
            self.redeem(t)

    def test_just_inside_ttl(self):
        t = self.issue()
        self.clock.advance(protocol.TICKET_TTL_S - 0.01)
        self.redeem(t)

    def test_parent_must_be_the_window(self):
        with self.assertRaises(TicketError):
            self.redeem(self.issue(), ppid=1)
        # Another process started in the same clock tick as the window is still not it.
        self.starts[501] = self.starts[500]
        with self.assertRaises(TicketError):
            self.redeem(self.issue(), ppid=501)

    def test_parent_start_time_must_match(self):
        t = self.issue()
        self.starts[500] = 5001                         # the window's pid was reused
        with self.assertRaises(TicketError):
            self.redeem(t)

    def test_parent_gone(self):
        t = self.issue()
        del self.starts[500]
        with self.assertRaises(TicketError):
            self.redeem(t)

    def test_uid_and_role_bound(self):
        with self.assertRaises(TicketError):
            self.redeem(self.issue(), uid=UID + 1)
        with self.assertRaises(TicketError):
            self.redeem(self.issue(), role="migrate")

    def test_window_closed(self):
        t = self.issue()
        self.ui.closed = True
        with self.assertRaises(TicketError):
            self.redeem(t)

    def test_revoke(self):
        t1, t2 = self.issue(), self.issue(role="migrate", purpose="import")
        self.assertEqual(self.book.revoke_uid(UID, role="clip"), 1)
        with self.assertRaises(TicketError):
            self.redeem(t1)
        self.redeem(t2, role="migrate")
        self.issue()
        self.assertEqual(self.book.revoke_uid(UID), 1)
        self.assertEqual(self.book.pending(UID), 0)

    def test_bad_ticket_throttle(self):
        for _ in range(protocol.BAD_TICKETS_PER_MIN):
            with self.assertRaises(TicketError):
                self.redeem("x" * 43)
        good = self.issue()
        with self.assertRaises(TicketError):
            self.redeem(good)                           # refused: the uid is throttled
        self.clock.advance(60)
        self.redeem(self.issue())

    def test_garbage_tokens(self):
        for token in (None, 5, "", "x" * 43, ["a"]):
            with self.assertRaises(TicketError):
                self.redeem(token)

    def test_only_ticket_roles(self):
        with self.assertRaises(ValueError):
            self.issue(role="autofill")


class TicketFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.h = await Harness().start()
        self.h.seed()
        self.ui, self.ui_peer = await self.h.ui()
        self.assertIn("entries", await self.ui.call("unlock"))

    async def asyncTearDown(self):
        await self.h.stop()

    async def clip(self, ticket, ppid=None):
        p = self.h.peer(ppid=self.ui_peer.pid if ppid is None else ppid)
        return await self.h.hello("clip", peer=p, ticket=ticket)

    async def test_copy_username_end_to_end(self):
        r = await self.ui.call("copy", id="e.1", field="username")
        self.assertEqual(r["ttl"], 10)
        c, hello = await self.clip(r["ticket"])
        self.assertEqual(hello["purpose"], "copy")
        red = await c.call("redeem")
        self.assertEqual(red, {"rid": red["rid"], "value": "user1", "sensitive": False,
                               "timeout": 30})
        self.assertEqual((await c.call("redeem"))["error"], "bad-ticket")
        self.assertEqual(await c.call("clip-result", outcome="pasted"),
                         {"rid": c.rid, "ok": True})
        ev = await self.ui.event("clip")
        self.assertEqual(ev, {"event": "clip", "id": "e.1", "field": "username",
                              "outcome": "pasted", "_seen": True})

    async def test_clip_from_another_parent_is_refused(self):
        r = await self.ui.call("copy", id="e.1", field="domain")
        c, hello = await self.clip(r["ticket"], ppid=1)
        self.assertEqual(hello, {"rid": 0, "error": "bad-ticket"})
        await asyncio.wait_for(c.closed.wait(), 5)
        c2, hello = await self.clip(r["ticket"])          # consumed by the failed hello
        self.assertEqual(hello["error"], "bad-ticket")

    async def test_clip_without_ticket(self):
        c, hello = await self.h.hello("clip", peer=self.h.peer(ppid=self.ui_peer.pid))
        self.assertEqual(hello["error"], "bad-ticket")

    async def test_ticket_is_role_bound(self):
        r = await self.ui.call("copy", id="e.1", field="domain")
        p = self.h.peer(ppid=self.ui_peer.pid)
        c, hello = await self.h.hello("migrate", peer=p, ticket=r["ticket"])
        self.assertEqual(hello["error"], "bad-ticket")

    async def test_lock_revokes_tickets_and_withdraws_clips(self):
        r1 = await self.ui.call("copy", id="e.1", field="domain")
        c, _ = await self.clip(r1["ticket"])
        r2 = await self.ui.call("copy", id="e.1", field="username")   # withdraws c
        self.assertEqual((await c.event("withdraw"))["event"], "withdraw")
        await asyncio.wait_for(c.closed.wait(), 5)
        await self.ui.call("lock")
        c2, hello = await self.clip(r2["ticket"])
        self.assertEqual(hello["error"], "bad-ticket")

    async def test_secret_copy_needs_a_grant_and_is_sensitive(self):
        self.assertEqual((await self.ui.call("copy", id="e.0", field="password"))["error"],
                         "no-grant")
        await self.ui.call("grant", id="e.0")
        r = await self.ui.call("copy", id="e.0", field="password")
        c, _ = await self.clip(r["ticket"])
        red = await c.call("redeem")
        self.assertEqual((red["value"], red["sensitive"]), ("pw-0-fake", True))

    async def test_ticket_from_a_closed_window_is_refused(self):
        r = await self.ui.call("copy", id="e.1", field="domain")
        self.ui.close()
        await asyncio.sleep(0.1)
        c, hello = await self.clip(r["ticket"])
        self.assertEqual(hello["error"], "bad-ticket")

    async def test_ticket_text_never_logged(self):
        with self.assertLogs("icp.daemon", level="WARNING") as logs:
            c, hello = await self.clip("A" * 43, ppid=1)
        self.assertFalse(any("A" * 43 in line for line in logs.output))
        self.assertTrue(re.search("refused", "\n".join(logs.output)))


if __name__ == "__main__":
    unittest.main()
