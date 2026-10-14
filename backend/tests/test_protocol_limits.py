"""Framing and connection limits of the daemon socket (docs/protocol.md 1 and 2).

Runs the real Server on a scratch unix socket with a fake peer check and fake store.
"""

import asyncio
import json
import unittest

from daemon_fakes import UID, Harness

from icp.daemon import protocol
from icp.daemon.server import parse_line, BadLine


class ParseLineTests(unittest.TestCase):
    def test_accepts_object_with_int_rid(self):
        self.assertEqual(parse_line(b'{"op":"x","rid":7}\n')["rid"], 7)

    def test_rejects(self):
        for raw, rid in ((b"[1]\n", None), (b"not json\n", None), (b'{"op":"x"}\n', None),
                         (b'{"op":"x","rid":true}\n', None), (b'{"op":"x","rid":-1}\n', None),
                         (b'{"op":"x","rid":9007199254740992}\n', None),
                         (b'{"op":"x","rid":1.5}\n', None), (b'{"rid":3}\n', 3),
                         (b'{"op":1,"rid":4}\n', 4), (b'{"op":"x","rid":1,"v":NaN}\n', None),
                         (b'\xff\xfe\n', None), (b"[" * 100000 + b"\n", None)):
            with self.assertRaises(BadLine, msg=raw[:40]) as cm:
                parse_line(raw)
            self.assertEqual(cm.exception.rid, rid, raw[:40])


class FramingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.h = await Harness().start()

    async def asyncTearDown(self):
        await self.h.stop()

    async def _closed(self, c):
        await asyncio.wait_for(c.closed.wait(), 5)

    async def test_first_line_must_be_hello(self):
        c = await self.h.connect()
        reply = await c.call("unlock", rid=1)
        self.assertIsNone(reply)                     # closed: the reply came with rid null
        await self._closed(c)
        self.assertEqual(c.raw, [{"rid": None, "error": "hello-required"}])

    async def test_hello_timeout(self):
        self.h.server.hello_timeout = 0.2
        c = await self.h.connect()
        await self._closed(c)
        self.assertEqual(c.raw, [{"rid": None, "error": "hello-required"}])

    async def test_wrong_proto(self):
        c = await self.h.connect()
        reply = await c.call("hello", rid=0, role="ui", proto=1)
        self.assertEqual(reply, {"rid": 0, "error": "proto", "proto": 2})
        await self._closed(c)

    async def test_unknown_role_closes_without_reply(self):
        c = await self.h.connect()
        c.send("hello", rid=0, role="cli", proto=2)
        await self._closed(c)
        self.assertEqual(c.raw, [])

    async def test_peer_failure(self):
        self.h.peers.clear()
        import os
        reader, writer = await asyncio.open_unix_connection(self.h.path)
        line = await asyncio.wait_for(reader.readline(), 5)
        self.assertEqual(json.loads(line), {"rid": None, "error": "peer"})
        self.assertEqual(await reader.readline(), b"")
        writer.close()
        del os

    async def test_line_limit_boundary(self):
        c, _ = await self.h.ui()
        base = b'{"op":"nosuch","rid":5,"pad":"'
        tail = b'"}\n'
        exact = base + b"x" * (protocol.MAX_REQUEST_LINE - len(base) - len(tail)) + tail
        self.assertEqual(len(exact), protocol.MAX_REQUEST_LINE)
        fut = asyncio.get_running_loop().create_future()
        c.replies[5] = fut
        c.send_raw(exact)
        self.assertEqual(await asyncio.wait_for(fut, 5), {"rid": 5, "error": "unknown-op"})
        over = base + b"x" * (protocol.MAX_REQUEST_LINE - len(base) - len(tail) + 1) + tail
        c.send_raw(over)
        await self._closed(c)
        self.assertEqual(c.raw[-1], {"rid": None, "error": "too-large"})

    async def test_bad_lines_keep_the_connection(self):
        c, _ = await self.h.ui()
        c.send_raw(b"garbage\n")
        c.send_raw(b'{"op":7,"rid":9}\n')
        reply = await c.call("settings", get=True)
        self.assertIn("settings", reply)
        self.assertEqual(c.raw[1], {"rid": None, "error": "bad-request"})
        self.assertEqual(c.raw[2], {"rid": 9, "error": "bad-request"})

    async def test_unknown_and_forbidden_ops(self):
        c, _ = await self.h.ui()
        self.assertEqual((await c.call("frobnicate"))["error"], "unknown-op")
        self.assertEqual((await c.call("redeem"))["error"], "forbidden")
        self.assertEqual((await c.call("autofill-fill", origin="https://a.b", id="x"))["error"],
                         "forbidden")
        self.assertEqual((await c.call("hello", role="ui", proto=2))["error"], "forbidden")

    async def test_inflight_limit_and_out_of_order_replies(self):
        gate = asyncio.Event()

        async def slow(reg, conn, req):
            await gate.wait()
            return {"n": req["rid"]}

        self.h.server.handlers["sync"] = slow
        c, _ = await self.h.ui()
        futs = [c.send("sync") for _ in range(protocol.MAX_INFLIGHT)]
        extra = await c.call("sync")
        self.assertEqual(extra["error"], "too-many")
        quick = await c.call("settings", get=True)       # still refused while 16 are pending
        self.assertEqual(quick["error"], "too-many")
        gate.set()
        done = await asyncio.wait_for(asyncio.gather(*futs), 5)
        self.assertEqual(sorted(r["n"] for r in done), sorted(r["rid"] for r in done))
        self.assertIn("settings", await c.call("settings", get=True))

    async def test_long_reply_lines_are_allowed(self):
        st = self.h.seed(n=600)
        for m in st.metas.values():
            m.title = m.title + " " + "y" * 200
        c, _ = await self.h.ui()
        reply = await c.call("unlock")
        self.assertEqual(len(reply["entries"]), 600)
        self.assertGreater(len(json.dumps(reply)), protocol.MAX_REQUEST_LINE)

    async def test_oversized_reply_becomes_internal(self):
        async def huge(reg, conn, req):
            return {"blob": "z" * (protocol.MAX_REPLY_LINE + 1)}

        self.h.server.handlers["sync"] = huge
        c, _ = await self.h.ui()
        self.assertEqual(await c.call("sync"), {"rid": c.rid, "error": "internal"})

    async def test_handler_crash_is_internal_without_detail(self):
        async def boom(reg, conn, req):
            raise RuntimeError("secret detail /var/lib/pear-passwords/u4242")

        self.h.server.handlers["sync"] = boom
        c, _ = await self.h.ui()
        with self.assertLogs("icp.daemon.server", level="ERROR"):
            reply = await c.call("sync")
        self.assertEqual(reply, {"rid": c.rid, "error": "internal"})

    async def test_second_ui_is_refused_and_first_focused(self):
        c1, _ = await self.h.ui()
        p = self.h.peer()
        c2, reply = await self.h.hello("ui", peer=p)
        self.assertEqual(reply, {"rid": 0, "error": "already-running"})
        await self._closed(c2)
        self.assertEqual((await c1.event("focus"))["event"], "focus")

    async def test_autofill_connection_cap(self):
        await self.h.enable_autofill()
        conns = []
        for _ in range(protocol.MAX_AUTOFILL_CONNS):
            c, reply = await self.h.hello("autofill")
            self.assertEqual(reply["state"], "unavailable")     # no store: empty
            self.assertEqual(set(reply), {"rid", "proto", "version", "state"})
            conns.append(c)
        c, reply = await self.h.hello("autofill")
        self.assertEqual(reply, {"rid": 0, "error": "too-many"})
        await self._closed(c)
        conns[0].close()
        await asyncio.sleep(0.1)
        c, reply = await self.h.hello("autofill")
        self.assertEqual(reply["state"], "unavailable")

    async def test_other_uids_are_separate(self):
        await self.h.ui()
        c2, _ = await self.h.ui(uid=UID + 1)
        self.assertEqual(c2.hello["state"], "empty")


if __name__ == "__main__":
    unittest.main()


class OutcomeLogTests(unittest.IsolatedAsyncioTestCase):
    """Ops that reach Apple or change the vault, and every op that ends in an error, leave one
    journal line: the op, its outcome code and how long it took. A create that failed while the
    owner was looking elsewhere left nothing to go on before this. Never a value."""

    async def asyncSetUp(self):
        self.h = await Harness().start()

    async def asyncTearDown(self):
        await self.h.stop()

    async def test_an_error_is_logged_with_its_code_and_never_a_value(self):
        c = await self.h.connect()
        await c.call("hello", rid=0, role="ui", proto=2)
        canary = "canary-value-that-must-not-be-logged"
        with self.assertLogs("icp.daemon.server", level="INFO") as logs:
            reply = await c.call("create", rid=1, fields={"title": canary, "password": canary})
        self.assertIn("error", reply)
        lines = [r.getMessage() for r in logs.records]
        self.assertTrue(any(l.startswith(f"op create: {reply['error']}") and l.endswith("s")
                            for l in lines), lines)
        self.assertFalse(any(canary in l for l in lines), lines)
