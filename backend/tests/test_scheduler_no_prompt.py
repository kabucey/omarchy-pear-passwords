"""The scheduler syncs only unlocked uids and can never raise a dialog (docs/protocol.md 4.3).

Two independent guards on the source (a text matcher and an AST walk), a check of what
importing it pulls in, and behaviour with a fake clock: a locked uid is never synced, an
unlocked one every 2 h +- 60 s, idle relock is enabled by default, and none of it reaches polkit.
"""

import ast
import asyncio
import os
import random
import re
import subprocess
import sys
import unittest

from daemon_fakes import UID, FakeClock, Harness

from icp.daemon import protocol
from icp.daemon.handlers import background_sync
from icp.daemon.scheduler import Scheduler

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON = os.path.join(BACKEND, "icp", "daemon")
NO_PROMPT_MODULES = ("scheduler.py", "apple.py")
# Spec 13.2: neither module imports or references polkit or sets AllowUserInteraction. The
# scheduler is also held to never calling the registry's authorize() (apple.py's frozen
# docstring talks about "the authorization module", so that word is not a guard there).
FORBIDDEN = r"polkit|allowuserinteraction|allow_user_interaction|checkauthorization"
FORBIDDEN_SCHEDULER = FORBIDDEN + r"|authoriz"


class SourceGuardTests(unittest.TestCase):
    def _src(self, name):
        with open(os.path.join(DAEMON, name), encoding="utf-8") as f:
            return f.read()

    def test_text_matcher(self):
        for name in NO_PROMPT_MODULES:
            src = self._src(name)
            pattern = FORBIDDEN_SCHEDULER if name == "scheduler.py" else FORBIDDEN
            hits = re.findall(pattern, src.replace("_", "").lower())
            self.assertEqual(hits, [], name)

    def test_ast(self):
        for name in NO_PROMPT_MODULES:
            tree = ast.parse(self._src(name))
            names, imports = [], []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports += [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imports += [node.module or ""] + [a.name for a in node.names]
                elif isinstance(node, ast.Name):
                    names.append(node.id)
                elif isinstance(node, ast.Attribute):
                    names.append(node.attr)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    names.append(node.value)
            names += imports
            pattern = FORBIDDEN_SCHEDULER if name == "scheduler.py" else FORBIDDEN
            bad = [n for n in names
                   if re.search(pattern, n.replace(".", "").replace("_", "").lower())]
            self.assertEqual(bad, [], name)
            if name == "scheduler.py":
                # It drives the registry by duck typing; importing sessions or handlers would
                # pull the authorization module in behind its back.
                imported = [n for n in imports
                            if n.rsplit(".", 1)[-1] in ("sessions", "handlers", "server")]
                self.assertEqual(imported, [], name)

    def test_importing_the_scheduler_loads_no_authorization_code(self):
        code = ("import sys, icp.daemon.scheduler; "
                "print(','.join(m for m in sys.modules if 'polkit' in m or m == 'jeepney'))")
        env = dict(os.environ, PYTHONPATH=BACKEND, PYTHONDONTWRITEBYTECODE="1")
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                             text=True, check=True)
        self.assertEqual(out.stdout.strip(), "")



class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = FakeClock()
        self.h = await Harness(clock=self.clock).start()
        self.st = self.h.seed()
        self.synced: list[int] = []

        async def run_sync(uid):
            self.synced.append(uid)
            return await background_sync(self.h.reg, uid)
        self.sched = Scheduler(self.h.reg, run_sync, clock=self.clock, rng=random.Random(7))
        self.run_sync = run_sync

    async def asyncTearDown(self):
        await self.h.stop()

    async def _drive(self, seconds, step=30.0):
        """Advance the clock and tick like run() would, running the syncs it starts."""
        actions = []
        end = self.clock.t + seconds
        while self.clock.t < end:
            self.clock.advance(step)
            for kind, uid in self.sched.tick():
                actions.append((kind, uid))
                if kind == "sync":
                    await self.run_sync(uid)
        return actions

    def test_interval_jitter(self):
        for _ in range(200):
            self.assertTrue(protocol.SYNC_INTERVAL_S - protocol.SYNC_JITTER_S
                            <= self.sched.interval()
                            <= protocol.SYNC_INTERVAL_S + protocol.SYNC_JITTER_S)

    async def test_locked_uid_is_never_synced(self):
        ui, _ = await self.h.ui()
        actions = await self._drive(10 * 3600, step=600)
        self.assertEqual(actions, [])
        self.assertEqual(self.h.apple.calls, [])
        self.assertEqual(self.h.authority.calls, [])
        self.assertEqual(await background_sync(self.h.reg, UID), "locked")
        self.assertEqual(self.h.apple.calls, [])

    async def test_a_latched_needs_login_is_not_repeated_every_tick(self):
        ui, _ = await self.h.ui()
        await ui.call("unlock")
        await ui.call("settings", set={"idle_lock_s": 0})
        await ui.event("synced")
        self.st.needs_login = True                  # Apple asked for a person once
        calls, events = len(self.h.apple.calls), len(ui.events)
        await self._drive(3 * protocol.SYNC_INTERVAL_S, step=600)
        self.assertEqual(await background_sync(self.h.reg, UID), "needs-login")
        self.assertEqual(len(self.h.apple.calls), calls)        # Apple was not contacted
        self.assertEqual(ui.events[events:], [])                # and nothing re-announced
        self.assertEqual((await ui.call("sync"))["skipped"], "needs-login")
        self.assertEqual(len(self.h.authority.calls), 1)

    async def test_unlocked_uid_syncs_every_two_hours_without_prompting(self):
        ui, _ = await self.h.ui()
        await ui.call("unlock")
        await ui.call("settings", set={"idle_lock_s": 0})
        await ui.event("synced")                    # the sync right after the unlock
        dialogs = len(self.h.authority.calls)
        self.assertEqual(dialogs, 1)
        actions = await self._drive(protocol.SYNC_INTERVAL_S - protocol.SYNC_JITTER_S - 60)
        self.assertEqual([a for a in actions if a[0] == "sync"], [])
        actions = await self._drive(2 * protocol.SYNC_JITTER_S + 120)
        self.assertEqual([a for a in actions if a[0] == "sync"], [("sync", UID)])
        actions = await self._drive(2 * protocol.SYNC_INTERVAL_S)
        self.assertEqual(len([a for a in actions if a[0] == "sync"]), 2)
        self.assertEqual(len(self.h.authority.calls), dialogs)
        self.assertEqual(self.st.unseal_count, 0)
        self.assertEqual(self.h.apple.calls.count("sync"), 4)

    async def test_lock_stops_the_schedule(self):
        ui, _ = await self.h.ui()
        await ui.call("unlock")
        await self._drive(60)
        await ui.call("lock")
        actions = await self._drive(6 * 3600, step=300)
        self.assertEqual(actions, [])
        self.assertEqual(len(self.h.authority.calls), 1)

    async def test_idle_lock_by_default_wipes_keys_after_five_minutes(self):
        ui, _ = await self.h.ui()
        await ui.call("unlock")
        await ui.event("synced")
        await self._drive(270)
        self.assertTrue(self.h.reg.get(UID).unlocked())
        actions = await self._drive(30)
        self.assertIn(("idle-lock", UID), actions)
        self.assertFalse(self.h.reg.get(UID).unlocked())
        self.assertFalse(self.st.keys)

    async def test_idle_lock_when_chosen(self):
        ui, _ = await self.h.ui()
        await ui.call("unlock")
        await ui.call("settings", set={"idle_lock_s": 300})
        await self._drive(240)
        await ui.call("settings", get=True)           # a request resets the idle clock
        actions = await self._drive(240)
        self.assertNotIn(("idle-lock", UID), actions)
        actions = await self._drive(90)
        self.assertIn(("idle-lock", UID), actions)
        self.assertEqual((await ui.event("locked"))["reason"], "idle")
        self.assertFalse(self.st.keys)

    async def test_sync_failure_is_reported_not_prompted(self):
        from icp.daemon.context import NeedsLogin
        self.h.apple.sync_error = NeedsLogin("password")
        ui, _ = await self.h.ui()
        await ui.call("unlock")
        ev = await ui.event("sync-failed")
        self.assertEqual(ev["reason"], "needs-login")
        self.assertEqual((await ui.event("needs-login"))["event"], "needs-login")
        self.assertTrue(self.st.needs_login)
        self.assertEqual(len(self.h.authority.calls), 1)

    async def test_run_loop_survives_a_bad_tick(self):
        class Broken:
            sessions = property(lambda self: (_ for _ in ()).throw(RuntimeError("x")))
        s = Scheduler(Broken(), self.run_sync, clock=self.clock, tick_s=0.01)
        task = asyncio.get_running_loop().create_task(s.run())
        with self.assertLogs("icp.daemon.scheduler", "ERROR"):
            await asyncio.sleep(0.05)
        task.cancel()


if __name__ == "__main__":
    unittest.main()
