"""A lock that lands while create()/reset() runs (round 2 audit, problem 2).

create() and reset() build a NEW store object that comes back unlocked. A lock that lands
meanwhile (PrepareForSleep, logind Lock, the Lock button, the window closing) used to wipe only
the old object the session held: wipe_after stayed False, so the sleep inhibitor let go at once,
and the handler then put the new, unlocked store in place and opened tier 1 on it (and, for
migrate-begin, issued an import ticket; for signin, ran the Apple sign-in) with no new dialog.

Now run_store(replaces=True) keeps the wipe pending until the call returns, then wipes the new
object, and the handlers end with `cancelled` instead of opening tier 1.
"""

import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from daemon_fakes import UID, FakeStore, Harness
from fixtures import FakeSealBackend, vstore_env

from icp import vstore
from icp.daemon.sessions import Registry, Session


class _Gate:
    """Makes FakeStore.create/reset (a classmethod) wait until the test lets it go."""

    def __init__(self):
        self.started = threading.Event()
        self.proceed = threading.Event()

    def wrap(self, name):
        orig = getattr(FakeStore, name).__func__
        gate = self

        def slow(cls, uid, **kw):
            gate.started.set()
            gate.proceed.wait(10)
            return orig(cls, uid, **kw)
        return mock.patch.object(FakeStore, name, classmethod(slow))


class HandlerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.h = await Harness().start()
        self.ui, self.peer = await self.h.ui()

    async def asyncTearDown(self):
        await self.h.stop()

    async def _lock_during(self, op, make, lock, **fields):
        gate = _Gate()
        with gate.wrap(make):
            fut = self.ui.send(op, **fields)
            self.assertTrue(await asyncio.to_thread(gate.started.wait, 10))
            lock()
            # The fresh keys are still landing: the wipe is pending, so a PrepareForSleep
            # holds the suspend back (for its second) instead of letting go at once.
            self.assertTrue(self.h.reg.wipes_pending())
            gate.proceed.set()
            r = await asyncio.wait_for(fut, 30)
        s = self.h.reg.get(UID)
        self.assertEqual(r.get("error"), "cancelled", r)
        self.assertNotIn("ticket", r)
        self.assertFalse(s.unlocked())
        self.assertIsNone(s.tier1)
        self.assertIs(s.store, self.h.store())        # the new store is the one held...
        self.assertFalse(self.h.store().keys)          # ...and it is wiped
        self.assertFalse(self.h.reg.wipes_pending())
        self.assertEqual(self.h.reg.tickets.pending(UID), 0)
        self.assertNotIn("login", self.h.apple.calls)
        return r

    def _sleep(self):
        self.h.reg.lock_all("sleep")

    def _nothing_held(self):
        st = self.h.store()
        st.exists, st.keys = True, False

    async def test_migrate_begin_on_an_empty_store(self):
        await self._lock_during("migrate-begin", "create", self._sleep)

    async def test_migrate_begin_over_a_store_that_holds_nothing(self):
        self._nothing_held()
        await self._lock_during("migrate-begin", "reset", self._sleep)

    async def test_reset(self):
        st = self.h.store()
        st.exists, st.keys, st.recorded_state = True, False, "tpm-cleared"
        await self._lock_during("reset", "reset", self._sleep)

    async def test_signin_on_an_empty_store(self):
        await self._lock_during("signin", "create", self._sleep, mode="login")

    async def test_the_lock_button_too(self):
        await self._lock_during("migrate-begin", "create",
                                lambda: self.h.reg.lock(UID, "user"))

    async def test_the_store_works_again_after_a_new_unlock(self):
        await self._lock_during("migrate-begin", "create", self._sleep)
        # The cancelled import left keys and nothing else: migrate-begin starts it over.
        r = await self.ui.call("migrate-begin")
        self.assertIn("ticket", r)
        self.assertTrue(self.h.reg.get(UID).unlocked())
        self.assertTrue(self.h.store().keys)

    async def test_a_lock_while_the_pending_import_is_recorded(self):
        # The last await before tier 1 opens: the migration_pending write.
        started, proceed = threading.Event(), threading.Event()
        orig = FakeStore.save_settings

        def slow_save(store, d):
            started.set()
            proceed.wait(10)
            return orig(store, d)
        with mock.patch.object(FakeStore, "save_settings", slow_save):
            fut = self.ui.send("migrate-begin")
            self.assertTrue(await asyncio.to_thread(started.wait, 10))
            self._sleep()
            proceed.set()
            r = await asyncio.wait_for(fut, 30)
        s = self.h.reg.get(UID)
        self.assertEqual(r.get("error"), "cancelled", r)
        self.assertFalse(s.unlocked())
        self.assertFalse(self.h.store().keys)
        self.assertEqual(self.h.reg.tickets.pending(UID), 0)

    async def _lock_during_reset_reads(self, nth, lock):
        # reset re-reads the store state after its dialog (_resettable, then the discard
        # check) before it locks the old store itself; that lock bumps the epoch, so a lock
        # that lands during those reads was lost and tier 1 opened on the new store
        # (round 3 audit, problem 1).
        st = self.h.store()
        st.exists, st.keys, st.recorded_state = True, False, "tpm-cleared"
        started, proceed = threading.Event(), threading.Event()
        orig = FakeStore.state
        seen = {"n": 0}
        authority = self.h.authority

        def slow_state(store):
            if authority.calls:
                seen["n"] += 1
                if seen["n"] == nth:
                    started.set()
                    proceed.wait(10)
            return orig(store)
        with mock.patch.object(FakeStore, "state", slow_state):
            fut = self.ui.send("reset")
            self.assertTrue(await asyncio.to_thread(started.wait, 10))
            lock()
            proceed.set()
            r = await asyncio.wait_for(fut, 30)
        s = self.h.reg.get(UID)
        self.assertEqual(r.get("error"), "cancelled", r)
        self.assertFalse(s.unlocked())
        self.assertIsNone(s.tier1)
        self.assertEqual(FakeStore.resets, [])          # the old store is left as it was

    async def test_reset_sleep_during_the_resettable_check(self):
        await self._lock_during_reset_reads(1, self._sleep)

    async def test_reset_sleep_during_the_discard_check(self):
        await self._lock_during_reset_reads(2, self._sleep)

    async def test_reset_lock_button_during_the_resettable_check(self):
        await self._lock_during_reset_reads(1, lambda: self.h.reg.lock(UID, "user"))

    async def test_without_a_lock_nothing_changes(self):
        gate = _Gate()
        gate.proceed.set()
        with gate.wrap("create"):
            r = await self.ui.call("migrate-begin")
        self.assertIn("ticket", r)
        self.assertTrue(self.h.reg.get(UID).unlocked())


class RealStoreTests(unittest.IsolatedAsyncioTestCase):
    """The same with vstore.UserStore, whose create/reset really return a new object."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.seal = FakeSealBackend(tpm=False)
        self._env = vstore_env(Path(self._tmp.name), self.seal)
        self._env.__enter__()
        self.reg = Registry(store_cls=vstore.UserStore)
        self.s = Session(UID, vstore.UserStore.open(UID))
        self.s.settings_loaded = True
        self.reg.sessions[UID] = self.s

    def tearDown(self):
        self.reg.shutdown()
        self._env.__exit__(None, None, None)
        self._tmp.cleanup()

    async def _slow_make(self, make):
        started, proceed = threading.Event(), threading.Event()
        real = self.seal.encrypt

        def slow_encrypt(name, plaintext):          # a seal that sits in systemd-creds
            started.set()
            proceed.wait(10)
            return real(name, plaintext)
        with mock.patch.object(self.seal, "encrypt", slow_encrypt):
            call = asyncio.ensure_future(self.reg.run_store(UID, make, UID, replaces=True))
            self.assertTrue(await asyncio.to_thread(started.wait, 10))
            self.reg.lock(UID, "sleep")
            self.assertTrue(self.s.wipe_after)
            self.assertTrue(self.reg.wipes_pending())
            proceed.set()
            new = await asyncio.wait_for(call, 30)
        self.assertIsNot(new, self.s.store)
        self.assertEqual(new.state(), "locked")      # the new object's keys are gone
        self.assertFalse(self.s.wipe_after)
        self.assertFalse(self.reg.wipes_pending())

    async def test_create(self):
        await self._slow_make(vstore.UserStore.create)

    async def test_reset(self):
        vstore.UserStore.create(UID).lock()
        await self._slow_make(vstore.UserStore.reset)

    async def test_a_cancelled_create_wipes_what_it_made(self):
        # The handler that would have held the new store is gone (its task was cancelled):
        # nobody can lock that object later, so run_store wipes it as the worker returns.
        made = []
        real_create = vstore.UserStore.create.__func__

        def create(cls, uid):
            made.append(real_create(cls, uid))
            return made[-1]
        started, proceed = threading.Event(), threading.Event()
        real = self.seal.encrypt

        def slow_encrypt(name, plaintext):
            started.set()
            proceed.wait(10)
            return real(name, plaintext)
        with mock.patch.object(vstore.UserStore, "create", classmethod(create)), \
                mock.patch.object(self.seal, "encrypt", slow_encrypt):
            call = asyncio.ensure_future(self.reg.run_store(
                UID, vstore.UserStore.create, UID, replaces=True))
            self.assertTrue(await asyncio.to_thread(started.wait, 10))
            call.cancel()
            proceed.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(call, 30)
        self.assertEqual(len(made), 1)
        self.assertEqual(made[0].state(), "locked")
        self.assertFalse(self.reg.wipes_pending())

    async def test_no_lock_leaves_it_unlocked(self):
        new = await self.reg.run_store(UID, vstore.UserStore.create, UID, replaces=True)
        self.assertEqual(new.state(), "unlocked")
        self.assertFalse(self.reg.wipes_pending())


if __name__ == "__main__":
    unittest.main()
