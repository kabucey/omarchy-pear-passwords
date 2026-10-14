"""A lock never waits on the event loop (audit: event-loop stall in lock()).

Registry.lock() runs on the event loop, which serves every uid. A store call can sit in
systemd-creds for up to a minute on a slow TPM. The lock must return at once: wipe now when
nothing holds the store, otherwise flag wipe-after, refuse new store calls for that uid, and
wipe the moment the running call returns. PrepareForSleep holds the suspend back for about a
second at the most.
"""

import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fixtures import FakeSealBackend, vstore_env

from icp import vstore
from icp.daemon import logind
from icp.daemon.protocol import OpError
from icp.daemon.sessions import Registry, Session
from icp.vstore import entries as E
from icp.vstore import ids

UID = 1000


def item(domain, username, pw):
    id = ids.entry_id(domain, username)
    meta = vstore.Meta(id=id, title=domain, domain=domain, sites=[], username=username,
                       nickname="", has_totp=False, has_notes=False, mdat=1.0,
                       history_count=0)
    return vstore.SyncItem(id=id, meta=meta, secrets=vstore.Secrets(
        password=pw, notes="", totp_secret=None, apple_history=[], totp_params={}))


class RegistryLockTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = vstore_env(Path(self._tmp.name), FakeSealBackend(tpm=False))
        self._env.__enter__()
        self.store = vstore.UserStore.create(UID)
        self.store.apply_sync([item("a.example.test", "me", "pw-a")], set())
        self.reg = Registry(store_cls=vstore.UserStore)
        self.s = Session(UID, self.store)
        self.s.settings_loaded = True
        self.reg.sessions[UID] = self.s

    def tearDown(self):
        self.reg.shutdown()
        self._env.__exit__(None, None, None)
        self._tmp.cleanup()

    async def test_lock_returns_at_once_while_a_store_call_runs(self):
        started, proceed = threading.Event(), threading.Event()
        real = E.EntryFiles.write

        def slow_write(files, id, blob):          # a systemd-creds call that hangs
            real(files, id, blob)
            started.set()
            proceed.wait(10)
        with mock.patch.object(E.EntryFiles, "write", slow_write):
            call = asyncio.ensure_future(self.reg.run_store(
                UID, self.store.apply_sync, [item("a.example.test", "me", "pw-a2")], set()))
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            t0 = time.monotonic()
            self.reg.lock(UID, "sleep")
            self.assertLess(time.monotonic() - t0, 0.5, "lock() waited for the store call")
            self.assertTrue(self.s.wipe_after)
            self.assertTrue(self.reg.wipes_pending())
            # Any new store call for this uid is refused at once, not queued.
            with self.assertRaises(OpError) as cm:
                await asyncio.wait_for(self.reg.run_store(UID, self.store.list_meta), 0.5)
            self.assertEqual(cm.exception.code, "locked")
            proceed.set()
            await asyncio.wait_for(call, 5)
        self.assertEqual(self.store.state(), "locked")      # wiped as the call returned
        self.assertFalse(self.s.wipe_after)
        self.assertFalse(self.reg.wipes_pending())
        # Nothing was half-applied.
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual(s2.open_entry(ids.entry_id("a.example.test", "me")).password, "pw-a2")

    async def test_keyless_reads_are_served_while_a_wipe_is_pending(self):
        # Round 2 audit note (a): a window opened during a pending wipe got "the background
        # service refused this window (locked)", because hello's status went through the
        # refusing path. status/state/load_settings read no key.
        started, proceed = threading.Event(), threading.Event()
        real = E.EntryFiles.write

        def slow_write(files, id, blob):
            real(files, id, blob)
            started.set()
            proceed.wait(10)
        with mock.patch.object(E.EntryFiles, "write", slow_write):
            call = asyncio.ensure_future(self.reg.run_store(
                UID, self.store.apply_sync, [item("a.example.test", "me", "pw-a2")], set()))
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            self.reg.lock(UID, "user")
            self.assertTrue(self.s.wipe_after)
            st = await asyncio.wait_for(
                self.reg.run_store(UID, self.store.status, keyless=True), 2)
            self.assertIn(st["state"], ("locked", "unlocked"))
            self.assertIsInstance(await asyncio.wait_for(
                self.reg.run_store(UID, self.store.load_settings, keyless=True), 2), dict)
            # Only those: anything else asked for keyless is refused.
            with self.assertRaises(OpError):
                await self.reg.run_store(UID, self.store.list_meta, keyless=True)
            proceed.set()
            await asyncio.wait_for(call, 5)
        self.assertEqual(self.store.state(), "locked")

    async def test_lock_with_nothing_running_wipes_now(self):
        self.reg.lock(UID, "user")
        self.assertEqual(self.store.state(), "locked")
        self.assertFalse(self.s.wipe_after)


class LockInsideOneStoreCallTests(unittest.IsolatedAsyncioTestCase):
    """Round 2 audit, problem 2: one run_store call can be many store calls (a sync is a
    session save, a nickname read, apply_sync and a status write). A lock landing during
    one of them must stop the rest: the keys are wiped the moment that store method returns,
    and every later store method in the same call is refused."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = vstore_env(Path(self._tmp.name), FakeSealBackend(tpm=False))
        self._env.__enter__()
        self.store = vstore.UserStore.create(UID)
        self.store.apply_sync([item("a.example.test", "me", "pw-a")], set())
        self.reg = Registry(store_cls=vstore.UserStore)
        self.s = Session(UID, self.store)
        self.s.settings_loaded = True
        self.reg.sessions[UID] = self.s

    def tearDown(self):
        self.reg.shutdown()
        self._env.__exit__(None, None, None)
        self._tmp.cleanup()

    async def _lock_during_first_step(self, steps):
        started, proceed = threading.Event(), threading.Event()
        real = E.EntryFiles.write
        first = {"done": False}

        def slow_write(files, id, blob):
            real(files, id, blob)
            if not first["done"]:
                first["done"] = True
                started.set()
                proceed.wait(10)
        with mock.patch.object(E.EntryFiles, "write", slow_write):
            call = asyncio.ensure_future(self.reg.run_store(UID, steps, self.store))
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            self.reg.lock(UID, "screen-locked")
            proceed.set()
            return await asyncio.wait_for(asyncio.gather(call, return_exceptions=True), 10)

    async def test_the_rest_of_a_multi_step_call_is_refused_after_a_lock(self):
        seen = {}

        def sync_like(store):
            store.apply_sync([item("a.example.test", "me", "pw-a2")], set())
            seen["keys_after_step_1"] = store.state()
            try:
                store.list_meta()
                seen["list_meta"] = "served"
            except vstore.StoreLocked:
                seen["list_meta"] = "refused"
            store.apply_sync([item("b.example.test", "you", "pw-b")], set())
            seen["step_3"] = "ran"
        (res,) = await self._lock_during_first_step(sync_like)
        self.assertIsInstance(res, vstore.StoreLocked)
        self.assertEqual(seen["keys_after_step_1"], "locked")   # wiped as step 1 returned
        self.assertEqual(seen["list_meta"], "refused")
        self.assertNotIn("step_3", seen)
        self.assertEqual(self.store.state(), "locked")
        self.assertFalse(self.s.wipe_after)
        # Step 1 completed whole; nothing was written after the lock.
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual([m.domain for m in s2.list_meta()], ["a.example.test"])
        self.assertEqual(s2.open_entry(ids.entry_id("a.example.test", "me")).password, "pw-a2")

    async def test_the_store_opens_again_after_such_a_lock(self):
        def steps(store):
            store.apply_sync([item("a.example.test", "me", "pw-a2")], set())
            store.list_meta()
        await self._lock_during_first_step(steps)
        self.assertFalse(self.store._wipe_req)
        await self.reg.run_store(UID, self.store.unlock)        # no wipe request left over
        self.assertEqual(len(await self.reg.run_store(UID, self.store.list_meta)), 1)

    async def test_lock_pending_is_seen_while_the_call_still_runs(self):
        seen = {}

        def steps(store):
            store.apply_sync([item("a.example.test", "me", "pw-a2")], set())
            seen["pending"] = store.lock_pending()
        await self._lock_during_first_step(steps)
        self.assertTrue(seen["pending"])


class AppleSyncStopsAfterALockTests(unittest.TestCase):
    """apple.sync checks between its network steps and stops once the user has locked."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = vstore_env(Path(self._tmp.name), FakeSealBackend(tpm=False))
        self._env.__enter__()
        self.store = vstore.UserStore.create(UID)

    def tearDown(self):
        self._env.__exit__(None, None, None)
        self._tmp.cleanup()

    def test_a_lock_during_the_token_refresh_stops_before_the_keychain_fetch(self):
        from icp.daemon import apple
        from icp.daemon.context import UserContext
        fetched = []

        class Client:
            def __init__(self, *a, **kw):
                fetched.append("client")

            def sync_and_decrypt(self, **kw):
                fetched.append("fetch")
                return []

        def tokens_then_lock(ctx, s, device, anisette):
            ctx.store.try_lock()             # the user locks while Apple answers
        ctx = UserContext(UID, self.store, "http://127.0.0.1:1", None)
        with mock.patch.object(apple, "_session", lambda ctx: {"x": 1}), \
                mock.patch.object(apple, "_device", lambda ctx: (None, None)), \
                mock.patch.object(apple, "_fresh_tokens", tokens_then_lock), \
                mock.patch("icp.octagon.client.OctagonClient", Client), \
                mock.patch.object(apple, "fetch_aliases") as aliases:
            with self.assertRaises(vstore.StoreLocked):
                apple.sync(ctx)
        self.assertEqual(fetched, [])
        aliases.assert_not_called()

    def test_a_lock_during_the_fetch_stops_before_anything_is_applied(self):
        from icp.daemon import apple
        from icp.daemon.context import UserContext
        store = self.store

        class Client:
            failed_zones = []

            def sync_and_decrypt(self, **kw):
                store.try_lock()
                return [item("b.example.test", "you", "pw-b")]
        ctx = UserContext(UID, store, "http://127.0.0.1:1", None)
        with mock.patch.object(vstore.UserStore, "apply_sync") as applied:
            with self.assertRaises(vstore.StoreLocked):
                apple._sync_with(ctx, {}, None, None, client=Client())
        applied.assert_not_called()


class SleepWaitTests(unittest.TestCase):
    def test_prepare_for_sleep_never_holds_the_suspend_past_about_a_second(self):
        log = []

        class Inh:
            def close(self):
                log.append("released")
        w = logind.LogindWatcher(on_lock=lambda *a: None, on_sleep=lambda: log.append("wipe"),
                                 call_in_loop=lambda fn, **kw: fn(),
                                 take_inhibitor=lambda: Inh(),
                                 pending=lambda: True)     # a store call that never returns
        w.take_inhibitor()
        t0 = time.monotonic()
        w.before_sleep()
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertEqual(log, ["wipe", "released"])
        self.assertLessEqual(logind.SLEEP_WAIT_S, 1.0)

    def test_sleep_waits_for_a_pending_wipe_that_finishes(self):
        state = {"n": 0}

        def pending():
            state["n"] += 1
            return state["n"] < 3
        w = logind.LogindWatcher(on_lock=lambda *a: None, on_sleep=lambda: None,
                                 call_in_loop=lambda fn, **kw: fn(), take_inhibitor=lambda: None,
                                 pending=pending)
        w.before_sleep()
        self.assertGreaterEqual(state["n"], 3)


if __name__ == "__main__":
    unittest.main()
