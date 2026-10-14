"""Background timing: the 2-hourly sync of unlocked uids, and the optional idle relock.

2.0 has no sync lease. Only a uid whose tier 1 is open in the Pear window has a schedule at all;
a locked uid has none, so nothing here can ever need a key that is not already in memory, and
nothing here can ever ask anyone anything. This module deliberately knows nothing about the
module that raises dialogs: it does not import it, name it, or set any interaction flag, and
backend/tests/test_scheduler_no_prompt.py walks its AST to keep it that way. It drives the
registry by duck typing (sessions, lock, check_grant_expiry) for the same reason.

Idle relock defaults to five minutes; the user may explicitly change it in Settings.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import random
import time
from typing import Awaitable, Callable

from . import protocol

logger = logging.getLogger(__name__)

TICK_S = 5.0


class Scheduler:
    def __init__(self, registry, run_sync: Callable[[int], Awaitable], *,
                 clock: Callable[[], float] = time.monotonic, rng: random.Random | None = None,
                 tick_s: float = TICK_S):
        self._reg = registry
        self._run_sync = run_sync
        self._clock = clock
        self._rng = rng or random.SystemRandom()
        self._tick_s = tick_s

    def interval(self) -> float:
        return protocol.SYNC_INTERVAL_S + self._rng.uniform(-protocol.SYNC_JITTER_S,
                                                            protocol.SYNC_JITTER_S)

    def tick(self) -> list[tuple[str, int]]:
        """One pass: idle locks first, then due syncs. Returns what it decided, as
        ("idle-lock" | "sync", uid) pairs; syncs are for the caller to start."""
        now = self._clock()
        actions: list[tuple[str, int]] = []
        for s in list(self._reg.sessions.values()):
            if not s.unlocked():
                if s.next_sync_at is not None and now >= s.next_sync_at:
                    logger.info("uid %d: locked: skipped", s.uid)
                    s.next_sync_at = None
                continue
            idle = s.settings.get("idle_lock_s", protocol.IDLE_LOCK_S_DEFAULT)
            if idle and now - s.last_ui_request >= idle:
                self._reg.lock(s.uid, "idle")
                actions.append(("idle-lock", s.uid))
                continue
            if s.next_sync_at is None:
                # Tier 1 just opened, and that unlock ran its own sync.
                s.next_sync_at = now + self.interval()
                continue
            if now >= s.next_sync_at:
                s.next_sync_at = now + self.interval()
                actions.append(("sync", s.uid))
        self._reg.check_grant_expiry()
        return actions

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                for kind, uid in self.tick():
                    if kind == "sync":
                        loop.create_task(self._sync(uid), context=contextvars.Context())
            except Exception:
                logger.exception("scheduler tick failed")
            await asyncio.sleep(self._tick_s)

    async def _sync(self, uid: int) -> None:
        try:
            outcome = await self._run_sync(uid)
            logger.info("uid %d: scheduled sync: %s", uid, outcome)
        except Exception:
            logger.exception("uid %d: scheduled sync failed", uid)
