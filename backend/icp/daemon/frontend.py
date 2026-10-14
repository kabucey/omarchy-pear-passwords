"""The sign-in frontend that draws in the Pear window: context.Frontend over the socket.

The Apple pipeline's login and relogin run in a worker thread and call emit / stage / ask / secret /
confirm_yn / choose exactly as they call cli/jsonui.py during development. Each call here becomes
an event carrying the signin request's rid (docs/protocol.md 9.2); a question blocks the worker
until the window's `answer` op arrives on the event loop. Cancelling - an `answer` with cancel,
a `cancel` op on the signin rid, a lock, or the window closing - raises context.Cancelled in the
worker, which is a KeyboardInterrupt so no broad `except Exception` in the Apple code eats it.

Answers are never logged. Secrets typed into the window travel in this process's memory only.
"""

from __future__ import annotations

import concurrent.futures
import itertools
import json
import threading

from .context import Cancelled

_CANCEL = object()


def _jsonable(value):
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


class SocketFrontend:
    def __init__(self, loop, conn, rid: int):
        self._loop = loop
        self._conn = conn
        self._rid = rid
        self._ids = itertools.count(1)
        self._asks: dict[int, concurrent.futures.Future] = {}
        self._lock = threading.Lock()
        self._cancelled = False

    # --- worker side ------------------------------------------------------------------------
    def _post(self, event: dict) -> None:
        event = {"event": event.pop("event"), "rid": self._rid, **event}

        def send():
            if not self._conn.closed:
                self._conn.send_event(event)
        self._loop.call_soon_threadsafe(send)

    def _await(self, need: str, prompt: str, kind, **extra) -> str:
        with self._lock:
            if self._cancelled:
                raise Cancelled("sign-in cancelled")
            ask_id = next(self._ids)
            fut: concurrent.futures.Future = concurrent.futures.Future()
            self._asks[ask_id] = fut
        self._post({"event": "ask", "ask_id": ask_id, "need": need, "kind": kind,
                    "prompt": str(prompt), **extra})
        try:
            value = fut.result()
        finally:
            with self._lock:
                self._asks.pop(ask_id, None)
        if value is _CANCEL:
            raise Cancelled("sign-in cancelled")
        return value

    def emit(self, kind: str, text: str) -> None:
        self._post({"event": "out", "kind": str(kind), "text": str(text)})

    def stage(self, stage_name: str, **info) -> None:
        self._post({"event": "stage", "stage": str(stage_name),
                    "info": {str(k): _jsonable(v) for k, v in info.items()}})

    def ask(self, prompt: str, kind: str | None = None, default: str | None = None) -> str:
        return self._await("text", prompt, kind, default=default, detail=None).strip()

    def secret(self, prompt: str, kind: str | None = None, detail: str | None = None) -> str:
        return self._await("secret", prompt, kind, default=None, detail=detail)

    def confirm_yn(self, prompt: str, kind: str | None = None,
                   detail: str | None = None) -> bool:
        reply = self._await("confirm", prompt, kind, default=None, detail=detail)
        return reply.strip().lower() in ("y", "yes", "true")

    def choose(self, prompt: str, options: list, kind: str | None = None,
               details: list | None = None) -> int | None:
        reply = self._await("choice", prompt, kind, default=None, detail=None,
                            options=[str(o) for o in options],
                            details=[str(d) for d in (details or [""] * len(options))])
        reply = reply.strip()
        return int(reply) if reply.isdigit() and int(reply) < len(options) else None

    # --- event-loop side --------------------------------------------------------------------
    def answer(self, ask_id, value=None, cancel: bool = False) -> bool:
        """Deliver the window's answer. False for an unknown or already answered ask_id."""
        with self._lock:
            fut = self._asks.get(ask_id) if isinstance(ask_id, int) else None
            if fut is None or fut.done():
                return False
            if cancel:
                self._cancelled = True
                for f in self._asks.values():
                    if not f.done():
                        f.set_result(_CANCEL)
                return True
            fut.set_result("" if value is None else str(value))
            return True

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            for f in self._asks.values():
                if not f.done():
                    f.set_result(_CANCEL)

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def rid(self) -> int:
        return self._rid

    @property
    def conn(self):
        return self._conn
