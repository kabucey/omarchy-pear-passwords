"""Fakes for the daemon tests: an in-memory UserStore, a polkit authority, an Apple
pipeline, and a harness that runs the real Server and Registry on a scratch unix socket.

Not a test module (no test_ prefix). Every value here is made up; nothing reads a real vault.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import threading
from dataclasses import replace

from icp import vstore
from icp.daemon import polkit, protocol
from icp.daemon.peer import PeerInfo
from icp.daemon.server import Server
from icp.daemon.sessions import Registry

UID = 4242


def meta(id, title="GitHub", domain="github.com", username="me@example.com", **kw):
    base = dict(id=id, title=title, domain=domain, sites=[], username=username, nickname="",
                has_totp=False, has_notes=False, mdat=1.0, history_count=0)
    base.update(kw)
    return vstore.Meta(**base)


def secrets(password="hunter2-fake", notes="", seed=None, history=None):
    return vstore.Secrets(password=password, notes=notes, totp_secret=seed,
                          apple_history=list(history or []),
                          totp_params={"digits": 6, "period": 30, "algorithm": 0} if seed else {})


class FakeStore:
    """vstore.UserStore in memory. One instance per uid survives across sessions, like the
    files would; `seal_error` makes the next unlock fail with that kind."""

    instances: dict[int, "FakeStore"] = {}

    def __init__(self, uid):
        self.uid = uid
        self.exists = False
        self.keys = False
        self.metas: dict[str, vstore.Meta] = {}
        self.secrets: dict[str, vstore.Secrets] = {}
        self.history_items: dict[str, list] = {}
        self.session: dict = {}
        self.settings: dict = {}
        self.nicknames: dict = {}
        self.seal_error: str | None = None
        self.recorded_state: str | None = None
        self.sealed_with = "host"
        self.unseal_count = 0
        self.synced_at = None
        self.needs_login = False
        self.calls: list[str] = []
        self.imported = None
        self.lock_calls = 0

    # --- lifecycle
    @classmethod
    def reset_all(cls):
        cls.instances = {}
        cls.blocked_reason = None
        cls.resets = []

    @classmethod
    def open(cls, uid):
        return cls.instances.setdefault(uid, cls(uid))

    @classmethod
    def create(cls, uid):
        # Like UserStore.create, the result is a NEW object: locking the one the session held
        # before does not reach it (round 2 audit, problem 2). It keeps whatever a test set on
        # the empty store, and shares its call log.
        old = cls.open(uid)
        if old.exists:
            raise vstore.StoreError("exists")
        st = cls(uid)
        st.__dict__.update({k: v for k, v in old.__dict__.items()
                            if k not in ("exists", "keys", "lock_calls")})
        st.exists = True
        st.keys = True
        st.recorded_state = None
        cls.instances[uid] = st
        st.calls.append("create")
        return st

    resets: list = []                  # discard_empty of every reset(), in order

    @classmethod
    def reset(cls, uid, discard_empty=False):
        cls.resets.append(discard_empty)
        old = cls.open(uid)
        new = cls(uid)
        new.settings = dict(old.settings)
        new.exists = True
        new.keys = True
        cls.instances[uid] = new
        new.calls.append("reset")
        return new

    def state(self):
        if not self.exists:
            return "empty"
        if self.keys:
            return "unlocked"
        return self.recorded_state or "locked"

    def status(self):
        st = self.state()
        return {"state": st, "signed_in": bool(self.session),
                "sealed_with": self.sealed_with if self.exists else None,
                "synced_at": self.synced_at if self.keys else None,
                "needs_login": self.needs_login if self.keys else None}

    blocked_reason = None             # what create_blocked() says (class-wide, like a PEM)

    @classmethod
    def create_blocked(cls):
        return cls.blocked_reason

    def holds_nothing(self):
        return not self.exists or not (self.metas or self.history_items or self.session
                                       or self.nicknames)

    def unlock(self):
        self.calls.append("unlock")
        if self.seal_error:
            self.recorded_state = self.seal_error
            raise vstore.SealError(self.seal_error)
        self.keys = True

    def lock(self):
        self.lock_calls += 1
        self.keys = False

    tpm_state = "no-tpm"

    def tpm_move_state(self):
        return self.tpm_state

    def reseal_if_tpm_available(self):
        self.calls.append("reseal")
        if self.tpm_state != "available" or not self.keys:
            return False
        self.tpm_state = "sealed"
        return True

    def _need(self):
        if not self.keys:
            raise vstore.StoreLocked()

    # --- tier 1
    def list_meta(self):
        self._need()
        return list(self.metas.values())

    def get_meta(self, id):
        self._need()
        if id not in self.metas:
            raise vstore.EntryNotFound(id)
        return self.metas[id]

    def set_sync_status(self, *, synced_at=None, needs_login=None):
        self._need()
        if synced_at is not None:
            self.synced_at = synced_at
        if needs_login is not None:
            self.needs_login = needs_login

    # --- tier 2
    def open_entry(self, id):
        self._need()
        if id not in self.secrets:
            raise vstore.EntryNotFound(id)
        self.unseal_count += 1
        return replace(self.secrets[id])

    def history(self, id):
        self._need()
        self.unseal_count += 1
        return list(self.history_items.get(id, []))

    def set_secrets(self, id, s):
        self.secrets[id] = s

    def apply_sync(self, items, deleted):
        return {"added": 0, "changed": 0, "deleted": 0, "unchanged": len(self.metas)}

    def pwmac_matches(self, texts):
        self._need()
        pw = {s.password for s in self.secrets.values()}
        return [i for i, t in enumerate(texts) if t in pw]

    def load_session(self):
        self._need()
        return dict(self.session)

    def save_session(self, d):
        self._need()
        self.session = dict(d)

    def load_aliases(self):
        return []

    def save_aliases(self, aliases):
        pass

    def load_nicknames(self):
        self._need()
        return dict(self.nicknames)

    def save_nicknames(self, names):
        self._need()
        self.nicknames = dict(names)

    def load_device(self):
        return {}

    def save_device(self, d):
        pass

    def load_settings(self):
        return {**protocol.DEFAULT_SETTINGS, **self.settings}

    def save_settings(self, d):
        self.settings = dict(d)

    def import_v1(self, files, key):
        self._need()
        if files.get("vault.enc") == b"mismatch":
            raise vstore.ImportMismatch()
        self.imported = (dict(files), bytes(key))
        return {"counts": {"credentials": 2, "history": 0, "nicknames": 0, "aliases": 0,
                           "session_keys": 1}, "digest": "ab" * 32}


class FakeAuthority:
    """polkit.Authority with scripted outcomes. With `block` set, check() waits until the test
    calls release() or the registry cancels it."""

    def __init__(self, outcome=polkit.AUTHORIZED):
        self.outcome = outcome
        self.calls: list[tuple] = []
        self.cancels: list[str] = []
        self.block = False
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self.started = threading.Event()

    def check(self, subject, action, details, cancel_id):
        ev = threading.Event()
        with self._lock:
            self.calls.append((subject, action, dict(details), cancel_id))
            self._events[cancel_id] = ev
        self.started.set()
        if self.block:
            ev.wait(10)
            if cancel_id in self.cancels:
                return polkit.CANCELLED
        out = self.outcome
        return out(action, details) if callable(out) else out

    def cancel(self, cancel_id):
        with self._lock:
            self.cancels.append(cancel_id)
            ev = self._events.get(cancel_id)
        if ev:
            ev.set()

    def release(self):
        with self._lock:
            evs = list(self._events.values())
        for ev in evs:
            ev.set()

    def actions(self):
        return [c[1] for c in self.calls]


class FakeApple:
    def __init__(self):
        self.calls: list[str] = []
        self.sync_error = None
        self.login_script = None           # fn(ctx) run by login
        self.apple_named: set = set()      # ids whose rename Apple can hold (a details record)
        self.shape = None                  # what a sync reports as ctx.item_shape

    def sync(self, ctx):
        self.calls.append("sync")
        if self.sync_error:
            raise self.sync_error
        if self.shape is not None:
            ctx.item_shape = self.shape
        return {"added": 0, "changed": 1, "deleted": 0, "unchanged": 1, "synced_at": 123.0}

    def login(self, ctx):
        self.calls.append("login")
        if self.login_script:
            self.login_script(ctx)
        ctx.store.save_session({"dsid": "fake"})

    def relogin(self, ctx):
        self.calls.append("relogin")

    def push_set(self, ctx, id, fields):
        self.calls.append(("push_set", id, sorted(fields)))
        self.last_fields = dict(fields)
        if not ctx.store.session:
            from icp.daemon.apple import NotSignedIn
            raise NotSignedIn("not signed in to iCloud")
        if "password" in fields:
            ctx.store.secrets[id] = replace(ctx.store.secrets[id], password=fields["password"])
        if "nickname" in fields:           # apple.push_set's rule: iCloud if it can, else local
            if id in self.apple_named or not fields["nickname"]:
                ctx.store.nicknames.pop(id, None)
            else:
                ctx.store.nicknames[id] = fields["nickname"]

    def create(self, ctx, fields):
        self.calls.append(("create", sorted(fields)))
        return "new.1"

    def delete(self, ctx, id):
        self.calls.append(("delete", id))
        ctx.store.metas.pop(id, None)

    def fetch_aliases(self, ctx):
        return 0

    def signout(self, ctx):
        self.calls.append("signout")
        ctx.store.save_session({})


class Client:
    """A line-JSON client over a real unix socket."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.rid = 0
        self.replies: dict[int, asyncio.Future] = {}
        self.events: list[dict] = []
        self.event_q: asyncio.Queue = asyncio.Queue()
        self.raw: list[dict] = []
        self.closed = asyncio.Event()
        self._task = asyncio.get_running_loop().create_task(self._pump())

    async def _pump(self):
        try:
            while True:
                line = await self.reader.readline()
                if not line.endswith(b"\n"):
                    break                      # EOF, possibly mid-line at teardown
                obj = json.loads(line)
                self.raw.append(obj)
                if "event" in obj:
                    self.events.append(obj)
                    self.event_q.put_nowait(obj)
                    continue
                fut = self.replies.pop(obj.get("rid"), None)
                if fut is not None and not fut.done():
                    fut.set_result(obj)
        finally:
            self.closed.set()
            for fut in self.replies.values():
                if not fut.done():
                    fut.set_result(None)

    def send_raw(self, data: bytes):
        self.writer.write(data)

    def send(self, op, **fields) -> asyncio.Future:
        self.rid += 1
        rid = fields.pop("rid", self.rid)
        fut = asyncio.get_running_loop().create_future()
        self.replies[rid] = fut
        self.writer.write((json.dumps({"op": op, "rid": rid, **fields}) + "\n").encode())
        return fut

    # 30 s: only a failing test waits that long, and the gate VM under load timed out at 5 s.
    async def call(self, op, timeout=30, **fields):
        return await asyncio.wait_for(self.send(op, **fields), timeout)

    async def event(self, name, timeout=30):
        while True:
            for e in self.events:
                if e["event"] == name and not e.get("_seen"):
                    e["_seen"] = True
                    return e
            await asyncio.wait_for(self.event_q.get(), timeout)

    def close(self):
        self.writer.close()


class Harness:
    """The real Server + Registry with fakes behind them, on a scratch socket."""

    def __init__(self, *, authority=None, apple=None, clock=None, wall=None):
        FakeStore.reset_all()
        self.authority = authority or FakeAuthority()
        self.apple = apple or FakeApple()
        kw = {}
        if clock:
            kw["clock"] = clock
        if wall:
            kw["wall"] = wall
        self.parent_start: dict[int, int] = {}
        self.reg = Registry(store_cls=FakeStore, authority=self.authority, apple=self.apple,
                            parent_start_time=lambda pid: self.parent_start.get(pid), **kw)
        self.peers: list[PeerInfo] = []
        self.server = Server(self.reg, verify_peer=self._verify)
        self.dir = tempfile.mkdtemp(prefix="pearwp1-")
        self.path = os.path.join(self.dir, "s")
        self.srv = None
        self.clients: list[Client] = []
        self._pid = 50000

    def _verify(self, sock):
        if not self.peers:
            from icp.daemon.peer import PeerError
            raise PeerError("no fake peer queued")
        return self.peers.pop(0)

    async def start(self):
        import socket as _s
        sock = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        sock.bind(self.path)
        sock.listen()
        sock.setblocking(False)
        self.srv = await self.server.start(sock)
        return self

    async def stop(self):
        for c in self.clients:
            c.close()
        await asyncio.sleep(0.05)
        if self.srv:
            self.srv.close()
        self.reg.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def peer(self, *, uid=UID, pid=None, ppid=1, start_time=None) -> PeerInfo:
        if pid is None:
            self._pid += 1
            pid = self._pid
        st = start_time if start_time is not None else pid * 10
        self.parent_start[pid] = st
        return PeerInfo(pid=pid, uid=uid, gid=999, pidfd=os.pidfd_open(os.getpid()),
                        start_time=st, ppid=ppid)

    async def connect(self, peer=None) -> Client:
        self.peers.append(peer or self.peer())
        reader, writer = await asyncio.open_unix_connection(self.path, limit=16 * 1024 * 1024)
        c = Client(reader, writer)
        self.clients.append(c)
        return c

    async def syncs_done(self, timeout=30) -> None:
        """Wait for every background sync running in the daemon to end. The daemon starts one
        right after an unlock's reply is queued (the task exists before the client reads the
        reply); while it runs, create/delete/set/signin/signout/tpm-move are refused
        busy-sync and raise no dialog."""
        me = asyncio.current_task()
        tasks = [t for t in asyncio.all_tasks()
                 if t is not me and getattr(t.get_coro(), "__qualname__", "") == "background_sync"]
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout)

    async def unlock(self, c, **fields) -> dict:
        """`unlock` on window `c`, then wait out the sync it starts (round 2 gate finding 4:
        an op sent meanwhile was sometimes refused busy-sync, so tests that expected its
        dialog failed under load)."""
        r = await c.call("unlock", **fields)
        await self.syncs_done()
        return r

    async def enable_autofill(self, uid=UID) -> None:
        """What `autofill-enable {enabled:true}` in the window leaves behind."""
        (await self.reg.session_for(uid)).autofill_enabled = True

    async def hello(self, role="ui", peer=None, **fields) -> tuple[Client, dict]:
        c = await self.connect(peer)
        reply = await c.call("hello", role=role, proto=2, rid=0, **fields)
        return c, reply

    async def ui(self, uid=UID, **kw) -> tuple[Client, PeerInfo]:
        p = self.peer(uid=uid, **kw)
        c, reply = await self.hello("ui", peer=p)
        assert "error" not in reply, reply
        c.hello = reply
        return c, p

    def store(self, uid=UID) -> FakeStore:
        return FakeStore.open(uid)

    def seed(self, uid=UID, n=2, signed_in=True):
        st = self.store(uid)
        st.exists = True
        st.keys = False
        for i in range(n):
            id = f"e.{i}"
            st.metas[id] = meta(id, title=f"Site {i}", domain=f"site{i}.example",
                                username=f"user{i}", has_notes=(i == 0), has_totp=(i == 0),
                                history_count=1 if i == 0 else 0)
            st.secrets[id] = secrets(password=f"pw-{i}-fake", notes="note" if i == 0 else "",
                                     seed=b"12345678901234567890" if i == 0 else None,
                                     history=[{"date": "2026-01-01T00:00:00Z",
                                               "value": "old-apple"}] if i == 0 else [])
            st.history_items[id] = [("2026-01-01T00:00:00Z", "old-apple"),
                                    ("2026-02-01T00:00:00Z", "old-local")] if i == 0 else []
        if signed_in:
            st.session = {"dsid": "fake"}
        return st


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt
