"""autofill-query and autofill-fill against a fake SessionRegistry (daemon/autofill.py).

The fake follows docs/protocol.md section 5 for authorize(): one outstanding dialog and three
answered dialogs per minute per (uid, bucket), with the bucket taken from the connection's role,
no-agent and busy not counted. What is under test is the handlers: a locked Pear says nothing
and never prompts, unknown and non-matching ids look the same, every fill raises its own dialog
on the autofill connection, and everything is re-checked after the dialog.
"""

import asyncio
import os
import time
import unittest

from icp.daemon import autofill, paths, protocol
from icp.daemon.protocol import OpError
from icp.vstore import EntryNotFound, Meta, Secrets, StoreLocked

FAKE_PW = "fixture-password-not-real"


def meta(id, domain, username="me", title="", sites=(), aliases=(), mdat=0.0, nickname=""):
    return Meta(id=id, title=title or domain, domain=domain, sites=list(sites),
                username=username, nickname=nickname, has_totp=False, has_notes=False,
                mdat=mdat, history_count=0, aliases=list(aliases))


class FakeStore:
    def __init__(self, metas, state="locked"):
        self.metas = {m.id: m for m in metas}
        self.state_value = state
        self.calls = []
        self.unseal_count = 0
        self.on_open = None

    def state(self):
        self.calls.append("state")
        return self.state_value

    def list_meta(self):
        self.calls.append("list_meta")
        if self.state_value != "unlocked":
            raise StoreLocked()
        return list(self.metas.values())

    def get_meta(self, id):
        self.calls.append("get_meta")
        if self.state_value != "unlocked":
            raise StoreLocked()
        if id not in self.metas:
            raise EntryNotFound(id)
        return self.metas[id]

    def open_entry(self, id):
        self.calls.append("open_entry")
        if self.state_value != "unlocked":
            raise StoreLocked()
        if id not in self.metas:
            raise EntryNotFound(id)
        self.unseal_count += 1
        if self.on_open:
            self.on_open()
        return Secrets(password=FAKE_PW + ":" + id, notes="fixture notes", totp_secret=b"seed",
                       apple_history=[])


class FakeConn:
    def __init__(self, uid=1000, role="autofill"):
        self.uid, self.role = uid, role
        self.pid, self.pidfd, self.start_time = 4242, -1, 1
        self.closed = False
        self.events = []

    def send_event(self, event):
        self.events.append(event)


class FakeSession:
    def __init__(self, uid, store, ui=None, unlocked=False):
        self.uid, self.store, self.ui = uid, store, ui
        self.settings = dict(protocol.DEFAULT_SETTINGS)
        self._unlocked = unlocked
        self.autofill_enabled = True
        self.autofill_key = os.urandom(32) if unlocked else None
        self.epoch = 0

    def unlocked(self):
        return self._unlocked and self.ui is not None

    def lock(self):
        self._unlocked = False
        self.epoch += 1
        self.autofill_key = None
        self.store.state_value = "locked"


class FakeRegistry:
    """protocol.SessionRegistry with the documented prompt rules."""

    def __init__(self):
        self.sessions = {}
        self.ui_events = []
        self.dialogs = []                # (conn, action, details) for every dialog SHOWN
        self.answers = []                # scripted results, default "approve"
        self.during = None               # called while a dialog is up
        self.gate = None                 # an asyncio.Event a dialog waits on, if set
        self.outstanding = set()
        self.answered = {}               # (uid, bucket) -> [timestamps]
        self.clock = time.monotonic

    def get(self, uid):
        return self.sessions.get(uid)

    def connections(self, uid, role):
        return []

    async def authorize(self, conn, action, details):
        bucket = protocol.PROMPT_BUCKET[conn.role]
        key = (conn.uid, bucket)
        if key in self.outstanding:
            raise OpError("prompt-pending")
        now = self.clock()
        recent = [t for t in self.answered.get(key, []) if now - t < 60]
        self.answered[key] = recent
        if len(recent) >= protocol.PROMPT_ANSWERED_PER_MIN:
            raise OpError("rate-limited", retry_after=int(60 - (now - recent[0])) + 1)
        self.outstanding.add(key)
        try:
            answer = self.answers.pop(0) if self.answers else "approve"
            if answer in ("no-agent", "busy"):
                raise OpError(answer)
            self.dialogs.append((conn, action, dict(details)))
            if self.gate is not None:
                await self.gate.wait()
            if self.during:
                self.during()
            if conn.closed:
                raise OpError("cancelled")
            recent.append(self.clock())
            if answer != "approve":
                raise OpError(answer)
        finally:
            self.outstanding.discard(key)

    async def run_store(self, uid, fn, *args):
        return await asyncio.to_thread(fn, *args)

    def notify_ui(self, uid, event):
        self.ui_events.append((uid, event))


def run(coro):
    return asyncio.run(coro)


class Base(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore([
            meta("gh1", "github.com", username="alice", mdat=10),
            meta("gh2", "github.com", username="bob", mdat=20),
            meta("gist", "gist.github.com", username="carol"),
            meta("other", "example.org", username="dave", aliases=["github.com"]),
            meta("sited", "example.net", username="erin", sites=["github.com"], mdat=5),
        ])
        self.reg = FakeRegistry()
        self.ui = FakeConn(role="ui")
        self.conn = FakeConn()
        self.session = FakeSession(1000, self.store, ui=self.ui)
        self.reg.sessions[1000] = self.session

    def unlock(self):
        self.session._unlocked = True
        self.session.autofill_key = os.urandom(32)
        self.store.state_value = "unlocked"

    def h(self, id):
        """The handle an autofill client sees for entry `id` in this unlock."""
        return autofill.handle_for(self.session.autofill_key, id)

    def query(self, origin="https://github.com", conn=None):
        return run(autofill.handle_autofill_query(self.reg, conn or self.conn,
                                                  {"op": "autofill-query", "origin": origin}))

    def fill(self, id="gh1", origin="https://github.com", conn=None, raw=False):
        if not raw and self.session.autofill_key is not None:
            id = self.h(id)
        return run(autofill.handle_autofill_fill(self.reg, conn or self.conn,
                                                 {"op": "autofill-fill", "origin": origin,
                                                  "id": id}))

    def fill_error(self, *a, **kw):
        with self.assertRaises(OpError) as cm:
            self.fill(*a, **kw)
        return cm.exception


class LockedRevealsNothingTests(Base):
    def test_query_while_locked_is_one_word(self):
        for origin in ("https://github.com", "https://example.org", "https://nothing.invalid"):
            self.assertEqual(self.query(origin), {"state": "locked"}, origin)
        self.assertEqual(set(self.store.calls), {"state"})
        self.assertEqual(self.reg.dialogs, [])
        self.assertEqual(self.reg.ui_events, [])

    def test_fill_while_locked_never_prompts_or_reads(self):
        for id in ("gh1", "nope", "other"):
            e = self.fill_error(id)
            self.assertEqual((e.code, e.extra), ("locked", {}), id)
        self.assertEqual(self.store.calls, [])
        self.assertEqual(self.reg.dialogs, [])
        self.assertEqual(self.store.unseal_count, 0)
        self.assertEqual(self.reg.ui_events, [])

    def test_store_unlocked_without_a_ui_counts_as_locked(self):
        # tier 1 belongs to the window's connection; a store left unlocked without one (a
        # migration in progress, a race with EOF) is still locked to autofill.
        self.store.state_value = "unlocked"
        self.session.ui = None
        self.session._unlocked = True
        self.assertEqual(self.query(), {"state": "locked"})
        self.assertEqual(self.fill_error().code, "locked")
        self.assertNotIn("list_meta", self.store.calls)

    def test_no_session_at_all(self):
        self.reg.sessions.clear()
        self.assertEqual(self.query(), {"state": "locked"})
        self.assertEqual(self.fill_error().code, "locked")

    def test_broken_or_empty_store_is_unavailable_and_nothing_more(self):
        for state in ("empty",) + protocol.SEAL_STATES:
            self.store.state_value = state
            self.assertEqual(self.query(), {"state": "unavailable"}, state)
            self.assertEqual(self.fill_error().code, "locked", state)
        self.assertEqual(self.reg.dialogs, [])

    def test_origin_is_still_validated_while_locked(self):
        with self.assertRaises(OpError) as cm:
            self.query("http://github.com")
        self.assertEqual(cm.exception.code, "insecure-origin")
        with self.assertRaises(OpError) as cm:
            self.query("https://user@github.com")
        self.assertEqual(cm.exception.code, "bad-origin")
        for req in ({}, {"origin": 5}, {"origin": None}):
            with self.assertRaises(OpError) as cm:
                run(autofill.handle_autofill_query(self.reg, self.conn, req))
            self.assertEqual(cm.exception.code, "bad-request")
        with self.assertRaises(OpError) as cm:
            run(autofill.handle_autofill_fill(self.reg, self.conn,
                                              {"origin": "https://github.com"}))
        self.assertEqual(cm.exception.code, "bad-request")


class QueryTests(Base):
    def test_lists_matching_accounts_ranked_without_secrets(self):
        self.unlock()
        r = self.query()
        self.assertEqual(r["state"], "unlocked")
        self.assertEqual(r["host"], "github.com")
        ids = [a["id"] for a in r["accounts"]]
        # exact (newest first: bob 20, alice 10, erin 5 via sites), then related
        self.assertEqual(ids, [self.h(i) for i in ("gh2", "gh1", "sited", "gist")])
        self.assertNotIn(self.h("other"), ids)               # aliases never match
        for a in r["accounts"]:
            self.assertEqual(set(a), {"id", "match"})        # no names before a fill
        self.fill("gh2")                                      # one approved fill...
        r = self.query()
        for a in r["accounts"]:
            self.assertEqual(set(a), {"id", "username", "label", "match"})
        self.assertEqual(r["accounts"][0]["label"], "github.com — bob")
        self.assertEqual([a["match"] for a in r["accounts"]],
                         ["exact", "exact", "exact", "related"])
        self.assertNotIn(FAKE_PW, repr(r))

    def test_no_query_ever_unseals_or_prompts(self):
        self.unlock()
        self.query()
        self.assertEqual(self.store.unseal_count, 0)
        self.assertEqual(self.reg.dialogs, [])

    def test_names_need_an_approved_fill_on_this_connection_since_the_unlock(self):
        # escape-autofill-role-ungated: any program of yours can open an autofill
        # connection; it does not get the account list without a dialog.
        self.unlock()
        self.assertEqual(self.fill_error("gh1", origin="https://example.invalid").code,
                         "no-match")                          # no dialog, no approval
        self.reg.answers = ["denied"]
        self.assertEqual(self.fill_error("gh1").code, "denied")
        for a in self.query()["accounts"]:
            self.assertNotIn("username", a)
            self.assertNotIn("label", a)
        self.fill("gh1")
        self.assertIn("username", self.query()["accounts"][0])
        other = FakeConn()
        self.assertNotIn("username", self.query(conn=other)["accounts"][0])
        self.session.lock()
        self.unlock()
        self.assertNotIn("username", self.query()["accounts"][0])   # a new unlock, again

    def names(self, origin="https://github.com", conn=None):
        return run(autofill.handle_autofill_names(self.reg, conn or self.conn,
                                                  {"op": "autofill-names", "origin": origin}))

    def test_names_for_one_site_cost_one_dialog_and_no_secret(self):
        self.unlock()
        r = self.names()
        self.assertEqual(self.reg.dialogs, [(self.conn, paths.ACTION_AUTOFILL_NAMES,
                                             {"origin": "github.com"})])
        self.assertEqual([a["username"] for a in r["accounts"]], ["bob", "alice", "erin", "carol"])
        self.assertEqual(r["accounts"][0]["label"], "github.com — bob")
        self.assertEqual(self.store.unseal_count, 0)
        self.assertNotIn(FAKE_PW, repr(r))
        # this site stays named on this connection, with no second dialog...
        self.assertIn("username", self.query()["accounts"][0])
        self.names()
        self.assertEqual(len(self.reg.dialogs), 1)
        # ...but not another site, nor another connection
        self.assertNotIn("username", self.query("https://example.net")["accounts"][0])
        self.assertNotIn("username", self.query(conn=FakeConn())["accounts"][0])

    def test_names_end_with_the_unlock(self):
        self.unlock()
        self.names()
        self.session.lock()
        self.unlock()
        self.assertNotIn("username", self.query()["accounts"][0])
        self.names()
        self.assertEqual(len(self.reg.dialogs), 2)

    def test_a_refused_names_dialog_names_nothing(self):
        self.unlock()
        for answer in ("dismissed", "denied"):
            self.reg.answers = [answer]
            with self.assertRaises(OpError) as cm:
                self.names()
            self.assertEqual(cm.exception.code, answer)
            self.assertNotIn("username", self.query()["accounts"][0])

    def test_a_lock_while_the_names_dialog_is_up_reveals_nothing(self):
        # (names while locked unlocks for the browser: test_autofill_browser_unlock.py)
        self.unlock()
        self.reg.during = self.session.lock
        self.assertEqual(self.names(), {"state": "locked"})
        self.reg.during = None
        self.unlock()
        self.assertNotIn("username", self.query()["accounts"][0])

    def test_a_connection_gone_during_the_names_dialog_gets_nothing(self):
        self.unlock()
        self.reg.during = lambda: setattr(self.conn, "closed", True)
        with self.assertRaises(OpError) as cm:
            self.names()
        self.assertEqual(cm.exception.code, "cancelled")

    def test_a_connection_gone_just_after_approval_gets_nothing(self):
        # The registry cancels a dialog whose connection closes while it is up; the handler
        # also refuses one that closed in the moment after the approval.
        self.unlock()
        approve = self.reg.authorize

        async def approve_then_close(conn, action, details):
            await approve(conn, action, details)
            conn.closed = True
        self.reg.authorize = approve_then_close
        with self.assertRaises(OpError) as cm:
            self.names()
        self.assertEqual(cm.exception.code, "cancelled")
        self.assertNotIn("username", self.query(conn=self.conn)["accounts"][0])

    def test_an_approved_fill_already_names_so_names_asks_nothing(self):
        self.unlock()
        self.fill("gh1")
        self.names("https://github.com")
        self.assertEqual([d[1] for d in self.reg.dialogs], [paths.ACTION_AUTOFILL])

    def test_switched_off_in_the_window_serves_nothing(self):
        self.unlock()
        self.session.autofill_enabled = False
        for call in (self.query, self.fill):
            with self.assertRaises(OpError) as cm:
                call()
            self.assertEqual(cm.exception.code, "forbidden")
        self.assertEqual(self.reg.dialogs, [])
        self.assertEqual(self.store.unseal_count, 0)

    def test_no_match_is_an_empty_list(self):
        self.unlock()
        self.assertEqual(self.query("https://unrelated.example")["accounts"], [])

    def test_capped_at_twenty(self):
        self.unlock()
        for i in range(30):
            m = meta(f"x{i}", "many.example", username=f"u{i:02d}", mdat=i)
            self.store.metas[m.id] = m
        accts = self.query("https://many.example")["accounts"]
        self.assertEqual(len(accts), autofill.MAX_ACCOUNTS)
        self.assertEqual(accts[0]["id"], self.h("x29"))

    def test_lock_while_listing_wins(self):
        self.unlock()
        orig = self.store.list_meta

        def list_then_lock():
            out = orig()
            self.session.lock()
            return out
        self.store.list_meta = list_then_lock
        self.assertEqual(self.query(), {"state": "locked"})


class FillTests(Base):
    def setUp(self):
        super().setUp()
        self.unlock()

    def test_no_code_for_an_account_without_one(self):
        real_open = self.store.open_entry

        def no_totp(id):
            sec = real_open(id)
            return Secrets(password=sec.password, notes=sec.notes, totp_secret=None,
                           apple_history=[])
        self.store.open_entry = no_totp
        self.assertNotIn("code", self.fill("gh1"))

    def test_fill_prompts_on_the_autofill_connection_and_returns_one_credential(self):
        from icp import totp
        self.reg.wall = lambda: 1_700_000_000.0
        r = self.fill("gh1")
        # the account has a one-time code, so the same approval brings its current code
        self.assertEqual(r, {"id": self.h("gh1"), "username": "alice",
                             "password": FAKE_PW + ":gh1",
                             "code": totp.code(b"seed", at=1_700_000_000.0)})
        self.assertEqual(len(self.reg.dialogs), 1)
        conn, action, details = self.reg.dialogs[0]
        self.assertIs(conn, self.conn)
        self.assertEqual(action, paths.ACTION_AUTOFILL)
        self.assertEqual(details, {"account": "github.com — alice", "origin": "github.com"})
        self.assertEqual(self.reg.ui_events,
                         [(1000, {"event": "autofill", "id": "gh1", "origin": "github.com",
                                  "outcome": "filled"})])

    def test_every_fill_is_its_own_dialog(self):
        self.fill("gh1")
        self.fill("gh1")
        self.assertEqual(len(self.reg.dialogs), 2)
        self.assertEqual(self.store.unseal_count, 2)

    def test_unknown_and_non_matching_ids_look_the_same(self):
        errors = [self.fill_error(i) for i in ("nope", "other")]
        errors += [self.fill_error(i, raw=True) for i in ("", "x" * 500, "../gh1", "gh1\n",
                                                          "gh1", "h-" + "0" * 32)]
        self.assertEqual({(e.code, tuple(e.extra.items())) for e in errors}, {("no-match", ())})
        self.assertEqual(self.reg.dialogs, [])
        self.assertNotIn("open_entry", self.store.calls)

    def test_a_related_site_fills_but_an_alias_does_not(self):
        self.assertEqual(self.fill("gh1", origin="https://login.github.com")["id"],
                         self.h("gh1"))
        self.assertEqual(self.fill_error("other").code, "no-match")
        self.assertEqual(self.fill_error("gh1", origin="https://github.com.evil.com").code,
                         "no-match")

    def test_refusals_are_passed_on_and_nothing_is_opened(self):
        for answer in ("denied", "dismissed"):
            self.reg.answers = [answer]
            self.assertEqual(self.fill_error().code, answer)
        self.assertNotIn("open_entry", self.store.calls)
        self.assertEqual([e["outcome"] for _, e in self.reg.ui_events], ["denied", "dismissed"])

    def test_no_dialog_refusals_tell_the_window_nothing(self):
        for answer in ("no-agent", "busy"):
            self.reg.answers = [answer]
            self.assertEqual(self.fill_error().code, answer)
        self.assertEqual(self.reg.ui_events, [])
        self.assertNotIn("open_entry", self.store.calls)

    def test_lock_during_the_dialog(self):
        self.reg.during = self.session.lock
        self.assertEqual(self.fill_error().code, "locked")
        self.assertNotIn("open_entry", self.store.calls)
        self.assertEqual(self.reg.ui_events[-1][1]["outcome"], "failed")

    def test_window_closed_during_the_dialog(self):
        def close_ui():
            self.session.ui = None
        self.reg.during = close_ui
        self.assertEqual(self.fill_error().code, "locked")
        self.assertNotIn("open_entry", self.store.calls)

    def test_entry_deleted_during_the_dialog(self):
        self.reg.during = lambda: self.store.metas.pop("gh1")
        self.assertEqual(self.fill_error().code, "no-match")
        self.assertNotIn("open_entry", self.store.calls)

    def test_entry_moved_to_another_site_during_the_dialog(self):
        def move():
            self.store.metas["gh1"] = meta("gh1", "evil.example", username="alice")
        self.reg.during = move
        self.assertEqual(self.fill_error().code, "no-match")
        self.assertNotIn("open_entry", self.store.calls)

    def test_browser_gone_during_the_dialog(self):
        def close():
            self.conn.closed = True
        self.reg.during = close
        self.assertEqual(self.fill_error().code, "cancelled")
        self.assertNotIn("open_entry", self.store.calls)

    def test_browser_gone_right_after_approval(self):
        # EOF racing the approval: authorize() returned before it saw the close.
        approve = self.reg.authorize

        async def approve_then_close(conn, action, details):
            await approve(conn, action, details)
            conn.closed = True
        self.reg.authorize = approve_then_close
        self.assertEqual(self.fill_error().code, "cancelled")
        self.assertNotIn("open_entry", self.store.calls)

    def test_lock_while_opening_drops_the_secret(self):
        self.store.on_open = lambda: setattr(self.session, "_unlocked", False)
        e = self.fill_error()
        self.assertEqual(e.code, "locked")
        self.assertNotIn(FAKE_PW, repr(e.extra))


class RateLimitTests(Base):
    def setUp(self):
        super().setUp()
        self.unlock()
        self.now = 1000.0
        self.reg.clock = lambda: self.now

    def test_three_answered_fills_per_minute(self):
        self.fill()
        self.reg.answers = ["denied"]
        self.fill_error()
        self.fill()
        e = self.fill_error()
        self.assertEqual(e.code, "rate-limited")
        self.assertIn("retry_after", e.extra)
        self.assertEqual(len(self.reg.dialogs), 3)       # the fourth never showed a dialog
        self.now += 61
        self.fill()

    def test_no_agent_and_busy_do_not_count(self):
        self.reg.answers = ["no-agent", "busy", "no-agent"]
        for _ in range(3):
            self.fill_error()
        for _ in range(3):
            self.fill()

    def test_queries_and_refused_lookups_never_spend_the_budget(self):
        for _ in range(10):
            self.query()
            self.fill_error("nope")
        for _ in range(3):
            self.fill()

    def test_the_window_has_its_own_bucket(self):
        for _ in range(3):
            self.fill()
        self.assertEqual(self.fill_error().code, "rate-limited")
        # the window can still unlock or reveal: autofill never starves it
        run(self.reg.authorize(self.ui, paths.ACTION_REVEAL, {"account": "x"}))

    def test_one_dialog_at_a_time(self):
        async def two():
            self.reg.gate = asyncio.Event()
            first = asyncio.ensure_future(autofill.handle_autofill_fill(
                self.reg, self.conn, {"origin": "https://github.com", "id": self.h("gh1")}))
            await asyncio.sleep(0.05)
            other = FakeConn()                     # a second browser window, same uid
            with self.assertRaises(OpError) as cm:
                await autofill.handle_autofill_fill(
                    self.reg, other, {"origin": "https://github.com", "id": self.h("gh2")})
            self.assertEqual(cm.exception.code, "prompt-pending")
            # a query still answers while the dialog is up
            q = await autofill.handle_autofill_query(self.reg, other,
                                                     {"origin": "https://github.com"})
            self.assertEqual(q["state"], "unlocked")
            self.reg.gate.set()
            return await first
        self.assertEqual(run(two())["id"], self.h("gh1"))


class HandleTests(Base):
    """Autofill ids were the entry ids, an unkeyed sha256 of (domain, username): any program
    could confirm a guessed username offline from a query. Every autofill reply now carries
    handles keyed by a secret that exists only while the uid is unlocked."""

    def setUp(self):
        from icp.vstore import ids
        self.real = {ids.entry_id("github.com", u): u for u in ("alice", "bob")}
        super().setUp()
        self.store.metas = {i: meta(i, "github.com", username=u) for i, u in self.real.items()}
        self.unlock()

    def test_no_reply_carries_an_entry_id(self):
        q = self.query()
        got = [a["id"] for a in q["accounts"]]
        self.assertEqual(len(got), 2)
        for id in self.real:
            self.assertNotIn(id, repr(q))
            self.assertNotIn(id[3:], repr(q))          # nor its hex
        r = self.fill(raw=True, id=got[0])
        self.assertEqual(r["id"], got[0])
        self.assertEqual(set(r), {"id", "username", "password", "code"})

    def test_a_guess_cannot_be_checked_offline(self):
        from icp.vstore import ids
        handles = {a["id"] for a in self.query()["accounts"]}
        for guess in ("alice", "bob"):
            self.assertNotIn(ids.entry_id("github.com", guess), handles)

    def test_an_entry_id_is_not_a_handle(self):
        for id in self.real:
            self.assertEqual(self.fill_error(id, raw=True).code, "no-match")
        self.assertEqual(self.reg.dialogs, [])

    def test_handles_die_with_the_lock(self):
        old = self.query()["accounts"][0]["id"]
        self.session.lock()
        self.unlock()
        self.assertNotIn(old, {a["id"] for a in self.query()["accounts"]})
        self.assertEqual(self.fill_error(old, raw=True).code, "no-match")
        self.assertEqual(self.reg.dialogs, [])

    def test_the_registry_keys_handles_only_while_unlocked(self):
        from icp.daemon.sessions import Registry, Session
        reg = Registry(store_cls=object)
        s = Session(1000, self.store)
        reg.sessions[1000] = s
        self.assertIsNone(s.autofill_key)
        reg.open_tier1(s, self.ui)
        k1 = s.autofill_key
        self.assertEqual(len(k1), 32)
        reg.lock(1000, "user", notify=False)
        self.assertIsNone(s.autofill_key)
        reg.open_tier1(s, self.ui)
        self.assertNotEqual(s.autofill_key, k1)
        reg.shutdown()


if __name__ == "__main__":
    unittest.main()
