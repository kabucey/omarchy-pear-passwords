"""Fakes for the Apple pipeline tests: an in-memory UserStore stand-in that records what
the pipeline asked of it, and a scripted frontend. Not a test module itself."""

from __future__ import annotations

from icp.vstore import EntryNotFound, Meta


class FakeStore:
    """The slice of vstore.UserStore the Apple pipeline uses, in memory.

    `open_entry` and `history` count unseals exactly as the real store's unseal_count does,
    so a test can assert that a sync never reached for the entry key."""

    def __init__(self, session=None, metas=(), needs_login=False, nicknames=None,
                 aliases=None, device=None):
        self.session = dict(session or {})
        self.metas = {m.id: m for m in metas}
        self.nicknames = dict(nicknames or {})
        self.aliases = list(aliases or [])
        self.device = dict(device or {})
        self.sync_status = {"synced_at": None, "needs_login": needs_login}
        self.unseal_count = 0
        self.applied = []          # (items, deleted) per apply_sync call
        self.secrets_set = []      # (id, Secrets) per set_secrets call
        self.session_saves = 0

    # --- what hello reports
    def status(self) -> dict:
        return {"state": "unlocked", "signed_in": bool(self.session), "sealed_with": "host",
                **self.sync_status}

    # --- session, device, nicknames, aliases
    def load_session(self) -> dict:
        return dict(self.session)

    def save_session(self, d: dict) -> None:
        self.session_saves += 1
        self.session = dict(d)

    def load_device(self) -> dict:
        return dict(self.device)

    def save_device(self, d: dict) -> None:
        self.device = dict(d)

    def load_nicknames(self) -> dict:
        return dict(self.nicknames)

    def save_nicknames(self, names: dict) -> None:
        self.nicknames = dict(names)

    def load_aliases(self) -> list:
        return list(self.aliases)

    def save_aliases(self, aliases: list) -> None:
        self.aliases = list(aliases)

    # --- tier 1
    def list_meta(self) -> list[Meta]:
        return list(self.metas.values())

    def get_meta(self, id: str) -> Meta:
        try:
            return self.metas[id]
        except KeyError:
            raise EntryNotFound(id) from None

    def set_sync_status(self, *, synced_at=None, needs_login=None) -> None:
        if synced_at is not None:
            self.sync_status["synced_at"] = synced_at
        if needs_login is not None:
            self.sync_status["needs_login"] = needs_login

    def apply_sync(self, items, deleted) -> dict:
        items = list(items)
        self.applied.append((items, set(deleted)))
        added = sum(1 for i in items if i.id not in self.metas)
        for i in items:
            self.metas[i.id] = i.meta
        for d in deleted:
            self.metas.pop(d, None)
        return {"added": added, "changed": len(items) - added, "deleted": len(deleted),
                "unchanged": 0}

    def set_secrets(self, id: str, s) -> None:
        self.secrets_set.append((id, s))

    # --- tier 2: the pipeline must never call these during a sync
    def open_entry(self, id: str):
        self.unseal_count += 1
        raise AssertionError("the Apple pipeline opened an entry")

    def history(self, id: str):
        self.unseal_count += 1
        raise AssertionError("the Apple pipeline read an entry's history")


class ScriptedFrontend:
    """A daemon.context.Frontend that answers from a script and records everything it was
    shown. `answers` maps a question kind to its answer (a callable gets the prompt)."""

    def __init__(self, answers: dict | None = None):
        self.answers = dict(answers or {})
        self.events = []

    def _answer(self, need, prompt, kind):
        self.events.append(("ask", need, kind))
        a = self.answers[kind]
        return a(prompt) if callable(a) else a

    def emit(self, kind, text):
        self.events.append(("emit", kind, str(text)))

    def stage(self, stage_name, **info):
        self.events.append(("stage", stage_name, info))

    def ask(self, prompt, kind=None, default=None):
        return self._answer("text", prompt, kind)

    def secret(self, prompt, kind=None, detail=None):
        return self._answer("secret", prompt, kind)

    def confirm_yn(self, prompt, kind=None, detail=None):
        return self._answer("confirm", prompt, kind)

    def choose(self, prompt, options, kind=None, details=None):
        return self._answer("choice", prompt, kind)

    def stages(self) -> list:
        return [e[1] for e in self.events if e[0] == "stage"]
