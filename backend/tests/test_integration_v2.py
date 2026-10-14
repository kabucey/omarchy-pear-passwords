"""The parts together: the real daemon server and registry over the real per-user store, the
real Apple pipeline module with only the network replaced, and the autofill handlers - driven over a unix socket the way the window, the importer and the
browser host drive them.

Only polkit (a fake authority that approves), the seal backend (FakeSealBackend) and the
CloudKit fetch (the fixture's own credentials) are stand-ins. Everything is fake data.
"""

import asyncio
import base64
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from daemon_fakes import UID, FakeAuthority, Harness
from fixtures import V1_COUNTS, V1_PASSPHRASE, v1_files, vstore_env

from icp import vstore
from icp.daemon import paths, protocol
from icp.daemon.server import Server
from icp.daemon.sessions import Registry
from icp.vault.host import Credential
from icp.vstore import ids, legacy


def v1_key(files):
    return vstore.v1_key_from_passphrase(files["kdf.json"], V1_PASSPHRASE)


def keychain(files):
    """What a fetch from iCloud returns for the fixture account: the same credentials."""
    return [Credential(**{k: v for k, v in c.items() if k != "totp"}, totp=c.get("totp"))
            for c in legacy.read(files, v1_key(files)).credentials]


class VersionTests(unittest.TestCase):
    def test_hello_version_is_the_release(self):
        """hello's version is a constant in the daemon; the release number lives in the
        manifest and pyproject.toml. All three move together."""
        import json
        import re
        from icp.daemon import handlers
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        with open(os.path.join(root, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)["version"]
        with open(os.path.join(root, "backend", "pyproject.toml"), encoding="utf-8") as f:
            pyproject = re.search(r'^version = "([^"]+)"', f.read(), re.M).group(1)
        self.assertEqual({handlers.VERSION, manifest, pyproject}, {"2.0.3"})


class NoLeaseCodeTests(unittest.TestCase):
    """Owner decision (spec 16.5): no sync lease, and no code path for one. Two matchers over
    every code file: Python's AST (names, attributes, arguments, keys and non-docstring
    strings) and Python's tokenizer, plus comment-stripped text for QML, shell and units.
    Comments and docstrings may say that there is no lease."""

    WORD = re.compile(r"(?i)(?<!re)lease")
    DIRS = ("backend/icp", "app", "plugin", "native", "system")
    ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")

    def files(self, exts):
        for d in self.DIRS:
            for dirpath, _, names in os.walk(os.path.join(self.ROOT, d)):
                for n in names:
                    if n.endswith(exts) or (not exts and "." not in n):
                        yield os.path.join(dirpath, n)

    def ast_hits(self, src):
        import ast
        tree = ast.parse(src)
        docs = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = getattr(node, "body", [])
                if body and isinstance(body[0], ast.Expr) and isinstance(
                        getattr(body[0], "value", None), ast.Constant):
                    docs.add(id(body[0].value))
        hits = []
        for node in ast.walk(tree):
            for text in (getattr(node, "id", None), getattr(node, "attr", None),
                         getattr(node, "arg", None),
                         node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef,
                                                        ast.AsyncFunctionDef)) else None,
                         node.value if isinstance(node, ast.Constant) and isinstance(
                             node.value, str) and id(node) not in docs else None):
                if isinstance(text, str) and self.WORD.search(text):
                    hits.append(text)
        return hits

    def token_hits(self, src):
        import io as _io
        import tokenize
        hits, prev = [], None
        for tok in tokenize.generate_tokens(_io.StringIO(src).readline):
            if tok.type == tokenize.NAME and self.WORD.search(tok.string):
                hits.append(tok.string)
            # A string statement right after a newline/indent is a docstring: skipped.
            if tok.type == tokenize.STRING and self.WORD.search(tok.string) and prev not in (
                    tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, None, tokenize.NL):
                hits.append(tok.string)
            if tok.type not in (tokenize.COMMENT,):
                prev = tok.type
        return hits

    def test_no_lease_in_python(self):
        n = 0
        for path in self.files((".py",)):
            with open(path, encoding="utf-8") as f:
                src = f.read()
            n += 1
            self.assertEqual(self.ast_hits(src), [], path)
            self.assertEqual(self.token_hits(src), [], path)
        self.assertGreater(n, 50)

    def test_no_lease_elsewhere(self):
        for path in self.files((".qml", ".sh", ".c", ".service", ".socket", ".policy", ".js")):
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    code = re.split(r"(^|\s)(#|//)", line, maxsplit=1)[0]
                    self.assertIsNone(self.WORD.search(code), f"{path}:{i}: {line.strip()}")

    def test_the_matchers_see_a_lease(self):
        src = 'SYNC_LEASE_H = 0\ndef f(lease_h):\n    return {"sync_lease_h": lease_h}\n'
        self.assertEqual(len(self.ast_hits(src)), 4)
        self.assertGreaterEqual(len(self.token_hits(src)), 4)
        self.assertEqual(self.ast_hits('"""no sync lease"""\n# no lease\nrelease = 1\n'), [])
        self.assertEqual(self.token_hits('"""no sync lease"""\n# no lease\nrelease = 1\n'), [])


class RealStoreHarness(Harness):
    """Harness with vstore.UserStore and icp.daemon.apple instead of the in-memory fakes."""

    def __init__(self, authority):
        super().__init__(authority=authority)
        self.reg = Registry(store_cls=vstore.UserStore, authority=self.authority, apple=None,
                            parent_start_time=lambda pid: self.parent_start.get(pid))
        self.server = Server(self.reg, verify_peer=self._verify)


class _Client:
    """Stands in for OctagonClient: the keychain is the fixture's credentials."""
    creds: list = []
    fetches = 0

    def __init__(self, record, device, anisette):
        self.failed_zones = []

    def sync_and_decrypt(self, nicknames=None):
        from icp.octagon import items
        type(self).fetches += 1
        return items.to_sync_items(self.creds, nicknames)


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pear-int-")
        self.env = vstore_env(os.path.join(self.tmp, "state"))
        self.backend = self.env.__enter__()
        self.files = v1_files()
        _Client.creds = keychain(self.files)
        _Client.fetches = 0
        from icp.auth import signin
        from icp.daemon import apple
        from icp.octagon import client as octagon
        self.patches = [
            mock.patch.object(octagon, "OctagonClient", _Client),
            mock.patch.object(octagon, "is_joined", lambda s: True),
            mock.patch.object(signin, "ensure_fresh_tokens", lambda *a, **k: None),
            mock.patch.object(apple, "fetch_aliases", lambda ctx: 0),
        ]
        for p in self.patches:
            p.start()
        self.authority = FakeAuthority()
        self.h = await RealStoreHarness(self.authority).start()
        self.ui, self.peer = await self.h.ui()

    async def asyncTearDown(self):
        await self.h.stop()
        for p in self.patches:
            p.stop()
        self.env.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def migrate(self):
        r = await self.ui.call("migrate-begin")
        self.assertIn("ticket", r, r)
        m, hello = await self.h.hello("migrate", peer=self.h.peer(ppid=self.peer.pid),
                                      ticket=r["ticket"])
        self.assertEqual(hello["purpose"], "import")
        return m

    async def send_files(self, m, files):
        for name, data in files.items():
            chunk = protocol.IMPORT_CHUNK_MAX
            parts = [data[i:i + chunk] for i in range(0, len(data), chunk)] or [b""]
            for seq, part in enumerate(parts):
                r = await m.call("import-file", name=name, seq=seq,
                                 b64=base64.b64encode(part).decode(),
                                 eof=seq == len(parts) - 1)
                self.assertNotIn("error", r, (name, r))

    async def import_fixture(self):
        m = await self.migrate()
        await self.send_files(m, self.files)
        r = await m.call("import-key", key_b64=base64.b64encode(v1_key(self.files)).decode())
        self.assertNotIn("error", r, r)
        r = await m.call("import-commit", timeout=30)
        self.assertEqual(r.get("counts"), V1_COUNTS, r)
        return m

    def store(self):
        return self.h.reg.get(UID).store

    async def test_migrate_list_sync_grant_reveal_lock(self):
        self.assertEqual(self.ui.hello["state"], "empty")
        await self.import_fixture()
        await self.ui.event("migrated")
        st = self.store()
        self.assertEqual(st.state(), "unlocked")
        r = await self.ui.call("unlock", timeout=30)
        entries = {e["id"]: e for e in r["entries"]}
        gh = ids.entry_id("github.com", "dev@example.test")
        self.assertIn(gh, entries)
        for e in entries.values():
            for secret in ("password", "notes", "totp_secret", "pwmac"):
                self.assertNotIn(secret, e)

        # The first sync after the import: the pipeline's ids are the importer's, so nothing
        # is added, re-sealed or tombstoned, and SK_secret is never unsealed.
        before = st.unseal_count
        if not _Client.fetches:
            await self.ui.call("sync")
        ev = await self.ui.event("synced", timeout=30)
        self.assertGreaterEqual(_Client.fetches, 1)
        self.assertEqual(ev["counts"], {"added": 0, "changed": 0, "deleted": 0,
                                        "unchanged": V1_COUNTS["credentials"]})
        self.assertEqual(st.unseal_count, before)
        self.assertEqual(st.load_nicknames()[gh], "Work GitHub")

        g = await self.ui.call("grant", id=gh, timeout=30)
        self.assertNotIn("error", g, g)
        self.assertEqual(self.authority.actions()[-1], paths.ACTION_REVEAL)
        rv = await self.ui.call("reveal", id=gh, field="password", timeout=30)
        self.assertEqual(rv["value"], "gh-TEST-pw-1")
        hist = await self.ui.call("history", id=gh, timeout=30)
        self.assertEqual({i["source"] for i in hist["items"]}, {"local", "apple"})
        self.assertGreater(st.unseal_count, before)

        await self.ui.call("lock")
        self.assertEqual(st.state(), "locked")
        self.assertEqual((await self.ui.call("reveal", id=gh, field="password"))["error"],
                         "locked")

    async def test_feature_flags_outlive_the_daemon_session(self):
        """op features through the real store: state.json keeps the flags, so a new daemon
        session (a restart) still has them. FakeStore keeps any key; only the real one could
        drop them, which the gate VM found it doing."""
        await self.import_fixture()
        await self.ui.call("unlock", timeout=30)
        await self.h.syncs_done()
        r = await self.ui.call("features", set={"apple_deleted": True}, timeout=30)
        self.assertEqual(r["features"], {"passkeys": False, "apple_deleted": True})
        self.assertEqual(self.authority.actions()[-1], paths.ACTION_MANAGE)
        self.ui.close()
        await asyncio.sleep(0.05)
        self.h.reg.sessions.clear()
        ui2, _ = await self.h.ui()
        self.assertEqual((await ui2.call("features", get=True))["features"],
                         {"passkeys": False, "apple_deleted": True})
        r = await ui2.call("unlock", timeout=30)
        self.assertEqual(r["features"], {"passkeys": False, "apple_deleted": True})

    async def test_a_failed_import_can_be_started_over(self):
        m = await self.migrate()
        bad = dict(self.files)
        bad["vault.enc"] = self.files["check.enc"]          # opens with the key, wrong shape
        await self.send_files(m, bad)
        await m.call("import-key", key_b64=base64.b64encode(v1_key(self.files)).decode())
        r = await m.call("import-commit", timeout=30)
        self.assertEqual(r.get("error"), "mismatch", r)
        self.assertIs(self.store().load_settings().get("migration_pending"), True)
        # The store now holds keys, so it is not "empty"; the pending marker lets a second
        # Continue start over instead of being refused for good.
        await self.ui.call("lock")
        self.assertNotEqual(self.store().state(), "empty")
        await self.import_fixture()
        self.assertNotIn("migration_pending", self.store().load_settings())

    async def test_autofill_reveals_nothing_while_locked_and_prompts_per_fill(self):
        await self.import_fixture()
        af, hello = await self.h.hello("autofill")
        self.assertEqual(hello.get("error"), "forbidden")         # off until turned on
        r = await self.ui.call("autofill-enable", enabled=True, timeout=30)
        self.assertTrue(r["autofill"]["enabled"])
        await self.ui.call("lock")
        af, hello = await self.h.hello("autofill")
        self.assertNotIn("error", hello, hello)
        n = len(self.authority.actions())
        q = await af.call("autofill-query", origin="https://github.com")
        self.assertEqual(q, {"rid": q["rid"], "state": "locked"})
        f = await af.call("autofill-fill", origin="https://github.com",
                          id=ids.entry_id("github.com", "dev@example.test"))
        self.assertEqual(f.get("error"), "locked")
        self.assertEqual(len(self.authority.actions()), n)       # no dialog while locked

        await self.ui.call("unlock", timeout=30)
        q = await af.call("autofill-query", origin="https://github.com", timeout=30)
        self.assertEqual(q["state"], "unlocked")
        for a in q["accounts"]:
            self.assertEqual(set(a), {"id", "match"})            # no names before a fill
        gh = q["accounts"]
        self.assertEqual(len(gh), 1, q)
        # A handle, never the entry id (an unkeyed hash a program could check guesses with).
        self.assertNotEqual(gh[0]["id"], ids.entry_id("github.com", "dev@example.test"))
        self.assertEqual(len(self.authority.actions()), n + 1)   # only the window's unlock

        f = await af.call("autofill-fill", origin="https://github.com", id=gh[0]["id"],
                          timeout=30)
        self.assertEqual((f["username"], f["password"]), ("dev@example.test", "gh-TEST-pw-1"))
        self.assertEqual(self.authority.actions()[-1], paths.ACTION_AUTOFILL)
        qb = await af.call("autofill-query", origin="https://bank.example.test", timeout=30)
        bank = qb["accounts"][0]["id"]
        f = await af.call("autofill-fill", origin="https://github.com", id=bank)
        self.assertEqual(f.get("error"), "no-match")              # wrong site: no dialog
        self.assertEqual(self.authority.actions()[-1], paths.ACTION_AUTOFILL)
        self.assertEqual(len(self.authority.actions()), n + 2)


if __name__ == "__main__":
    unittest.main()
