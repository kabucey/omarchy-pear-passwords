"""The frozen 2.0 interfaces keep their shape.

These tests pin the names and parameters of vstore, daemon/apple.py and daemon/autofill.py,
and the few behaviours the shared modules implement themselves (UserContext and the background
frontend).
"""

import ast
import dataclasses
import inspect
import os
import subprocess
import sys
import unittest

from icp import vstore
from icp.cli.jsonui import JsonFrontend
from icp.daemon import apple, autofill, context
from icp.daemon import protocol

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _params(fn) -> list:
    return [p for p in inspect.signature(fn).parameters if p not in ("self", "cls")]


class VstoreShapeTests(unittest.TestCase):
    def test_dataclass_fields(self):
        names = lambda c: [f.name for f in dataclasses.fields(c)]   # noqa: E731
        self.assertEqual(names(vstore.Meta)[:10], [
            "id", "title", "domain", "sites", "username", "nickname", "has_totp",
            "has_notes", "mdat", "history_count"])
        self.assertEqual(names(vstore.Secrets)[:4],
                         ["password", "notes", "totp_secret", "apple_history"])
        self.assertIn("totp_params", names(vstore.Secrets))
        self.assertEqual(names(vstore.SyncItem), ["id", "meta", "secrets"])

    def test_user_store_methods(self):
        expected = {
            "open": ["uid"], "create": ["uid"], "reset": ["uid", "discard_empty"],
            "state": [], "status": [], "unlock": [], "lock": [],
            "reseal_if_tpm_available": [], "tpm_move_state": [], "list_meta": [],
            "get_meta": ["id"],
            "set_sync_status": ["synced_at", "needs_login"],
            "open_entry": ["id"], "history": ["id"], "set_secrets": ["id", "s"],
            "apply_sync": ["items", "deleted"], "pwmac_matches": ["texts"],
            "load_session": [], "save_session": ["d"],
            "load_aliases": [], "save_aliases": ["aliases"],
            "load_nicknames": [], "save_nicknames": ["names"],
            "load_device": [], "save_device": ["d"],
            "load_settings": [], "save_settings": ["d"],
            "import_v1": ["files", "key"],
        }
        for name, params in expected.items():
            self.assertTrue(hasattr(vstore.UserStore, name), name)
            self.assertEqual(_params(getattr(vstore.UserStore, name)), params, name)
        self.assertIn("unseal_count", vstore.UserStore.__annotations__)

    def test_lock_has_no_lease_parameter(self):
        # 2.0 has no sync lease, so there is no partial lock that keeps the session key.
        self.assertNotIn("keep_session", inspect.signature(vstore.UserStore.lock).parameters)

    def test_seal_error_kinds(self):
        for kind in ("tpm-missing", "tpm-cleared", "damaged"):
            self.assertEqual(vstore.SealError(kind).kind, kind)
        self.assertEqual(set(protocol.SEAL_STATES), {"tpm-missing", "tpm-cleared", "damaged"})
        with self.assertRaises(ValueError):
            vstore.SealError("locked")

    def test_v1_helpers(self):
        self.assertEqual(_params(vstore.v1_key_from_passphrase), ["kdf_json", "passphrase"])
        self.assertEqual(_params(vstore.v1_key_opens), ["check_enc", "key"])


class ContextTests(unittest.TestCase):
    def test_background_questions_raise_needs_login(self):
        ui = context.UserContext(uid=1000, store=None, anisette_url="http://x").ui
        self.assertIsInstance(ui, context.BackgroundFrontend)
        ui.emit("step", "fine")            # progress is dropped, not an error
        ui.stage("syncing")
        for call in (lambda: ui.ask("Apple ID"), lambda: ui.secret("Password"),
                     lambda: ui.confirm_yn("Sure?"), lambda: ui.choose("Pick", ["a"])):
            with self.assertRaises(context.NeedsLogin):
                call()

    def test_interactive_context_uses_its_frontend(self):
        fe = JsonFrontend()
        ctx = context.UserContext(uid=1000, store=None, anisette_url="http://x", frontend=fe)
        self.assertIs(ctx.ui, fe)
        self.assertTrue(ctx.interactive)
        self.assertFalse(context.UserContext(1000, None, "http://x").interactive)

    def test_existing_frontends_satisfy_the_protocol(self):
        self.assertIsInstance(JsonFrontend(), context.Frontend)
        self.assertIsInstance(context.BackgroundFrontend(), context.Frontend)

    def test_cancelled_escapes_broad_excepts(self):
        self.assertTrue(issubclass(context.Cancelled, KeyboardInterrupt))
        self.assertFalse(issubclass(context.Cancelled, Exception))
        self.assertTrue(issubclass(context.NeedsLogin, Exception))


class HandlerShapeTests(unittest.TestCase):
    def test_autofill_handlers(self):
        for fn in (autofill.handle_autofill_query, autofill.handle_autofill_fill):
            self.assertTrue(inspect.iscoroutinefunction(fn), fn.__name__)
            self.assertEqual(_params(fn), ["session_registry", "conn", "req"])
        self.assertEqual(_params(autofill.parse_origin), ["origin"])
        self.assertEqual(_params(autofill.match_rank), ["host", "meta"])

    def test_apple_functions(self):
        expected = {"sync": ["ctx"], "login": ["ctx"], "relogin": ["ctx"],
                    "push_set": ["ctx", "id", "fields"], "create": ["ctx", "fields"],
                    "delete": ["ctx", "id"], "fetch_aliases": ["ctx"], "signout": ["ctx"]}
        for name, params in expected.items():
            self.assertEqual(_params(getattr(apple, name)), params, name)

    def test_apple_never_names_the_prompt_module(self):
        path = os.path.join(BACKEND, "icp", "daemon", "apple.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("polkit", src.lower())
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
                self.assertFalse(any("polkit" in n for n in names), names)
            if isinstance(node, ast.Name):
                self.assertNotEqual(node.id, "AllowUserInteraction")


class ImportWeightTests(unittest.TestCase):
    def test_clients_can_import_shared_constants_cheaply(self):
        # clip, migrate and autofill import icp.daemon.paths and .protocol; that must not drag
        # in the store, the Apple pipeline or a D-Bus library.
        code = ("import sys, icp.daemon.paths, icp.daemon.protocol; "
                "bad = [m for m in ('jeepney', 'icp.vstore', 'icp.daemon.apple', "
                "'icp.daemon.autofill', 'requests', 'nacl') if m in sys.modules]; "
                "print(','.join(bad))")
        env = dict(os.environ, PYTHONPATH=BACKEND, PYTHONDONTWRITEBYTECODE="1")
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                             text=True, check=True)
        self.assertEqual(out.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
