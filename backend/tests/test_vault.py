"""Offline test for the encrypted credential vault (round-trip via a temp config dir).

Run: .venv/bin/python -m unittest tests.test_vault
"""

import importlib
import os
import tempfile
import unittest
from unittest import mock


class VaultRoundTripTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        # ensure the keyring-less fallback key file path is used (no Secret Service in CI)
        self._old_dbus = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        os.environ["ICP_ALLOW_KEYFILE"] = "1"  # fallback is opt-in; this test wants it

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        if self._old_dbus is not None:
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self._old_dbus
        self._tmp.cleanup()

    def test_save_then_load(self):
        from icp.vault import store as vault
        from icp.vault.host import Credential, CredentialStore
        importlib.reload(vault)  # pick up XDG override

        self.assertEqual(len(vault.load_vault()), 0)  # empty before save

        store = CredentialStore([
            Credential("example.com", "alice", "pw1", "Example"),
            Credential("login.bank.test", "bob", "pw2", "Bank"),
        ])
        vault.save_vault(store)

        loaded = vault.load_vault()
        self.assertEqual(len(loaded), 2)
        hit = loaded.match("www.example.com")
        self.assertEqual(hit[0].password, "pw1")
        self.assertEqual(loaded.match("bank.test")[0].username, "bob")

    def test_sync_does_not_replace_corrupt_ciphertext(self):
        from icp.octagon import client as octagon
        from icp.vault import store as vault
        from icp.vault.host import Credential, CredentialStore

        vault.save_vault(CredentialStore([Credential("example.com", "alice", "pw", "Example")]))
        path = vault.paths.vault_file()
        path.write_bytes(b"damaged ciphertext")
        before = path.read_bytes()

        class _Encryption:
            private_key = None

        class _Keys:
            encryption = _Encryption()

        with mock.patch.object(octagon, "load_peer_keys", return_value=_Keys()), \
                mock.patch.object(octagon.pipeline, "build_credential_store",
                                  return_value=CredentialStore([])):
            with self.assertRaises(vault.VaultError):
                octagon.decrypt_to_vault({}, {"peer_id": "peer"}, authoritative=True)
        self.assertEqual(path.read_bytes(), before)

    def test_incomplete_pipeline_preserves_existing_vault(self):
        from icp.keychain import pipeline
        from icp.octagon import client as octagon
        from icp.vault import store as vault
        from icp.vault.host import Credential, CredentialStore

        existing = CredentialStore([Credential("example.com", "alice", "old", "Example")])
        vault.save_vault(existing)
        path = vault.paths.vault_file()
        before = path.read_bytes()
        diagnostics = pipeline.PipelineDiagnostics(
            authoritative=True, item_failures={"item-2": "InvalidTag"})
        result = pipeline.PipelineResult(
            CredentialStore([Credential("example.com", "alice", "partial", "Example")]),
            diagnostics)

        class _Encryption:
            private_key = None

        class _Keys:
            encryption = _Encryption()

        with mock.patch.object(octagon, "load_peer_keys", return_value=_Keys()), \
                mock.patch.object(octagon.pipeline, "build_credential_snapshot",
                                  return_value=result):
            with self.assertRaisesRegex(octagon.OctagonError, "pipeline incomplete"):
                octagon.decrypt_to_vault({}, {"peer_id": "peer"}, authoritative=True)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(vault.load_vault().all()[0].password, "old")

    def test_authoritative_empty_snapshot_replaces_old_vault(self):
        from icp.keychain import pipeline
        from icp.octagon import client as octagon
        from icp.vault import store as vault
        from icp.vault.host import Credential, CredentialStore

        vault.save_vault(CredentialStore([Credential("example.com", "alice", "old", "Example")]))
        result = pipeline.PipelineResult(
            CredentialStore([]), pipeline.PipelineDiagnostics(authoritative=True))

        class _Encryption:
            private_key = None

        class _Keys:
            encryption = _Encryption()

        with mock.patch.object(octagon, "load_peer_keys", return_value=_Keys()), \
                mock.patch.object(octagon.pipeline, "build_credential_snapshot",
                                  return_value=result):
            self.assertEqual(octagon.decrypt_to_vault(
                {}, {"peer_id": "peer"}, authoritative=True), 0)
        self.assertEqual(vault.load_vault().all(), [])

    def test_auxiliary_corruption_is_preserved_and_rejected(self):
        from icp.hme import store as aliases
        from icp.hme.client import HmeAlias
        from icp.vault import history, nicknames

        history.save({"example.com\x1falice": [{"new": "old"}]})
        nickname_id = "example.com\x1falice"
        nicknames.save({nickname_id: "Work"})
        aliases.save_aliases([HmeAlias("id1", "x@icloud.com", "shop", "", "me@icloud.com",
                                       True, "icloud.com", 0.0)])

        cases = (
            (history.paths.history_file(), history.load, history.HistoryError),
            (nicknames.paths.nicknames_file(), nicknames.load, nicknames.NicknamesError),
            (aliases.paths.aliases_file(), aliases.load_aliases, aliases.AliasesError),
        )
        for path, load, error in cases:
            path.write_bytes(b"damaged ciphertext")
            before = path.read_bytes()
            with self.assertRaises(error):
                load()
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
