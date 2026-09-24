"""Offline tests for the passphrase lockbox and the idle-timeout agent.

Run: PYTHONPATH=. .venv/bin/python -m unittest tests.test_lockbox
"""

import os
import tempfile
import unittest


class LockboxTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        self._tmp.cleanup()

    def test_roundtrip_and_wrong_passphrase(self):
        from icp.auth import lockbox
        self.assertFalse(lockbox.is_initialised())
        key = lockbox.initialise("correct horse battery staple")
        self.assertTrue(lockbox.is_initialised())
        self.assertEqual(len(key), 32)
        self.assertEqual(lockbox.unlock("correct horse battery staple"), key)
        with self.assertRaises(lockbox.WrongPassphrase):
            lockbox.unlock("Correct Horse Battery Staple")

    def test_passphrase_is_never_stored(self):
        """The whole point: nothing on disk may contain the passphrase or the key."""
        from icp.auth import lockbox
        from icp import paths
        secret = "zomboidfeatherquartz"
        key = lockbox.initialise(secret)
        for f in (lockbox.params_file(), lockbox.check_file()):
            blob = f.read_bytes()
            self.assertNotIn(secret.encode(), blob)
            self.assertNotIn(key, blob)
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertFalse(paths.vault_key_file().exists())

    def test_rederives_same_key_across_processes(self):
        """Salt is persisted, so a fresh process gets the same key from the same passphrase."""
        from icp.auth import lockbox
        key = lockbox.initialise("a passphrase that is long")
        self.assertEqual(lockbox.derive("a passphrase that is long"), key)


class AgentTimeoutTests(unittest.TestCase):
    """Drives the agent over a real socket in a temp runtime dir."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = {k: os.environ.get(k) for k in
                     ("XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "ICP_LOCK_TIMEOUT")}
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        os.environ["XDG_RUNTIME_DIR"] = self._tmp.name
        os.environ["ICP_LOCK_TIMEOUT"] = "0"  # expire immediately

    def tearDown(self):
        from icp.auth import agent
        try:
            agent._request("QUIT", autostart=False)
        except Exception:
            pass
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def test_key_is_dropped_after_timeout(self):
        from icp.auth import agent, lockbox
        lockbox.initialise("a passphrase that is long")
        agent.unlock("a passphrase that is long")
        # ICP_LOCK_TIMEOUT=0 means the lease is already stale on the next request.
        self.assertIsNone(agent.get_key(), "key survived past its timeout")
        self.assertEqual(agent.status(), "locked")

    def test_socket_is_private(self):
        from icp.auth import agent, lockbox
        lockbox.initialise("a passphrase that is long")
        agent.unlock("a passphrase that is long")
        self.assertEqual(os.stat(agent.socket_path()).st_mode & 0o777, 0o600)

    def test_wrong_passphrase_rejected(self):
        from icp.auth import agent, lockbox
        lockbox.initialise("a passphrase that is long")
        with self.assertRaises(agent.AgentError):
            agent.unlock("wrong")

    def test_transient_derived_key_load_is_not_persisted(self):
        """Migration can stage a new KDF before publishing it, without writing the key."""
        from icp.auth import agent, lockbox
        self._old_timeout = os.environ["ICP_LOCK_TIMEOUT"]
        os.environ["ICP_LOCK_TIMEOUT"] = "60"
        key = lockbox.prepare_initialisation("a passphrase that is long")[0]
        agent.unlock_key(key)
        self.assertEqual(agent.get_key(), key)
        agent.lock_strict()
        self.assertFalse(lockbox.params_file().exists())
        self.assertFalse(lockbox.check_file().exists())

    def test_raw_key_load_command_is_not_an_unlock_path(self):
        from icp.auth import agent, lockbox
        lockbox.initialise("a passphrase that is long")
        key = lockbox.derive("a passphrase that is long")
        self.assertEqual(agent._request("LOAD " + key.hex()), "ERR unknown command")
        self.assertEqual(agent.status(), "locked")


if __name__ == "__main__":
    unittest.main()
