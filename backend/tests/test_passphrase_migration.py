"""Setting a passphrase changes the master key. Everything encrypted under the old key has to
be re-written under the new one - history and nicknames included, or they become unreadable."""
import argparse
import os
import subprocess
import sys
import threading
import types

import pytest

from icp.auth import agent, held_key, lockbox, prompt, session
from icp.cli import app
from icp.errors import PassphraseMigrationError
from icp.hme import store as hme_store
from icp.vault import history, nicknames, store as vault_store

MODULES_WITH_KEY = (session, vault_store, hme_store, history, nicknames)


class _SecretItem:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.deleted = False

    def delete(self):
        if self.fail:
            raise RuntimeError("delete failed")
        self.deleted = True


class _SecretCollection:
    def __init__(self, held_items=None, master_items=None):
        self.held_items = held_items if held_items is not None else []
        self.master_items = master_items if master_items is not None else []

    def is_locked(self):
        return False

    def search_items(self, attrs):
        if attrs == held_key._ATTRS:
            return [item for item in self.held_items if not item.deleted]
        if attrs == session._ATTRS:
            return [item for item in self.master_items if not item.deleted]
        raise AssertionError(f"unexpected Secret Service attributes: {attrs}")


def _install_secret_service(monkeypatch, *, held_items=None, master_items=None,
                            dbus_init=None):
    collection = _SecretCollection(held_items, master_items)
    if dbus_init is None:
        dbus_init = lambda: object()
    monkeypatch.setitem(sys.modules, "secretstorage", types.SimpleNamespace(
        dbus_init=dbus_init,
        get_default_collection=lambda conn: collection,
    ))
    return collection


@pytest.fixture
def keys(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    state = {"key": os.urandom(32)}
    for m in MODULES_WITH_KEY:
        monkeypatch.setattr(m, "_master_key", lambda: state["key"], raising=True)
    new_key = os.urandom(32)

    def prepare_initialisation(passphrase):
        state["key"] = new_key            # from now on everything reads with the new key
        return new_key, b"new kdf parameters", b"new check ciphertext"
    monkeypatch.setattr(lockbox, "prepare_initialisation", prepare_initialisation)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: False)
    monkeypatch.setattr(prompt, "ask_passphrase", lambda **kw: "correct horse battery")
    monkeypatch.setattr(agent, "lock", lambda: None)
    monkeypatch.setattr(agent, "lock_strict", lambda: None)
    monkeypatch.setattr(agent, "unlock", lambda p: None)
    monkeypatch.setattr(agent, "unlock_key", lambda key: None)
    monkeypatch.setattr(held_key, "_purge_keyring", lambda: None)
    monkeypatch.setattr(session, "ensure_legacy_master_key_clean", lambda: None)
    monkeypatch.setitem(sys.modules, "secretstorage", types.SimpleNamespace(
        dbus_init=lambda: (_ for _ in ()).throw(RuntimeError("no dbus in tests"))))
    return state


def test_history_and_nicknames_survive_a_passphrase_change(keys):
    accounts = {}
    history.record(accounts, "example.com", "alex", old="a", new="b", source="sync", when=1.0)
    history.save(accounts)
    nicknames.save({"example.com\x1falex": "Work"})
    assert app.cmd_passphrase(argparse.Namespace()) == 0
    assert history.for_account(history.load(), "example.com", "alex")
    assert nicknames.load() == {"example.com\x1falex": "Work"}
    from icp import paths
    assert not paths.vault_key_file().exists()


def test_keyring_mode_migration_uses_new_key_for_staged_ciphertext(monkeypatch, tmp_path):
    """When no old KDF is active, staged stores must not fall back to the old keyring key."""
    from icp import paths
    from icp.vault.host import Credential, CredentialStore

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("ICP_ALLOW_KEYFILE", "1")
    monkeypatch.setitem(sys.modules, "secretstorage", types.SimpleNamespace(
        dbus_init=lambda: (_ for _ in ()).throw(RuntimeError("no dbus in tests"))))
    new_state = {"key": None}
    monkeypatch.setattr(agent, "lock_strict", lambda: None)
    monkeypatch.setattr(agent, "unlock_key", lambda key: new_state.update(key=bytes(key)))
    monkeypatch.setattr(agent, "get_key", lambda: new_state["key"])
    monkeypatch.setattr(prompt, "ask_passphrase", lambda **kw: "correct horse battery")
    monkeypatch.setattr(held_key, "ensure_clean", lambda: None)
    monkeypatch.setattr(session, "ensure_legacy_master_key_clean", lambda: None)

    old = CredentialStore([Credential("example.com", "alice", "old", "Example")])
    vault_store.save_vault(old)
    assert paths.fallback_key_file().exists()

    assert app.cmd_passphrase(argparse.Namespace()) == 0
    assert vault_store.load_vault().all()[0].password == "old"
    assert new_state["key"] is not None
    assert lockbox.unlock("correct horse battery") == new_state["key"]


def test_passphrase_mode_unlocks_agent_and_discards_legacy_file(monkeypatch, tmp_path):
    """A legacy raw key never becomes an unlock path after the passphrase migration."""
    from icp import paths
    from icp.auth import held_key

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    legacy = paths.vault_key_file()
    legacy.write_bytes(os.urandom(32))

    derived = os.urandom(32)
    state = {"key": None}
    prompts = []
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: state["key"])

    def ask(**kwargs):
        prompts.append(kwargs)
        return "correct horse battery"

    def unlock(passphrase):
        assert passphrase == "correct horse battery"
        state["key"] = derived

    monkeypatch.setattr(prompt, "ask_passphrase", ask)
    monkeypatch.setattr(agent, "unlock", unlock)
    monkeypatch.setattr(held_key, "_purge_keyring", lambda: None)
    # This fixture exercises the legacy lockbox-key file only.  A real upgrade must also
    # inspect the old session-key namespace; make that strict cleanup succeed explicitly here.
    monkeypatch.setattr(session, "_purge_master_keyring", lambda: None)

    assert session._master_key() == derived
    assert prompts
    assert not legacy.exists()


def test_lock_removes_legacy_file_without_affecting_keyring_mode(monkeypatch, tmp_path):
    from icp import paths
    from icp.auth import held_key

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    legacy = paths.vault_key_file()
    legacy.write_bytes(os.urandom(32))
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "lock_strict", lambda: None)
    monkeypatch.setattr(held_key, "_purge_keyring", lambda: None)

    assert app.cmd_lock(argparse.Namespace()) == 0
    assert not legacy.exists()


def test_cleanup_marker_avoids_keyring_on_clean_unlock(monkeypatch, tmp_path):
    from icp import paths
    from icp.auth import held_key

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    paths.atomic_write_private(paths.master_key_cleanup_file(), session._MASTER_CLEAN_MARKER)
    derived = os.urandom(32)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: derived)
    monkeypatch.setattr(held_key, "_purge_keyring",
                        lambda: (_ for _ in ()).throw(RuntimeError("must not inspect")))

    assert session._master_key() == derived
    assert paths.legacy_key_cleanup_file().exists()


def test_cleanup_marker_never_hides_a_legacy_file(monkeypatch, tmp_path):
    from icp.auth import held_key
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    paths.vault_key_file().write_bytes(os.urandom(32))
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: os.urandom(32))
    monkeypatch.setattr(held_key, "_purge_keyring",
                        lambda: (_ for _ in ()).throw(RuntimeError("legacy remains")))

    with pytest.raises(held_key.LegacyKeyCleanupError):
        session._master_key()


def test_clean_markers_self_heal_recreated_held_and_master_items(monkeypatch, tmp_path):
    """A marker records completion, not permission to leave a later item behind."""
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    paths.atomic_write_private(paths.master_key_cleanup_file(), session._MASTER_CLEAN_MARKER)
    held_items = [_SecretItem()]
    master_items = [_SecretItem()]
    _install_secret_service(monkeypatch, held_items=held_items, master_items=master_items)

    derived = os.urandom(32)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: derived)

    assert session._master_key() == derived
    assert held_items[0].deleted
    assert master_items[0].deleted
    assert held_key.cleanup_complete()
    assert session.master_key_cleanup_complete()


def test_clean_markers_tolerate_transient_keyring_outage(monkeypatch, tmp_path):
    """An already-clean vault remains usable while DBus/Secret Service is unavailable."""
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    paths.atomic_write_private(paths.master_key_cleanup_file(), session._MASTER_CLEAN_MARKER)
    _install_secret_service(
        monkeypatch,
        dbus_init=lambda: (_ for _ in ()).throw(RuntimeError("DBus unavailable")),
    )
    derived = os.urandom(32)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: derived)

    assert session._master_key() == derived


def test_recreated_held_item_delete_failure_fails_closed(monkeypatch, tmp_path):
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    paths.atomic_write_private(paths.master_key_cleanup_file(), session._MASTER_CLEAN_MARKER)
    _install_secret_service(monkeypatch, held_items=[_SecretItem(fail=True)])
    derived = os.urandom(32)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: derived)

    with pytest.raises(held_key.LegacyKeyCleanupError):
        session._master_key()


def test_recreated_master_item_delete_failure_fails_closed(monkeypatch, tmp_path):
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    paths.atomic_write_private(paths.master_key_cleanup_file(), session._MASTER_CLEAN_MARKER)
    _install_secret_service(monkeypatch, master_items=[_SecretItem(fail=True)])
    derived = os.urandom(32)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: derived)

    with pytest.raises(session.MasterKeyCleanupError):
        session._master_key()


def test_master_cleanup_marker_failure_retries_on_normal_unlock(monkeypatch, tmp_path):
    """A failed marker write is not allowed to suppress cleanup on the next ordinary use."""
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    held_key.mark_cleanup_complete()
    collection = _install_secret_service(monkeypatch)
    derived = os.urandom(32)
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent, "get_key", lambda: derived)

    real_write = paths.atomic_write_private
    failed = {"once": True}

    def fail_master_marker(path, data):
        if path == paths.master_key_cleanup_file() and failed["once"]:
            failed["once"] = False
            raise OSError("marker write failed")
        return real_write(path, data)

    monkeypatch.setattr(paths, "atomic_write_private", fail_master_marker)
    with pytest.raises(session.MasterKeyCleanupError):
        session._master_key()
    assert not paths.master_key_cleanup_file().exists()

    assert session._master_key() == derived
    assert session.master_key_cleanup_complete()
    assert collection.master_items == []


def test_legacy_cleanup_failure_keeps_committed_journal_and_new_key(monkeypatch, tmp_path, keys):
    from icp import paths
    from icp.auth import held_key

    legacy = paths.vault_key_file()
    legacy.write_bytes(b"legacy raw key")
    before = legacy.read_bytes()
    monkeypatch.setattr(held_key, "_purge_keyring",
                        lambda: (_ for _ in ()).throw(RuntimeError("delete failed")))

    with pytest.raises(held_key.LegacyKeyCleanupError):
        app.cmd_passphrase(argparse.Namespace())

    assert legacy.read_bytes() == before
    assert lockbox.params_file().exists()
    assert lockbox.check_file().exists()
    journal = session._read_migration_journal()
    assert journal["state"] == "committed"


def test_store_failure_rolls_back_kdf_and_ciphertext(monkeypatch, tmp_path, keys):
    from icp import paths
    from icp.vault.host import Credential, CredentialStore

    vault_store.save_vault(CredentialStore([Credential("example.com", "alice", "old", "Example")]))
    before = paths.vault_file().read_bytes()
    monkeypatch.setattr(vault_store, "save_vault",
                        lambda store, *, path=None:
                        (_ for _ in ()).throw(OSError("disk full")))

    with pytest.raises(OSError, match="disk full"):
        app.cmd_passphrase(argparse.Namespace())

    assert paths.vault_file().read_bytes() == before
    assert not lockbox.params_file().exists()
    assert not lockbox.check_file().exists()


def test_failed_agent_invalidation_skips_rollback(monkeypatch, tmp_path, keys):
    """Never restore old ciphertext while the newly derived key may remain in the agent."""
    from icp import paths
    from icp.auth import agent as agent_module
    from icp.vault.host import Credential, CredentialStore

    vault_store.save_vault(CredentialStore([Credential("example.com", "alice", "old", "Example")]))
    before = paths.vault_file().read_bytes()
    original_save = vault_store.save_vault

    def write_then_fail(store, *, path=None):
        original_save(store, path=path)
        raise OSError("fault after replacement")

    monkeypatch.setattr(vault_store, "save_vault", write_then_fail)
    calls = {"count": 0}

    def lock_then_fail():
        calls["count"] += 1
        if calls["count"] == 2:
            raise agent_module.AgentError("lock unavailable")

    monkeypatch.setattr(agent_module, "lock_strict", lock_then_fail)

    with pytest.raises(PassphraseMigrationError, match="runtime key could not be invalidated"):
        app.cmd_passphrase(argparse.Namespace())

    # The destination was never published.  The failed invalidation still leaves the preparing
    # journal in place so a later command can discard the staged bytes without guessing.
    assert paths.vault_file().read_bytes() == before
    assert paths.passphrase_migration_file().exists()
    assert session._read_migration_journal()["state"] == "preparing"


def test_preparing_recovery_invalidates_agent_before_discarding_old_ciphertext(
        monkeypatch, tmp_path):
    """A power loss after unlock_key must not leave the new key active over old ciphertext."""
    from icp import paths
    from icp.auth import agent as agent_module
    from icp.vault.host import Credential, CredentialStore

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    old_key = os.urandom(32)
    new_key = os.urandom(32)
    runtime = {"key": old_key}
    monkeypatch.setattr(agent_module, "get_key", lambda: runtime["key"])
    monkeypatch.setattr(agent_module, "unlock_key",
                        lambda key: runtime.update(key=bytes(key)))
    monkeypatch.setattr(agent_module, "lock_strict",
                        lambda: runtime.update(key=None))
    monkeypatch.setattr(held_key, "ensure_clean", lambda: None)
    monkeypatch.setattr(session, "ensure_legacy_master_key_clean", lambda: None)

    # Keep the old lockbox active while the stores remain encrypted by old_key.
    paths.config_dir()
    lockbox.params_file().write_bytes(b"old kdf parameters")
    lockbox.check_file().write_bytes(b"old check ciphertext")
    session.save({"session": "old"})
    vault_store.save_vault(CredentialStore([
        Credential("example.com", "alice", "old", "Example")]))
    transaction = session.begin_passphrase_migration({
        "params": True, "check": True, "session": True, "vault": True,
    })
    stage = session.migration_stage(transaction, "vault")
    stage.write_bytes(b"staged ciphertext")

    # This is the fault boundary: unlock_key has completed, but no destination or commit state
    # has changed. A new process starts with migration-active state reset and recovers the journal.
    agent_module.unlock_key(new_key)
    assert runtime["key"] == new_key
    session.recover_passphrase_migration()

    assert runtime["key"] is None
    assert not paths.passphrase_migration_file().exists()
    assert not stage.exists()
    runtime["key"] = old_key  # the user unlocks the still-active old passphrase
    assert session.load() == {"session": "old"}
    assert vault_store.load_vault().all()[0].password == "old"


def test_preparing_recovery_retains_state_when_agent_invalidation_fails(
        monkeypatch, tmp_path):
    """A failed strict invalidation must leave recovery state intact and fail closed."""
    from icp import paths
    from icp.auth import agent as agent_module

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    transaction = session.begin_passphrase_migration({"vault": True})
    stage = session.migration_stage(transaction, "vault")
    stage.write_bytes(b"staged ciphertext")
    monkeypatch.setattr(agent_module, "lock_strict",
                        lambda: (_ for _ in ()).throw(agent_module.AgentError("lock unavailable")))

    with pytest.raises(PassphraseMigrationError, match="runtime key could not be invalidated"):
        session.recover_passphrase_migration()

    assert paths.passphrase_migration_file().exists()
    assert stage.exists()
    assert session._read_migration_journal()["state"] == "preparing"


def test_lock_does_not_claim_success_when_agent_invalidation_fails(monkeypatch, tmp_path, capsys):
    from icp.auth import agent as agent_module

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(agent_module, "lock_strict",
                        lambda: (_ for _ in ()).throw(agent_module.AgentError("socket gone")))

    assert app.cmd_lock(argparse.Namespace()) == 1
    captured = capsys.readouterr()
    assert "Locked." not in captured.out
    assert "could not lock" in captured.err


def test_unlock_retries_legacy_cleanup(monkeypatch, tmp_path):
    from icp.auth import agent as agent_module

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(lockbox, "is_initialised", lambda: True)
    monkeypatch.setattr(prompt, "ask_passphrase", lambda **kw: "correct horse battery")
    monkeypatch.setattr(agent_module, "unlock", lambda passphrase: None)
    monkeypatch.setattr(agent_module, "status", lambda: "unlocked 900")
    calls = []
    monkeypatch.setattr(session, "_master_key", lambda: calls.append("cleanup"))

    assert app.cmd_unlock(argparse.Namespace()) == 0
    assert calls == ["cleanup"]


def _seed_all_migration_stores():
    """Write one record to every encrypted destination covered by the journal."""
    from icp.hme.client import HmeAlias
    from icp.vault.host import Credential, CredentialStore

    session.save({"session": "old"})
    vault_store.save_vault(CredentialStore([
        Credential("example.com", "alice", "old", "Example")]))
    hme_store.save_aliases([HmeAlias("a1", "a@icloud.com", "Alias", "note",
                                     "me@example.com", True, "example.com", 1.0)])
    history.save({"example.com\x1falice": [{"old": "older", "new": "old"}]})
    nicknames.save({"example.com\x1falice": "Work"})


@pytest.mark.parametrize("replacement", session._MIGRATION_NAMES)
def test_power_loss_after_each_migration_replacement_recovers_without_old_key(
        monkeypatch, tmp_path, keys, replacement):
    """A process death after any destination replace is completed from the journal and stages."""
    from icp import paths

    _seed_all_migration_stores()
    real_replace = paths.replace_private
    tripped = {"value": False}

    def replace_then_power_loss(source, destination):
        real_replace(source, destination)
        if destination == session._migration_targets()[replacement] and not tripped["value"]:
            tripped["value"] = True
            raise SystemExit("simulated SIGKILL after replace")

    monkeypatch.setattr(paths, "replace_private", replace_then_power_loss)
    with pytest.raises(PassphraseMigrationError, match="commit began"):
        app.cmd_passphrase(argparse.Namespace())
    assert tripped["value"]
    assert session._read_migration_journal()["state"] == "committing"

    # Recovery must not ask for, or decrypt with, the old key.  The fixture's key is already the
    # newly derived one, while the real implementation gets it from the passphrase agent.
    monkeypatch.setattr(paths, "replace_private", real_replace)
    session.recover_passphrase_migration()
    assert session._read_migration_journal()["state"] == "committed"
    assert session.load() == {"session": "old"}
    assert vault_store.load_vault().all()[0].password == "old"
    assert len(hme_store.load_aliases()) == 1
    assert history.for_account(history.load(), "example.com", "alice")
    assert nicknames.load() == {"example.com\x1falice": "Work"}
    session.finish_passphrase_migration()
    assert not paths.passphrase_migration_file().exists()


def test_mutation_lock_serializes_other_processes(monkeypatch, tmp_path):
    """A writer in another process cannot enter while migration owns the shared lock."""
    from icp import paths

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    source_root = os.path.dirname(os.path.dirname(__file__))
    child_env = os.environ.copy()
    child_env["PYTHONPATH"] = source_root + os.pathsep + child_env.get("PYTHONPATH", "")
    script = (
        "from icp import paths; import sys\n"
        "with paths.mutation_lock:\n"
        " print('locked', flush=True)\n"
        " sys.stdin.readline()\n"
    )
    child = subprocess.Popen([sys.executable, "-c", script], env=child_env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        entered = threading.Event()

        def writer():
            with paths.mutation_lock:
                entered.set()

        thread = threading.Thread(target=writer)
        thread.start()
        assert not entered.wait(0.2)
        child.stdin.write("release\n")
        child.stdin.flush()
        thread.join(timeout=2)
        assert entered.is_set()
        assert child.wait(timeout=2) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)


def test_cleanup_failure_after_commit_does_not_restore_new_ciphertext(monkeypatch, tmp_path, keys):
    from icp import paths
    from icp.auth import held_key
    from icp.vault.host import Credential, CredentialStore

    vault_store.save_vault(CredentialStore([Credential("example.com", "alice", "old", "Example")]))
    before = paths.vault_file().read_bytes()
    monkeypatch.setattr(session, "ensure_legacy_master_key_clean",
                        lambda: (_ for _ in ()).throw(OSError("keyring delete failed")))

    with pytest.raises(OSError, match="keyring delete failed"):
        app.cmd_passphrase(argparse.Namespace())

    # All encrypted data is already under the new key at this point. Rolling back would make
    # it unreadable if the keyring deletion had actually completed before reporting the error.
    assert paths.vault_file().read_bytes() != before
    assert held_key.cleanup_complete()
