"""pear-migrate (the v1 importer) against a fake daemon and a fake 1.3.2 agent.

Everything runs in a scratch HOME and runtime directory with made-up files: no real vault, no
real agent, no real systemctl and no Secret Service (both are injected fakes, and the session
bus address is pointed at nothing for good measure).
"""

import base64
import datetime
import itertools
import hashlib
import io
import json
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

from icp.client import migrate
from icp.daemon import protocol

KEY = bytes(range(32))
RIGHT_PASSPHRASE = "correct horse"
TICKET = "T" * 43


class FakeDaemon:
    def __init__(self, test, root, purpose="import", commit_error=None, hello_extra=None):
        self.path = os.path.join(root, "client.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(1)
        test.addCleanup(self.srv.close)
        self.purpose = purpose
        self.commit_error = commit_error
        self.hello_extra = hello_extra or {}
        self.seen = []
        self.files = {}
        self.chunks = {}
        self.key_ok = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _reply(self, req):
        op, rid = req["op"], req["rid"]
        if op == "hello":
            return {"rid": rid, "proto": 2, "version": "2.0.0", "purpose": self.purpose,
                    **self.hello_extra}
        if op == "import-file":
            name = req["name"]
            self.chunks.setdefault(name, []).append((req["seq"], len(req["b64"]), req["eof"]))
            self.files[name] = self.files.get(name, b"") + base64.b64decode(req["b64"])
            if req["eof"]:
                return {"rid": rid, "ok": True, "size": len(self.files[name]),
                        "sha256": hashlib.sha256(self.files[name]).hexdigest()}
            return {"rid": rid, "ok": True}
        if op == "import-key":
            if "check.enc" not in self.files and ("vault.enc" not in self.files
                                                  or "passphrase" in req):
                return {"rid": rid, "error": "incomplete"}
            ok = (req.get("key_b64") == base64.b64encode(KEY).decode()
                  or req.get("passphrase") == RIGHT_PASSPHRASE)
            self.key_ok = self.key_ok or ok
            return {"rid": rid, "ok": True} if ok else {"rid": rid, "error": "wrong-passphrase"}
        if op == "import-commit":
            if self.commit_error:
                return {"rid": rid, "error": self.commit_error}
            if not self.key_ok:
                return {"rid": rid, "error": "incomplete"}
            return {"rid": rid, "counts": {"credentials": 3, "history": 1, "nicknames": 0,
                                           "aliases": 0, "session_keys": 2}, "digest": "ab" * 32}
        return {"rid": rid, "ok": True}

    def _serve(self):
        conn, _ = self.srv.accept()
        f = conn.makefile("rwb")
        for line in f:
            req = json.loads(line)
            self.seen.append(req)
            f.write(json.dumps(self._reply(req)).encode() + b"\n")
            f.flush()
        conn.close()

    def ops(self):
        return [r["op"] for r in self.seen]


class FakeAgent:
    """The 1.3.2 agent's socket: records every command, answers PEEK from its 'grace window'."""

    def __init__(self, test, runtime, warm=True):
        d = os.path.join(runtime, "icp")
        os.makedirs(d, mode=0o700)
        self.path = os.path.join(d, "agent.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(8)
        test.addCleanup(self.srv.close)
        self.warm = warm
        self.commands = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                cmd = conn.makefile("rb").readline().decode().strip()
                self.commands.append(cmd)
                if cmd in ("GET", "PEEK"):
                    conn.sendall(b"OK " + KEY.hex().encode() + b"\n" if self.warm
                                 else b"LOCKED\n")
                else:
                    conn.sendall(b"OK\n")


class FakeKeyring:
    """The Secret Service as the importer sees it: keys from unlocked items and whether
    locked ones exist. It has no unlock: the importer must never ask for one. `unlocked_after`
    reads stand in for the user unlocking the keyring outside Pear."""

    def __init__(self, keys=(), locked=False, locked_keys=(KEY,), unlocked_after=None):
        self._keys = [bytes(k) for k in keys]
        self.locked = locked
        self.locked_keys = [bytes(k) for k in locked_keys]
        self.unlocked_after = unlocked_after
        self.reads = 0
        self.handed = []

    def keys(self):
        self.reads += 1
        if self.locked and self.unlocked_after is not None and self.reads > self.unlocked_after:
            self.locked = False
            self._keys += self.locked_keys
        out = [bytearray(k) for k in self._keys]
        self.handed += out
        return out, self.locked


class Scratch:
    def __init__(self, test):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.home = os.path.join(self.root, "home")
        self.runtime = os.path.join(self.root, "run")
        os.makedirs(self.runtime, mode=0o700)
        self.config = os.path.join(self.home, ".config", "icp")
        os.makedirs(self.config, mode=0o700)
        self.files = {"kdf.json": b'{"salt":"00","alg":"argon2id"}',
                      "check.enc": b"C" * 40,
                      "vault.enc": os.urandom(100 * 1024),
                      "session.enc": b"S" * 300,
                      "history.enc": b"H" * 50}
        for name, data in self.files.items():
            with open(os.path.join(self.config, name), "wb") as f:
                f.write(data)
        with open(os.path.join(self.config, "vault.key"), "wb") as f:
            f.write(b"stray key copy")
        self.units = []
        self.secret_service_calls = 0
        p = mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent"})
        p.start()
        test.addCleanup(p.stop)
        self.not_stopped = []
        self.retired = []

    def fake_stop_units(self):
        self.units.extend(migrate.LEGACY_UNITS)
        return [u for u in migrate.LEGACY_UNITS if u not in self.not_stopped], list(self.not_stopped)

    def fake_retire_app(self, home):
        self.retired.append(home)
        return []

    def fake_secret_service(self):
        self.secret_service_calls += 1
        return 0

    def keyring_vault(self):
        """1.x's default: the key only in the login keyring, no kdf.json or check.enc."""
        for name in ("kdf.json", "check.enc"):
            os.unlink(os.path.join(self.config, name))
            del self.files[name]

    def run(self, daemon, stdin_lines, keyring=None):
        out = io.StringIO()
        self.keyring = keyring or FakeKeyring()
        rc = migrate.run(io.StringIO("".join(line + "\n" for line in stdin_lines)), out,
                         daemon.path, self.home, self.runtime,
                         stop_units=self.fake_stop_units, secret_service=self.fake_secret_service,
                         retire_app=self.fake_retire_app, keyring=self.keyring)
        msgs = [json.loads(line) for line in out.getvalue().splitlines()]
        return rc, msgs

    def write_manifest(self, rel, path=None, ext=migrate.LEGACY_EXTENSION_ID):
        d = os.path.join(self.home, rel)
        os.makedirs(d, exist_ok=True)
        m = {"name": "org.icp.native", "description": "Apple Passwords native messaging host",
             "path": path or os.path.join(self.home, "icp/host/icp-host.sh"),
             "type": "stdio", "allowed_extensions": [ext]}
        p = os.path.join(d, "org.icp.native.json")
        with open(p, "w") as f:
            json.dump(m, f)
        return p


OPTS = json.dumps({"move_manifests": True})


class ImportTests(unittest.TestCase):
    def test_peek_path_imports_and_cleans_up_after_verification(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        agent = FakeAgent(self, s.runtime, warm=True)
        rc, msgs = s.run(d, [TICKET, OPTS])
        self.assertEqual(rc, 0, msgs)
        self.assertEqual(d.seen[0]["role"], "migrate")
        self.assertEqual(d.seen[0]["ticket"], TICKET)
        # Every file arrived intact.
        for name, data in s.files.items():
            self.assertEqual(d.files[name], data, name)
        # The key came from PEEK; no passphrase was asked for.
        self.assertFalse(any("need" in m for m in msgs))
        key_reqs = [r for r in d.seen if r["op"] == "import-key"]
        self.assertEqual(len(key_reqs), 1)
        self.assertIn("key_b64", key_reqs[0])
        # Only PEEK before the import; LOCK and QUIT after it; never GET.
        self.assertEqual(agent.commands, ["PEEK", "LOCK", "QUIT"])
        done = msgs[-1]
        self.assertTrue(done["done"])
        self.assertEqual(done["counts"]["credentials"], 3)
        self.assertNotIn("extension_id", done)            # no 1.x extension manifest here
        backup = done["backup_dir"]
        self.assertEqual(os.path.basename(backup),
                         "icp.v1-backup-" + datetime.date.today().strftime("%Y%m%d"))
        commit = [r for r in d.seen if r["op"] == "import-commit"][0]
        self.assertEqual(commit["backup_dir"], backup)
        self.assertFalse(os.path.exists(s.config))
        self.assertTrue(os.path.isdir(backup))
        self.assertEqual(os.stat(backup).st_mode & 0o777, 0o700)
        self.assertFalse(os.path.exists(os.path.join(backup, "vault.key")))
        self.assertTrue(os.path.exists(os.path.join(backup, "vault.enc")))
        self.assertFalse(os.path.exists(agent.path))
        self.assertEqual(s.units, list(migrate.LEGACY_UNITS))
        self.assertEqual(done["units_not_stopped"], [])
        self.assertEqual(s.retired, [s.home])
        self.assertEqual(s.secret_service_calls, 1)
        self.assertEqual([m.get("stage") for m in msgs if "stage" in m],
                         ["reading", "peek", "converting", "cleanup"])

    def test_never_sends_get(self):
        # Mutation guard: the importer must only PEEK. A cold agent answers LOCKED to PEEK;
        # a GET would have been the call that can raise a legacy prompt.
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        agent = FakeAgent(self, s.runtime, warm=False)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"passphrase": RIGHT_PASSPHRASE})])
        self.assertEqual(rc, 0, msgs)
        self.assertNotIn("GET", agent.commands)
        self.assertEqual(agent.commands[0], "PEEK")

    def test_large_file_is_chunked(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        FakeAgent(self, s.runtime)
        s.run(d, [TICKET, OPTS])
        chunks = d.chunks["vault.enc"]
        self.assertEqual([c[0] for c in chunks], [0, 1, 2, 3])
        self.assertEqual([c[2] for c in chunks], [False, False, False, True])
        for req in d.seen:
            if req["op"] == "import-file":
                self.assertLessEqual(len(base64.b64decode(req["b64"])), protocol.IMPORT_CHUNK_MAX)
                self.assertLess(len(json.dumps(req)) + 1, protocol.MAX_REQUEST_LINE)

    def test_cold_agent_asks_for_the_passphrase_and_retries(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        FakeAgent(self, s.runtime, warm=False)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"passphrase": "wrong"}),
                             json.dumps({"passphrase": RIGHT_PASSPHRASE})])
        self.assertEqual(rc, 0, msgs)
        needs = [m for m in msgs if "need" in m]
        self.assertEqual(needs, [{"need": "passphrase", "retry": False},
                                 {"need": "passphrase", "retry": True}])
        self.assertTrue(msgs[-1]["done"])
        # The passphrase never appears on stdout.
        self.assertNotIn(RIGHT_PASSPHRASE, json.dumps(msgs))

    def test_no_agent_at_all(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"passphrase": RIGHT_PASSPHRASE})])
        self.assertEqual(rc, 0, msgs)
        self.assertEqual([m for m in msgs if "need" in m], [{"need": "passphrase",
                                                             "retry": False}])

    def test_cancel_changes_nothing(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"cancel": True})])
        self.assertEqual(rc, 4)
        self.assertNotIn("import-commit", d.ops())
        self.assertTrue(os.path.isdir(s.config))
        self.assertTrue(os.path.exists(os.path.join(s.config, "vault.key")))
        self.assertEqual(s.units, [])

    def test_mismatch_changes_nothing(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root, commit_error="mismatch")
        agent = FakeAgent(self, s.runtime)
        rc, msgs = s.run(d, [TICKET, OPTS])
        self.assertEqual(rc, 1)
        self.assertEqual(msgs[-1]["error"], "mismatch")
        self.assertTrue(os.path.isdir(s.config))
        self.assertTrue(os.path.exists(os.path.join(s.config, "vault.key")))
        self.assertEqual(agent.commands, ["PEEK"])
        self.assertEqual(s.units, [])
        self.assertEqual(s.secret_service_calls, 0)

    def test_bad_ticket(self):
        s = Scratch(self)
        out = io.StringIO()
        rc = migrate.run(io.StringIO("nope\n"), out, "/nonexistent", s.home, s.runtime)
        self.assertEqual(rc, 2)


class KeyringVaultTests(unittest.TestCase):
    """audit: a 1.x vault keyed by the login keyring sent users to 1.3.2's terminal
    passphrase prompt. Its key now comes from the Secret Service, with no prompt of Pear's."""

    def test_an_unlocked_keyring_imports_with_no_prompt_at_all(self):
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        agent = FakeAgent(self, s.runtime, warm=True)
        rc, msgs = s.run(d, [TICKET, OPTS], keyring=FakeKeyring(keys=[KEY]))
        self.assertEqual(rc, 0, msgs)
        self.assertFalse(any("need" in m for m in msgs), msgs)
        self.assertEqual([m.get("stage") for m in msgs if "stage" in m],
                         ["reading", "keyring", "converting", "cleanup"])
        self.assertNotIn("PEEK", agent.commands)        # no passphrase vault, no agent key
        self.assertNotIn("kdf.json", d.files)
        self.assertTrue(msgs[-1]["done"])
        self.assertEqual(s.secret_service_calls, 1)     # the items are removed afterwards
        for k in s.keyring.handed:
            self.assertEqual(bytes(k), bytes(len(k)))   # every candidate was zeroed
        self.assertNotIn(KEY.hex(), json.dumps(msgs))

    def test_a_wrong_candidate_is_skipped(self):
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        rc, msgs = s.run(d, [TICKET, OPTS], keyring=FakeKeyring(keys=[b"w" * 32, KEY]))
        self.assertEqual(rc, 0, msgs)
        self.assertEqual(len([r for r in d.seen if r["op"] == "import-key"]), 2)

    def test_a_locked_keyring_is_never_asked_to_unlock(self):
        # Round 2 audit, problem 4: Service.Unlock put up the keyring's own password dialog,
        # a second password prompt started by Pear. The window says the keyring is locked;
        # "Check again" (after the user unlocked it their usual way) only reads again.
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        kr = FakeKeyring(locked=True, unlocked_after=1)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"check_keyring": True})], keyring=kr)
        self.assertEqual(rc, 0, msgs)
        self.assertEqual([m for m in msgs if "need" in m],
                         [{"need": "keyring-locked", "retry": False}])
        self.assertEqual(kr.reads, 2)
        self.assertTrue(msgs[-1]["done"])

    def test_nothing_is_read_again_without_the_click(self):
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        kr = FakeKeyring(locked=True, unlocked_after=1)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"cancel": True})], keyring=kr)
        self.assertEqual(rc, 4)
        self.assertEqual(kr.reads, 1)
        self.assertNotIn("import-commit", d.ops())
        self.assertTrue(os.path.isdir(s.config))

    def test_an_old_unlock_request_is_not_a_check(self):
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        kr = FakeKeyring(locked=True, unlocked_after=1)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"unlock_keyring": True})], keyring=kr)
        self.assertEqual(rc, 4)
        self.assertEqual(kr.reads, 1)

    def test_still_locked_asks_again(self):
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        kr = FakeKeyring(locked=True)
        rc, msgs = s.run(d, [TICKET, OPTS, json.dumps({"check_keyring": True}),
                             json.dumps({"cancel": True})], keyring=kr)
        self.assertEqual(rc, 4)
        self.assertEqual([m for m in msgs if "need" in m],
                         [{"need": "keyring-locked", "retry": False},
                          {"need": "keyring-locked", "retry": True}])

    def test_no_key_anywhere_is_a_clear_error_never_a_passphrase(self):
        s = Scratch(self)
        s.keyring_vault()
        d = FakeDaemon(self, s.root)
        rc, msgs = s.run(d, [TICKET, OPTS], keyring=FakeKeyring())
        self.assertEqual(rc, 1)
        self.assertEqual(msgs[-1]["error"], "no-key")
        self.assertFalse(any(m.get("need") == "passphrase" for m in msgs))
        self.assertNotIn("import-commit", d.ops())
        self.assertTrue(os.path.isdir(s.config))

    def test_a_passphrase_vault_takes_a_keyring_copy_before_asking(self):
        s = Scratch(self)
        d = FakeDaemon(self, s.root)
        FakeAgent(self, s.runtime, warm=False)
        rc, msgs = s.run(d, [TICKET, OPTS], keyring=FakeKeyring(keys=[KEY]))
        self.assertEqual(rc, 0, msgs)
        self.assertFalse(any("need" in m for m in msgs), msgs)

    def test_decode(self):
        self.assertEqual(migrate.decode_v1_key(base64.b64encode(KEY)), bytearray(KEY))
        self.assertEqual(migrate.decode_v1_key(KEY), bytearray(KEY))
        for bad in (b"", b"short", base64.b64encode(b"x" * 31), None):
            self.assertIsNone(migrate.decode_v1_key(bad))


class BlockingConn:
    """A jeepney blocking connection's send/receive/outgoing_serial over a fake's
    send_and_get_reply, with replies stamped as a real bus stamps them: the owner lookup
    answered by the driver (sender org.freedesktop.DBus), every other reply sent by that
    owner. dbus_safe.call_blocking accepts nothing else."""

    OWNER = ":1.42"

    @property
    def outgoing_serial(self):
        if "_bc_serial" not in self.__dict__:
            self.__dict__["_bc_serial"] = itertools.count(1)
        return self.__dict__["_bc_serial"]

    def send(self, msg, serial=None):
        from jeepney import HeaderFields, MessageType
        f = msg.header.fields
        driver = f.get(HeaderFields.destination) == "org.freedesktop.DBus"
        if driver and f.get(HeaderFields.member) == "GetNameOwner":
            reply = mock.Mock()
            reply.header.message_type = MessageType.method_return
            reply.body = (self.OWNER,)
        else:
            reply = self.send_and_get_reply(msg)
        sender = "org.freedesktop.DBus" if driver else self.OWNER
        fields = reply.header.fields if isinstance(reply.header.fields, dict) else {}
        reply.header.fields = {**fields, HeaderFields.reply_serial: serial,
                               HeaderFields.sender: sender}
        self.__dict__.setdefault("_bc_queue", []).append(reply)

    def receive(self, timeout=None):
        q = self.__dict__.setdefault("_bc_queue", [])
        if not q:
            raise TimeoutError
        return q.pop(0)


class FakeSecretsBus(BlockingConn):
    """Just enough of a jeepney blocking connection for SecretServiceKeyring."""

    def __init__(self, running=True, unlocked=(), locked=(), secrets=None, prompt="/",
                 dismissed=False):
        self.running, self.unlocked, self.locked = running, list(unlocked), list(locked)
        self.secrets = secrets or {}
        self.prompt, self.dismissed = prompt, dismissed
        self.calls = []

    def send_and_get_reply(self, msg, timeout=None):
        from jeepney import HeaderFields, MessageType
        f = msg.header.fields
        member = f.get(HeaderFields.member)
        self.calls.append((member, msg.body))
        body = ()
        if member == "NameHasOwner":
            body = (self.running,)
        elif member == "SearchItems":
            kind = msg.body[0]["type"]
            body = ([p for p in self.unlocked if kind in p], [p for p in self.locked if kind in p])
        elif member == "OpenSession":
            self.assertPlain = msg.body[0]
            body = (("s", ""), "/org/freedesktop/secrets/session/s1")
        elif member == "GetSecrets":
            body = ({p: ("/s", b"", self.secrets[p], "text/plain") for p in msg.body[0]
                     if p in self.secrets},)
        elif member == "Unlock":
            body = ([], self.prompt)
        reply = mock.Mock()
        reply.header.message_type = MessageType.method_return
        reply.body = body
        return reply

    def filter(self, rule):
        bus = self

        class Q:
            def __enter__(self):
                return "q"

            def __exit__(self, *a):
                return False
        return Q()

    def recv_until_filtered(self, q, timeout=None):
        m = mock.Mock()
        m.body = (self.dismissed, ("s", ""))
        return m

    def close(self):
        pass


class SecretServiceKeyringTests(unittest.TestCase):
    MK = "/org/freedesktop/secrets/collection/login/master-key/1"
    LK = "/org/freedesktop/secrets/collection/login/lockbox-key/2"

    def test_reads_only_unlocked_items_and_never_unlocks(self):
        bus = FakeSecretsBus(unlocked=[self.MK], locked=[self.LK],
                      secrets={self.MK: base64.b64encode(KEY)})
        kr = migrate.SecretServiceKeyring(open_bus=lambda: bus)
        keys, locked = kr.keys()
        self.assertEqual([bytes(k) for k in keys], [KEY])
        self.assertTrue(locked)
        members = [m for m, _ in bus.calls]
        self.assertNotIn("Unlock", members)
        self.assertNotIn("Prompt", members)
        self.assertIn("Close", members)
        searched = [b[0] for m, b in bus.calls if m == "SearchItems"]
        self.assertEqual(searched, [{"application": "icp", "type": "master-key"},
                                    {"application": "icp", "type": "lockbox-key"}])
        self.assertEqual(bus.assertPlain, "plain")

    def test_a_service_that_is_not_running_is_never_started(self):
        bus = FakeSecretsBus(running=False)
        keys, locked = migrate.SecretServiceKeyring(open_bus=lambda: bus).keys()
        self.assertEqual((keys, locked), ([], False))
        self.assertEqual([m for m, _ in bus.calls], ["NameHasOwner"])

    def test_there_is_no_way_to_ask_the_keyring_to_unlock(self):
        # Round 2 audit, problem 4: requirement 2 allows no password prompt besides polkit
        # and the one-time old passphrase in the window; the keyring's unlock dialog was one.
        self.assertFalse(hasattr(migrate.SecretServiceKeyring, "unlock"))
        with open(migrate.__file__) as f:
            src = f.read()
        code = "\n".join(l.split("#")[0] for l in src.splitlines()
                         if not l.lstrip().startswith(("#", '"', "'")))
        for gone in ('"Unlock"', '"Prompt"', "org.freedesktop.Secret.Prompt",
                     '"unlock_keyring"', "unlock_keyring"):
            self.assertNotIn(gone, code, gone)


class FileHygieneTests(unittest.TestCase):
    def _expect(self, s, code):
        d = FakeDaemon(self, s.root)
        rc, msgs = s.run(d, [TICKET, OPTS])
        self.assertEqual(rc, 1, msgs)
        self.assertEqual(msgs[-1]["error"], code)
        self.assertNotIn("import-commit", d.ops())
        return msgs

    def test_symlinked_directory_refused(self):
        s = Scratch(self)
        real = os.path.join(s.root, "elsewhere")
        os.rename(s.config, real)
        os.symlink(real, s.config)
        self._expect(s, "unsafe-file")

    def test_symlinked_file_refused(self):
        s = Scratch(self)
        target = os.path.join(s.root, "planted")
        with open(target, "wb") as f:
            f.write(b"x")
        os.unlink(os.path.join(s.config, "vault.enc"))
        os.symlink(target, os.path.join(s.config, "vault.enc"))
        self._expect(s, "unsafe-file")

    def test_fifo_refused_without_hanging(self):
        s = Scratch(self)
        os.unlink(os.path.join(s.config, "check.enc"))
        os.mkfifo(os.path.join(s.config, "check.enc"))
        self._expect(s, "unsafe-file")

    def test_oversize_refused(self):
        s = Scratch(self)
        with open(os.path.join(s.config, "history.enc"), "wb") as f:
            f.truncate(protocol.IMPORT_FILE_MAX + 1)
        self._expect(s, "unsafe-file")

    def test_missing_required_is_no_v1(self):
        s = Scratch(self)
        os.unlink(os.path.join(s.config, "vault.enc"))
        self._expect(s, "no-v1")

    def test_no_directory_is_no_v1(self):
        s = Scratch(self)
        os.rename(s.config, s.config + ".gone")
        self._expect(s, "no-v1")


class ManifestTests(unittest.TestCase):
    def test_matching_manifests_move_with_consent_others_stay(self):
        s = Scratch(self)
        good = s.write_manifest(".mozilla/native-messaging-hosts")
        other = s.write_manifest(".zen/native-messaging-hosts", path="/opt/someone-else")
        foreign_ext = s.write_manifest(".config/zen/native-messaging-hosts", ext="{other}")
        d = FakeDaemon(self, s.root)
        FakeAgent(self, s.runtime)
        rc, msgs = s.run(d, [TICKET, OPTS])
        self.assertEqual(rc, 0, msgs)
        done = msgs[-1]
        self.assertFalse(os.path.exists(good))
        moved = os.path.join(done["backup_dir"], migrate.MANIFESTS_SUBDIR,
                             "firefox-org.icp.native.json")
        self.assertTrue(os.path.exists(moved))
        self.assertTrue(os.path.exists(other))
        self.assertTrue(os.path.exists(foreign_ext))
        self.assertEqual(sorted(done["kept_manifests"]), sorted([other, foreign_ext]))
        # The window shows the one register command with the old extension's id filled in.
        self.assertEqual(done["extension_id"], migrate.LEGACY_EXTENSION_ID)
        # ~/icp is never touched (it does not even need to exist), and no new host is
        # registered: no io.github.dragosol manifest anywhere.
        for root, _, files in os.walk(s.home):
            self.assertNotIn("io.github.dragosol.pearpasswords.json", files)

    def test_without_consent_nothing_moves(self):
        s = Scratch(self)
        good = s.write_manifest(".mozilla/native-messaging-hosts")
        d = FakeDaemon(self, s.root)
        FakeAgent(self, s.runtime)
        rc, msgs = s.run(d, [TICKET, json.dumps({"move_manifests": False})])
        self.assertEqual(rc, 0, msgs)
        self.assertTrue(os.path.exists(good))
        self.assertEqual(msgs[-1]["kept_manifests"], [good])
        self.assertEqual(msgs[-1]["extension_id"], migrate.LEGACY_EXTENSION_ID)
        # The legacy units are stopped regardless of the checkbox.
        self.assertEqual(len(s.units), len(migrate.LEGACY_UNITS))

    def test_units_that_could_not_be_stopped_are_reported(self):
        # function-legacy-units-not-stopped: a failure is no longer silent.
        s = Scratch(self)
        s.not_stopped = ["icp-host.service"]
        d = FakeDaemon(self, s.root)
        FakeAgent(self, s.runtime, warm=True)
        rc, msgs = s.run(d, [TICKET, OPTS])
        self.assertEqual(rc, 0, msgs)
        self.assertEqual(msgs[-1]["units_not_stopped"], ["icp-host.service"])
        self.assertNotIn("icp-host.service", msgs[-1]["units_stopped"])

    def test_matcher(self):
        home = "/home/u"
        ok = json.dumps({"name": "org.icp.native", "description": "x",
                         "path": "/home/u/icp/host/icp-host.sh", "type": "stdio",
                         "allowed_extensions": [migrate.LEGACY_EXTENSION_ID]}).encode()
        self.assertTrue(migrate.legacy_manifest_matches(ok, home))
        self.assertFalse(migrate.legacy_manifest_matches(ok, "/home/v"))
        extra = json.loads(ok)
        extra["allowed_origins"] = ["chrome-extension://x/"]
        self.assertFalse(migrate.legacy_manifest_matches(json.dumps(extra).encode(), home))
        self.assertFalse(migrate.legacy_manifest_matches(b"not json", home))


class PurgeTests(unittest.TestCase):
    def _backup(self, s):
        b = os.path.join(s.home, ".config", "icp.v1-backup-20261008")
        os.rename(s.config, b)
        return b

    def test_removes_only_matching_recorded_files(self):
        s = Scratch(self)
        b = self._backup(s)
        recorded = [{"name": n, "sha256": hashlib.sha256(d).hexdigest()}
                    for n, d in s.files.items()]
        with open(os.path.join(b, "session.enc"), "wb") as f:
            f.write(b"edited since the import")
        d = FakeDaemon(self, s.root, purpose="purge",
                       hello_extra={"files": recorded, "dir": b})
        rc, msgs = s.run(d, [TICKET])
        self.assertEqual(rc, 0, msgs)
        done = msgs[-1]
        self.assertEqual(done["kept"], ["session.enc"])
        self.assertEqual(sorted(done["removed"]),
                         sorted(n for n in s.files if n != "session.enc"))
        self.assertTrue(os.path.exists(os.path.join(b, "session.enc")))
        self.assertTrue(os.path.exists(os.path.join(b, "vault.key")))   # not recorded: kept
        self.assertFalse(os.path.exists(os.path.join(b, "vault.enc")))
        result = [r for r in d.seen if r["op"] == "purge-result"][0]
        self.assertEqual(result["kept"], ["session.enc"])

    def test_refuses_a_directory_pear_did_not_make(self):
        s = Scratch(self)
        recorded = [{"name": "vault.enc",
                     "sha256": hashlib.sha256(s.files["vault.enc"]).hexdigest()}]
        d = FakeDaemon(self, s.root, purpose="purge",
                       hello_extra={"files": recorded, "dir": s.config})
        rc, msgs = s.run(d, [TICKET])
        self.assertEqual(rc, 1)
        self.assertEqual(msgs[-1]["error"], "unsafe-file")
        self.assertTrue(os.path.exists(os.path.join(s.config, "vault.enc")))

    def test_refuses_unknown_names(self):
        s = Scratch(self)
        b = self._backup(s)
        with open(os.path.join(b, "keepme"), "wb") as f:
            f.write(b"k")
        d = FakeDaemon(self, s.root, purpose="purge", hello_extra={
            "files": [{"name": "keepme", "sha256": hashlib.sha256(b"k").hexdigest()},
                      {"name": "../.bashrc", "sha256": "00"}], "dir": b})
        rc, msgs = s.run(d, [TICKET])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(os.path.join(b, "keepme")))


class FakeBus(BlockingConn):
    """The systemd user manager on the session bus, as far as stop_legacy_units uses it."""

    def __init__(self, files=(), fail=()):
        self.files, self.fail = set(files), set(fail)
        self.calls = []
        self.closed = False

    def send_and_get_reply(self, msg, timeout=None):
        from jeepney import HeaderFields, MessageType
        member = msg.header.fields[HeaderFields.member]
        self.calls.append((member, msg.body))
        err = None
        if member == "GetUnitFileState" and msg.body[0] not in self.files:
            err = "org.freedesktop.DBus.Error.FileNotFound"
        elif member == "DisableUnitFiles" and set(msg.body[0]) & self.fail:
            err = "org.freedesktop.DBus.Error.AccessDenied"
        elif member == "StopUnit" and msg.body[0] in self.fail:
            err = "org.freedesktop.DBus.Error.AccessDenied"
        mtype = MessageType.error if err else MessageType.method_return
        fields = {HeaderFields.error_name: err} if err else {}
        return mock.Mock(header=mock.Mock(message_type=mtype, fields=fields), body=("enabled",))

    def close(self):
        self.closed = True


class LegacyUnitTests(unittest.TestCase):
    """function-legacy-units-not-stopped: the importer runs set-gid, where systemctl --user
    cannot find the user bus (secure_getenv); the units are stopped over D-Bus instead."""

    def test_present_units_are_disabled_and_stopped_absent_ones_skipped(self):
        bus = FakeBus(files={"icp-host.service", "icp-sync.timer"})
        stopped, failed = migrate.stop_legacy_units(open_bus=lambda: bus)
        self.assertEqual(stopped, ["icp-host.service", "icp-sync.timer"])
        self.assertEqual(failed, [])
        self.assertIn(("DisableUnitFiles", (["icp-host.service", "icp-sync.timer"], False)),
                      bus.calls)
        self.assertEqual([b for m, b in bus.calls if m == "StopUnit"],
                         [("icp-host.service", "replace"), ("icp-sync.timer", "replace")])
        self.assertTrue(bus.closed)

    def test_a_failure_is_reported_not_swallowed(self):
        bus = FakeBus(files={"icp-host.service"}, fail={"icp-host.service"})
        stopped, failed = migrate.stop_legacy_units(open_bus=lambda: bus)
        self.assertEqual((stopped, failed), ([], ["icp-host.service"]))

    def test_no_bus_means_none_stopped(self):
        def broken():
            raise OSError("no bus")
        stopped, failed = migrate.stop_legacy_units(open_bus=broken)
        self.assertEqual((stopped, failed), ([], list(migrate.LEGACY_UNITS)))

    def test_systemctl_is_never_run(self):
        self.assertFalse(hasattr(migrate, "SYSTEMCTL"))
        self.assertFalse(hasattr(migrate, "subprocess"))


LAUNCHER_132 = ("[Desktop Entry]\nType=Application\nName=Pear Passwords\n"
                "Comment=Your passwords on iCloud\nExec=@DATA@/app/launch.sh\n"
                "Icon=@DATA@/app/icon.svg\nTerminal=false\nCategories=Utility;Security;\n"
                "Keywords=password;passwords;icloud;login;credentials;2fa;pear;\n")


class RetireOneXAppTests(unittest.TestCase):
    """installer-1x-launcher-never-retired: after the move, the 1.x launcher (which would start
    1.3.2's own first-run passphrase prompts) goes, if it is a released copy."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        self.data = os.path.join(self.home, migrate.DATA_1X)
        self.launcher = os.path.join(self.home, migrate.LAUNCHER_1X)
        os.makedirs(os.path.dirname(self.launcher))
        os.makedirs(os.path.join(self.data, "venv", "bin"))
        os.makedirs(os.path.join(self.data, "app"))
        self.desktop_2x = os.path.join(self.home, "system.desktop")
        open(self.desktop_2x, "w").close()

    def write_launcher(self, text):
        with open(self.launcher, "w") as f:
            f.write(text.replace("@DATA@", self.data))

    def test_released_launcher_and_backend_are_removed(self):
        self.write_launcher(LAUNCHER_132)
        removed = migrate.retire_1x_app(self.home, self.desktop_2x)
        self.assertFalse(os.path.exists(self.launcher))
        self.assertFalse(os.path.exists(self.data))
        self.assertIn(self.launcher, removed)

    def test_an_edited_launcher_stays(self):
        self.write_launcher(LAUNCHER_132 + "# mine\n")
        migrate.retire_1x_app(self.home, self.desktop_2x)
        self.assertTrue(os.path.exists(self.launcher))

    def test_nothing_goes_before_the_2x_launcher_exists(self):
        self.write_launcher(LAUNCHER_132)
        os.unlink(self.desktop_2x)
        self.assertEqual(migrate.retire_1x_app(self.home, self.desktop_2x), [])
        self.assertTrue(os.path.exists(self.launcher))
        self.assertTrue(os.path.isdir(os.path.join(self.data, "venv")))

    def test_hashes_match_the_installers(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, "system", "lib", "user-files.sh")) as f:
            shell = {l.split()[0] for l in f if l.strip().endswith(" pear-passwords.desktop")
                     and len(l.split()[0]) == 64}
        self.assertEqual(shell, set(migrate.RELEASED_LAUNCHER_SHA256))


if __name__ == "__main__":
    unittest.main()
