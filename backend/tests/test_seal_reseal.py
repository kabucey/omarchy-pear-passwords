"""Sealing the key blobs: the systemd-creds command line, the TPM pickup with its rollback
window, and the three ways an unseal can fail.

The real systemd-creds is never run: a fake executable stands in for the command line tests,
and tests/fixtures/fake_seal.py for everything that needs a TPM to appear, vanish or change.
"""

import base64
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fixtures import FakeSealBackend, vstore_env

from icp import vstore
from icp.daemon import paths as system_paths
from icp.vstore import seal

from test_store_v2 import UID, StoreCase, item

FAKE_CREDS = """#!{python}
import base64, os, sys
argv = sys.argv[1:]
with open({log!r}, "a") as f:
    f.write(repr(argv) + "\\n")
ctl = {ctl!r}
mode = open(ctl).read().strip() if os.path.exists(ctl) else ""
head = bytes.fromhex(open(ctl + ".head").read().strip()) if os.path.exists(ctl + ".head") \\
    else bytes.fromhex("55b9ed1d38594d43a8319d2ebb332ac6")
data = sys.stdin.buffer.read()
if mode == "down":
    sys.stderr.write("Failed to connect to io.systemd.Credentials: Connection refused\\n")
    sys.exit(1)
if mode == "broken":
    sys.stderr.write("Failed to frobnicate: Input/output error\\n")
    sys.exit(1)
if argv[:2] == ["--user", "encrypt"]:
    sys.stdout.buffer.write(base64.b64encode(head + b"ENC:" + data))
elif argv[:2] == ["--user", "decrypt"]:
    try:
        raw = base64.b64decode(data, validate=True)[16:]
    except ValueError:
        raw = b""
    if not raw.startswith(b"ENC:"):
        sys.stderr.write("Failed to decrypt: refused\\n")
        sys.exit(1)
    sys.stdout.buffer.write(raw[4:])
else:
    sys.exit(2)
"""


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.log = d / "argv.log"
        exe = d / "systemd-creds"
        self.ctl = d / "mode"
        exe.write_text(FAKE_CREDS.format(python=sys.executable, log=str(self.log),
                                         ctl=str(self.ctl)))
        exe.chmod(0o755)
        self._patch = mock.patch.object(seal, "SYSTEMD_CREDS", str(exe))
        self._patch.start()
        self._tpm = mock.patch.object(seal, "tpm_present", return_value=False)
        self._tpm.start()

    def tearDown(self):
        self._tpm.stop()
        self._patch.stop()
        self._tmp.cleanup()

    def mode(self, m):
        self.ctl.write_text(m)

    def head(self, h: bytes):
        Path(str(self.ctl) + ".head").write_text(h.hex())

    def argvs(self):
        return [eval(line) for line in self.log.read_text().splitlines()]

    def test_encrypt_argv_and_pipe(self):
        b = seal.SystemdCredsBackend()
        secret = bytes(range(32))
        blob = b.encrypt("pear.list.u1000", secret)
        self.assertEqual(b.decrypt("pear.list.u1000", blob), secret)
        enc, dec = self.argvs()
        # In uid scope --with-key and --tpm2-* never reach the service; none is passed, and
        # the key type is read back from the blob instead.
        self.assertEqual(enc, ["--user", "encrypt", "--name=pear.list.u1000", "-", "-"])
        self.assertEqual(b.key_type(blob), "host")
        self.assertEqual(dec, ["--user", "decrypt", "--name=pear.list.u1000", "-", "-"])
        # The secret travels on the pipe only.
        for argv in (enc, dec):
            joined = " ".join(argv)
            self.assertNotIn(secret.hex(), joined)
            self.assertNotIn(base64.b64encode(secret).decode(), joined)

    def test_key_type_comes_from_the_header_and_bad_types_are_refused(self):
        # crypto-user-scope-drops-tpm-flags
        b = seal.SystemdCredsBackend()
        for bad in (seal.CRED_BY_TPM2_WITH_PK, seal.CRED_BY_HOST, seal.CRED_BY_NULL,
                    seal.CRED_BY_TPM2):
            self.head(bad)
            with self.assertRaises(seal.SealUnavailable, msg=bad.hex()):
                b.encrypt("pear.list.u1000", b"k" * 32)
        with mock.patch.object(seal, "tpm_present", return_value=True):
            for good in (seal.CRED_BY_HOST_SCOPED_AND_TPM2, seal.CRED_BY_HOST_SCOPED_AND_TPM2_262):
                self.head(good)
                self.assertEqual(b.key_type(b.encrypt("pear.list.u1000", b"k" * 32)),
                                 "host+tpm2")

    def test_key_type_is_an_allowlist(self):
        # audit: the user-scope key type was a deny-list, so any other id (including the
        # public-key-bound ones) read as host+tpm2 when a TPM was present. Now only the ids
        # confirmed on the swtpm VM (systemd 261.2 and 262) are accepted.
        b = seal.SystemdCredsBackend()
        ok = {"55b9ed1d38594d43a8319d2ebb332ac6": "host",
              "ef4ac13679a9480ea7db68897f9f165d": "host+tpm2",        # 261, swtpm VM
              "2a1f877a4275431ab3f9ed1f5d8f6601": "host+tpm2"}        # 262, swtpm VM
        pk = ["adbc4ca3efb64201ba881b6f2e4095ea", "16e492949f94400286758f94b7c52bc7",
              "af4950a849134eb1a73846304ff30c05", "afbfeaaceb6a4a3795419d135c47f37b",
              "faf7eb9341e3412ca1a436f95a29362f", "5e2d5c7603724eaf843c6fb5f64098f5"]
        unknown = ["a219cb0785b24c04b16d18cab9d2ee01",                  # in 261's table
                   "93a894094874449090caf2fc93cab553",                  # system scope
                   "1414258818a240cd900bce862db5c7b9", "d4062dfb71ad4c86804b40ef1180f1fc",
                   "00" * 16, os.urandom(16).hex()]
        with mock.patch.object(seal, "tpm_present", return_value=True):
            for h, kind in ok.items():
                self.assertEqual(b.key_type(base64.b64encode(bytes.fromhex(h) + b"x")), kind)
            for h in pk:
                with self.assertRaises(seal.SealRefused, msg=h) as cm:
                    b.key_type(base64.b64encode(bytes.fromhex(h) + b"x"))
                self.assertEqual(cm.exception.reason, "pcr-policy", h)
            for h in unknown:
                with self.assertRaises(seal.SealRefused, msg=h) as cm:
                    b.key_type(base64.b64encode(bytes.fromhex(h) + b"x"))
                self.assertEqual(cm.exception.reason, "key-type", h)
            for short in (b"", b"abc"):
                with self.assertRaises(seal.SealRefused):
                    b.key_type(short)
            # An unknown type straight from systemd-creds is refused at encrypt time.
            self.head(bytes.fromhex(unknown[0]))
            with self.assertRaises(seal.SealRefused):
                b.encrypt("pear.list.u1000", b"k" * 32)

    def test_a_refused_seal_is_reported_by_name(self):
        from icp.daemon import handlers
        e = handlers._store_error(seal.SealRefused("pcr-policy", "x"))
        self.assertEqual((e.code, e.extra), ("seal-refused", {"reason": "pcr-policy"}))
        e = handlers._store_error(seal.SealUnavailable("down"))
        self.assertEqual(e.code, "seal-unavailable")

    def test_a_pcr_public_key_blocks_tpm_sealing(self):
        b = seal.SystemdCredsBackend()
        pem = Path(self._tmp.name) / "tpm2-pcr-public-key.pem"
        pem.write_text("-----BEGIN PUBLIC KEY-----\n")
        with mock.patch.object(seal, "PCR_PUBLIC_KEY_PATHS", (str(pem),)):
            with mock.patch.object(seal, "tpm_present", return_value=True):
                with self.assertRaises(seal.SealRefused) as cm:
                    b.encrypt("pear.list.u1000", b"k" * 32)
                self.assertIn(str(pem), str(cm.exception))
                self.assertEqual(cm.exception.reason, "pcr-policy")
                self.assertFalse(self.log.exists(), "systemd-creds ran anyway")
            # without a TPM, auto cannot use the public key: host sealing goes ahead
            self.assertEqual(b.key_type(b.encrypt("pear.list.u1000", b"k" * 32)), "host")

    def test_a_mechanism_failure_is_never_a_refusal(self):
        # crypto-transient-unseal-is-damaged / function-transient-unseal-is-damaged
        b = seal.SystemdCredsBackend()
        blob = b.encrypt("pear.list.u1000", b"k" * 32)
        self.mode("down")
        with self.assertRaises(seal.SealUnavailable):
            b.decrypt("pear.list.u1000", blob)
        self.mode("broken")                     # unknown message, and the canary fails too
        with self.assertRaises(seal.SealUnavailable):
            b.decrypt("pear.list.u1000", blob)
        self.mode("")                           # the tool works: this blob is refused
        with self.assertRaises(seal.UnsealRefused):
            b.decrypt("pear.list.u1000", base64.b64encode(bytes(16) + b"garbage"))

    def test_a_transient_failure_leaves_the_store_locked_not_damaged(self):
        with tempfile.TemporaryDirectory() as root, \
                vstore_env(root, seal.SystemdCredsBackend()):
            s = vstore.UserStore.create(UID)
            s.apply_sync([item("a.example.test", "me", "TEST-pw")], set())
            s.lock()
            before = sorted(p.name for p in (Path(root) / f"u{UID}" / "keys").iterdir())
            s2 = vstore.UserStore.open(UID)
            for m in ("down", "broken"):
                self.mode(m)
                with self.assertRaises(seal.SealUnavailable):
                    s2.unlock()
                self.assertEqual(s2.state(), "locked", m)
            self.assertEqual(sorted(p.name for p in (Path(root) / f"u{UID}" / "keys").iterdir()),
                             before)
            self.mode("")
            s2.unlock()
            self.assertEqual(s2.state(), "unlocked")

    def test_refusal_and_absence_are_different(self):
        b = seal.SystemdCredsBackend()
        with self.assertRaises(seal.UnsealRefused):
            b.decrypt("pear.list.u1000", b"not a credential")
        with mock.patch.object(seal, "SYSTEMD_CREDS", "/nonexistent/systemd-creds"):
            with self.assertRaises(seal.SealUnavailable):
                b.decrypt("pear.list.u1000", b"x")
            with self.assertRaises(seal.SealUnavailable):
                b.encrypt("pear.list.u1000", b"x")
        self.assertTrue(issubclass(seal.SealUnavailable, vstore.StoreError))

    def test_store_end_to_end_through_the_command(self):
        with tempfile.TemporaryDirectory() as root, \
                vstore_env(root, seal.SystemdCredsBackend()), \
                mock.patch.object(seal, "tpm_present", return_value=False):
            s = vstore.UserStore.create(UID)
            s.apply_sync([item("a.example.test", "me", "TEST-pw")], set())
            s.lock()
            s2 = vstore.UserStore.open(UID)
            s2.unlock()
            self.assertEqual(s2.open_entry(s2.list_meta()[0].id).password, "TEST-pw")
        names = [a[2] for a in self.argvs() if a[1] == "encrypt"]
        self.assertEqual(names, [f"--name=pear.list.u{UID}", f"--name=pear.secret.u{UID}"])


class SelectionTests(unittest.TestCase):
    def tearDown(self):
        seal.set_backend(None)

    def test_environment_picks_the_backend(self):
        for value, cls in (("user-creds", seal.SystemdCredsBackend),
                           ("seal-service", seal.SealServiceBackend)):
            seal.set_backend(None)
            with mock.patch.dict(os.environ, {seal.BACKEND_ENV: value}):
                self.assertIsInstance(seal.get_backend(), cls)
        seal.set_backend(None)
        with mock.patch.dict(os.environ, {seal.BACKEND_ENV: "bogus"}):
            with self.assertRaises(vstore.StoreError):
                seal.get_backend()

    def test_default_is_systemd_creds(self):
        seal.set_backend(None)
        env = {k: v for k, v in os.environ.items() if k != seal.BACKEND_ENV}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsInstance(seal.get_backend(), seal.SystemdCredsBackend)


class SealServiceTests(unittest.TestCase):
    """The G1 fallback client against a stand-in for the root seal service."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "seal.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(4)
        self.seen = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.close()
        self._tmp.cleanup()

    def serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                req = json.loads(buf)
                self.seen.append((req["op"], req["name"]))
                data = base64.b64decode(req["b64"])
                if req["op"] == "encrypt":
                    reply = {"b64": base64.b64encode(seal.CRED_BY_HOST + b"S" + data).decode()}
                elif data[16:].startswith(b"S"):
                    reply = {"b64": base64.b64encode(data[17:]).decode()}
                else:
                    reply = {"error": "refused", "detail": "no"}
                conn.sendall(json.dumps(reply).encode() + b"\n")

    def test_round_trip_and_refusal(self):
        b = seal.SealServiceBackend(self.path)
        patcher = mock.patch.object(seal, "tpm_present", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        blob = b.encrypt("pear.secret.u1000", b"k" * 32)
        self.assertEqual(b.decrypt("pear.secret.u1000", blob), b"k" * 32)
        with self.assertRaises(seal.UnsealRefused):
            b.decrypt("pear.secret.u1000", b"garbage")
        self.assertEqual(self.seen[0], ("encrypt", "pear.secret.u1000"))

    def test_unreachable_is_unavailable(self):
        b = seal.SealServiceBackend(os.path.join(self._tmp.name, "nope.sock"))
        with self.assertRaises(seal.SealUnavailable):
            b.decrypt("pear.list.u1000", b"x")


class ProbeTests(unittest.TestCase):
    def test_srk_fingerprint_reads_the_pem(self):
        der = b"\x30\x59" + bytes(89)
        pem = (b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) +
               b"\n-----END PUBLIC KEY-----\n")
        with tempfile.NamedTemporaryFile() as f:
            f.write(pem)
            f.flush()
            with mock.patch.object(system_paths, "TPM_SRK_PUBLIC_KEY", f.name):
                import hashlib
                self.assertEqual(seal.srk_fingerprint(), hashlib.sha256(der).hexdigest())
        with mock.patch.object(system_paths, "TPM_SRK_PUBLIC_KEY", "/nonexistent.pem"):
            self.assertIsNone(seal.srk_fingerprint())

    def test_tpm_present_needs_a_device_and_has_tpm2(self):
        with mock.patch.object(system_paths, "TPM_DEVICE", "/nonexistent/tpmrm0"), \
                mock.patch.object(seal, "TPM_SYSFS", "/nonexistent/tpm0"):
            self.assertFalse(seal.tpm_present())
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(seal, "TPM_SYSFS", d), \
                mock.patch.object(seal, "SYSTEMD_ANALYZE", "/bin/false"):
            self.assertFalse(seal.tpm_present())
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(seal, "TPM_SYSFS", d), \
                mock.patch.object(seal, "SYSTEMD_ANALYZE", "/bin/true"):
            self.assertTrue(seal.tpm_present())

    def test_classify(self):
        b = FakeSealBackend(tpm=False)
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "tpm-missing")
        self.assertEqual(seal.classify(b, "host", None), "damaged")
        b = FakeSealBackend(tpm=True, srk="srk-two")
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "tpm-cleared")
        b.srk = "srk-one"
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "damaged")

    def test_classify_without_an_srk_to_compare(self):
        # crypto-tpm-cleared-unreachable / gate G1 tpm-cleared: no systemd-tpm2-setup PEM on a
        # Limine or GRUB boot without a UKI, so nothing was recorded and nothing is readable.
        b = FakeSealBackend(tpm=True)
        b.srk_visible = False
        self.assertEqual(seal.classify(b, "host+tpm2", None), "tpm-cleared")
        self.assertEqual(seal.classify(b, "host+tpm2", "srk-one"), "tpm-cleared")
        self.assertEqual(seal.classify(b, "host", None), "damaged")


class ResealTests(StoreCase):
    def keyfiles(self):
        kd = self.udir / "keys"
        return {p.name: p.read_bytes() for p in sorted(kd.iterdir())}

    def datafiles(self):
        return {k: v for k, v in self.snapshot().items() if "/keys/" not in k}

    def test_no_tpm_no_reseal(self):
        s = self.populated(1)
        self.assertFalse(s.reseal_if_tpm_available())
        self.assertEqual(s.status()["sealed_with"], "host")

    def rich(self):
        """A store with history, notes, a nickname and a session, so every file is in play."""
        s = self.populated(2)
        first = s.list_meta()[0].id
        s.apply_sync([item("site0.example.test", "user0", "pw-0-new", notes="n")], set())
        s.save_nicknames({first: "Work"})
        s.save_session({"dsid": "1", "token": "t"})
        return s, first

    def test_tpm_appears_and_keys_are_rotated(self):
        # crypto-ptt-reseal-does-not-rotate-keys: new RK_list and SK/PK, every file rewritten.
        s, first = self.rich()
        old_keys, old_data = self.keyfiles(), self.datafiles()
        old_list_blob = old_keys["list.cred"]
        self.backend.tpm = True
        s.lock()
        s.unlock()
        self.assertTrue(s.reseal_if_tpm_available())
        kj = json.loads((self.udir / "keys" / "keys.json").read_bytes())
        self.assertEqual(kj["sealed_with"], "host+tpm2")
        self.assertEqual(kj["tpm_srk_fp"], "srk-one")
        new, new_data = self.keyfiles(), self.datafiles()
        self.assertFalse(any(n.endswith((".prev", ".new")) for n in new), new)
        self.assertFalse(os.path.exists(str(self.udir) + ".rotate"))
        for name in ("list.cred", "secret.cred", "secret.pub"):
            self.assertNotEqual(new[name], old_keys[name])
        self.assertEqual(set(new_data) - {f"u{UID}/state.json"},
                         set(old_data) - {f"u{UID}/state.json"})
        for name, data in new_data.items():
            if not name.endswith(("device.json", "state.json")):
                self.assertNotEqual(data, old_data[name], name)
        # The pre-TPM blob (what an old snapshot holds) still opens with the host key alone,
        # and what it opens is useless against the new files.
        from icp.vstore import format as fmt, keys
        old_rk = keys.SecretBytes(self.backend.decrypt(f"pear.list.u{UID}", old_list_blob))
        old_sub = keys.derive(old_rk)
        with self.assertRaises(vstore.SealError):
            fmt.read_sealed(self.udir, "meta.v2", bytes(old_sub["meta"]), fmt.KIND_META, UID)
        self.assertFalse(s.reseal_if_tpm_available())        # already host+tpm2
        # The live object and a fresh unlock both read everything back.
        self.assertEqual(s.open_entry(first).password, "pw-0-new")
        s.lock()
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertEqual(s2.status()["sealed_with"], "host+tpm2")
        self.assertEqual(s2.open_entry(first).password, "pw-0-new")
        self.assertEqual(s2.open_entry(first).notes, "n")
        self.assertEqual([h[1] for h in s2.history(first)], ["pw-0"])
        self.assertEqual(s2.load_nicknames(), {first: "Work"})
        self.assertEqual(s2.load_session(), {"dsid": "1", "token": "t"})
        # pwmac moved to the new key: an unchanged sync changes nothing.
        unseals = s2.unseal_count
        counts = s2.apply_sync([item("site0.example.test", "user0", "pw-0-new", notes="n"),
                                item("site1.example.test", "user1", "pw-1")], set())
        self.assertEqual(counts["unchanged"], 2)
        self.assertEqual(s2.unseal_count, unseals)

    def test_failed_verification_changes_nothing(self):
        s = self.populated(1)
        before = self.snapshot()
        self.backend.tpm = True
        self.backend.corrupt_next_encrypts = 2
        self.assertFalse(s.reseal_if_tpm_available())
        self.assertEqual(self.snapshot(), before)            # no .rotate, same blobs
        self.assertEqual(s.status()["sealed_with"], "host")
        s.lock()
        vstore.UserStore.open(UID).unlock()                   # still opens

    def test_no_host_only_copy_survives_the_rotation(self):
        s = self.populated(1)
        self.backend.tpm = True
        self.assertTrue(s.reseal_if_tpm_available())
        s.lock()
        # The TPM goes away again: there is no host-only key left to fall back to (it would
        # be exactly what an old snapshot holds), so this is tpm-missing, and turning PTT
        # back on is the recovery.
        self.backend.tpm = False
        s2 = vstore.UserStore.open(UID)
        with self.assertRaises(vstore.SealError) as cm:
            s2.unlock()
        self.assertEqual(cm.exception.kind, "tpm-missing")
        self.backend.tpm = True
        s2.unlock()
        self.assertEqual(s2.open_entry(s2.list_meta()[0].id).password, "pw-0")

    def test_a_rotation_interrupted_before_the_swap_leaves_the_old_store(self):
        # crypto-reseal-swap-not-crash-safe
        from icp.vstore import format as fmt
        s, first = self.rich()
        self.backend.tpm = True
        with mock.patch.object(fmt, "exchange", side_effect=SystemExit("power cut")):
            with self.assertRaises(SystemExit):
                s.reseal_if_tpm_available()
        self.assertTrue(os.path.isdir(str(self.udir) + ".rotate"))
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertFalse(os.path.exists(str(self.udir) + ".rotate"))
        self.assertEqual(s2.status()["sealed_with"], "host")
        self.assertEqual(s2.open_entry(first).password, "pw-0-new")
        self.assertTrue(s2.reseal_if_tpm_available())        # and it simply runs again
        self.assertEqual(s2.open_entry(first).password, "pw-0-new")

    def test_a_rotation_interrupted_after_the_swap_leaves_the_new_store(self):
        from icp import vstore as v
        from icp.vstore import format as fmt
        s, first = self.rich()
        self.backend.tpm = True
        real_remove, real_exchange = v._remove_tree, fmt.exchange
        swapped = []

        def exchange(a, b):
            real_exchange(a, b)
            swapped.append(True)

        def remove(path):
            if swapped:                      # the removal of the old tree, after the swap
                raise SystemExit("power cut")
            real_remove(path)
        with mock.patch.object(v, "_remove_tree", remove), \
                mock.patch.object(fmt, "exchange", exchange):
            with self.assertRaises(SystemExit):
                s.reseal_if_tpm_available()
        self.assertTrue(os.path.isdir(str(self.udir) + ".rotate"))   # the old tree
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertFalse(os.path.exists(str(self.udir) + ".rotate"))
        self.assertEqual(s2.status()["sealed_with"], "host+tpm2")
        self.assertEqual(s2.open_entry(first).password, "pw-0-new")
        self.assertEqual([h[1] for h in s2.history(first)], ["pw-0"])

    def test_a_prev_is_never_dropped_while_it_is_the_only_copy(self):
        # crypto-reseal-swap-not-crash-safe (the old swap's state): secret.cred moved aside,
        # its replacement still .new. The unlock must not delete secret.cred.prev.
        s = self.populated(1)
        s.lock()
        kd = self.udir / "keys"
        os.replace(kd / "secret.cred", kd / "secret.cred.prev")
        (kd / "secret.cred.new").write_bytes(b"x")
        s2 = vstore.UserStore.open(UID)
        s2.unlock()
        self.assertTrue((kd / "secret.cred.prev").exists())

    def test_reseal_needs_unlock(self):
        s = vstore.UserStore.create(UID)
        s.lock()
        with self.assertRaises(vstore.StoreLocked):
            s.reseal_if_tpm_available()


class RefusedCreateTests(StoreCase):
    def test_a_refused_seal_leaves_nothing_behind(self):
        # Gate run (round 1, PEM case): a refused create left an empty u<uid>/ skeleton.
        with mock.patch.object(self.backend, "encrypt",
                               side_effect=seal.SealRefused("pcr-policy", "x")):
            with self.assertRaises(seal.SealRefused):
                vstore.UserStore.create(UID)
        self.assertFalse(self.udir.exists())
        self.assertEqual(vstore.UserStore.open(UID).state(), "empty")


class CreateBlockedTests(StoreCase):
    """Gate finding 1 / audit note (b): known before any dialog that create() would be
    refused, so migrate-begin and reset can say so before the .manage dialog."""

    def test_a_tpm_with_a_pcr_public_key_blocks_a_new_store(self):
        with mock.patch.object(seal, "tpm_present", return_value=True), \
                mock.patch.object(seal, "pcr_public_key_present", return_value="/run/x.pem"), \
                mock.patch.object(seal, "get_backend", return_value=seal.SystemdCredsBackend()):
            self.assertEqual(vstore.UserStore.create_blocked(), "pcr-policy")

    def test_otherwise_nothing_is_known_to_block_it(self):
        for tpm, pem in ((False, "/run/x.pem"), (True, None), (False, None)):
            with mock.patch.object(seal, "tpm_present", return_value=tpm), \
                    mock.patch.object(seal, "pcr_public_key_present", return_value=pem), \
                    mock.patch.object(seal, "get_backend",
                                      return_value=seal.SystemdCredsBackend()):
                self.assertIsNone(vstore.UserStore.create_blocked(), (tpm, pem))
        # The seal service passes an empty --tpm2-public-key=, so it is never blocked.
        with mock.patch.object(seal, "tpm_present", return_value=True), \
                mock.patch.object(seal, "pcr_public_key_present", return_value="/run/x.pem"), \
                mock.patch.object(seal, "get_backend", return_value=seal.SealServiceBackend()):
            self.assertIsNone(vstore.UserStore.create_blocked())


class TpmMoveStateTests(StoreCase):
    """What the window is told before it offers "Move your keys onto the security chip"."""

    def test_states(self):
        s = vstore.UserStore.create(UID)
        self.assertEqual(s.tpm_move_state(), "no-tpm")
        self.backend.tpm = True
        self.assertEqual(s.tpm_move_state(), "available")
        # Unlocking with a TPM present changes nothing on its own.
        s.lock()
        s.unlock()
        self.assertEqual(json.loads((self.udir / "keys" / "keys.json").read_text())["sealed_with"],
                         "host")
        self.assertTrue(s.reseal_if_tpm_available())
        self.assertEqual(s.tpm_move_state(), "sealed")

    def test_a_pcr_public_key_blocks_the_move(self):
        s = vstore.UserStore.create(UID)
        with mock.patch.object(seal, "tpm_present", return_value=True), \
                mock.patch.object(seal, "pcr_public_key_present", return_value="/run/x.pem"), \
                mock.patch.object(seal, "get_backend", return_value=seal.SystemdCredsBackend()):
            self.assertEqual(s.tpm_move_state(), "pcr-policy")


class SealStateTests(StoreCase):
    tpm = True

    def test_created_with_a_tpm_records_it(self):
        s = vstore.UserStore.create(UID)
        kj = json.loads((self.udir / "keys" / "keys.json").read_bytes())
        self.assertEqual((kj["sealed_with"], kj["tpm_srk_fp"]), ("host+tpm2", "srk-one"))
        self.assertFalse(s.reseal_if_tpm_available())

    def locked_store(self):
        s = self.populated(1)
        s.lock()
        return vstore.UserStore.open(UID)

    def test_tpm_switched_off_is_tpm_missing(self):
        s = self.locked_store()
        before = self.snapshot()
        self.backend.tpm = False
        with self.assertRaises(vstore.SealError) as cm:
            s.unlock()
        self.assertEqual(cm.exception.kind, "tpm-missing")
        self.assertEqual(s.state(), "tpm-missing")
        self.assertEqual(self.snapshot(), before)
        # Switching it back on is the whole recovery.
        self.backend.tpm = True
        s.unlock()
        self.assertEqual(s.state(), "unlocked")

    def test_tpm_cleared_is_not_tpm_missing(self):
        s = self.locked_store()
        before = self.snapshot()
        self.backend.srk = "srk-two"          # a TPM is there, but it is not the same one
        with self.assertRaises(vstore.SealError) as cm:
            s.unlock()
        self.assertEqual(cm.exception.kind, "tpm-cleared")
        self.assertEqual(s.status()["state"], "tpm-cleared")
        self.assertEqual(self.snapshot(), before)

    def test_tpm_cleared_on_a_boot_without_an_srk_pem(self):
        self.backend.srk_visible = False       # no UKI: no tpm2-srk-public-key.pem, ever
        s = vstore.UserStore.create(UID)
        s.apply_sync([item("a.example.test", "me", "pw")], set())
        s.lock()
        kj = json.loads((self.udir / "keys" / "keys.json").read_bytes())
        self.assertNotIn("tpm_srk_fp", kj)
        self.backend.srk = "srk-two"           # BIOS "Clear TPM"
        s2 = vstore.UserStore.open(UID)
        with self.assertRaises(vstore.SealError) as cm:
            s2.unlock()
        self.assertEqual(cm.exception.kind, "tpm-cleared")

    def test_host_key_lost_is_damaged(self):
        s = self.locked_store()
        self.backend.host_key = os.urandom(32)
        with self.assertRaises(vstore.SealError) as cm:
            s.unlock()
        self.assertEqual(cm.exception.kind, "damaged")

    def test_tool_unavailable_is_not_a_seal_state(self):
        s = self.locked_store()
        self.backend.unavailable = True
        with self.assertRaises(seal.SealUnavailable):
            s.unlock()
        self.assertEqual(s.state(), "locked")

    def test_entry_key_refused_mid_session(self):
        s = self.populated(1)
        self.backend.tpm = False
        with self.assertRaises(vstore.SealError) as cm:
            s.open_entry(s.list_meta()[0].id)
        self.assertEqual(cm.exception.kind, "tpm-missing")


if __name__ == "__main__":
    unittest.main()
