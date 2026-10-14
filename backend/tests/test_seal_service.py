"""The gate G1 fallback, root's seal service (icp.vstore.seal_service), against the daemon's
own client for it (seal.SealServiceBackend), over a real unix socket. systemd-creds is a fake
runner; nothing here is root or touches a real credential.
"""

import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from icp.daemon import paths
from icp.vstore import seal, seal_service

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeCreds:
    """Stands in for system-scope systemd-creds: 'seals' by prefixing the name."""

    def __init__(self, refuse=False, rc=0):
        self.refuse = refuse
        self.rc = rc
        self.argvs = []

    def __call__(self, argv, data):
        self.argvs.append(list(argv))
        name = [a for a in argv if a.startswith("--name=")][0][7:].encode()
        if self.rc:
            return self.rc, b"", b"failed"
        if argv[1] == "encrypt":
            head = {"--with-key=host": seal.CRED_BY_HOST,
                    "--with-key=host+tpm2": seal.CRED_BY_HOST_AND_TPM2}[argv[2]]
            return 0, base64.b64encode(head + b"SEALED:" + name + b":" + data), b""
        try:
            raw = base64.b64decode(data, validate=True)[16:]
        except ValueError:
            raw = b""
        if self.refuse or not raw.startswith(b"SEALED:" + name + b":"):
            return 1, b"", b"Failed to decrypt the credential."
        return 0, raw[len(b"SEALED:" + name + b":"):], b""


class ServiceCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pear-seal-")
        self.path = os.path.join(self.tmp, "seal.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen()
        self.creds = FakeCreds()
        self.uid = os.getuid()
        self.served = []

    def tearDown(self):
        self.srv.close()
        os.unlink(self.path)
        os.rmdir(self.tmp)

    def accept_once(self):
        def run():
            conn, _ = self.srv.accept()
            with conn:
                self.served.append(seal_service.serve(conn, self.uid, self.creds))
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def call(self, fn, *args):
        t = self.accept_once()
        try:
            return fn(*args)
        finally:
            t.join(5)


class RoundTripTests(ServiceCase):
    def setUp(self):
        super().setUp()
        self._tpm = mock.patch.object(seal, "tpm_present", return_value=False)
        self._tpm.start()

    def tearDown(self):
        self._tpm.stop()
        super().tearDown()

    def test_encrypt_then_decrypt_through_the_daemons_client(self):
        client = seal.SealServiceBackend(self.path)
        blob = self.call(client.encrypt, "pear.list.u1000", b"k" * 32)
        self.assertNotEqual(blob, b"k" * 32)
        self.assertEqual(client.key_type(blob), "host")
        self.assertEqual(self.call(client.decrypt, "pear.list.u1000", blob), b"k" * 32)
        enc, dec = self.creds.argvs
        # System scope, where the flags apply: an explicit key type (never auto), no PCRs,
        # and an empty public key so no signed PCR policy is picked up.
        self.assertEqual(enc, [seal.SYSTEMD_CREDS, "encrypt", "--with-key=host",
                               "--tpm2-pcrs=", "--tpm2-public-key=",
                               "--name=pear.list.u1000", "-", "-"])
        self.assertEqual(dec, [seal.SYSTEMD_CREDS, "decrypt", "--name=pear.list.u1000",
                               "-", "-"])
        for argv in (enc, dec):
            self.assertNotIn("--user", argv)
            self.assertNotIn("k" * 32, " ".join(argv))          # the secret never in argv

    def test_with_a_tpm_it_asks_for_host_and_tpm2_explicitly(self):
        # crypto-user-scope-drops-tpm-flags: never auto, so a tpm2-pcr-public-key.pem can
        # never bind the blob; and sealed_with comes from the blob, not a guess.
        client = seal.SealServiceBackend(self.path)
        with mock.patch.object(seal, "tpm_present", return_value=True):
            blob = self.call(client.encrypt, "pear.list.u1000", b"k" * 32)
        self.assertEqual(self.creds.argvs[0][2], "--with-key=host+tpm2")
        self.assertEqual(client.key_type(blob), "host+tpm2")
        for bad in (seal.CRED_BY_TPM2_WITH_PK, seal.CRED_BY_NULL, seal.CRED_BY_HOST_SCOPED):
            with self.assertRaises(seal.SealUnavailable):
                client.key_type(base64.b64encode(bad + b"x"))

    def test_system_key_type_is_an_allowlist(self):
        # audit: the seal service's key type was a deny-list too.
        client = seal.SealServiceBackend(self.path)
        for h, kind in (("5a1c6a86df9d4096b1d5a65e0862f19a", "host"),
                        ("93a894094874449090caf2fc93cab553", "host+tpm2"),      # 261
                        ("1414258818a240cd900bce862db5c7b9", "host+tpm2")):     # 262
            self.assertEqual(client.key_type(base64.b64encode(bytes.fromhex(h) + b"x")), kind)
        for h in ("af4950a849134eb1a73846304ff30c05", "afbfeaaceb6a4a3795419d135c47f37b",
                  "a219cb0785b24c04b16d18cab9d2ee01", "ef4ac13679a9480ea7db68897f9f165d",
                  "d4062dfb71ad4c86804b40ef1180f1fc", "ff" * 16):
            with self.assertRaises(seal.SealRefused, msg=h):
                client.key_type(base64.b64encode(bytes.fromhex(h) + b"x"))

    def test_the_root_side_never_hands_out_another_key_type(self):
        def creds(head):
            def run(argv, data):
                return 0, base64.b64encode(head + b"blob"), b""
            return run
        req = json.dumps({"op": "encrypt", "name": "pear.list.u1000",
                          "b64": base64.b64encode(b"k" * 32).decode(), "with": "host"}).encode()
        for head in (seal.CRED_BY_HOST_AND_TPM2_WITH_PK, bytes.fromhex("a219cb0785b24c04b16d18cab9d2ee01"),
                     seal.CRED_BY_HOST_AND_TPM2):           # the last: not what was asked
            r = seal_service.handle(req, creds(head))
            self.assertEqual(r.get("error"), "internal", head.hex())
            self.assertNotIn("b64", r)
        self.assertIn("b64", seal_service.handle(req, creds(seal.CRED_BY_HOST)))

    def test_with_is_only_a_key_type_and_only_for_encrypt(self):
        for req in ({"op": "encrypt", "name": "pear.list.u1", "b64": "eA==", "with": "auto"},
                    {"op": "encrypt", "name": "pear.list.u1", "b64": "eA==",
                     "with": "host+tpm2-with-public-key"},
                    {"op": "decrypt", "name": "pear.list.u1", "b64": "eA==", "with": "host"}):
            self.assertEqual(seal_service.handle(json.dumps(req).encode(), self.creds)["error"],
                             "bad-request", req)
        self.assertEqual(self.creds.argvs, [])

    def test_a_refused_decrypt_is_unseal_refused_not_unavailable(self):
        client = seal.SealServiceBackend(self.path)
        self.creds.refuse = True
        with self.assertRaises(seal.UnsealRefused):
            self.call(client.decrypt, "pear.secret.u1000", b"blob")

    def test_a_tool_failure_is_transient(self):
        client = seal.SealServiceBackend(self.path)
        self.creds.rc = -9
        with self.assertRaises(seal.SealUnavailable):
            self.call(client.decrypt, "pear.secret.u1000", b"blob")
        self.creds.rc = 1
        with self.assertRaises(seal.SealUnavailable):
            self.call(client.encrypt, "pear.secret.u1000", b"x")

    def test_no_service_is_transient(self):
        with self.assertRaises(seal.SealUnavailable):
            seal.SealServiceBackend(os.path.join(self.tmp, "nope.sock")).encrypt(
                "pear.list.u1000", b"x")


class RefusalTests(ServiceCase):
    def raw(self, line: bytes):
        t = self.accept_once()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.path)
            try:
                s.sendall(line)
                s.shutdown(socket.SHUT_WR)
                out = s.makefile("rb").read()
            except (ConnectionResetError, BrokenPipeError):
                out = b""                         # closed on us without a reply
        t.join(5)
        return json.loads(out) if out else None

    def test_another_uid_gets_nothing(self):
        self.uid = os.getuid() + 1
        self.assertIsNone(self.raw(b'{"op":"encrypt","name":"pear.list.u1","b64":"eA=="}\n'))
        self.assertEqual(self.served, [False])
        self.assertEqual(self.creds.argvs, [])

    def test_only_pear_key_names(self):
        for name in ("pear.list.u", "pear.list.u1000x", "pear.other.u1", "x/../pear.list.u1",
                     "pear.list.u1\n", "pear.list.u12345678901", 7):
            req = json.dumps({"op": "encrypt", "name": name, "b64": "eA=="}).encode() + b"\n"
            self.assertEqual(self.raw(req), {"error": "bad-request", "detail": "name"}, name)
        self.assertEqual(self.creds.argvs, [])

    def test_malformed_requests(self):
        cases = [(b"not json\n", "not JSON"),
                 (b'{"op":"encrypt","name":"pear.list.u1"}\n', "expected op, name and b64"),
                 (b'{"op":"exec","name":"pear.list.u1","b64":"eA=="}\n', "op"),
                 (b'{"op":"encrypt","name":"pear.list.u1","b64":"!!"}\n', "b64"),
                 (b'{"op":"encrypt","name":"pear.list.u1","b64":""}\n', "b64"),
                 (b'{"op":"encrypt","name":"pear.list.u1","b64":"eA==","x":1}\n',
                  "expected op, name and b64")]
        for line, detail in cases:
            self.assertEqual(self.raw(line), {"error": "bad-request", "detail": detail}, line)
        big = b'{"op":"encrypt","name":"pear.list.u1","b64":"' + b"A" * (300 * 1024)
        self.assertEqual(self.raw(big), {"error": "bad-request", "detail": "too large"})
        self.assertEqual(self.creds.argvs, [])


class UnitTests(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(ROOT, "system", "units", name), encoding="utf-8") as f:
            return f.read()

    def test_socket_reaches_only_the_daemons_group(self):
        u = self.read(paths.SEAL_SOCKET_UNIT)
        self.assertIn(f"ListenStream={paths.SEAL_SOCKET_PATH}\n", u)
        self.assertEqual(seal.SEAL_SERVICE_SOCKET, paths.SEAL_SOCKET_PATH)
        for line in ("SocketUser=root", f"SocketGroup={paths.SERVICE_GROUP}", "SocketMode=0660",
                     "Accept=yes"):
            self.assertIn(line + "\n", u)

    def test_service_runs_this_module_hardened(self):
        u = self.read(paths.SEAL_SERVICE_UNIT)
        self.assertIn(f"ExecStart={paths.VENV_PYTHON} -I -m icp.vstore.seal_service\n", u)
        for line in ("StandardInput=socket", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
                     "ProtectSystem=strict", "ProtectHome=yes", "PrivateNetwork=yes",
                     "DevicePolicy=closed", "RestrictAddressFamilies=AF_UNIX", "LimitCORE=0"):
            self.assertIn(line + "\n", u)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not installed")
    def test_exposure_score(self):
        path = os.path.join(ROOT, "system", "units", paths.SEAL_SERVICE_UNIT)
        out = subprocess.run(["systemd-analyze", "security", "--offline=true", "--no-pager",
                              path], capture_output=True, text=True, timeout=60)
        m = re.search(r"Overall exposure level for \S+: ([0-9.]+)", out.stdout + out.stderr)
        if not m:
            self.skipTest("systemd-analyze gave no score: " + (out.stderr or "")[-200:])
        self.assertLessEqual(float(m.group(1)), 2.5)

    def test_daemon_unit_ships_with_the_primary_path(self):
        """The switch is off: systemd-creds --user (gate G1) until the VM says otherwise."""
        u = self.read(paths.SERVICE_UNIT)
        self.assertIn("#Environment=PEAR_SEAL_BACKEND=seal-service\n", u)
        self.assertNotRegex(u, re.compile(r"^Environment=PEAR_SEAL_BACKEND", re.M))
        self.assertIsInstance(seal.SystemdCredsBackend(), seal.SystemdCredsBackend)

    def test_backend_selection(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "backend"))
        code = ("from icp.vstore import seal; import sys; "
                "print(type(seal.get_backend()).__name__)")
        for value, want in ((None, "SystemdCredsBackend"), ("user-creds", "SystemdCredsBackend"),
                            ("seal-service", "SealServiceBackend")):
            e = dict(env)
            e.pop(seal.BACKEND_ENV, None)
            if value:
                e[seal.BACKEND_ENV] = value
            out = subprocess.run([sys.executable, "-c", code], env=e, capture_output=True,
                                 text=True, timeout=30)
            self.assertEqual(out.stdout.strip(), want, out.stderr)

    def test_main_refuses_arguments(self):
        old = sys.argv
        sys.argv = ["seal_service", "extra"]
        try:
            self.assertEqual(seal_service.main(), 64)
        finally:
            sys.argv = old


if __name__ == "__main__":
    unittest.main()
