"""The systemd units, sysusers/tmpfiles entries and the ABI wrapper (spec 4.1, 4.2, 11.5).

Every hardening setting the spec requires is asserted one by one, the settings it rules out are
asserted absent, and paths are compared with system/paths.env. When systemd-analyze is present
the offline exposure score must be 2.5 or lower.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYSTEM = os.path.join(ROOT, "system")
SERVICE = os.path.join(SYSTEM, "units", "pear-passwordsd.service")
SOCKET = os.path.join(SYSTEM, "units", "pear-passwordsd.socket")
WRAPPER = os.path.join(SYSTEM, "libexec", "pear-passwordsd")


def env_file() -> dict:
    out = {}
    with open(os.path.join(SYSTEM, "paths.env"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                k, _, v = line.partition("=")
                out[k] = v
    return out


def unit(path) -> list[tuple[str, str, str]]:
    """(section, key, value) for every assignment, repeats kept (systemd allows them)."""
    rows, section = [], None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            m = re.fullmatch(r"\[(\w+)\]", line)
            if m:
                section = m.group(1)
                continue
            k, _, v = line.partition("=")
            rows.append((section, k.strip(), v.strip()))
    return rows


def values(rows, section, key) -> list[str]:
    return [v for s, k, v in rows if s == section and k == key]


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = unit(SERVICE)
        cls.env = env_file()

    def one(self, key):
        v = values(self.rows, "Service", key)
        self.assertEqual(len(v), 1, key)
        return v[0]

    def test_identity_and_state(self):
        self.assertEqual(self.one("User"), self.env["SERVICE_USER"])
        self.assertEqual(self.one("Group"), self.env["SERVICE_GROUP"])
        self.assertEqual(self.one("SupplementaryGroups"), "")
        self.assertEqual(self.one("ExecStart"), self.env["DAEMON_WRAPPER"])
        self.assertEqual(self.one("Type"), "notify")
        self.assertEqual(self.one("StateDirectory"), "pear-passwords")
        self.assertEqual("/var/lib/" + self.one("StateDirectory"), self.env["STATE_DIR"])
        self.assertEqual(self.one("StateDirectoryMode"), "0700")
        self.assertEqual(self.one("UMask"), "0077")

    def test_required_hardening(self):
        required = {
            "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
            "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
            "PrivateDevices": "yes", "DevicePolicy": "closed", "PrivateIPC": "yes",
            "RemoveIPC": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes",
            "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes", "ProtectClock": "yes",
            "ProtectHostname": "yes", "RestrictNamespaces": "yes", "RestrictRealtime": "yes",
            "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
            "MemoryDenyWriteExecute": "yes", "KeyringMode": "private",
            "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
            "SystemCallArchitectures": "native", "SystemCallErrorNumber": "EPERM",
            "LimitCORE": "0", "LimitMEMLOCK": "16M", "Restart": "on-failure",
            "WatchdogSec": "60", "ProtectProc": "default",
            # gate bug 5: an ABI mismatch (78) is not restarted into the start limit
            "RestartPreventExitStatus": "78",
        }
        for key, value in required.items():
            self.assertEqual(self.one(key), value, key)
        self.assertEqual(values(self.rows, "Service", "SystemCallFilter"),
                         ["@system-service",
                          "~@privileged @mount @debug @cpu-emulation @obsolete"])
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", values(self.rows, "Service", "Environment"))

    def test_ruled_out_settings(self):
        keys = {k for _, k, _ in self.rows}
        # PrivateUsers would map peer uids to nobody; MemoryMax would kill the migration's
        # 256 MiB Argon2id; ProtectProc=invisible would hide the peers' /proc entries.
        for key in ("PrivateUsers", "MemoryMax", "DynamicUser", "AmbientCapabilities=CAP"):
            self.assertNotIn(key, keys)
        self.assertNotIn("invisible", values(self.rows, "Service", "ProtectProc"))
        for _, k, v in self.rows:
            self.assertNotIn("/tmp", v, k)
            self.assertNotIn("/home", v, k)

    def test_no_lease_or_timer(self):
        text = open(SERVICE, encoding="utf-8").read().lower()
        self.assertNotIn("lease", text)
        self.assertNotIn("ontimer", text.replace(" ", ""))

    def test_socket_activated(self):
        self.assertIn(os.path.basename(SOCKET), values(self.rows, "Unit", "Requires"))

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not installed")
    def test_exposure_score(self):
        out = subprocess.run(["systemd-analyze", "security", "--offline=true",
                              "--no-pager", SERVICE], capture_output=True, text=True)
        m = re.search(r"Overall exposure level for \S+: ([0-9.]+)", out.stdout + out.stderr)
        if not m:
            self.skipTest("systemd-analyze gave no score: " + (out.stderr or "")[-200:])
        self.assertLessEqual(float(m.group(1)), 2.5)


class SocketTests(unittest.TestCase):
    def test_socket(self):
        rows = unit(SOCKET)
        env = env_file()
        want = {"ListenStream": env["SOCKET_PATH"], "SocketUser": env["SERVICE_USER"],
                "SocketGroup": env["CLIENT_GROUP"], "SocketMode": "0660",
                "DirectoryMode": "0755", "Accept": "no",
                # gate bug 3: a stopped socket leaves no pear-passwords-owned file in /run
                "RemoveOnStop": "yes"}
        for key, value in want.items():
            self.assertEqual(values(rows, "Socket", key), [value], key)
        self.assertEqual(os.path.dirname(env["SOCKET_PATH"]), env["RUNTIME_DIR"])
        self.assertEqual(values(rows, "Install", "WantedBy"), ["sockets.target"])

    def test_seal_socket_removes_its_file_on_stop(self):
        rows = unit(os.path.join(SYSTEM, "units", "pear-passwords-seal.socket"))
        self.assertEqual(values(rows, "Socket", "RemoveOnStop"), ["yes"])


class SystemFileTests(unittest.TestCase):
    def lines(self, rel):
        with open(os.path.join(SYSTEM, rel), encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    def test_sysusers(self):
        env = env_file()
        self.assertEqual(self.lines("sysusers.d/pear-passwords.conf"), [
            f'u {env["SERVICE_USER"]} - "Pear Passwords vault" {env["STATE_DIR"]}',
            f'g {env["CLIENT_GROUP"]} -'])
        self.assertEqual(os.path.basename(env["SYSUSERS_CONF"]), "pear-passwords.conf")

    def test_tmpfiles(self):
        env = env_file()
        self.assertEqual(self.lines("tmpfiles.d/pear-passwords.conf"), [
            f'd {env["STATE_DIR"]} 0700 {env["SERVICE_USER"]} {env["SERVICE_GROUP"]}'])


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pearabi-")
        self.env = env_file()
        with open(WRAPPER, encoding="utf-8") as f:
            self.src = f.read()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_paths_and_exit_code(self):
        self.assertIn(f'P={self.env["PREFIX"]}\n', self.src)
        self.assertIn(f'ABI_MISMATCH_EXIT={self.env["ABI_MISMATCH_EXIT"]}\n', self.src)
        self.assertIn('exec "$P/venv/bin/python" -I -m icp.daemon\n', self.src)
        self.assertTrue(os.stat(WRAPPER).st_mode & stat.S_IXUSR)

    def _copy(self):
        prefix = os.path.join(self.dir, "p")
        os.makedirs(os.path.join(prefix, "venv", "bin"))
        fake = os.path.join(prefix, "venv", "bin", "python")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\necho "ran: $*"\n')
        os.chmod(fake, 0o755)
        script = os.path.join(self.dir, "pear-passwordsd")
        with open(script, "w") as f:
            f.write(self.src.replace(f'P={self.env["PREFIX"]}\n', f"P={prefix}\n"))
        return prefix, script

    def test_python_bump_exits_78(self):
        prefix, script = self._copy()
        os.makedirs(os.path.join(prefix, "venv", "lib", "python2.7"))
        r = subprocess.run(["sh", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, int(self.env["ABI_MISMATCH_EXIT"]))
        self.assertIn("re-run", r.stderr)

    def test_matching_abi_execs_the_daemon(self):
        prefix, script = self._copy()
        v = subprocess.run(["/usr/bin/python3", "-I", "-c",
                            "import sys; print('%d.%d' % sys.version_info[:2])"],
                           capture_output=True, text=True, check=True).stdout.strip()
        os.makedirs(os.path.join(prefix, "venv", "lib", f"python{v}"))
        r = subprocess.run(["sh", script], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (0, "ran: -I -m icp.daemon\n"))


if __name__ == "__main__":
    unittest.main()
