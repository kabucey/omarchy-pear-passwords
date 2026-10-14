"""system/install-root.sh, system/uninstall-root.sh and system/lib/files.sh, run for real.

The root step is the one part of Pear that writes outside $HOME, so what it may overwrite or
delete is decided by one rule (lib/files.sh): a path is ours only if it is a regular file whose
bytes are the staged source, the receipt's record, or a frozen RELEASED copy. These tests run
the actual scripts in their test mode (PP_TEST_ROOT): every system path is taken under a scratch
directory, nothing is chowned, and commands that would change the running system (systemctl,
systemd-sysusers, userdel, ...) are written to commands.log instead. The stage is synthetic
but has the real shape: the real paths.env, files.sh and both scripts, plus stand-ins for the
the files the rest of the repository provides.
"""

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYSTEM = os.path.join(ROOT, "system")


def _env():
    out = {}
    with open(os.path.join(SYSTEM, "paths.env"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k] = v
    return out


P = _env()
PREFIX = P["PREFIX"]
LEGACY = P["LEGACY_POLICY_FILE"]
LEGACY_SRC = os.path.join(ROOT, "polkit", "org.icp.unlock.policy")
# The 3 Sep "iCloud Keychain for Linux" copy of the legacy action, one of the RELEASED hashes.
LEGACY_RELEASED_SAMPLE = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE policyconfig PUBLIC\n'
    b' "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"\n'
    b' "http://www.freedesktop.org/software/polkit/policyconfig-1.dtd">\n<policyconfig>\n'
    b'  <vendor>iCloud Keychain for Linux</vendor>\n\n'
    b'  <!-- Re-authentication for an already-unlocked keychain. auth_self prompts via the desktop\n'
    b'       polkit agent for whichever factors PAM offers - here the user\'s own password, or a\n'
    b'       fingerprint, because polkit-1 includes system-auth and that carries pam_fprintd.\n\n'
    b'       This gates nothing privileged: it is checked with pkcheck, which runs no command. The\n'
    b'       vault key still comes from the passphrase; this only decides whether an existing agent\n'
    b'       lease may be used without retyping it. -->\n'
    b'  <action id="org.icp.unlock">\n'
    b'    <description>Unlock the iCloud Keychain viewer</description>\n'
    b'    <message>Authenticate to view your saved passwords</message>\n'
    b'    <defaults>\n      <allow_any>auth_self</allow_any>\n'
    b'      <allow_inactive>auth_self</allow_inactive>\n'
    b'      <allow_active>auth_self</allow_active>\n    </defaults>\n  </action>\n'
    b'</policyconfig>\n')

FAKE_POLICY = b"""<?xml version="1.0"?>
<policyconfig>
  <action id="io.github.dragosol.pearpasswords.unlock"><message>m</message></action>
</policyconfig>
"""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Harness:
    """A scratch stage and a scratch root, and the commands to run against them."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.stage = os.path.join(tmp, "stage")
        self.root = os.path.join(tmp, "root")
        os.makedirs(self.root)
        for d in ("etc", "var/lib", "usr/share/polkit-1/actions", "etc/systemd/system"):
            os.makedirs(self.r(d), exist_ok=True)
        with open(self.r("etc/passwd"), "w") as f:
            f.write("root:x:0:0::/root:/bin/bash\n")
        with open(self.r("etc/group"), "w") as f:
            f.write("root:x:0:\n")
        self.make_stage()

    def r(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    # --- the stage ------------------------------------------------------------------------
    def write(self, rel, data, mode=0o644):
        p = os.path.join(self.stage, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(p, mode)

    def make_stage(self):
        shutil.rmtree(self.stage, ignore_errors=True)
        os.makedirs(self.stage)
        for rel in ("system/paths.env", "system/lib/files.sh", "system/install-root.sh",
                    "system/uninstall-root.sh"):
            with open(os.path.join(ROOT, rel), "rb") as f:
                self.write(rel, f.read())
        self.write("manifest.json", '{\n  "version": "2.0.0"\n}\n')
        self.write("app/shell.qml", "// window\n")
        self.write("app/qmldir", "Theme 1.0 Theme.qml\n")
        self.write("app/Theme.qml", "// theme\n")
        self.write("app/fonts.conf", "<fontconfig/>\n")
        self.write(f"app/{P['APP_ID']}.desktop", f"[Desktop Entry]\nExec={P['PEAR_EXEC']} ui\n")
        self.write("backend/icp/__init__.py", "")
        self.write("backend/requirements.lock", "# lock\n")
        self.write("backend/build-requirements.lock", "# lock\n")
        self.write("native/pear-exec.c", "int main(void) { return 0; }\n")
        self.write(f"polkit/{P['POLKIT_ACTION_PREFIX']}.policy", FAKE_POLICY)
        self.write(f"system/units/{P['SOCKET_UNIT']}", "[Socket]\n")
        self.write(f"system/units/{P['SERVICE_UNIT']}", "[Service]\n")
        self.write(f"system/units/{P['SEAL_SOCKET_UNIT']}", "[Socket]\nAccept=yes\n")
        self.write(f"system/units/{P['SEAL_SERVICE_UNIT']}", "[Service]\n")
        self.write("system/sysusers.d/pear-passwords.conf", "u pear-passwords -\n")
        self.write("system/tmpfiles.d/pear-passwords.conf", "d /var/lib/pear-passwords\n")
        self.write("system/libexec/pear-passwordsd", "#!/bin/sh\n", 0o755)
        self.write("system/libexec/pear-autofill-host", "#!/bin/sh\n", 0o755)
        self.write("system/bin/pear-passwords-autofill", "#!/bin/sh\n", 0o755)
        os.makedirs(os.path.join(self.stage, "wheels"))
        self.write("wheels/fake-1.0-py3-none-any.whl", b"PK")
        self.sums()

    def sums(self):
        lines = []
        for d, _, files in os.walk(self.stage):
            for name in files:
                p = os.path.join(d, name)
                rel = os.path.relpath(p, self.stage)
                if rel == "SHA256SUMS" or rel.startswith("wheels/"):
                    continue
                with open(p, "rb") as f:
                    lines.append(f"{sha(f.read())}  {rel}")
        with open(os.path.join(self.stage, "SHA256SUMS"), "w") as f:
            f.write("\n".join(sorted(lines, key=lambda l: l[66:])) + "\n")

    # --- running --------------------------------------------------------------------------
    def run(self, script, *args, stdin=""):
        env = {"PP_TEST_ROOT": self.root, "PATH": "/usr/bin:/bin", "HOME": self.tmp}
        return subprocess.run(["sh", script, *args], env=env, input=stdin, text=True,
                              capture_output=True, timeout=60)

    def install(self, stop_at=None):
        script = os.path.join(self.stage, "system", "install-root.sh")
        if stop_at is None:
            return self.run(script, self.stage)
        env = {"PP_TEST_ROOT": self.root, "PATH": "/usr/bin:/bin", "HOME": self.tmp,
               "PP_TEST_STOP_AT": stop_at}
        return subprocess.run(["sh", script, self.stage], env=env, text=True,
                              capture_output=True, timeout=60)

    def uninstall(self, *args, stdin=""):
        # The installed copy, as a user would run it.
        return self.run(self.r(P["UNINSTALL_ROOT"]), *args, stdin=stdin)

    def receipt(self):
        with open(self.r(P["INSTALL_RECEIPT"])) as f:
            return [l.rstrip("\n").split("\t") for l in f if not l.startswith("#")]

    def commands(self):
        p = self.r("commands.log")
        return open(p).read() if os.path.exists(p) else ""

    def files_sh(self, snippet):
        """Run a snippet with paths.env and files.sh loaded, in test mode."""
        script = (f'. "{SYSTEM}/paths.env"; . "{SYSTEM}/lib/files.sh"; pp_init_mode; '
                  f'PP_OLD={self.tmp}/old; pp_load_receipt "$PP_OLD"; {snippet}')
        env = {"PP_TEST_ROOT": self.root, "PATH": "/usr/bin:/bin"}
        return subprocess.run(["sh", "-c", script], env=env, text=True, capture_output=True,
                              timeout=30)


class InstallRootTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.h = Harness(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def ok(self, proc):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def refused(self, proc, needle):
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(needle, proc.stderr)

    def assertNothingWritten(self):
        self.assertFalse(os.path.exists(self.h.r(PREFIX)), "something under $P was written")
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_RECEIPT"])))
        self.assertNotIn("systemd-sysusers", self.h.commands())

    # --- a fresh install ------------------------------------------------------------------
    def test_fresh_install_writes_everything_with_its_mode_and_a_receipt(self):
        self.ok(self.h.install())
        modes = {
            P["PEAR_EXEC"]: 0o2755, P["DAEMON_WRAPPER"]: 0o755, P["AUTOFILL_HOST"]: 0o755,
            P["UNINSTALL_ROOT"]: 0o755, P["AUTOFILL_REGISTER_BIN"]: 0o755,
            P["FONTS_CONF"]: 0o644, P["DESKTOP_FILE"]: 0o644, P["POLICY_FILE"]: 0o644,
            P["SYSUSERS_CONF"]: 0o644, P["TMPFILES_CONF"]: 0o644,
            f"{P['UNIT_DIR']}/{P['SOCKET_UNIT']}": 0o644,
            f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}": 0o644,
            f"{P['APP_DIR']}/shell.qml": 0o644, P["EMPTY_DIR"]: 0o555,
            P["INSTALL_RECEIPT"]: 0o600, P["INSTALL_STATE_DIR"]: 0o700,
        }
        for path, mode in modes.items():
            st = os.lstat(self.h.r(path))
            self.assertEqual(stat.S_IMODE(st.st_mode), mode, path)
        self.assertEqual(os.listdir(self.h.r(P["EMPTY_DIR"])), [])
        self.assertEqual(os.readlink(self.h.r(f"{P['APP_DIR']}/Ui")), "/usr/share/omarchy/shell/Ui")
        # fonts.conf and the launcher go to their own places, not into the app tree
        self.assertFalse(os.path.exists(self.h.r(f"{P['APP_DIR']}/fonts.conf")))
        self.assertFalse(os.path.exists(self.h.r(f"{P['APP_DIR']}/{P['APP_ID']}.desktop")))

        entries = {e[2]: e for e in self.h.receipt()}
        for path in modes:
            if path not in (P["INSTALL_RECEIPT"], P["INSTALL_STATE_DIR"], P["EMPTY_DIR"]):
                self.assertIn(path, entries, path)
        with open(self.h.r(P["POLICY_FILE"]), "rb") as f:
            self.assertEqual(entries[P["POLICY_FILE"]][:2], ["f", sha(f.read())])
        self.assertEqual(entries[f"{P['APP_DIR']}/Ui"][:2], ["l", "/usr/share/omarchy/shell/Ui"])
        # the venv is recorded file by file
        self.assertTrue(any(p.startswith(P["VENV"] + "/") for p in entries))
        self.assertFalse(any(p.startswith(P["VENV"] + ".new") for p in entries))
        # scripts were rewritten to the final venv path
        with open(self.h.r(P["VENV"] + "/bin/icp")) as f:
            self.assertIn(self.h.r(P["VENV"]) + "/bin/python", f.read())

        cmds = self.h.commands()
        for c in (f"systemd-sysusers {P['SYSUSERS_CONF']}",
                  f"systemd-tmpfiles --create {P['TMPFILES_CONF']}",
                  "systemctl daemon-reload", f"systemctl enable --now {P['SOCKET_UNIT']}"):
            self.assertIn(c, cmds)
        self.assertLess(cmds.index("systemd-sysusers"), cmds.index("systemctl enable"))

        with open(self.h.r(f"{PREFIX}/VERSION")) as f:
            version = f.read()
        with open(os.path.join(self.h.stage, "SHA256SUMS"), "rb") as f:
            self.assertEqual(version, f"version=2.0.0\nsums={sha(f.read())}\n")

    def test_seal_service_runs_only_when_the_daemon_unit_selects_it(self):
        """Gate G1 fallback switch: the root seal socket is installed either way, enabled
        only by an active PEAR_SEAL_BACKEND=seal-service line in the shipped daemon unit."""
        self.ok(self.h.install())
        cmds = self.h.commands()
        self.assertTrue(os.path.isfile(self.h.r(f"{P['UNIT_DIR']}/{P['SEAL_SOCKET_UNIT']}")))
        self.assertNotIn(P["SEAL_SOCKET_UNIT"], cmds)        # a fresh install leaves it alone

        os.unlink(self.h.r("commands.log"))
        self.h.write(f"system/units/{P['SERVICE_UNIT']}",
                     "[Service]\n#Environment=PEAR_SEAL_BACKEND=seal-service\n")
        self.h.sums()
        self.ok(self.h.install())
        self.assertNotIn(f"enable --now {P['SEAL_SOCKET_UNIT']}", self.h.commands())

        os.unlink(self.h.r("commands.log"))
        self.h.write(f"system/units/{P['SERVICE_UNIT']}",
                     "[Service]\nEnvironment=PEAR_SEAL_BACKEND=seal-service\n")
        self.h.sums()
        self.ok(self.h.install())
        cmds = self.h.commands()
        self.assertIn(f"systemctl enable --now {P['SEAL_SOCKET_UNIT']}", cmds)
        self.assertLess(cmds.index(P["SEAL_SOCKET_UNIT"]),
                        cmds.index(f"enable --now {P['SOCKET_UNIT']}"))

        # Back to the primary path in a later release: the upgrade turns the socket off.
        os.unlink(self.h.r("commands.log"))
        self.h.write(f"system/units/{P['SERVICE_UNIT']}", "[Service]\n")
        self.h.sums()
        self.ok(self.h.install())
        self.assertIn(f"systemctl disable --now {P['SEAL_SOCKET_UNIT']}", self.h.commands())

        os.unlink(self.h.r("commands.log"))
        self.ok(self.h.uninstall())
        self.assertIn(f"disable --now {P['SEAL_SOCKET_UNIT']}", self.h.commands())

    def test_installed_uninstaller_is_self_contained(self):
        self.ok(self.h.install())
        with open(self.h.r(P["UNINSTALL_ROOT"])) as f:
            body = f.read()
        self.assertTrue(body.startswith("#!/bin/sh\n"))
        self.assertNotIn("stage-only", body)
        self.assertNotIn(". \"$here", body)
        self.assertIn(f"PREFIX={PREFIX}\n", body)
        self.assertIn("pp_ours()", body)

    def test_stage_files_are_never_symlinks_or_unlisted(self):
        self.h.write("app/extra.qml", "// not in SHA256SUMS\n")
        self.refused(self.h.install(), "SHA256SUMS does not list")
        self.assertNothingWritten()

        self.h.make_stage()
        os.symlink("/etc/passwd", os.path.join(self.h.stage, "app", "link.qml"))
        self.refused(self.h.install(), "symlinks")
        self.assertNothingWritten()

        self.h.make_stage()
        self.h.write("app/shell.qml", "// changed after SHA256SUMS\n")
        self.refused(self.h.install(), "does not match its SHA256SUMS")
        self.assertNothingWritten()

    def test_incomplete_stage_is_refused(self):
        os.remove(os.path.join(self.h.stage, "native", "pear-exec.c"))
        self.h.sums()
        self.refused(self.h.install(), "native/pear-exec.c")
        self.assertNothingWritten()

    # --- refusals before any write ----------------------------------------------------------
    def test_foreign_file_at_a_destination_is_refused(self):
        unit = self.h.r(f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}")
        with open(unit, "w") as f:
            f.write("[Service]\nExecStart=/bin/something-else\n")
        self.refused(self.h.install(), f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}")
        self.assertNothingWritten()
        with open(unit) as f:
            self.assertIn("something-else", f.read())

    def test_identical_file_at_a_destination_is_ours(self):
        # A re-install over a lost receipt's files is harmless when the bytes are ours...
        os.makedirs(self.h.r("/usr/local/bin"), exist_ok=True)
        shutil.copy(os.path.join(self.h.stage, "system/bin/pear-passwords-autofill"),
                    self.h.r(P["AUTOFILL_REGISTER_BIN"]))
        self.ok(self.h.install())

    def test_symlink_at_a_destination_is_refused(self):
        os.makedirs(self.h.r("/usr/local/bin"), exist_ok=True)
        target = os.path.join(self.h.tmp, "mine")
        with open(target, "w") as f:
            f.write("#!/bin/sh\n")
        os.symlink(target, self.h.r(P["AUTOFILL_REGISTER_BIN"]))
        self.refused(self.h.install(), "is a symlink")
        self.assertNothingWritten()

    def test_a_first_install_interrupted_after_the_venv_build_can_be_rerun(self):
        # installer-interrupted-install-bricks-reruns: $P and $VENV.new exist, no final receipt.
        proc = self.h.install(stop_at="venv")
        self.assertEqual(proc.returncode, 99, proc.stdout + proc.stderr)
        self.assertTrue(os.path.isdir(self.h.r(P["VENV"] + ".new")))
        self.ok(self.h.install())
        self.assertFalse(os.path.exists(self.h.r(P["VENV"] + ".new")))
        self.assertTrue(os.path.exists(self.h.r(P["VENV"] + "/bin/icp")))
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.h.r(PREFIX)))

    def test_an_upgrade_interrupted_after_the_venv_swap_can_be_rerun(self):
        self.ok(self.h.install())
        self.h.write("backend/icp/__init__.py", "# 2.0.1\n")     # a new venv tree
        self.h.write("manifest.json", '{\n  "version": "2.0.1"\n}\n')
        self.h.sums()
        proc = self.h.install(stop_at="swap")
        self.assertEqual(proc.returncode, 99, proc.stdout + proc.stderr)
        self.ok(self.h.install())
        names = {e[2] for e in self.h.receipt()}
        self.assertIn(P["VENV"] + "/lib/site-packages/icp/__init__.py", names)
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.h.r(PREFIX)), proc.stdout)

    def test_a_venv_new_is_never_deleted_before_the_prefix_is_proven_ours(self):
        planted = self.h.r(P["VENV"] + ".new/keep-me")
        os.makedirs(os.path.dirname(planted))
        with open(planted, "w") as f:
            f.write("x")
        self.refused(self.h.install(), "there is no install receipt")
        self.assertTrue(os.path.exists(planted), "deleted before any ownership check")
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_RECEIPT"])))

    def test_a_leftover_pp_new_is_checked_and_cleaned(self):
        # audit: a <dest>.pp-new under $P was accepted without a check and never removed.
        self.ok(self.h.install())
        self.h.write("app/shell.qml", "// window, 2.0.1, a longer file\n")
        self.h.sums()
        dest = self.h.r(PREFIX + "/app/shell.qml")
        self.assertTrue(os.path.exists(dest))
        # An interrupted copy of the new file: a byte prefix of it.
        with open(dest + ".pp-new", "w") as f:
            f.write("// window, 2.0")
        with open(self.h.r(P["INSTALL_RECEIPT"]) + ".pp-new", "w") as f:
            f.write("# half a receipt")
        # Gone as soon as the checks pass, before any file is (re)written.
        proc = self.h.install(stop_at="venv")
        self.assertEqual(proc.returncode, 99, proc.stdout + proc.stderr)
        self.assertFalse(os.path.exists(dest + ".pp-new"))
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_RECEIPT"]) + ".pp-new"))
        self.ok(self.h.install())
        self.assertFalse(os.path.exists(dest + ".pp-new"))
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_RECEIPT"]) + ".pp-new"))
        with open(dest) as f:
            self.assertEqual(f.read(), "// window, 2.0.1, a longer file\n")

    def test_a_pp_new_that_is_not_part_of_the_staged_file_is_in_the_way(self):
        self.ok(self.h.install())
        dest = self.h.r(PREFIX + "/app/shell.qml")
        for planted in ("#!/bin/sh\nevil\n", "// window\n// and more than the staged file\n"):
            with open(dest + ".pp-new", "w") as f:
                f.write(planted)
            proc = self.h.install()
            self.refused(proc, "shell.qml.pp-new  (left over, and not part of the file")
            self.assertTrue(os.path.exists(dest + ".pp-new"), "deleted before the check")
        os.unlink(dest + ".pp-new")
        os.symlink("/etc/shadow", dest + ".pp-new")
        self.refused(self.h.install(), "shell.qml.pp-new  (left over, and not a plain file)")

    def test_prefix_without_a_receipt_is_refused(self):
        os.makedirs(self.h.r(PREFIX))
        self.refused(self.h.install(), "there is no install receipt")
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_RECEIPT"])))

    def test_shadowing_units_dropins_and_policies_are_refused(self):
        cases = [
            f"/usr/lib/systemd/system/{P['SERVICE_UNIT']}",
            f"/run/systemd/system/{P['SOCKET_UNIT']}",
            f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}.d/override.conf",
            f"/usr/local/share/polkit-1/actions/{P['POLKIT_ACTION_PREFIX']}.policy",
        ]
        for path in cases:
            with self.subTest(path=path):
                p = self.h.r(path)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write("x\n")
                shadow = path if not path.endswith(".d/override.conf") else os.path.dirname(path)
                self.refused(self.h.install(), shadow)
                self.assertNothingWritten()
                shutil.rmtree(os.path.dirname(p)) if path.endswith(".conf") else os.remove(p)

    def test_another_policy_declaring_our_action_is_refused(self):
        other = self.h.r("/usr/share/polkit-1/actions/zz-other.policy")
        with open(other, "wb") as f:
            f.write(FAKE_POLICY)
        self.refused(self.h.install(), "declares a Pear polkit action")
        self.assertNothingWritten()

    def test_existing_identities_must_be_what_pear_creates(self):
        cases = [
            ("passwd", f"pear-passwords:x:970:970::/home/pear:/usr/bin/nologin\n", "home"),
            ("passwd", f"pear-passwords:x:970:970::{P['STATE_DIR']}:/bin/bash\n", "login shell"),
            ("passwd", f"pear-passwords:x:1001:1001::{P['STATE_DIR']}:/usr/bin/nologin\n",
             "regular account"),
            ("group", "pear-client:x:971:dragos\n", "has members"),
        ]
        for db, line, needle in cases:
            with self.subTest(needle=needle):
                path = self.h.r(f"/etc/{db}")
                with open(path) as f:
                    keep = f.read()
                with open(path, "a") as f:
                    f.write(line)
                self.refused(self.h.install(), needle)
                self.assertNothingWritten()
                with open(path, "w") as f:
                    f.write(keep)
        with open(self.h.r("/etc/passwd"), "a") as f:
            f.write(f"pear-passwords:x:970:970::{P['STATE_DIR']}:/usr/bin/nologin\n")
        with open(self.h.r("/etc/group"), "a") as f:
            f.write("pear-client:x:971:\n")
        self.ok(self.h.install())

    # --- upgrades -------------------------------------------------------------------------
    def test_rerun_upgrades_over_its_own_receipt(self):
        self.ok(self.h.install())
        self.ok(self.h.install())
        self.h.write("app/shell.qml", "// version 2\n")
        os.remove(os.path.join(self.h.stage, "app", "Theme.qml"))
        self.h.sums()
        self.ok(self.h.install())
        with open(self.h.r(f"{P['APP_DIR']}/shell.qml")) as f:
            self.assertEqual(f.read(), "// version 2\n")
        # a file the new version no longer ships, unchanged since installed: removed
        self.assertFalse(os.path.exists(self.h.r(f"{P['APP_DIR']}/Theme.qml")))
        paths = [e[2] for e in self.h.receipt()]
        self.assertNotIn(f"{P['APP_DIR']}/Theme.qml", paths)

    def test_edited_file_blocks_the_upgrade(self):
        self.ok(self.h.install())
        unit = self.h.r(f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}")
        with open(unit, "a") as f:
            f.write("# local edit\n")
        self.refused(self.h.install(), "was edited")
        with open(unit) as f:
            self.assertIn("# local edit", f.read())

    def test_planted_files_under_the_prefix_block_the_upgrade(self):
        self.ok(self.h.install())
        planted = self.h.r(f"{P['APP_DIR']}/Planted.qml")
        with open(planted, "w") as f:
            f.write("// imported by qmldir?\n")
        self.refused(self.h.install(), "not in the receipt")
        os.remove(planted)
        venv_file = self.h.r(P["VENV"] + "/lib/site-packages/icp/__init__.py")
        with open(venv_file, "a") as f:
            f.write("import os\n")
        self.refused(self.h.install(), "not in the receipt, or edited")

    def test_edited_file_no_longer_shipped_blocks_the_upgrade(self):
        self.ok(self.h.install())
        theme = self.h.r(f"{P['APP_DIR']}/Theme.qml")
        with open(theme, "a") as f:
            f.write("// edit\n")
        os.remove(os.path.join(self.h.stage, "app", "Theme.qml"))
        self.h.sums()
        self.refused(self.h.install(), "Theme.qml")
        self.assertTrue(os.path.exists(theme))

    # --- the 1.x polkit action ------------------------------------------------------------
    def test_legacy_policy_removed_only_when_released(self):
        legacy = self.h.r(LEGACY)
        with open(legacy, "wb") as f:
            f.write(LEGACY_RELEASED_SAMPLE)
        self.ok(self.h.install())
        self.assertFalse(os.path.exists(legacy), "a released 1.x action was left behind")

        with open(legacy, "wb") as f:
            f.write(LEGACY_RELEASED_SAMPLE.replace(b"auth_self", b"yes"))
        proc = self.ok(self.h.install())
        self.assertTrue(os.path.exists(legacy), "an edited legacy action was deleted")
        self.assertIn("not a copy Pear 1.x installed", proc.stderr)

    def test_every_repo_revision_of_the_legacy_policy_is_released(self):
        self.assertEqual(sha(LEGACY_RELEASED_SAMPLE),
                         "e52090fecadf25f26061ecd08b7cae0f2aa5c870cffcb91afd92038e5aa050cf")
        # 2.0 deletes polkit/org.icp.unlock.policy, so every revision is read from git
        # history instead; a checkout without history falls back to the working tree.
        blobs = []
        try:
            revs = subprocess.run(
                ["git", "-C", ROOT, "log", "--all", "--format=%H", "--",
                 "polkit/org.icp.unlock.policy"],
                capture_output=True, text=True, check=True).stdout.split()
            for rev in revs:
                show = subprocess.run(["git", "-C", ROOT, "show",
                                       f"{rev}:polkit/org.icp.unlock.policy"],
                                      capture_output=True)
                if show.returncode == 0 and show.stdout:  # absent in the deleting commit
                    blobs.append(show.stdout)
        except (OSError, subprocess.CalledProcessError):
            pass
        if not blobs and os.path.exists(LEGACY_SRC):
            with open(LEGACY_SRC, "rb") as f:
                blobs.append(f.read())
        if not blobs:
            self.skipTest("no revision of polkit/org.icp.unlock.policy is reachable")
        for blob in blobs:
            digest = sha(blob)
            proc = self.h.files_sh(f'pp_released "{LEGACY}" "{digest}" && echo yes')
            self.assertEqual(proc.stdout.strip(), "yes", f"{digest} {proc.stderr}")

    # --- ours(), directly -------------------------------------------------------------------
    def test_ours_rule(self):
        p = self.h.r("/etc/x.conf")
        with open(p, "w") as f:
            f.write("a\n")
        src = os.path.join(self.h.tmp, "src")
        with open(src, "w") as f:
            f.write("a\n")
        other = os.path.join(self.h.tmp, "other")
        with open(other, "w") as f:
            f.write("b\n")
        q = lambda s: self.h.files_sh(s + " && echo yes || echo no").stdout.strip()
        self.assertEqual(q(f'pp_ours /etc/x.conf "{src}"'), "yes")      # the staged source
        self.assertEqual(q(f'pp_ours /etc/x.conf "{other}"'), "no")
        self.assertEqual(q("pp_ours /etc/x.conf"), "no")
        self.assertEqual(q("pp_ours /etc/missing"), "no")
        os.makedirs(self.h.r(P["INSTALL_STATE_DIR"]))
        with open(self.h.r(P["INSTALL_RECEIPT"]), "w") as f:
            f.write(f"# receipt\nf\t{sha(b'a' + bytes([10]))}\t/etc/x.conf\n")
        self.assertEqual(q("pp_ours /etc/x.conf"), "yes")                 # the receipt
        self.assertEqual(q(f'pp_released "{LEGACY}" "{sha(LEGACY_RELEASED_SAMPLE)}"'), "yes")
        self.assertEqual(q(f'pp_released /etc/x.conf "{sha(LEGACY_RELEASED_SAMPLE)}"'), "no")
        os.remove(p)
        os.symlink(src, p)
        self.assertEqual(q(f'pp_ours /etc/x.conf "{src}"'), "no")       # never a symlink

    # --- the command users paste ---------------------------------------------------------
    def _published_command(self, digest):
        """README's root command with only what needs root swapped for scratch paths."""
        import re
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            cmd = re.search(r"^sudo sh -c '.*'$", f.read(), re.M).group(0)
        home = os.path.join(self.h.tmp, "home")
        rootdir = os.path.join(self.h.tmp, "rootdir")
        os.makedirs(rootdir, exist_ok=True)
        swaps = [("sudo sh -c ", "sh -c "),
                 ('$(getent passwd "${SUDO_USER:?run this with sudo}" | cut -d: -f6)', home),
                 ("/root/pear-stage.XXXXXX", f"{rootdir}/pear-stage.XXXXXX")]
        for old, new in swaps:
            self.assertIn(old, cmd)
            cmd = cmd.replace(old, new)
        cmd = re.sub(r'echo "[0-9a-f]{64}  SHA256SUMS"', f'echo "{digest}  SHA256SUMS"', cmd)
        cache = os.path.join(home, ".cache", "pear-passwords")
        os.makedirs(cache, exist_ok=True)
        if not os.path.exists(os.path.join(cache, "stage")):
            shutil.move(self.h.stage, os.path.join(cache, "stage"))
            self.h.stage = os.path.join(cache, "stage")
        return cmd, rootdir

    def _run_published(self, cmd):
        env = {"PP_TEST_ROOT": self.h.root, "PATH": "/usr/bin:/bin", "HOME": self.h.tmp}
        return subprocess.run(["sh", "-c", cmd], env=env, text=True, capture_output=True,
                              timeout=60)

    def test_the_published_root_command_end_to_end(self):
        with open(os.path.join(self.h.stage, "SHA256SUMS"), "rb") as f:
            digest = sha(f.read())
        cmd, rootdir = self._published_command(digest)
        self.ok(self._run_published(cmd))
        self.assertTrue(os.path.exists(self.h.r(P["PEAR_EXEC"])))
        self.assertEqual(os.listdir(rootdir), [], "the root copy of the stage was left behind")

    def test_the_published_root_command_refuses_a_wrong_hash_or_a_changed_file(self):
        with open(os.path.join(self.h.stage, "SHA256SUMS"), "rb") as f:
            digest = sha(f.read())
        cmd, rootdir = self._published_command("0" * 64)
        proc = self._run_published(cmd)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNothingWritten()
        cmd, rootdir = self._published_command(digest)
        with open(os.path.join(self.h.stage, "app", "shell.qml"), "a") as f:
            f.write("// tampered after staging\n")
        proc = self._run_published(cmd)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNothingWritten()
        self.assertEqual(os.listdir(rootdir), [])

    def test_test_mode_needs_an_absolute_root(self):
        env = {"PP_TEST_ROOT": "relative/dir", "PATH": "/usr/bin:/bin"}
        proc = subprocess.run(["sh", os.path.join(SYSTEM, "install-root.sh"), self.h.stage],
                              env=env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("absolute", proc.stderr)
        # and the guard against running it as root is in the code that sets test mode up
        with open(os.path.join(SYSTEM, "lib", "files.sh")) as f:
            body = f.read()
        self.assertIn('[ "$(id -u)" -ne 0 ] || pp_die "PP_TEST_ROOT is for the test suite', body)


class UninstallRootTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.h = Harness(self._tmp.name)
        proc = self.h.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(self.h.r("/etc/passwd"), "a") as f:
            f.write(f"pear-passwords:x:970:970::{P['STATE_DIR']}:/usr/bin/nologin\n")
        with open(self.h.r("/etc/group"), "a") as f:
            f.write("pear-passwords:x:970:\npear-client:x:971:\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_uninstall_removes_everything_it_installed(self):
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.h.r(PREFIX)))
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_STATE_DIR"])))
        for path in (P["POLICY_FILE"], P["DESKTOP_FILE"], P["AUTOFILL_REGISTER_BIN"],
                     f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}", P["SYSUSERS_CONF"]):
            self.assertFalse(os.path.exists(self.h.r(path)), path)
        cmds = self.h.commands()
        self.assertIn(f"systemctl disable --now {P['SOCKET_UNIT']} {P['SERVICE_UNIT']}", cmds)
        self.assertIn("userdel pear-passwords", cmds)
        self.assertIn("groupdel pear-client", cmds)

    def test_uninstall_removes_pp_new_leftovers_so_the_prefix_is_gone(self):
        # audit: an interrupted copy's <dest>.pp-new kept $P from being fully removed.
        dest = self.h.r(PREFIX + "/app/shell.qml")
        with open(dest + ".pp-new", "w") as f:
            f.write("// win")
        unit = self.h.r(f"{P['UNIT_DIR']}/{P['SERVICE_UNIT']}")
        with open(unit + ".pp-new", "w") as f:
            f.write("[Serv")
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.h.r(PREFIX)), proc.stdout)
        self.assertFalse(os.path.exists(unit + ".pp-new"))
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_STATE_DIR"])))

    def test_uninstall_keeps_edited_files_and_lists_them(self):
        policy = self.h.r(P["POLICY_FILE"])
        with open(policy, "ab") as f:
            f.write(b"<!-- local -->\n")
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(policy), "an edited file was deleted")
        self.assertIn(P["POLICY_FILE"], proc.stdout)
        # still recorded, with the hash Pear wrote, so a reinstall calls it edited
        self.assertEqual([e[2] for e in self.h.receipt() if e[0] != "d"], [P["POLICY_FILE"]])
        self.assertFalse(os.path.exists(self.h.r(P["DESKTOP_FILE"])))
        self.assertFalse(os.path.exists(self.h.r(PREFIX + "/venv")))
        proc = self.h.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(P["POLICY_FILE"], proc.stderr)

    def test_edited_units_are_not_disabled(self):
        unit = self.h.r(f"{P['UNIT_DIR']}/{P['SOCKET_UNIT']}")
        with open(unit, "a") as f:
            f.write("# mine\n")
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("disable", self.h.commands())
        self.assertTrue(os.path.exists(unit))

    def test_a_vault_keeps_the_user_and_the_uninstaller(self):
        vault = self.h.r(P["STATE_DIR"] + "/u1000")
        os.makedirs(vault)
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isdir(vault), "uninstall without --purge deleted a vault")
        self.assertTrue(os.path.exists(self.h.r(P["UNINSTALL_ROOT"])))
        self.assertEqual([e[2] for e in self.h.receipt() if e[0] != "d"], [P["UNINSTALL_ROOT"]])
        self.assertNotIn("userdel", self.h.commands())
        self.assertIn("--purge", proc.stdout)

        # Then --purge, from the uninstaller that was kept.
        os.makedirs(self.h.r(P["STATE_DIR"] + "/u1000.tmp"))
        os.makedirs(self.h.r(P["STATE_DIR"] + "/u10000"))   # another uid: must survive
        proc = self.h.uninstall("--purge", "1000", stdin="nope\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(os.path.isdir(vault), "deleted without the typed confirmation")
        proc = self.h.uninstall("--purge", "1000", stdin="delete\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(vault))
        self.assertFalse(os.path.exists(vault + ".tmp"))
        self.assertTrue(os.path.isdir(self.h.r(P["STATE_DIR"] + "/u10000")))
        self.assertNotIn("userdel", self.h.commands(), "removed the user while u10000 remains")

        os.rmdir(self.h.r(P["STATE_DIR"] + "/u10000"))
        os.makedirs(self.h.r(P["STATE_DIR"] + "/u10000"))
        proc = self.h.uninstall("--purge", "10000", stdin="delete\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.h.r(PREFIX)))
        self.assertIn("userdel pear-passwords", self.h.commands())

    def test_a_leftover_owned_file_keeps_the_uninstaller_and_the_receipt(self):
        # Gate bug 3: the identities were kept, and the only tool that removes them went too.
        env_run = self.h.run

        def run(script, *args, stdin=""):
            env = {"PP_TEST_ROOT": self.h.root, "PATH": "/usr/bin:/bin", "HOME": self.h.tmp,
                   "PP_TEST_LEFTOVER": "/srv/thing"}
            return subprocess.run(["sh", script, *args], env=env, input=stdin, text=True,
                                  capture_output=True, timeout=60)
        self.h.run = run
        try:
            proc = self.h.uninstall()
        finally:
            self.h.run = env_run
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(self.h.r(P["UNINSTALL_ROOT"])))
        self.assertEqual([e[2] for e in self.h.receipt() if e[0] != "d"], [P["UNINSTALL_ROOT"]])
        self.assertNotIn("userdel", self.h.commands())
        self.assertIn("run this again", proc.stdout)
        # Once the file is gone, the kept uninstaller finishes the job.
        proc = self.h.uninstall()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.h.r(PREFIX)))
        self.assertFalse(os.path.exists(self.h.r(P["INSTALL_RECEIPT"])))
        self.assertIn("userdel pear-passwords", self.h.commands())

    def test_leftover_runtime_sockets_are_removed(self):
        import socket as _socket
        socks = []
        for key in ("SOCKET_PATH", "SEAL_SOCKET_PATH"):
            path = self.h.r(P[key])
            os.makedirs(os.path.dirname(path))
            s = _socket.socket(_socket.AF_UNIX)
            s.bind(path)
            socks.append(s)
        try:
            proc = self.h.uninstall()
        finally:
            for s in socks:
                s.close()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for key in ("SOCKET_PATH", "SEAL_SOCKET_PATH"):
            self.assertFalse(os.path.exists(self.h.r(P[key])), key)
            self.assertFalse(os.path.exists(os.path.dirname(self.h.r(P[key]))), key)

    def test_purge_takes_only_a_numeric_uid(self):
        for bad in ("../x", "1000/..", "", "u1000"):
            proc = self.h.uninstall("--purge", bad, stdin="delete\n")
            self.assertNotEqual(proc.returncode, 0, bad)
        self.assertTrue(os.path.exists(self.h.r(P["INSTALL_RECEIPT"])))


if __name__ == "__main__":
    unittest.main()
