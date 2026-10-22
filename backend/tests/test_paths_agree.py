"""system/paths.env and icp.daemon.paths must name the same paths.

The installer, pear-exec and the daemon each read one of the two; if they drifted, the daemon
would listen on a socket the installer never created, or pear-exec would exec a target the
installer never wrote. Every key in paths.env must be checked here, so a new one cannot be
added on one side only.
"""

import os
import re
import unittest

from icp.daemon import paths

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV_FILE = os.path.join(ROOT, "system", "paths.env")


def _read_env() -> dict:
    out = {}
    with open(ENV_FILE, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            m = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\s'\"$`\\]+)", line)
            if not m:
                raise AssertionError(f"paths.env:{n}: not a literal KEY=VALUE line: {line!r}")
            if m.group(1) in out:
                raise AssertionError(f"paths.env:{n}: duplicate key {m.group(1)}")
            out[m.group(1)] = m.group(2)
    return out


class PathsAgreeTests(unittest.TestCase):
    def setUp(self):
        self.env = _read_env()

    def test_every_key_matches_python(self):
        targets = {
            "TARGET_UI": paths.ROLE_TARGETS["ui"][0],
            "TARGET_CLIP_MODULE": paths.ROLE_TARGETS["clip"][-1],
            "TARGET_MIGRATE_MODULE": paths.ROLE_TARGETS["migrate"][-1],
            "TARGET_AUTOFILL_MODULE": paths.ROLE_TARGETS["autofill"][-1],
        }
        for key, value in self.env.items():
            if key in targets:
                self.assertEqual(value, targets[key], key)
                continue
            self.assertTrue(hasattr(paths, key), f"paths.env {key} has no paths.py twin")
            self.assertEqual(value, str(getattr(paths, key)), key)

    def test_python_constants_are_all_in_env(self):
        # The other direction: every upper-case scalar in paths.py is in paths.env, except the
        # few that only Python needs.
        python_only = {"WINDOW_TITLE", "TPM_DEVICE", "TPM_SRK_PUBLIC_KEY"}
        for name in dir(paths):
            value = getattr(paths, name)
            if not name.isupper() or not isinstance(value, (str, int)) or name in python_only:
                continue
            self.assertIn(name, self.env, f"paths.py {name} missing from paths.env")

    def test_installed_tree_is_under_prefix(self):
        p = paths.PREFIX + "/"
        for name in ("VENV", "VENV_PYTHON", "APP_DIR", "LIBEXEC", "PEAR_EXEC", "DAEMON_WRAPPER",
                     "AUTOFILL_HOST", "UNINSTALL_ROOT", "FONTS_CONF", "EMPTY_DIR"):
            self.assertTrue(getattr(paths, name).startswith(p), name)

    def test_role_targets(self):
        self.assertEqual(paths.ROLES, ("ui", "clip", "migrate", "autofill"))
        self.assertEqual(paths.ROLE_TARGETS["ui"], ("/usr/bin/quickshell", "-p", paths.APP_DIR))
        for role in ("clip", "migrate", "autofill"):
            argv = paths.ROLE_TARGETS[role]
            # -I: isolated mode, so no PYTHON* variable or user site can reach the client.
            self.assertEqual(argv[:3], (paths.VENV_PYTHON, "-I", "-m"), role)
            self.assertEqual(argv[3], f"icp.client.{role}", role)
        for argv in paths.ROLE_TARGETS.values():
            self.assertTrue(os.path.isabs(argv[0]))

    def test_policy_ids(self):
        self.assertEqual(len(paths.ACTIONS), 4)
        for a in paths.ACTIONS:
            self.assertTrue(a.startswith(paths.POLKIT_ACTION_PREFIX + "."), a)
        self.assertEqual(paths.ACTION_AUTOFILL, "io.github.dragosol.pearpasswords.autofill")
        self.assertEqual(paths.POLICY_FILE,
                         "/usr/share/polkit-1/actions/io.github.dragosol.pearpasswords.policy")

    def test_native_host_name(self):
        # Native-messaging host names allow only [a-z0-9_.]; a capital or a dash and every
        # browser refuses the manifest.
        self.assertRegex(paths.NATIVE_HOST_NAME, r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
        self.assertEqual(paths.NATIVE_HOST_MANIFEST, paths.NATIVE_HOST_NAME + ".json")

    def test_user_dirs_take_only_int_uids(self):
        self.assertEqual(paths.user_dir(1000), "/var/lib/pear-passwords/u1000")
        self.assertEqual(paths.user_tmp_dir(1000), "/var/lib/pear-passwords/u1000.tmp")
        self.assertEqual(paths.credential_name("list", 1000), "pear.list.u1000")
        self.assertEqual(paths.credential_name("secret", 1000), "pear.secret.u1000")
        for bad in ("1000", "../x", -1, True, 1.0, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                paths.user_dir(bad)
        with self.assertRaises(ValueError):
            paths.credential_name("meta", 1000)


if __name__ == "__main__":
    unittest.main()
