"""pear-passwords-autofill register / unregister (client/autofill_register.py), in a scratch HOME.

Autofill is off until the user registers one extension for one browser. The command writes
only manifests it can prove are its own: it refuses to replace a file whose hash is not in its
receipt (or is not byte-for-byte its own rendering), removes only hash-matching files, and
takes the directories from its browser table, never from the receipt.
"""

import contextlib
import io
import json
import os
import re
import stat
import tempfile
import unittest
from unittest import mock

from icp.client import autofill_register as reg
from icp.daemon import paths

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ZEN_ID = "{5ad01040-3351-492c-9a42-1d56b881da78}"
OTHER_ID = "pear-autofill@example.org"
CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"


class Scratch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        home = os.path.join(self.tmp.name, "home")
        os.makedirs(home)
        self.env = reg.Env(home, os.path.join(home, ".config"),
                           os.path.join(home, ".local", "state"))
        host = os.path.join(self.tmp.name, "pear-autofill-host")
        with open(host, "w") as f:
            f.write("#!/bin/sh\n")
        p = mock.patch.object(reg, "HOST_PATH", host)
        p.start()
        self.addCleanup(p.stop)
        self.host = host
        self.out = []

    def mk(self, *parts):
        d = os.path.join(self.env.home, *parts)
        os.makedirs(d, exist_ok=True)
        return d

    def manifest(self, *parts):
        return os.path.join(self.env.home, *parts, paths.NATIVE_HOST_MANIFEST)

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def register(self, browser="zen", ext=ZEN_ID):
        return reg.register(browser, ext, self.env, out=self.out.append)

    def unregister(self, browser="zen"):
        return reg.unregister(browser, self.env, out=self.out.append, err=self.out.append)


class RegisterTests(Scratch):
    def test_zen_writes_a_manifest_for_one_extension(self):
        self.mk(".zen")
        written = self.register()
        moz = self.manifest(".mozilla", "native-messaging-hosts")
        zen = self.manifest(".zen", "native-messaging-hosts")
        self.assertEqual(written, [moz, zen])
        for path in written:
            doc = json.loads(self.read(path))
            self.assertEqual(doc, {
                "name": paths.NATIVE_HOST_NAME,
                "description": doc["description"],
                "path": self.host, "type": "stdio", "allowed_extensions": [ZEN_ID]})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(os.stat(self.env.receipt).st_mode), 0o600)
        receipt = reg.load_receipt(self.env)
        self.assertEqual(set(receipt), {moz, zen})
        self.assertEqual(receipt[moz]["sha256"], reg.sha256(self.read(moz)))

    def test_symlinked_config_dir_is_one_file(self):
        self.mk(".zen")
        os.makedirs(self.env.config)
        os.symlink(os.path.join(self.env.home, ".zen"), os.path.join(self.env.config, "zen"))
        self.assertEqual(len(self.register()), 2)          # ~/.mozilla and ~/.zen, not three

    def test_never_run_browser_is_refused(self):
        with self.assertRaisesRegex(reg.RegisterError, "no Zen profile"):
            self.register()
        with self.assertRaisesRegex(reg.RegisterError, "no Chromium profile"):
            self.register("chromium", CHROME_ID)
        self.assertFalse(os.path.exists(os.path.join(self.env.home, ".mozilla")))

    def test_extension_ids_are_validated(self):
        self.mk(".zen")
        self.mk(".config", "chromium")
        for browser, bad in (("zen", "evil\"},{\"path\":\"/bin/sh"), ("zen", ""),
                             ("zen", "{not-a-guid}"), ("zen", "x@y\n"), ("zen", CHROME_ID),
                             ("chromium", ZEN_ID), ("chromium", "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"),
                             ("chromium", "abcdefghijklmnopabcdefghijklmnoq")):
            with self.assertRaisesRegex(reg.RegisterError, "not a valid", msg=bad):
                self.register(browser, bad)
        self.assertFalse(os.path.exists(self.env.receipt))

    def test_needs_the_system_part(self):
        self.mk(".zen")
        os.unlink(self.host)
        with self.assertRaisesRegex(reg.RegisterError, "not installed"):
            self.register()

    def test_refuses_to_overwrite_a_foreign_file_and_writes_nothing(self):
        self.mk(".zen")
        zen_dir = self.mk(".zen", "native-messaging-hosts")
        foreign = os.path.join(zen_dir, paths.NATIVE_HOST_MANIFEST)
        with open(foreign, "w") as f:
            f.write('{"name": "io.github.dragosol.pearpasswords", "path": "/home/x/evil"}\n')
        with self.assertRaisesRegex(reg.RegisterError, "not written by"):
            self.register()
        self.assertIn(b"evil", self.read(foreign))
        # all or nothing: the ~/.mozilla manifest was not written either
        self.assertFalse(os.path.exists(self.manifest(".mozilla", "native-messaging-hosts")))
        self.assertFalse(os.path.exists(self.env.receipt))

    def test_a_near_copy_is_still_foreign(self):
        self.mk(".zen")
        self.register()
        path = self.manifest(".zen", "native-messaging-hosts")
        data = self.read(path)
        os.unlink(self.env.receipt)
        with open(path, "wb") as f:
            f.write(data.replace(b'"stdio"', b'"stdio" '))
        with self.assertRaises(reg.RegisterError):
            self.register()

    def test_lost_receipt_is_rebuilt_only_for_our_exact_rendering(self):
        self.mk(".zen")
        self.register()
        os.unlink(self.env.receipt)
        self.register(ext=OTHER_ID)
        doc = json.loads(self.read(self.manifest(".zen", "native-messaging-hosts")))
        # the old id's owner is unknown, so it is kept rather than dropped
        self.assertEqual(doc["allowed_extensions"], sorted([ZEN_ID, OTHER_ID]))

    def test_symlink_at_the_manifest_path_is_refused(self):
        self.mk(".zen")
        d = self.mk(".zen", "native-messaging-hosts")
        target = os.path.join(self.tmp.name, "elsewhere.json")
        with open(target, "w") as f:
            f.write("{}")
        os.symlink(target, os.path.join(d, paths.NATIVE_HOST_MANIFEST))
        with self.assertRaisesRegex(reg.RegisterError, "symlink"):
            self.register()
        self.assertEqual(self.read(target), b"{}")

    def test_re_register_replaces_the_browsers_id(self):
        self.mk(".zen")
        self.register()
        self.register(ext=OTHER_ID)
        doc = json.loads(self.read(self.manifest(".zen", "native-messaging-hosts")))
        self.assertEqual(doc["allowed_extensions"], [OTHER_ID])

    def test_firefox_and_zen_share_the_mozilla_file(self):
        self.mk(".zen")
        self.mk(".mozilla")
        self.register("zen", ZEN_ID)
        self.register("firefox", OTHER_ID)
        moz = self.manifest(".mozilla", "native-messaging-hosts")
        self.assertEqual(json.loads(self.read(moz))["allowed_extensions"],
                         sorted([ZEN_ID, OTHER_ID]))
        self.unregister("zen")
        self.assertEqual(json.loads(self.read(moz))["allowed_extensions"], [OTHER_ID])
        self.assertFalse(os.path.exists(self.manifest(".zen", "native-messaging-hosts")))
        self.unregister("firefox")
        self.assertFalse(os.path.exists(moz))
        self.assertFalse(os.path.exists(self.env.receipt))

    def test_chromium_manifest(self):
        self.mk(".config", "chromium")
        (path,) = self.register("chromium", CHROME_ID)
        self.assertEqual(path, os.path.join(self.env.config, "chromium", "NativeMessagingHosts",
                                            paths.NATIVE_HOST_MANIFEST))
        doc = json.loads(self.read(path))
        self.assertEqual(doc["allowed_origins"], [f"chrome-extension://{CHROME_ID}/"])
        self.assertNotIn("allowed_extensions", doc)

    def test_xdg_firefox_without_legacy_dir(self):
        self.mk(".config", "mozilla")
        (path,) = self.register("firefox", OTHER_ID)
        self.assertEqual(path, os.path.join(self.env.config, "mozilla",
                                            "native-messaging-hosts",
                                            paths.NATIVE_HOST_MANIFEST))


class UnregisterTests(Scratch):
    def test_removes_only_hash_matching_files(self):
        self.mk(".zen")
        moz, zen = self.register()
        with open(zen, "ab") as f:
            f.write(b" ")                                    # the user edited it
        done, kept = self.unregister()
        self.assertEqual((done, kept), ([moz], [zen]))
        self.assertFalse(os.path.exists(moz))
        self.assertTrue(os.path.exists(zen))
        self.assertTrue(any("changed since" in m for m in self.out))
        # and it is no longer ours: register now refuses it
        with self.assertRaises(reg.RegisterError):
            self.register()

    def test_a_tampered_receipt_cannot_aim_unregister_elsewhere(self):
        self.mk(".zen")
        self.register()
        victim = os.path.join(self.env.home, "important.json")
        with open(victim, "wb") as f:
            f.write(b"precious")
        receipt = reg.load_receipt(self.env)
        receipt[victim] = {"sha256": reg.sha256(b"precious"), "kind": "mozilla",
                           "registrations": [{"browser": "zen", "extension_id": ZEN_ID}]}
        reg.save_receipt(self.env, receipt)
        reg.unregister(None, self.env, out=self.out.append, err=self.out.append)
        self.assertEqual(self.read(victim), b"precious")

    def test_leaves_the_legacy_host_manifest_alone(self):
        self.mk(".zen")
        d = self.mk(".mozilla", "native-messaging-hosts")
        legacy = os.path.join(d, paths.LEGACY_NATIVE_HOST_MANIFEST)
        with open(legacy, "w") as f:
            f.write("{}")
        self.register()
        reg.unregister(None, self.env, out=self.out.append, err=self.out.append)
        self.assertTrue(os.path.exists(legacy))

    def test_missing_file_just_drops_the_receipt_line(self):
        self.mk(".zen")
        moz, zen = self.register()
        os.unlink(moz)
        done, kept = self.unregister()
        self.assertEqual((done, kept), ([zen], []))
        self.assertFalse(os.path.exists(self.env.receipt))

    def test_nothing_registered(self):
        self.assertEqual(self.unregister(), ([], []))
        self.assertTrue(any("nothing registered" in m for m in self.out))

    def test_unreadable_receipt_refuses(self):
        os.makedirs(os.path.dirname(self.env.receipt))
        with open(self.env.receipt, "w") as f:
            f.write("not json")
        with self.assertRaisesRegex(reg.RegisterError, "not readable"):
            self.unregister()


class CommandTests(Scratch):
    def run_main(self, *argv):
        env = {"HOME": self.env.home, "XDG_CONFIG_HOME": self.env.config,
               "XDG_STATE_HOME": self.env.state}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                rc = reg.main(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_round_trip(self):
        self.mk(".zen")
        rc, out, _ = self.run_main("register", "--browser", "zen", "--extension-id", ZEN_ID)
        self.assertEqual(rc, 0)
        self.assertIn("registered", out)
        rc, out, _ = self.run_main("status")
        self.assertEqual((rc, out.count(": ok (")), (0, 2))
        rc, out, _ = self.run_main("unregister", "--all")
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.env.receipt))

    def test_usage_and_refusals(self):
        self.assertEqual(self.run_main("register", "--browser", "netscape",
                                       "--extension-id", ZEN_ID)[0], 2)
        self.assertEqual(self.run_main("unregister")[0], 2)
        rc, _, err = self.run_main("register", "--browser", "zen", "--extension-id", ZEN_ID)
        self.assertEqual(rc, 1)
        self.assertIn("no Zen profile", err)
        with mock.patch.object(reg.os, "getuid", return_value=0):
            rc, _, err = self.run_main("status")
        self.assertEqual(rc, 1)
        self.assertIn("not as root", err)

    def test_kept_files_make_unregister_fail(self):
        self.mk(".zen")
        self.run_main("register", "--browser", "zen", "--extension-id", ZEN_ID)
        with open(self.manifest(".zen", "native-messaging-hosts"), "ab") as f:
            f.write(b"\n")
        self.assertEqual(self.run_main("unregister", "--browser", "zen")[0], 1)


class ShippedFilesTests(unittest.TestCase):
    def src(self, *parts):
        with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
            return f.read()

    def test_template_file_is_the_one_register_uses(self):
        self.assertEqual(self.src("system", "native-messaging",
                                  paths.NATIVE_HOST_MANIFEST + ".in"), reg.MANIFEST_TEMPLATE)

    def test_host_wrapper_drops_browser_arguments(self):
        text = self.src("system", "libexec", "pear-autofill-host")
        code = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        self.assertEqual(code, [f"exec {paths.PEAR_EXEC} autofill"])
        self.assertNotIn("$", "".join(code))
        self.assertTrue(os.access(os.path.join(ROOT, "system", "libexec",
                                               "pear-autofill-host"), os.X_OK))
        self.assertEqual(paths.AUTOFILL_HOST,
                         f"{paths.LIBEXEC}/pear-autofill-host")

    def test_register_command_wrapper(self):
        text = self.src("system", "bin", "pear-passwords-autofill")
        code = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        self.assertEqual(code, [f'exec {paths.VENV_PYTHON} -I -m icp.client.autofill_register "$@"'])
        self.assertTrue(os.access(os.path.join(ROOT, "system", "bin", "pear-passwords-autofill"),
                                  os.X_OK))

    def test_autofill_role_target_is_this_host(self):
        self.assertEqual(paths.ROLE_TARGETS["autofill"][-1], "icp.client.autofill")
        import icp.client.autofill as host
        self.assertTrue(callable(host.main))

    def test_help_lists_the_browsers_the_readme_names(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            reg.main(["--help"])
        listed = re.search(r"Browsers: ([a-z, ]+)\.", buf.getvalue()).group(1).split(", ")
        self.assertEqual(listed, list(reg.BROWSERS))
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("`pear-passwords-autofill --help` lists them", readme)
        for b in ("zen", "firefox", "librewolf", "chromium"):
            self.assertIn(b, listed)
            self.assertIn(f"`{b}`", readme)

    def test_manifest_points_at_the_root_owned_wrapper(self):
        with mock.patch.object(reg, "HOST_PATH", paths.AUTOFILL_HOST):
            doc = json.loads(reg.render("mozilla", [ZEN_ID]))
        self.assertEqual(doc["path"], paths.AUTOFILL_HOST)
        self.assertEqual(doc["name"], paths.NATIVE_HOST_NAME)
        self.assertTrue(re.fullmatch(r"[a-z0-9_.]+", doc["name"]))


if __name__ == "__main__":
    unittest.main()
