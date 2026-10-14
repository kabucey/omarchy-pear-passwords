"""native/pear-exec.c: the constants, and the environment and checks of a real build.

The C file is compiled twice into a scratch directory:

- in test mode (-DPEAR_EXEC_TEST_MODE), where every path is looked up under
  $PEAR_EXEC_TEST_ROOT, "root-owned" means owned by whoever runs the test, and the set-gid
  check is skipped. A fake compositor (a process whose comm is set to a unique name), a fake
  hyprland.lock and fake targets that record their argv, environment and open fds stand in for
  the real session;
- exactly as the installer builds it, to prove PEAR_EXEC_TEST_ROOT does nothing there.

No root, no set-gid bit and no real compositor is involved.
"""

import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from icp.daemon import paths

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE = os.path.join(REPO, "native", "pear-exec.c")
PATHS_ENV = os.path.join(REPO, "system", "paths.env")
CC = shutil.which("cc") or shutil.which("gcc")
CFLAGS = ["-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fPIE", "-pie",
          "-Wl,-z,relro,-z,now", "-Wall", "-Wextra", "-Werror"]

SIG = "testsig_1_2"
# The session's compositor (started first, in setUp) reserves this much address space, so a
# younger fake that reserves none always has the smaller virtual size (round 2 audit, problem 1).
BIG_RESERVE = 1 << 30
COMM = f"pfh{os.getpid() % 1000000}"

FAKE_TARGET = r'''#!/usr/bin/python3 -I
import json, os, sys
fds = sorted(os.listdir("/proc/self/fd"), key=int)
line = sys.stdin.readline()
status = open("/proc/self/status").read()
nnp = [l.split()[1] for l in status.splitlines() if l.startswith("NoNewPrivs:")]
um = os.umask(0)
with open(%(out)r, "w") as f:
    json.dump({"argv": sys.argv[1:], "env": dict(os.environ), "fds": fds, "stdin": line,
               "nnp": nnp[0] if nnp else None, "umask": um}, f)
sys.stdout.write("target-stdout\n")
'''

COMPOSITOR = r'''
import mmap, socket, sys
open("/proc/self/comm", "w").write(sys.argv[1])
# argv[3]: bytes of address space to reserve (never touched, so no memory is used). It makes
# the virtual size, field 23 of /proc/<pid>/stat, disagree with the start order on purpose.
reserve = mmap.mmap(-1, int(sys.argv[3]), flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
                    | getattr(mmap, "MAP_NORESERVE", 0), prot=mmap.PROT_READ)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[2])
s.listen(16)
print("ready", flush=True)
while True:
    c, _ = s.accept()
    c.close()
'''


def read_paths_env():
    out = {}
    with open(PATHS_ENV) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k] = v
    return out


def c_defines():
    import re
    with open(SOURCE) as f:
        src = f.read()
    return dict(re.findall(r'^#define\s+(PEAR_[A-Z_]+)\s+"([^"]*)"', src, re.M))


NO_SESSION_BUS = f"unix:path={paths.EMPTY_DIR}/no-session-bus"

QT_DISABLED = ("zwp_primary_selection_device_manager_v1,gtk_primary_selection_device_manager,"
               "zwp_text_input_manager_v1,zwp_text_input_manager_v2,zwp_text_input_manager_v3,"
               "qt_text_input_method_manager_v1")


@unittest.skipUnless(CC, "no C compiler")
class PearExecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pe")
        cls.test_bin = os.path.join(cls.tmp, "pear-exec-test")
        cls.prod_bin = os.path.join(cls.tmp, "pear-exec-prod")
        subprocess.run([CC, *CFLAGS, "-DPEAR_EXEC_TEST_MODE", "-o", cls.test_bin, SOURCE],
                       check=True)
        subprocess.run([CC, *CFLAGS, "-o", cls.prod_bin, SOURCE], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # --- fixture ---------------------------------------------------------------------------
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="r", dir=self.tmp)
        os.chmod(self.root, 0o755)
        self.uid = os.getuid()
        self.out = os.path.join(self.tmp, f"out-{id(self)}.json")
        if os.path.exists(self.out):
            os.unlink(self.out)
        target = FAKE_TARGET % {"out": self.out}
        for p in (paths.ROLE_TARGETS["ui"][0], paths.VENV_PYTHON):
            self._file(p, target, 0o755)
        self._file(paths.FONTS_CONF, "<fontconfig/>", 0o644)
        for d in (paths.APP_DIR, paths.EMPTY_DIR):
            os.makedirs(self.r(d), mode=0o755, exist_ok=True)
        self.rt = self.r(f"/run/user/{self.uid}")
        os.makedirs(self.rt, mode=0o755, exist_ok=True)
        os.chmod(self.rt, 0o700)
        self.comp = self.compositor("wayland-7")
        self.lock("wayland-7", self.comp.pid)

    def r(self, p):
        return self.root + p

    def _file(self, p, content, mode):
        full = self.r(p)
        os.makedirs(os.path.dirname(full), mode=0o755, exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        os.chmod(full, mode)

    def compositor(self, name, comm=COMM, reserve=BIG_RESERVE):
        sock = os.path.join(self.rt, name)
        p = subprocess.Popen([sys.executable, "-c", COMPOSITOR, comm, sock, str(reserve)],
                             stdout=subprocess.PIPE, text=True)
        self.addCleanup(self._reap, p)
        self.assertEqual(p.stdout.readline().strip(), "ready")
        return p

    @staticmethod
    def _reap(p):
        p.kill()
        p.wait()
        p.stdout.close()

    def lock(self, name, pid, sig=SIG):
        d = os.path.join(self.rt, "hypr", sig)
        os.makedirs(d, mode=0o700, exist_ok=True)
        with open(os.path.join(d, "hyprland.lock"), "w") as f:
            f.write(f"{pid}\n{name}\n")

    def env(self, **over):
        e = {
            "XDG_RUNTIME_DIR": self.rt,
            "WAYLAND_DISPLAY": "wayland-7",
            "HYPRLAND_INSTANCE_SIGNATURE": SIG,
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={self.rt}/bus",
            "PEAR_EXEC_TEST_ROOT": self.root,
            "PEAR_EXEC_TEST_COMM": COMM,
            "LANG": "C.UTF-8",
            "LC_TIME": "C.UTF-8",
            "XCURSOR_SIZE": "24",
            # everything below must be dropped or overridden
            "LD_PRELOAD": "libpearevil.so",
            "LD_LIBRARY_PATH": "evil",
            "PYTHONPATH": "evil",
            "PYTHONSTARTUP": "evil",
            "QT_PLUGIN_PATH": "evil",
            "QML_IMPORT_PATH": "evil",
            "QML2_IMPORT_PATH": "evil",
            "GCONV_PATH": "evil",
            "VK_ICD_FILENAMES": "evil",
            "__EGL_VENDOR_LIBRARY_DIRS": "evil",
            "MESA_LOADER_DRIVER_OVERRIDE": "evil",
            "QSG_RHI_BACKEND": "evil",
            "DISPLAY": ":0",
            "XDG_CONFIG_HOME": "evil",
            "XDG_DATA_DIRS": "evil",
            "QML_DISABLE_DISK_CACHE": "0",
            "FONTCONFIG_FILE": "evil",
            "QT_QPA_PLATFORMTHEME": "evil",
            "HOME": "evil",
            "PATH": "/home/evil/bin:/usr/bin",
            "LC_PAPER": "en_US.UTF-8; touch pwned",
        }
        for k, v in over.items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
        return e

    def run_exec(self, role="ui", binary=None, env=None, args=None, stdin="ticket-line\n",
                 pass_fd=False):
        argv = [binary or self.test_bin] + ([role] if args is None else args)
        kw = {}
        self.passed_fd = None
        if pass_fd:
            r, w = os.pipe()
            kw["pass_fds"] = (w,)
            self.passed_fd = w
            self.addCleanup(os.close, r)
            self.addCleanup(os.close, w)
        p = subprocess.run(argv, env=env if env is not None else self.env(), input=stdin,
                           capture_output=True, text=True, timeout=20, **kw)
        result = None
        if os.path.exists(self.out):
            with open(self.out) as f:
                result = json.load(f)
            os.unlink(self.out)
        return p, result

    def expect_refused(self, p, result, code=77):
        self.assertEqual(p.returncode, code, p.stderr)
        self.assertIsNone(result, "the target ran")

    # --- constants -------------------------------------------------------------------------
    def test_constants_match_paths_env(self):
        env = read_paths_env()
        d = c_defines()
        pairs = {"PEAR_PREFIX": "PREFIX", "PEAR_VENV": "VENV", "PEAR_VENV_PYTHON": "VENV_PYTHON",
                 "PEAR_APP_DIR": "APP_DIR", "PEAR_FONTS_CONF": "FONTS_CONF",
                 "PEAR_EMPTY_DIR": "EMPTY_DIR", "PEAR_CLIENT_GROUP": "CLIENT_GROUP",
                 "PEAR_TARGET_UI": "TARGET_UI",
                 "PEAR_TARGET_CLIP_MODULE": "TARGET_CLIP_MODULE",
                 "PEAR_TARGET_MIGRATE_MODULE": "TARGET_MIGRATE_MODULE",
                 "PEAR_TARGET_AUTOFILL_MODULE": "TARGET_AUTOFILL_MODULE"}
        for c_name, env_name in pairs.items():
            self.assertEqual(d.get(c_name), env[env_name], c_name)

    # --- the environment it builds -----------------------------------------------------------
    def expected_env(self):
        pw = pwd.getpwuid(self.uid)
        return {
            "HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name, "PATH": "/usr/bin",
            "XDG_RUNTIME_DIR": self.rt,
            # The full path: pear-clip connects to it as given. A nested pear-exec accepts
            # exactly this path back (vm-real, critical).
            "WAYLAND_DISPLAY": os.path.join(self.rt, "wayland-7"),
            # The window gets no session bus, so Qt's AT-SPI bridge never starts.
            "DBUS_SESSION_BUS_ADDRESS": NO_SESSION_BUS,
            "HYPRLAND_INSTANCE_SIGNATURE": SIG, "LANG": "C.UTF-8", "LC_TIME": "C.UTF-8",
            "XCURSOR_SIZE": "24",
            "QT_QPA_PLATFORM": "wayland", "QT_QPA_PLATFORMTHEME": "",
            "QML_DISABLE_DISK_CACHE": "1", "QT_LOGGING_RULES": "*=false",
            "QT_WAYLAND_DISABLED_INTERFACES": QT_DISABLED,
            "XDG_CONFIG_HOME": paths.EMPTY_DIR, "XDG_CACHE_HOME": paths.EMPTY_DIR,
            "XDG_STATE_HOME": paths.EMPTY_DIR, "XDG_DATA_HOME": paths.EMPTY_DIR,
            "XDG_DATA_DIRS": "/usr/share:/usr/local/share",
            "FONTCONFIG_FILE": paths.FONTS_CONF, "XCURSOR_PATH": "/usr/share/icons",
        }

    def test_environment_is_built_from_scratch(self):
        p, res = self.run_exec("ui")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(res["env"], self.expected_env())

    def test_window_environment_passes_nested_clip_and_migrate(self):
        # vm-real, critical: the window starts `pear-exec clip` and `pear-exec migrate` with
        # the environment `pear-exec ui` gave it. Feed exactly that back in; only the test
        # build's own hooks are added.
        p, res = self.run_exec("ui")
        self.assertEqual(p.returncode, 0, p.stderr)
        window_env = dict(res["env"])
        window_env["PEAR_EXEC_TEST_ROOT"] = self.root
        window_env["PEAR_EXEC_TEST_COMM"] = COMM
        for role in ("clip", "migrate"):
            p, nested = self.run_exec(role, env=window_env)
            self.assertEqual(p.returncode, 0, (role, p.stderr))
            self.assertEqual(nested["argv"], list(paths.ROLE_TARGETS[role][1:]), role)
            self.assertEqual(nested["env"]["WAYLAND_DISPLAY"],
                             window_env["WAYLAND_DISPLAY"], role)
            self.assertEqual(nested["env"]["DBUS_SESSION_BUS_ADDRESS"],
                             f"unix:path={self.rt}/bus", role)

    def test_only_the_runtime_dir_path_is_accepted(self):
        # The full-path form is only the verified runtime directory's own socket; every
        # other path, and every lookalike, is still refused.
        bad = [os.path.join(self.root, "wayland-7"),
               self.rt + "x/wayland-7",
               self.rt + "/../" + os.path.basename(self.rt) + "/wayland-7",
               self.rt + "//wayland-7",
               self.rt + "/wayland-7/",
               self.rt + "/hypr/wayland-7",
               self.rt + "/",
               self.rt,
               "/run/user/%d/wayland-7" % self.uid]
        for name in bad:
            p, res = self.run_exec(env=self.env(WAYLAND_DISPLAY=name))
            self.expect_refused(p, res)
        p, res = self.run_exec(env=self.env(WAYLAND_DISPLAY=self.rt + "/wayland-7"))
        self.assertEqual(p.returncode, 0, p.stderr)
        # Full path, but not the socket the instance lock names: still refused.
        self.compositor("wayland-8")
        p, res = self.run_exec(env=self.env(WAYLAND_DISPLAY=self.rt + "/wayland-8"))
        self.expect_refused(p, res)

    def test_specific_drops_and_forces(self):
        # Spelled out, so a failure names the variable rather than a dict diff.
        _, res = self.run_exec("clip")
        env = res["env"]
        for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "QT_PLUGIN_PATH",
                     "QML_IMPORT_PATH", "QML2_IMPORT_PATH", "GCONV_PATH", "VK_ICD_FILENAMES",
                     "__EGL_VENDOR_LIBRARY_DIRS", "MESA_LOADER_DRIVER_OVERRIDE",
                     "QSG_RHI_BACKEND", "DISPLAY", "LC_PAPER", "PEAR_EXEC_TEST_ROOT"):
            self.assertNotIn(name, env)
        self.assertEqual(env["QML_DISABLE_DISK_CACHE"], "1")
        # clipboard_ui-2: no primary selection, no input method for the secret fields
        disabled = env["QT_WAYLAND_DISABLED_INTERFACES"].split(",")
        for iface in ("zwp_primary_selection_device_manager_v1", "zwp_text_input_manager_v3"):
            self.assertIn(iface, disabled)
        self.assertEqual(env["FONTCONFIG_FILE"], paths.FONTS_CONF)
        self.assertEqual(env["XDG_CONFIG_HOME"], paths.EMPTY_DIR)

    def test_role_targets(self):
        for role in paths.ROLES:
            p, res = self.run_exec(role)
            self.assertEqual(p.returncode, 0, (role, p.stderr))
            self.assertEqual(res["argv"], list(paths.ROLE_TARGETS[role][1:]), role)

    def test_fds_umask_and_no_new_privs(self):
        p, res = self.run_exec("migrate", pass_fd=True, stdin="the-ticket\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(str(self.passed_fd), res["fds"])
        self.assertTrue(all(int(fd) <= 3 for fd in res["fds"]), res["fds"])  # 3: listdir's own
        self.assertEqual(res["stdin"], "the-ticket\n")      # stdin kept
        self.assertEqual(p.stdout, "target-stdout\n")        # stdout kept
        self.assertEqual(res["umask"], 0o077)
        self.assertEqual(res["nnp"], "1")

    def test_missing_dbus_gets_the_canonical_address(self):
        _, res = self.run_exec("clip", env=self.env(DBUS_SESSION_BUS_ADDRESS=None))
        self.assertEqual(res["env"]["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={self.rt}/bus")

    # --- AT-SPI (audit round 2, problem 1) ----------------------------------------------------
    def test_the_window_never_gets_the_session_bus(self):
        # Any program of the user's can set org.a11y.Status IsEnabled on the session bus; Qt
        # then exposes every field's text over AT-SPI. With a bus nobody can listen on (the
        # empty directory is root's) the bridge never starts.
        self.assertEqual(c_defines().get("PEAR_NO_SESSION_BUS"), NO_SESSION_BUS)
        for dbus in (f"unix:path={self.rt}/bus", None):
            p, res = self.run_exec("ui", env=self.env(DBUS_SESSION_BUS_ADDRESS=dbus))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(res["env"]["DBUS_SESSION_BUS_ADDRESS"], NO_SESSION_BUS)
            self.assertNotIn("AT_SPI_BUS_ADDRESS", res["env"])

    def test_the_other_roles_keep_the_session_bus_even_when_started_by_the_window(self):
        for role in ("clip", "migrate", "autofill"):
            for dbus in (f"unix:path={self.rt}/bus", NO_SESSION_BUS):
                p, res = self.run_exec(role, env=self.env(DBUS_SESSION_BUS_ADDRESS=dbus))
                self.assertEqual(p.returncode, 0, (role, dbus, p.stderr))
                self.assertEqual(res["env"]["DBUS_SESSION_BUS_ADDRESS"],
                                 f"unix:path={self.rt}/bus", role)

    def test_an_atspi_address_from_the_caller_is_dropped(self):
        p, res = self.run_exec("ui", env=self.env(
            AT_SPI_BUS_ADDRESS="unix:path=/tmp/evil-a11y", QT_LINUX_ACCESSIBILITY_ALWAYS_ON="1",
            QT_ACCESSIBILITY="1"))
        self.assertEqual(p.returncode, 0, p.stderr)
        for name in ("AT_SPI_BUS_ADDRESS", "QT_LINUX_ACCESSIBILITY_ALWAYS_ON",
                     "QT_ACCESSIBILITY"):
            self.assertNotIn(name, res["env"])

    # --- refusals ----------------------------------------------------------------------------
    def test_arguments(self):
        for args in ([], ["ui", "extra"], ["cli"], ["UI"], ["ui;sh"], ["../ui"]):
            p, res = self.run_exec(args=args)
            self.expect_refused(p, res, code=64)

    def test_wayland_display_must_be_a_bare_name(self):
        # A path that does lead to the real socket, with a lock file naming it exactly: only
        # the name rule can refuse these.
        os.makedirs(os.path.join(self.rt, "wayland-8"), mode=0o700)
        # (The runtime directory's own full path is accepted: see
        # test_only_the_runtime_dir_path_is_accepted.)
        for name in ("wayland-8/../wayland-7", os.path.join(self.rt, "wayland-8/../wayland-7"),
                     "./wayland-7", "wayland-", "wayland-7x", "Wayland-7"):
            self.lock(name, self.comp.pid)
            p, res = self.run_exec(env=self.env(WAYLAND_DISPLAY=name))
            self.expect_refused(p, res)
        self.lock("wayland-7", self.comp.pid)
        p, res = self.run_exec()
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_compositor_must_be_named_hyprland(self):
        other = self.compositor("wayland-3", comm="notthecomp")
        self.lock("wayland-3", other.pid)
        p, res = self.run_exec(env=self.env(WAYLAND_DISPLAY="wayland-3"))
        self.expect_refused(p, res)

    def test_compositor_must_match_the_lock_file(self):
        self.lock("wayland-7", self.comp.pid + 100000)
        p, res = self.run_exec()
        self.expect_refused(p, res)
        self.lock("wayland-6", self.comp.pid)
        p, res = self.run_exec()
        self.expect_refused(p, res)

    @staticmethod
    def _stat_field(pid, n):
        """Field n (1-based, as proc(5) numbers them) of /proc/<pid>/stat."""
        with open(f"/proc/{pid}/stat") as f:
            return int(f.read().rsplit(")", 1)[1].split()[n - 3])

    def _younger_small_compositor(self, name):
        # The younger one must really start later (in clock ticks, as pear-exec compares):
        # under load a fixed short sleep was not always enough (round 1 gate finding 4). It
        # reserves nothing, so it is also the smallest: a check that compared virtual size
        # (field 23) instead of start time (field 22) picks it as "the oldest".
        older = self._stat_field(self.comp.pid, 22)
        deadline = time.monotonic() + 10
        while True:
            time.sleep(0.02)
            younger = self.compositor(name, reserve=4096)
            if self._stat_field(younger.pid, 22) > older or time.monotonic() > deadline:
                break
            self._reap(younger)
        self.assertGreater(self._stat_field(younger.pid, 22), older)
        self.assertLess(self._stat_field(younger.pid, 23), self._stat_field(self.comp.pid, 23))
        return younger

    def test_compositor_must_be_the_oldest(self):
        younger = self._younger_small_compositor("wayland-9")
        self.lock("wayland-9", younger.pid)
        p, res = self.run_exec(env=self.env(WAYLAND_DISPLAY="wayland-9"))
        self.expect_refused(p, res)
        self.assertIn("older", p.stderr)

    def test_the_oldest_compositor_works_while_a_younger_smaller_one_runs(self):
        # A nested or test Hyprland (smaller, started later) must not lock the real session
        # out (round 2 audit, problem 1).
        self._younger_small_compositor("wayland-9")
        self.lock("wayland-7", self.comp.pid)
        p, res = self.run_exec()
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_runtime_dir_rules(self):
        p, res = self.run_exec(env=self.env(XDG_RUNTIME_DIR=self.rt + "/"))
        self.expect_refused(p, res)
        p, res = self.run_exec(env=self.env(XDG_RUNTIME_DIR=None))
        self.expect_refused(p, res)
        os.chmod(self.rt, 0o750)
        try:
            p, res = self.run_exec()
            self.expect_refused(p, res)
        finally:
            os.chmod(self.rt, 0o700)

    def test_dbus_address_must_be_the_session_bus(self):
        p, res = self.run_exec(env=self.env(DBUS_SESSION_BUS_ADDRESS="unix:path=/tmp/evil"))
        self.expect_refused(p, res)
        p, res = self.run_exec("clip", env=self.env(
            DBUS_SESSION_BUS_ADDRESS=NO_SESSION_BUS + "x"))
        self.expect_refused(p, res)

    def test_signature_is_required_and_plain(self):
        for sig in (None, "../..", "a/b", "x y"):
            p, res = self.run_exec(env=self.env(HYPRLAND_INSTANCE_SIGNATURE=sig))
            self.expect_refused(p, res)

    def test_writable_target_refused(self):
        target = self.r(paths.ROLE_TARGETS["ui"][0])
        os.chmod(target, 0o775)
        p, res = self.run_exec("ui")
        self.expect_refused(p, res)
        os.chmod(target, 0o755)
        os.chmod(os.path.dirname(target), 0o777)
        p, res = self.run_exec("ui")
        self.expect_refused(p, res)
        os.chmod(os.path.dirname(target), 0o755)

    def test_writable_fontconfig_or_app_refused(self):
        for p_ in (paths.FONTS_CONF, paths.APP_DIR):
            full = self.r(p_)
            mode = os.stat(full).st_mode & 0o777
            os.chmod(full, mode | 0o002)
            try:
                p, res = self.run_exec("ui")
                self.expect_refused(p, res)
            finally:
                os.chmod(full, mode)

    def test_symlink_to_a_writable_file_refused(self):
        evil = os.path.join(self.root, "writable-python")
        with open(evil, "w") as f:
            f.write(FAKE_TARGET % {"out": self.out})
        os.chmod(evil, 0o777)
        target = self.r(paths.VENV_PYTHON)
        os.unlink(target)
        os.symlink(evil, target)
        p, res = self.run_exec("clip")
        self.expect_refused(p, res)

    def test_member_of_the_client_group_refused(self):
        name = grp.getgrgid(os.getgroups()[0]).gr_name
        p, res = self.run_exec(env=self.env(PEAR_EXEC_TEST_GROUP=name))
        self.expect_refused(p, res)

    def test_production_build_ignores_test_root(self):
        # Same environment that works for the test build: the real build must refuse (it is
        # not set-gid pear-client here) and never look under PEAR_EXEC_TEST_ROOT.
        p, res = self.run_exec(binary=self.prod_bin)
        self.expect_refused(p, res)


if __name__ == "__main__":
    unittest.main()
