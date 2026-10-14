"""install.sh and uninstall.sh remove 1.x files from your home only on an exact hash match.

system/lib/user-files.sh is sourced into bash with HOME pointed at a scratch directory and a
stub `systemctl` first on PATH, so nothing on this machine is touched. The 1.x files are
rebuilt byte for byte from what 1.x installed (the launcher with this scratch home written
into it, as install.sh's heredoc did).
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 1.3.2's units and launcher template, exactly as released.
TIMER_132 = ("[Unit]\nDescription=Pear Passwords: keep your passwords on iCloud fresh\n\n[Timer]\n"
             "# Every two hours, catching up after sleep (Persistent= needs OnCalendar=).\n"
             "OnCalendar=0/2:00\nPersistent=true\nAccuracySec=1min\nRandomizedDelaySec=30s\n"
             "# And one shortly after login.\nOnStartupSec=2min\n\n[Install]\nWantedBy=timers.target\n")
LAUNCHER_132 = ("[Desktop Entry]\nType=Application\nName=Pear Passwords\nComment=Your passwords on iCloud\n"
                "Exec=@DATA@/app/launch.sh\nIcon=@DATA@/app/icon.svg\nTerminal=false\n"
                "Categories=Utility;Security;\nKeywords=password;passwords;icloud;login;credentials;2fa;pear;\n")


class UserFilesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self._tmp.name, "home")
        self.bin = os.path.join(self._tmp.name, "bin")
        os.makedirs(self.home)
        os.makedirs(self.bin)
        self.log = os.path.join(self._tmp.name, "systemctl.log")
        with open(os.path.join(self.bin, "systemctl"), "w") as f:
            f.write(f'#!/bin/sh\necho "$*" >> "{self.log}"\n')
        os.chmod(os.path.join(self.bin, "systemctl"), 0o755)
        self.desktop_2x = os.path.join(self._tmp.name, "system-launcher.desktop")
        self.data = os.path.join(self.home, ".local/share/pear-passwords")
        self.units = os.path.join(self.home, ".config/systemd/user")
        self.launcher = os.path.join(self.home, ".local/share/applications/pear-passwords.desktop")

    def tearDown(self):
        self._tmp.cleanup()

    def put(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def bash(self, snippet):
        script = (f'set -euo pipefail; . "{ROOT}/system/paths.env"; '
                  f'. "{ROOT}/system/lib/user-files.sh"; DESKTOP_FILE="{self.desktop_2x}"; {snippet}')
        env = {"HOME": self.home, "PATH": f"{self.bin}:/usr/bin:/bin"}
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True,
                              timeout=30)

    def retire(self):
        proc = self.bash("pp_retire_1x")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_released_sync_timer_is_disabled_and_removed(self):
        timer = os.path.join(self.units, "pear-passwords-sync.timer")
        self.put(timer, TIMER_132)
        out = self.retire()
        self.assertFalse(os.path.exists(timer))
        self.assertIn("--user disable --now pear-passwords-sync.timer", open(self.log).read())
        self.assertIn("Removed the 1.x unit", out)

    def test_edited_sync_timer_is_kept(self):
        timer = os.path.join(self.units, "pear-passwords-sync.timer")
        self.put(timer, TIMER_132.replace("0/2:00", "hourly"))
        out = self.retire()
        self.assertTrue(os.path.exists(timer))
        self.assertIn(timer, out)
        self.assertFalse(os.path.exists(self.log), "an edited unit was disabled")

    def test_launcher_goes_only_once_the_new_one_exists(self):
        self.put(self.launcher, LAUNCHER_132.replace("@DATA@", self.data))
        self.assertIn("Kept the 1.x launcher", self.retire())
        self.assertTrue(os.path.exists(self.launcher))
        self.put(self.desktop_2x, "[Desktop Entry]\n")
        self.retire()
        self.assertFalse(os.path.exists(self.launcher))

    def test_edited_or_foreign_launcher_is_kept(self):
        self.put(self.desktop_2x, "[Desktop Entry]\n")
        self.put(self.launcher, LAUNCHER_132.replace("@DATA@", "/home/someone-else/.local/share/pear-passwords"))
        self.assertIn(self.launcher, self.retire())
        self.assertTrue(os.path.exists(self.launcher))

    def test_1x_backend_stays_until_the_vault_has_moved(self):
        os.makedirs(os.path.join(self.data, "venv/bin"))
        os.makedirs(os.path.join(self.data, "app"))
        os.makedirs(os.path.join(self.home, ".config/icp"))
        self.assertIn("until your passwords are moved", self.retire())
        self.assertTrue(os.path.isdir(os.path.join(self.data, "venv")))
        # the move: ~/.config/icp renamed to its v1 backup
        os.rename(os.path.join(self.home, ".config/icp"),
                  os.path.join(self.home, ".config/icp.v1-backup-20261008"))
        self.retire()
        self.assertFalse(os.path.exists(self.data))
        self.assertTrue(os.path.isdir(os.path.join(self.home, ".config/icp.v1-backup-20261008")),
                        "the v1 backup must never be touched by the installer")

    def test_shipped_anisette_unit_is_ours(self):
        shipped = os.path.join(ROOT, "systemd", "pear-passwords-anisette.service")
        unit = os.path.join(self.units, "pear-passwords-anisette.service")
        os.makedirs(self.units, exist_ok=True)
        shutil.copy(shipped, unit)
        q = lambda: self.bash(f'pp_user_ours "{unit}" "{shipped}" && echo yes || echo no').stdout.strip()
        self.assertEqual(q(), "yes")
        with open(unit, "a") as f:
            f.write("# mine\n")
        self.assertEqual(q(), "no")
        # and the copy shipped today is a released one, so a future update recognises it
        with open(shipped, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        with open(os.path.join(ROOT, "system", "lib", "user-files.sh")) as f:
            self.assertIn(f"{digest} pear-passwords-anisette.service", f.read())

    def test_never_touches_the_1x_vault(self):
        with open(os.path.join(ROOT, "system", "lib", "user-files.sh")) as f:
            body = f.read()
        for script in ("install.sh",):
            with open(os.path.join(ROOT, script)) as f:
                body += f.read()
        code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(code, r"rm[^\n]*\.config/icp")
        self.assertNotRegex(code, r"mv[^\n]*\.config/icp")

    def test_download_venv_is_rebuilt_after_a_python_minor_upgrade(self):
        # installer-stale-pip-venv-after-python-upgrade: bin/python still runs, but its
        # lib/pythonX.Y is the old minor's, so `python -m pip` has no pip.
        venv = os.path.join(self.home, ".cache/pear-passwords/pip")
        os.makedirs(os.path.join(venv, "bin"))
        os.makedirs(os.path.join(venv, "lib/python3.0/site-packages/pip"))
        os.symlink("/usr/bin/python3", os.path.join(venv, "bin/python"))
        proc = self.bash(f'pp_pip_venv "{venv}" && "{venv}/bin/python" -m pip --version')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(os.path.exists(os.path.join(venv, "lib/python3.0")))
        # a matching venv is reused, not rebuilt
        marker = os.path.join(venv, "keep")
        open(marker, "w").close()
        self.assertEqual(self.bash(f'pp_pip_venv "{venv}"').returncode, 0)
        self.assertTrue(os.path.exists(marker))
        with open(os.path.join(ROOT, "install.sh")) as f:
            body = f.read()
        self.assertIn('pp_pip_venv "$pipenv"', body)
        self.assertNotIn('[ -x "$pipenv/bin/python" ] ||', body)

    def test_app_only_reports_without_writing(self):
        if os.path.exists("/usr/local/lib/pear-passwords"):
            self.skipTest("a system install exists on this machine")
        if not shutil.which("quickshell"):
            self.skipTest("quickshell is not installed")
        self.put(self.launcher, LAUNCHER_132.replace("@DATA@", self.data))
        env = {"HOME": self.home, "PATH": f"{self.bin}:/usr/bin:/bin"}
        proc = subprocess.run([os.path.join(ROOT, "install.sh"), "--app-only"], env=env,
                              text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("not installed", proc.stdout)
        self.assertTrue(os.path.exists(self.launcher))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".cache")))


if __name__ == "__main__":
    unittest.main()
