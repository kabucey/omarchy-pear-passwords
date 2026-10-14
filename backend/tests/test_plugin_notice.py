"""plugin/Service.qml's notice: once per state and version, and worded for a 1.x upgrade.

The owner's rule is no unsolicited pings: a pending system step is one notification, not one
at every login. The shell snippets are taken from Service.qml itself and run here.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
QML = open(os.path.join(ROOT, "plugin", "Service.qml"), encoding="utf-8").read()


def _snippet(name: str) -> str:
    """The sh -c script of the Process whose argv[0] marker is `name`, joined as QML joins it."""
    block = QML[:QML.index(f'"{name}"')]
    block = block[block.rindex('command: ["sh", "-c",') + len('command: ["sh", "-c",'):]
    return "".join(re.findall(r"'((?:[^'\\]|\\.)*)'", block)).replace("\\'", "'")


class NoticeOnceTests(unittest.TestCase):
    def run_once(self, state: str, checkout: str, home: str) -> int:
        env = {"PATH": "/usr/bin:/bin", "HOME": home, "XDG_STATE_HOME": os.path.join(home, "state")}
        return subprocess.run(["sh", "-c", _snippet("pear-notify-once"), "pear-notify-once",
                               state, checkout], env=env).returncode

    def test_a_pending_step_is_announced_once(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as co:
            with open(os.path.join(co, "SHA256SUMS"), "w") as f:
                f.write("abc  manifest.json\n")
            self.assertEqual(self.run_once("missing", co, home), 0)      # first time: tell
            self.assertEqual(self.run_once("missing", co, home), 1)      # every later login: quiet
            self.assertEqual(self.run_once("outdated", co, home), 0)     # a new state: tell
            with open(os.path.join(co, "SHA256SUMS"), "a") as f:          # a new version: tell
                f.write("def  app/shell.qml\n")
            self.assertEqual(self.run_once("outdated", co, home), 0)
            self.assertEqual(self.run_once("outdated", co, home), 1)

    def test_an_upgrade_from_1x_says_how_to_move(self):
        self.assertIn("property bool hasV1: false", QML)
        self.assertIn('/icp/vault.enc"', QML)
        hint = QML[QML.index('systemState === "missing" && hasV1'):]
        hint = hint[:hint.index(': systemState === "missing"')]
        self.assertIn("your 1.x passwords stay where they are", hint)
        self.assertIn("unlock Pear Passwords 1.x once", hint)
        # The 1.x check only asks whether the file exists; nothing is read.
        legacy = QML[QML.index("property Process legacy"):QML.index("property Process once")]
        self.assertIn("test -e", legacy)
        self.assertNotRegex(legacy, r"\bcat\b|\bhead\b|\bread\b")


if __name__ == "__main__":
    unittest.main()
