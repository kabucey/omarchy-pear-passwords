"""What the window and docs/protocol.md say "Start over" (reset) does to the old files
(round 3 audit, problem 2).

Since a092738 a reset of a store that opens normally and keeps nothing (only key wrappers and
settings) deletes the old directory instead of leaving another u<uid>.broken-<time>. The
daemon asks for that whenever the store opens normally, which is the case on the window's
migration-pending screen; only after tpm-cleared or damaged are the files always kept. Both
the window ("The old files are moved aside, not deleted.") and protocol.md ("renamed aside,
never deleted") still promised the files were kept on every screen.

Checks:
- protocol.md's reset bullet no longer says "never deleted" and says when the store is deleted;
- shell.qml's start-over confirmation comes from startOverNote(screen), the only place that
  says "not deleted", and (under qmltestrunner) it says so only for tpm-cleared and damaged.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

import qmlscan

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHELL = qmlscan.read(os.path.join(qmlscan.APP, "shell.qml"))
CODE = qmlscan.strip_comments(SHELL)
KEPT = ("tpm-cleared", "damaged")                # reset never passes discard_empty here
OFFERED = KEPT + ("migration-pending",)          # the screens with a Start over button
QMLTESTRUNNER = shutil.which("qmltestrunner") or (
    "/usr/lib/qt6/bin/qmltestrunner" if os.access("/usr/lib/qt6/bin/qmltestrunner", os.X_OK)
    else None)


def reset_bullet() -> str:
    with open(os.path.join(ROOT, "docs", "protocol.md"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^- `reset`:.*?(?=^- `)", text, re.S | re.M)
    if m is None:
        raise AssertionError("docs/protocol.md has no `reset` bullet")
    return " ".join(m.group(0).split())


def note_function() -> str:
    m = re.search(r"\bfunction startOverNote\s*\(screen\)\s*\{", CODE)
    if m is None:
        raise AssertionError("shell.qml has no function startOverNote(screen)")
    return "function startOverNote(screen) " + qmlscan.element_body(CODE, m.end() - 1)


class DocTests(unittest.TestCase):
    def test_protocol_says_when_reset_deletes(self):
        bullet = reset_bullet()
        self.assertNotIn("never deleted", bullet)
        self.assertIn("always kept", bullet)
        self.assertIn("keeps nothing", bullet)
        self.assertIn("deleted instead", bullet)


class SourceTests(unittest.TestCase):
    def test_the_confirmation_depends_on_the_screen(self):
        self.assertIn("text: root.startOverNote(root.screen)", CODE)

    def test_only_the_note_promises_the_files_are_kept(self):
        fn = note_function()
        self.assertIn("not deleted", fn)
        self.assertEqual(CODE.count("not deleted"), fn.count("not deleted"))


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class RuntimeTests(unittest.TestCase):
    """startOverNote from shell.qml, run under Qt itself, for every screen that offers it."""

    def test_not_deleted_only_where_reset_keeps_the_files(self):
        checks = []
        for screen in OFFERED:
            note = f"root.startOverNote({screen!r})"
            if screen in KEPT:
                checks.append(f"verify({note}.indexOf('moved aside, not deleted') >= 0, {screen!r});")
            else:
                checks.append(f"verify({note}.indexOf('not deleted') < 0, {screen!r});")
                checks.append(f"verify({note}.indexOf('deleted') >= 0, {screen!r});")
        qml = f"""import QtQuick
import QtTest

Item {{
    id: root
    {note_function()}
    TestCase {{
        name: "StartOverNote"
        function test_notes() {{
            {chr(10).join("            " + c for c in checks).lstrip()}
        }}
    }}
}}
"""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tst_startover.qml")
            with open(path, "w") as f:
                f.write(qml)
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d}
            r = subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True, text=True,
                               timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("StartOverNote::test_notes()", r.stdout)
        self.assertNotIn("FAIL", r.stdout)


if __name__ == "__main__":
    unittest.main()
