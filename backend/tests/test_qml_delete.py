"""The window's Delete: said in full first, then the daemon's .manage dialog (fingerprint).

Nothing is sent before the inline confirmation, read-only rows (Recently Deleted, passkey
only) and Wi-Fi networks offer no Delete, and a dismissed dialog keeps the question up.
"""

import os
import re
import unittest

import qmlscan

CODE = qmlscan.read(os.path.join(qmlscan.APP, "shell.qml"))


def function_text(name: str) -> str:
    m = re.search(r"\n    function " + name + r"\(.*?\n    \}\n", CODE, re.S)
    assert m, name
    return m.group(0)


class DeleteWiringTests(unittest.TestCase):
    def test_only_a_live_login_offers_delete(self):
        m = re.search(r"readonly property bool canDelete:(.*?)\n\n", CODE, re.S).group(1)
        for part in ("!!root.selected", "root.appUnlocked", "!root.selected.recently_deleted",
                     'root.selected.kind !== "passkey"', "!root.selected.is_wifi"):
            self.assertIn(part, m)

    def test_nothing_is_sent_before_the_confirmation(self):
        body = function_text("deleteSelected")
        guard = body.index("if (!root.canDelete || !root.deleteConfirm || root.deleting) return;")
        self.assertLess(guard, body.index('root.send("delete"'))
        self.assertEqual(CODE.count('root.send("delete"'), 1)

    def test_a_dismissed_dialog_keeps_the_question_up(self):
        body = function_text("deleteSelected")
        self.assertIn('if (d.error !== "dismissed" && d.error !== "cancelled")', body)

    def test_the_question_names_the_consequence(self):
        self.assertIn('" from iCloud Keychain on all your devices? Its password history goes"', CODE)
        self.assertIn("it won't be in Recently Deleted on your Apple devices.", CODE)
        self.assertIn("onTapped: root.deleteConfirm = true", CODE)
        self.assertIn("onClicked: root.deleteSelected()", CODE)

    def test_moving_on_drops_the_question(self):
        self.assertIn("if (!root.deleting) root.deleteConfirm = false;", function_text("forgetSecrets"))


if __name__ == "__main__":
    unittest.main()
