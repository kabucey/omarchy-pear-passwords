"""The list never moves on its own, and typing over it searches.

On the owner's machine the list kept drifting with nobody touching it: a bounce chased an end
computed from ListView's estimated contentHeight, which moves as rows are made. And with the
pointer over the search field or the list, typing should continue the search.
"""

import os
import re
import unittest

import qmlscan

CODE = qmlscan.read(os.path.join(qmlscan.APP, "shell.qml"))


def function_text(name: str) -> str:
    m = re.search(r"\n\s*function " + name + r"\(.*?\n\s*\}\n", CODE, re.S)
    assert m, name
    return m.group(0)


class ListMotionTests(unittest.TestCase):
    def test_a_bounce_aims_at_the_bounds_as_they_are_now(self):
        step = CODE[CODE.index('if (list.mode === "bounce") {'):]
        step = step[:step.index("// exact critically damped step")]
        self.assertIn("list.contentY >= list.minY && list.contentY <= list.maxY", step)
        self.assertIn('list.mode = "idle";', step)
        self.assertIn("list.bounceTarget = list.contentY < list.minY ? list.minY", step)

    def test_momentum_is_capped_and_stops_when_the_rows_change(self):
        self.assertIn("if (list.movingFor > 3000) { list.settle(); return; }", CODE)
        self.assertIn("onModelChanged: list.settle()", CODE)
        # The list's own settle (another settle() in the file belongs to the 1.x check).
        settle = CODE[CODE.index("function settle() {\n                                list.stopPhysics();"):]
        settle = settle[:settle.index("}")]
        self.assertIn("Math.max(list.minY, Math.min(list.maxY, list.contentY))", settle)


class TypeToSearchTests(unittest.TestCase):
    def test_it_is_the_windows_last_key_branch(self):
        self.assertIn("} else if (root.typeToSearch(ev)) {", CODE)
        self.assertIn("id: listHover", CODE)

    def test_only_over_the_list_and_never_over_an_open_editor(self):
        body = function_text("typeToSearch")
        for guard in ("!listHover.hovered", "search.activeFocus", "root.editorOpen",
                      "root.settingsOpen", "root.tagEditing", "root.deleteConfirm",
                      "Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier"):
            self.assertIn(guard, body)
        self.assertLess(body.index("return false"), body.index("root.leavePanel();"))


if __name__ == "__main__":
    unittest.main()


class SearchFollowsPointerTests(unittest.TestCase):
    def test_the_pointer_over_the_list_hands_the_keyboard_to_search(self):
        self.assertIn("onHoveredChanged: if (hovered) root.searchFollowsPointer()", CODE)
        self.assertIn("onPointChanged: root.searchFollowsPointer()", CODE)
        body = function_text("searchFollowsPointer")
        for guard in ("!listHover.hovered", "search.activeFocus", "root.editorOpen",
                      "root.settingsOpen", "root.tagEditing", "root.deleteConfirm"):
            self.assertIn(guard, body)
        self.assertLess(body.index("return;"), body.index("search.forceActiveFocus();"))


class DialogBackdropTests(unittest.TestCase):
    """Behind an editor, Settings or sign-in over an unlocked vault, the view darkens and blurs
    together, easing in and out; without shader effects it stays plainly dimmed."""

    def test_the_view_blurs_and_darkens_with_one_eased_value(self):
        self.assertIn("import QtQuick.Effects", CODE)
        self.assertIn("readonly property bool dialogOpen: root.editorOpen || root.settingsOpen", CODE)
        self.assertIn("Behavior on dialogT { NumberAnimation { duration: 260; easing.type: Easing.OutCubic } }", CODE)
        self.assertIn("blur: root.dialogT", CODE)
        self.assertIn("color: Qt.rgba(0, 0, 0, 0.55 * root.dialogT)", CODE)
        self.assertIn("layer.enabled: root.dialogT > 0.001 && GraphicsInfo.api !== GraphicsInfo.Software",
                      CODE)

    def test_the_sheets_no_longer_paint_their_own_darkness(self):
        self.assertNotIn("color: Qt.rgba(0, 0, 0, 0.55)\n", CODE)
