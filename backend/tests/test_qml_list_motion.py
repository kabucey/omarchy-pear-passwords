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
    """The account list scrolls the way the system does: Qt's own Flickable, so the wheel and
    touchpad follow Hyprland's scroll_factor and libinput, with nothing remapped in the app."""

    def test_the_list_uses_native_scrolling(self):
        lst = CODE[CODE.index("id: list\n"):]
        lst = lst[:lst.index("delegate:")]
        self.assertNotIn("interactive: false", lst)
        self.assertNotIn("WheelHandler", lst)
        self.assertNotIn("FrameAnimation", lst)

    def test_no_scroll_overrides_anywhere(self):
        # Every scroll area is a stock Flickable/ListView: no tuned bounds, deceleration,
        # velocity or wheel remapping in any of the window's files.
        import glob, os
        for path in glob.glob(os.path.join(qmlscan.APP, "*.qml")):
            with open(path, encoding="utf-8") as f:
                src = f.read()
            for word in ("boundsBehavior", "boundsMovement", "flickDeceleration",
                         "maximumFlickVelocity", "WheelHandler", "stopPhysics"):
                self.assertNotIn(word, src, f"{os.path.basename(path)}: {word}")

    def test_no_touchpad_watcher(self):
        self.assertNotIn("touchWatch", CODE)
        self.assertNotIn("touch_watch.py", CODE)

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


class LaunchFocusTests(unittest.TestCase):
    """A fresh launch takes the keyboard: the first showing asks Hyprland for focus, the same
    dispatch a second launch uses, so typing searches without touching the mouse."""

    def test_first_showing_asks_for_focus_once(self):
        self.assertIn("onVisibleChanged: if (visible && !root.launchFocused) "
                      "{ root.launchFocused = true; launchFocus.start(); }", CODE)
        self.assertIn("Timer { id: launchFocus; interval: 300; "
                      "onTriggered: focusProc.running = true }", CODE)

    def test_unlocking_asks_again_after_the_prompt_closes(self):
        self.assertIn("onAppUnlockedChanged: if (root.appUnlocked) "
                      "{ Qt.callLater(root.focusSearch); launchFocus.restart(); }", CODE)
