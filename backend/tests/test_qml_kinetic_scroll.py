"""Touchpad scrolling has momentum, the way GTK 4's does, and nothing else about scrolling changes.

Qt Quick on Wayland follows a touchpad's pixel deltas and stops dead when the fingers lift (it
only does momentum on macOS), and neither libinput nor Hyprland adds any. KineticScroll adds it
from the gesture's end (wl_pointer.axis_stop, Qt's ScrollEnd) with GTK 4's own constants. A
mouse wheel, presses, drags and the scroll bar stay Qt's.
"""

import glob
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import qmlscan

KINETIC = os.path.join(qmlscan.APP, "KineticScroll.qml")
QMLTESTRUNNER = shutil.which("qmltestrunner") or (
    "/usr/lib/qt6/bin/qmltestrunner" if os.access("/usr/lib/qt6/bin/qmltestrunner", os.X_OK)
    else None)


def app_sources():
    for path in sorted(glob.glob(os.path.join(qmlscan.APP, "*.qml"))):
        with open(path, encoding="utf-8") as f:
            yield os.path.basename(path), f.read()


class WiringTests(unittest.TestCase):
    def test_every_scroll_area_has_it(self):
        for name, src in app_sources():
            if name == "KineticScroll.qml":
                continue
            areas = re.findall(r"^\s*(?:Flickable|ListView|GridView|ScrollView) \{\n\s*id: (\w+)",
                               src, re.M)
            self.assertEqual(len(areas), len(re.findall(r"^\s*(?:Flickable|ListView|GridView|ScrollView) \{",
                                                       src, re.M)), f"{name}: a scroll area without an id")
            for fid in areas:
                self.assertRegex(src, r"KineticScroll \{ flickable: " + fid + r"(\.contentItem)? \}",
                                 f"{name}: {fid}")

    def test_it_is_the_only_scroll_code(self):
        # Momentum lives in one file; the scroll areas themselves stay stock.
        for name, src in app_sources():
            if name == "KineticScroll.qml":
                continue
            self.assertNotIn("FrameAnimation", src, name)
            for m in re.finditer(r"onWheel:.*", src):
                self.assertIn("w.accepted = true", m.group(0), f"{name}: only the click-through guard")

    def test_gtk_constants_and_mouse_wheels_untouched(self):
        with open(KINETIC, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("friction: 4", src)
        self.assertIn("captureMs: 150", src)
        self.assertIn("k.stop(); m.accepted = false;", src)
        self.assertIn("hoverEnabled: false", src)
        self.assertIn("return false;                                 // a mouse wheel", src)


TEST_QML = r"""
import QtQuick
import QtTest

Item {
    id: root
    width: 200; height: 200

    Flickable {
        id: f
        anchors.fill: parent
        contentWidth: width
        contentHeight: 5000
        MouseArea { id: target; width: 200; height: 5000; property int clicks: 0; onClicked: clicks++ }
        KineticScroll { id: k; flickable: f }
    }
    Flickable {
        id: short
        y: 200
        width: 200; height: 200
        contentHeight: 100
        KineticScroll { id: ks; flickable: short }
    }

    TestCase {
        name: "Kinetic"
        when: windowShown

        function swipe(target, dy, n, startT) {
            target.feed(Qt.ScrollBegin, 0, 0, startT);
            for (var i = 1; i <= n; ++i) target.feed(Qt.ScrollUpdate, 0, dy, startT + i * 8);
            return target.feed(Qt.ScrollEnd, 0, 0, startT + n * 8 + 1);
        }

        function init() { k.stop(); f.contentY = 0; }

        function test_it_sits_over_the_content_not_in_it() {
            compare(k.parent, f);
            compare(k.width, f.width);
        }

        function test_fingers_are_followed_exactly() {
            k.feed(Qt.ScrollBegin, 0, 0, 1000);
            k.feed(Qt.ScrollUpdate, 0, -10, 1008);
            k.feed(Qt.ScrollUpdate, 0, -15, 1016);
            compare(f.contentY, 25);
        }

        function test_a_flick_glides_on_and_stops() {
            verify(swipe(k, -20, 10, 1000));
            var lifted = f.contentY;
            compare(lifted, 200);
            tryVerify(function () { return f.contentY > lifted + 100; }, 2000);
            verify(k.gliding);
            tryCompare(k, "gliding", false, 5000);
            var rest = f.contentY;
            wait(100);
            compare(f.contentY, rest);
            compare(rest, Math.round(rest));
        }

        function test_fingers_that_paused_before_lifting_do_not_glide() {
            k.feed(Qt.ScrollBegin, 0, 0, 1000);
            for (var i = 1; i <= 5; ++i) k.feed(Qt.ScrollUpdate, 0, -20, 1000 + i * 8);
            k.feed(Qt.ScrollEnd, 0, 0, 1400);
            var at = f.contentY;
            wait(150);
            compare(f.contentY, at);
        }

        function test_the_glide_stops_at_the_end() {
            f.contentY = 4700;
            swipe(k, -80, 10, 1000);
            tryCompare(f, "contentY", 4800, 3000);
            wait(100);
            compare(f.contentY, 4800);
        }

        function test_a_new_gesture_stops_the_glide() {
            swipe(k, -20, 10, 1000);
            wait(50);
            k.feed(Qt.ScrollBegin, 0, 0, 5000);
            var at = f.contentY;
            wait(100);
            compare(f.contentY, at);
        }

        function test_someone_else_moving_it_wins() {
            swipe(k, -20, 10, 1000);
            wait(30);
            f.contentY = 0;
            wait(100);
            compare(f.contentY, 0);
        }

        function test_a_mouse_wheel_is_left_to_qt() {
            verify(!k.feed(Qt.NoScrollPhase, 0, 0, 1000));
            verify(!k.feed(Qt.ScrollUpdate, 0, -10, 1000));   // no ScrollBegin: not a touchpad
            compare(f.contentY, 0);
        }

        function test_a_click_stops_the_glide_and_still_lands() {
            swipe(k, -20, 10, 1000);
            verify(k.gliding);
            mouseClick(f, 50, 50);
            verify(!k.gliding);
            compare(target.clicks, 1);
        }

        function test_nothing_to_scroll_lets_it_through() {
            ks.feed(Qt.ScrollBegin, 0, 0, 1000);
            verify(!ks.feed(Qt.ScrollUpdate, 0, -10, 1008));
            compare(short.contentY, 0);
        }
    }
}
"""


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class RuntimeTests(unittest.TestCase):
    def test_kinetic_scroll(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(KINETIC, d)
            with open(os.path.join(d, "qmldir"), "w") as f:
                f.write("KineticScroll 1.0 KineticScroll.qml\n")
            path = os.path.join(d, "tst_kinetic.qml")
            with open(path, "w") as f:
                f.write(TEST_QML)
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d}
            r = subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True, text=True,
                               timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        passed = re.findall(r"^PASS   : qmltestrunner::Kinetic::(test_\w+)\(\)", r.stdout, re.M)
        self.assertEqual(len(passed), TEST_QML.count("        function test_"), r.stdout)


if __name__ == "__main__":
    unittest.main()
