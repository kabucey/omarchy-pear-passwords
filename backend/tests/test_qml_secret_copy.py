"""A secret leaves the window only through pear-clip (audit: Ctrl+C / context menu bypass).

The plain-text fields that hold a secret (notes, setup keys, new and typed passwords, the old
1.x passphrase, the Apple password and the verification code) supported Ctrl+C / Ctrl+X to
the regular clipboard and, on Qt 6.9 and later, a context menu with Copy and Cut. That put the
value on the clipboard with no one-paste or 30 s limit and into clipboard history.

Since 2.0's copy-text (features spec 6), Copy in a vault field works again, but only through
the daemon and pear-clip: Ctrl+C, Ctrl+Insert and the shared menu's Copy send the selection
as a `copy-text` request, and Qt's clipboard is never touched. Cut stays swallowed. The Apple
ID password, the 2FA code and the 1.x passphrase are account credentials, not vault data:
nothing copies from them and they have no menu.

Checks:
- on the source: each field calls root.guardSecretKeys from Keys.onPressed with its fixed
  source (or none), its menu is the shared secretMenu (or null), the menu's source matches
  the key path's, and the menu has no Cut;
- at run time (qmltestrunner, offscreen): the exact field lines, guard, copyText and menu
  from shell.qml, with a stubbed root.send, keep every value off the system clipboard after
  Ctrl+C, Ctrl+Insert, Ctrl+X and menu Copy, and send exactly one copy-text with the selected
  substring per Copy from a copyable field and none from the others; an unguarded field
  still copies (so the test can tell).
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

import qmlscan

SHELL = qmlscan.read(os.path.join(qmlscan.APP, "shell.qml"))
CODE = qmlscan.strip_comments(SHELL)

# id -> the copy-text source it sends (features spec 6.2); None: never copyable.
COPYABLE = {"edArea": "notes-edit", "edSetup": "totp-setup-edit", "newPw": "new-password",
            "crPass": "create-password", "crNotes": "create-notes",
            "crSetup": "create-totp-setup"}
NOT_COPYABLE = ("signinField", "codeField", "oldPass")
SECRET_FIELDS = tuple(COPYABLE) + NOT_COPYABLE
GRANT_BOUND = {"notes-edit", "totp-setup-edit", "new-password"}
KEYS_LINE = "Keys.onPressed: (event) => root.guardSecretKeys(event)"
MENU_NULL = "ContextMenu.menu: null"
QMLTESTRUNNER = shutil.which("qmltestrunner") or (
    "/usr/lib/qt6/bin/qmltestrunner" if os.access("/usr/lib/qt6/bin/qmltestrunner", os.X_OK)
    else None)


def element_of(ident: str) -> str:
    m = re.search(rf"\bid: {ident}\n", CODE)
    if m is None:
        raise AssertionError(f"shell.qml has no element with id {ident}")
    start = CODE.rfind("{", 0, m.start())
    return qmlscan.element_body(CODE, start)


def function_text(name: str) -> str:
    m = re.search(rf"\bfunction {name}\s*\([^)]*\)\s*\{{", CODE)
    if m is None:
        raise AssertionError(f"shell.qml has no function {name}")
    return m.group(0)[:-1] + qmlscan.element_body(CODE, m.end() - 1)


def field_lines(ident: str) -> list[str]:
    """The field's own Keys.onPressed and ContextMenu lines, exactly as shell.qml has them."""
    own = qmlscan.top_level(element_of(ident))
    return [l.strip() for l in own.splitlines()
            if re.match(r"\s*(Keys\.onPressed|ContextMenu\.\w+)\s*:", l)]


def keys_line(ident: str) -> str:
    return next(l for l in field_lines(ident) if l.startswith("Keys.onPressed"))


def secret_menu() -> str:
    body = element_of("secretMenu")
    return "Menu " + re.sub(r"\n\s*parent: scope\n", "\n", body)


class SourceTests(unittest.TestCase):
    def test_every_secret_field_has_the_guard(self):
        for ident in SECRET_FIELDS:
            self.assertIn("root.guardSecretKeys(event", keys_line(ident), ident)

    def test_copyable_fields_name_their_source_twice_the_same(self):
        for ident, source in COPYABLE.items():
            lines = field_lines(ident)
            want = (f'Keys.onPressed: (event) => root.guardSecretKeys(event, "{source}", {ident})'
                    if ident != "edArea" else
                    'Keys.onPressed: (event) => root.guardSecretKeys(event, root.editorMode === '
                    '"notes" ? "notes-edit" : "", edArea)')
            self.assertIn(want, lines, ident)
            self.assertIn(f'ContextMenu.onRequested: secretMenu.aim({ident}, "{source}")', lines,
                          ident)
            menu = [l for l in lines if l.startswith("ContextMenu.menu:")]
            self.assertEqual(len(menu), 1, ident)
            self.assertIn("secretMenu", menu[0], ident)
        # The websites editor shares edArea: there it copies nothing and has no menu.
        self.assertIn('ContextMenu.menu: root.editorMode === "notes" ? secretMenu : null',
                      field_lines("edArea"))

    def test_account_credentials_never_copy(self):
        for ident in NOT_COPYABLE:
            lines = field_lines(ident)
            self.assertIn(KEYS_LINE, lines, ident)
            self.assertIn(MENU_NULL, lines, ident)
            self.assertNotIn("secretMenu", element_of(ident), ident)

    def test_the_sources_are_the_protocols_fixed_list(self):
        sources = re.findall(r'guardSecretKeys\(event, (?:root\.editorMode === "notes" \? )?'
                             r'"([a-z-]+)"', CODE)
        self.assertEqual(sorted(sources), sorted(COPYABLE.values()))
        self.assertEqual(sorted(re.findall(r'secretMenu\.aim\(\w+, "([a-z-]+)"\)', CODE)),
                         sorted(COPYABLE.values()))
        copy_text = function_text("copyText")
        for s in GRANT_BOUND:
            self.assertIn(f'"{s}"', copy_text)
        self.assertRegex(copy_text, r'root\.send\("copy-text"')
        self.assertIn("root.withGrant(go)", copy_text)
        self.assertIn("clipComponent.createObject", copy_text)

    def test_the_clip_outcome_names_a_selection(self):
        # copy-text tickets carry field "text"; its clip event must not read "Username pasted".
        self.assertIn('field === "text" ? "Selection"', function_text("clipWords"))
        self.assertIn('clipComponent.createObject(root, { ticket: d.ticket, words: "Selection", running: true });',
                      function_text("copyText"))

    def test_copied_is_said_only_after_offered(self):
        # The VM: the toast said "copied" while pear-exec had refused the clip role and nothing
        # was on the clipboard. Only pear-clip's {"event":"offered"} line may say it.
        self.assertEqual(CODE.count('" copied — clears after one paste or "'), 1)
        for fn in ("copyField", "copyText"):
            self.assertNotIn("copied", function_text(fn), fn)
        comp = element_of("clipComponent")
        offered = comp[comp.index('if (m.event === "offered" && !clipProc.failed && !clipProc.offered) {'):]
        offered = offered[:offered.index("} else if")]
        self.assertIn('root.showFlash(clipProc.words + " copied — clears after one paste or "', offered)
        # An error line, or an exit before "offered", is a failure toast with its reason.
        self.assertIn('} else if (m.event === "error") {', comp)
        self.assertIn("onExited: function (code) {\n                clipProc.fail(", comp)
        self.assertIn("if (clipProc.offered || clipProc.failed) return;", comp)
        self.assertIn('root.showFlash("Couldn\'t copy — " + reason);', function_text("clipFailed"))

    def test_the_guard_swallows_copy_and_cut(self):
        fn = function_text("guardSecretKeys")
        self.assertIn("StandardKey.Copy", fn)
        self.assertIn("StandardKey.Cut", fn)
        self.assertEqual(fn.count("event.accepted = true"), 2)
        self.assertIn("root.copyText(source, field.selectedText)", fn)

    def test_the_menu_has_no_cut(self):
        menu = secret_menu()
        items = re.findall(r'Action \{\s*text: "([^"]+)"', menu)
        self.assertEqual(items, ["Copy", "Paste", "Select All"])
        # The items are Actions drawn by one themed delegate; no stray MenuItem with its own
        # text (which would skip the theme, or be a Cut).
        self.assertNotRegex(menu, r'MenuItem \{\s*text:')

    def test_the_menu_is_themed(self):
        menu = secret_menu()
        for want in ("font.family: Theme.uiFont", "font.pixelSize: Theme.fBody",
                     "color: Theme.bg", "border.color: Theme.line", "radius: Theme.radius",
                     "color: secretItem.enabled ? Theme.fg : Theme.dim",
                     "Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.24)",
                     "textFormat: Text.PlainText"):
            self.assertIn(want, menu)
        self.assertNotRegex(menu, r"\.cut\(\)|\bCut\b")
        self.assertIn("root.copyText(secretMenu.source, secretMenu.target.selectedText)", menu)

    def test_no_secret_field_copies_on_its_own(self):
        for ident in SECRET_FIELDS:
            self.assertNotRegex(element_of(ident), r"\.(copy|cut)\(\)", ident)
        self.assertNotRegex(CODE, r"\.copy\(\)|\.cut\(\)")


THEME = """pragma Singleton
import QtQuick
QtObject {
    readonly property color bg: "#16181c"
    readonly property color fg: "#e6e6e6"
    readonly property color dim: "#8a8f98"
    readonly property color accent: "#4aa8e8"
    readonly property color danger: "#e05252"
    readonly property color selected: "#2a2e35"
    readonly property color hover: "#2a2e35"
    readonly property color panel: "#1d2026"
    readonly property color line: "#33363d"
    readonly property string uiFont: "sans-serif"
    readonly property int radius: 6
    readonly property int fCaption: 12
    readonly property int fSmall: 13
    readonly property int fBody: 15
    readonly property int fHeading: 20
}
"""


def run_qml(files: dict) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
               "XDG_RUNTIME_DIR": d, "QT_QUICK_CONTROLS_STYLE": "Basic"}
        test = next(n for n in files if n.startswith("tst_"))
        return subprocess.run([QMLTESTRUNNER, "-input", os.path.join(d, test)],
                              capture_output=True, text=True, timeout=120, env=env)


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class RuntimeTests(unittest.TestCase):
    """The field lines, guard, copyText and menu from shell.qml, run under Qt itself."""

    TYPES = {"edArea": "TextArea", "codeField": "TextInput"}
    PASSWORD = ("newPw", "crPass", "signinField", "oldPass")

    def fields(self, guarded: bool) -> str:
        out = []
        for i, ident in enumerate(SECRET_FIELDS):
            kind = self.TYPES.get(ident, "TextField")
            lines = "\n        ".join(field_lines(ident)) if guarded else ""
            # Qt itself never copies from a password field, so the unguarded control has none.
            echo = "echoMode: TextInput.Password; " if guarded and ident in self.PASSWORD else ""
            out.append(f"    {kind} {{ id: {ident}; y: {i * 44}; width: 300; height: 40; "
                       f'{echo}text: "secret-{ident}"\n        {lines}\n    }}')
        return "\n".join(out)

    def qml(self, guarded: bool) -> str:
        sink_y = len(SECRET_FIELDS) * 44
        idents = ", ".join(SECRET_FIELDS)
        return f"""import QtQuick
import QtQuick.Controls
import QtTest

Item {{
    id: root
    width: 420; height: {sink_y + 120}
    property string editorMode: "notes"
    property string selectedId: "id-1"
    property var settings: ({{ clip_timeout_s: 30 }})
    property var sent: []
    property int grants: 0
    property int clips: 0
    function send(op, fields, done) {{
        root.sent = root.sent.concat([Object.assign({{ op: op }}, fields)]);
        if (done) done({{ ticket: "t".repeat(43), ttl: 10 }});
        return 1;
    }}
    function withGrant(after) {{ root.grants++; if (after) after(); }}
    function showFlash(text) {{}}
    function errorWords(d) {{ return d.error; }}
    QtObject {{
        id: clipComponent
        function createObject(parent, props) {{ root.clips++; return null; }}
    }}
    {function_text("guardSecretKeys") if guarded else ""}
    {function_text("copyText") if guarded else ""}
    {secret_menu() if guarded else ""}
{self.fields(guarded)}
    TextField {{ id: sink; y: {sink_y}; width: 300; height: 40 }}
    TestCase {{
        name: "SecretCopy"; when: windowShown
        function leaked(src) {{
            sink.text = ""; sink.forceActiveFocus(); keySequence(StandardKey.Paste);
            sink.text = ""; sink.forceActiveFocus(); sink.text = "x"; sink.selectAll();
            keySequence(StandardKey.Cut);                       // clipboard = "x"
            src.forceActiveFocus(); src.select(1, 6);
            keySequence(StandardKey.Copy);
            keyClick(Qt.Key_Insert, Qt.ControlModifier);
            keySequence(StandardKey.Cut);
            sink.text = ""; sink.forceActiveFocus(); keySequence(StandardKey.Paste);
            return sink.text.indexOf("ecret") >= 0 || src.text.indexOf("secret") !== 0;
        }}
        function test_unguarded() {{
            if ({"true" if guarded else "false"}) skip("guarded run");
            var out = [{idents}].map(leaked);
            verify(out.every(function (x) {{ return x; }}), JSON.stringify(out));
        }}
        function test_keys() {{
            if (!{"true" if guarded else "false"}) skip("unguarded run");
            var fields = [{idents}];
            for (var i = 0; i < fields.length; i++) {{
                var f = fields[i], before = root.sent.length;
                verify(!leaked(f), "leaked through keys: " + f.text);
                var mine = root.sent.slice(before);
                var want = {{ {", ".join(f'"{k}": "{v}"' for k, v in COPYABLE.items())} }};
                var name = ["{'", "'.join(SECRET_FIELDS)}"][i];
                if (want[name]) {{
                    // Ctrl+C and Ctrl+Insert: one request each; Ctrl+X none.
                    compare(mine.length, 2, name + " " + JSON.stringify(mine));
                    for (var j = 0; j < 2; j++) {{
                        compare(mine[j].op, "copy-text", name);
                        compare(mine[j].source, want[name], name);
                        compare(mine[j].text, f.text.substring(1, 6), name);
                        compare(mine[j].id === "id-1", ["notes-edit", "totp-setup-edit",
                                "new-password"].indexOf(want[name]) >= 0, name + " id");
                    }}
                }} else {{
                    compare(mine.length, 0, name + " " + JSON.stringify(mine));
                    compare(f.ContextMenu.menu, null, name);
                }}
            }}
            compare(root.clips, 12);
            compare(root.grants, 6);           // the three grant-bound fields, twice each
        }}
        function test_menu() {{
            if (!{"true" if guarded else "false"}) skip("unguarded run");
            var fields = [{", ".join(COPYABLE)}];
            var names = ["{'", "'.join(COPYABLE)}"];
            for (var i = 0; i < fields.length; i++) {{
                var f = fields[i];
                sink.text = ""; sink.forceActiveFocus(); sink.text = "x"; sink.selectAll();
                keySequence(StandardKey.Cut);                   // clipboard = "x"
                f.forceActiveFocus(); f.select(2, 7);
                var before = root.sent.length;
                mouseClick(f, 10, 10, Qt.RightButton);
                tryCompare(secretMenu, "opened", true);
                compare(secretMenu.target, f, names[i]);
                compare(secretMenu.count, 3, names[i]);
                verify(secretMenu.itemAt(0).enabled, names[i] + " Copy enabled");
                mouseClick(secretMenu.itemAt(0));
                tryCompare(secretMenu, "opened", false);
                var mine = root.sent.slice(before);
                compare(mine.length, 1, names[i] + " " + JSON.stringify(mine));
                compare(mine[0].op, "copy-text");
                compare(mine[0].text, f.text.substring(2, 7), names[i]);
                sink.text = ""; sink.forceActiveFocus(); keySequence(StandardKey.Paste);
                compare(sink.text, "x", names[i] + ": the system clipboard changed");
            }}
            // No selection, no Copy.
            crName.forceActiveFocus();
            newPw.forceActiveFocus(); newPw.deselect();
            mouseClick(newPw, 10, 10, Qt.RightButton);
            tryCompare(secretMenu, "opened", true);
            verify(!secretMenu.itemAt(0).enabled, "Copy without a selection");
            secretMenu.close();
            tryCompare(secretMenu, "opened", false);
            // The websites editor shares edArea: nothing is sent and there is no menu.
            root.editorMode = "sites";
            var n = root.sent.length;
            verify(!leaked(edArea));
            compare(root.sent.length, n);
            compare(edArea.ContextMenu.menu, null);
        }}
    }}
    TextField {{ id: crName; y: {sink_y + 50}; width: 300; height: 40 }}
}}
"""

    def run_both(self, guarded: bool) -> subprocess.CompletedProcess:
        return run_qml({"tst_secretcopy.qml": self.qml(guarded), "Theme.qml": THEME,
                        "qmldir": "singleton Theme 1.0 Theme.qml\n"})

    def test_unguarded_fields_do_copy(self):
        # The control: without the guard Qt copies, so the guarded run below means something.
        r = self.run_both(guarded=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS   : qmltestrunner::SecretCopy::test_unguarded()", r.stdout)

    def test_guarded_fields_never_reach_the_clipboard(self):
        r = self.run_both(guarded=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for t in ("test_keys", "test_menu"):
            self.assertIn(f"PASS   : qmltestrunner::SecretCopy::{t}()", r.stdout)


def clip_countdown_block() -> str:
    """shell.qml's countdown state: the properties, clipOffered/clipDone/clipTick and the Timer."""
    start = CODE.index("property QtObject clipOwner: null")
    end = CODE.index("\n", CODE.index("Timer { id: clipTimer;"))
    return CODE[start:end]


class ClipCountdownSourceTests(unittest.TestCase):
    """The status bar's "Password on clipboard · 27 s" follows pear-clip's own lines."""

    def test_offered_starts_it_and_done_or_exit_ends_it(self):
        comp = element_of("clipComponent")
        offered = comp[comp.index('if (m.event === "offered" && !clipProc.failed && !clipProc.offered) {'):]
        offered = offered[:offered.index("} else if")]
        self.assertIn("root.clipOffered(clipProc, clipProc.words);", offered)
        self.assertIn('} else if (m.event === "done") {\n                        root.clipDone(clipProc);', comp)
        exited = comp[comp.index("onExited: function (code) {"):]
        self.assertLess(exited.index("root.clipDone(clipProc);"), exited.index("destroy();"))
        self.assertEqual(CODE.count("root.clipOffered("), 2)          # the process, the preview

    def test_the_item_is_plain_text_and_not_clickable(self):
        item = element_of("clipCountdown")
        self.assertIn("textFormat: Text.PlainText", item)
        self.assertIn('text: root.clipLabel + " on clipboard · " + root.clipLeft + " s"', item)
        self.assertIn("visible: root.clipLive && !root.flash", item)
        # It shares the main slot: the count/toast Text gives way to it, so the bar never
        # carries both (x-audit #1: at 960 px the count shrank to "4 of 4…").
        self.assertIn("Layout.fillWidth: true", item)
        self.assertIn("visible: !clipCountdown.visible", CODE)
        self.assertNotRegex(item, r"TapHandler|MouseArea|onClicked")
        self.assertIn("(root.settings.clip_timeout_s || 30) * 1000", function_text("clipOffered"))


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class ClipCountdownRuntimeTests(unittest.TestCase):
    """The countdown's state and status-bar item from shell.qml, run under Qt itself."""

    def qml(self) -> str:
        return f"""import QtQuick
import QtQuick.Layouts
import QtTest
import "."

Item {{
    id: root
    width: 400; height: 40
    property var settings: ({{ clip_timeout_s: 5 }})
    property string flash: ""
    {clip_countdown_block()}
    QtObject {{ id: first }}
    QtObject {{ id: second }}
    RowLayout {{
        Text {element_of("clipCountdown")}
    }}
    TestCase {{
        name: "ClipCountdown"; when: windowShown
        function test_countdown() {{
            verify(!clipCountdown.visible);
            root.clipOffered(first, "Password");
            verify(clipCountdown.visible);
            compare(clipCountdown.text, "Password on clipboard · 5 s");
            tryCompare(clipCountdown, "text", "Password on clipboard · 4 s", 2500);
            tryCompare(clipCountdown, "text", "Password on clipboard · 3 s", 2500);
            // A new copy: the old offer's done (behind it) leaves the new countdown alone.
            root.clipOffered(second, "Selection");
            compare(clipCountdown.text, "Selection on clipboard · 5 s");
            root.clipDone(first);
            verify(clipCountdown.visible);
            compare(clipCountdown.text, "Selection on clipboard · 5 s");
            // Its own done ends it.
            root.clipDone(second);
            verify(!clipCountdown.visible);
            verify(!clipTimer.running);
            // Past the timeout without a done yet: it stays at 0 s until the outcome.
            root.settings = {{ clip_timeout_s: 1 }};
            root.clipOffered(first, "Code");
            tryCompare(clipCountdown, "text", "Code on clipboard · 0 s", 2500);
            verify(clipCountdown.visible);
            root.clipDone(first);
            verify(!clipCountdown.visible);
            // A toast takes the slot while it shows; the countdown comes back after it.
            root.clipOffered(second, "Password");
            root.flash = "Password copied";
            verify(!clipCountdown.visible);
            root.flash = "";
            verify(clipCountdown.visible);
            root.clipDone(second);
        }}
    }}
}}
"""

    def test_the_countdown_runs_and_ends_with_its_own_offer(self):
        r = run_qml({"tst_clipcountdown.qml": self.qml(), "Theme.qml": THEME,
                     "qmldir": "singleton Theme 1.0 Theme.qml\n"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS   : qmltestrunner::ClipCountdown::test_countdown()", r.stdout)


if __name__ == "__main__":
    unittest.main()
