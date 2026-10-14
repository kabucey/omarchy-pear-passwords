"""The search field's category drop-down and tag chip (features spec 3), and the Tags row (5b.7).

Source checks on shell.qml pin how the window wires it: the list filter and every count use
categories.js's one predicate, a lock clears the tag, a sync drops a tag nobody has, and the
whole feature runs on tier-1 list metadata (no send of any kind, no grant, no reveal).

Run-time checks load the real CategorySearch.qml and categories.js under qmltestrunner
(offscreen, with a stand-in Theme): hover opens after 200 ms and not on a pass-through, the
300 ms grace across the field and the list, Alt+Down and a leading '#', key routing while it is
open (Esc does not reach the window), choosing replaces the tag, the active row changes
nothing, All and the mini x clear it, the Backspace rule, the chip before the query, and that
every row's count is the number of entries the window then shows.
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
SEARCH_QML = os.path.join(qmlscan.APP, "CategorySearch.qml")
CATS_JS = os.path.join(qmlscan.APP, "categories.js")
QMLTESTRUNNER = shutil.which("qmltestrunner") or (
    "/usr/lib/qt6/bin/qmltestrunner" if os.access("/usr/lib/qt6/bin/qmltestrunner", os.X_OK)
    else None)


def function_body(name: str) -> str:
    m = re.search(rf"\bfunction {re.escape(name)}\s*\([^)]*\)\s*\{{", CODE)
    if not m:
        raise AssertionError(f"shell.qml has no function {name}")
    return qmlscan.element_body(CODE, m.end() - 1)


def element_of(ident: str) -> str:
    m = re.search(rf"\bid: {ident}\n", CODE)
    if m is None:
        raise AssertionError(f"shell.qml has no element with id {ident}")
    return qmlscan.element_body(CODE, CODE.rfind("{", 0, m.start()))


class WindowWiringTests(unittest.TestCase):
    def test_the_list_and_the_counts_share_one_predicate(self):
        body = function_body("applyFilter")
        self.assertIn("if (!Cat.matches(e, root.catTag)) continue;", body)
        # Typing a tag's name finds it as text too.
        self.assertIn('" #" + e.tags.join(" #")', body)
        js = qmlscan.read(CATS_JS)
        rows = js[js.index("function rows("):]
        self.assertEqual(len(re.findall(r"count\(entries, ", rows)), 3)
        self.assertRegex(js, r"function count\(entries, tag\) \{\s*let n = 0;\s*for \(.*\) "
                             r"if \(matches\(entries\[i\], tag\)\) n\+\+;")

    def test_the_search_field_gets_the_list_and_flags(self):
        box = element_of("search")
        self.assertRegex(CODE, r"\n\s*CategorySearch \{\s*id: search\n")
        for line in ("entries: root.entries", "features: root.features", "tag: root.catTag",
                     "onTagPicked: (t) => root.setCatTag(t)",
                     "onMoveRequested: (delta) => root.moveCursor(delta)",
                     "onTabbed: root.enterPanel(0)", "onCopyRequested: root.copyPassword()"):
            self.assertIn(line, box)
        self.assertIn("Cat.count(root.entries, root.catTag)", box)   # "Search 47 Wi-Fi"

    def test_flags_come_only_from_the_daemon_and_default_off(self):
        self.assertIn("property var features: ({ passkeys: false, apple_deleted: false })", CODE)
        # One setter; it takes only booleans, so anything else reads as off.
        self.assertEqual(len(re.findall(r"root\.features = ", CODE)), 1)
        self.assertIn("root.features = { passkeys: !!(f && f.passkeys), apple_deleted: !!(f && f.apple_deleted) };",
                      function_body("takeFeatures"))
        calls = re.findall(r"root\.takeFeatures\(([^;]*)\);", CODE)
        # The unlock reply, every synced event, op features (get and set), a lock (off), and
        # two development previews, which never connect.
        self.assertEqual(sorted(calls), sorted(["d.features", "m.features", "d.features",
                                                "d.features", "null",
                                                "{ passkeys: true, apple_deleted: true }",
                                                "{ passkeys: true, apple_deleted: false }"]))
        self.assertIn("root.takeFeatures(d.features);", function_body("authenticate"))
        self.assertIn("root.takeFeatures(null);", function_body("lockApp"))
        synced = CODE[CODE.index('case "synced":'):]
        synced = synced[:synced.index("return;")]
        self.assertLess(synced.index("if (m.features) root.takeFeatures(m.features);"),
                        synced.index("root.setEntries("))
        self.assertIn("root.takeFeatures({ passkeys: true, apple_deleted: true })",
                      function_body("applyPreview"))

    def test_a_flag_changes_only_through_op_features(self):
        # Turning a category on or off is op features {set}, which raises .manage in the
        # daemon; reading is {get}, which never asks. Nothing else sends "features".
        self.assertEqual(len(re.findall(r'send\("features"', CODE)), 2)
        self.assertIn('root.send("features", { get: true },', function_body("loadFeatures"))
        self.assertIn('root.send("features", { set: f },', function_body("setFeature"))
        self.assertIn('root.send("diag-items", {},', function_body("runDiag"))
        self.assertRegex(CODE, r"onSettingsOpenChanged: if \(root\.settingsOpen && root\.phase === "
                               r'"ready"\) root\.loadFeatures\(\)')
        self.assertIn('root.diagText = "";', function_body("lockApp"))

    def test_the_tag_clears_on_lock_and_survives_a_sync_only_while_someone_has_it(self):
        lock = function_body("lockApp")
        self.assertIn("root.catTag = null;", lock)
        self.assertIn("search.closeCats();", lock)
        self.assertIn('case "locked":\n            root.lockApp(', CODE)
        sync = function_body("setEntries")
        self.assertIn("if (!Cat.stillValid(list_, root.features, root.catTag)) root.catTag = null;",
                      sync)
        self.assertLess(sync.index("stillValid"), sync.index("root.entries = list_"))
        # A grant ending (endGrant -> forgetSecrets) is not a lock: the filter stays.
        for fn in ("forgetSecrets", "endGrant", "select", "hideSecrets"):
            self.assertNotIn("catTag", function_body(fn), fn)

    def test_nothing_drops_down_behind_a_sheet(self):
        search = element_of("search")
        self.assertIn("available: !root.editorOpen && !root.settingsOpen && !root.signinOpen", search)
        self.assertIn("bottomReserve: statusBar.height", search)

    def test_the_drop_down_lines_up_with_the_avatars(self):
        src = qmlscan.strip_comments(qmlscan.read(SEARCH_QML))
        panel = src[src.index('objectName: "catPanel"'):][:400]
        self.assertIn("x: -6\n", panel)
        self.assertIn("width: Math.max(catSearch.width + 6, 266)", panel)

    def test_the_window_going_inactive_closes_the_list(self):
        conn = CODE[CODE.index("function onStateChanged()"):]
        conn = conn[:conn.index("}\n")]
        self.assertIn("search.closeCats();", conn)

    def test_esc_clears_the_query_then_the_tag_then_quits(self):
        esc = CODE[CODE.index("if (ev.key === Qt.Key_Escape) {\n                    if (root.confirming)"):]
        esc = esc[:esc.index("ev.accepted = true;")]
        self.assertLess(esc.index("search.text = \"\""), esc.index("root.setCatTag(null)"))
        self.assertLess(esc.index("root.setCatTag(null)"), esc.index("Qt.quit()"))

    def test_the_feature_never_asks_for_a_secret(self):
        # Tier 1 only: nothing in the drop-down, the chip or the predicate sends anything.
        for path in (SEARCH_QML, CATS_JS):
            code = qmlscan.strip_comments(qmlscan.read(path))
            for bad in (r"\bsend\s*\(", r"withGrant", r'"reveal"', r'"grant"', r"\broot\.",
                        r"notesText", r"Process\b", r"Socket\b"):
                self.assertIsNone(re.search(bad, code), f"{path}: {bad}")
        for fn in ("setCatTag", "searchKind", "setEntries"):
            body = function_body(fn)
            self.assertNotRegex(body, r"\bsend\(|withGrant|reveal", fn)
        self.assertNotRegex(function_body("applyFilter"), r"\bsend\(|withGrant|reveal")

    def test_every_text_in_the_drop_down_is_plain(self):
        # test_qml_text_plain covers every app file; this names the chip label in particular.
        src = qmlscan.strip_comments(qmlscan.read(SEARCH_QML))
        chip = src[src.index("id: chipLabel"):]
        self.assertIn("textFormat: Text.PlainText", chip[:200])
        self.assertIn("ContextMenu.menu: null", src)
        self.assertNotIn("RichText", src)
        self.assertNotIn("StyledText", src)

    def test_the_timings(self):
        src = qmlscan.strip_comments(qmlscan.read(SEARCH_QML))
        self.assertIn("Timer { id: openTimer; interval: 200;", src)
        self.assertIn("Timer { id: closeTimer; interval: 300;", src)

    def test_a_read_only_title_opens_no_rename(self):
        # Audit #2: a click on the title raised the account's dialog and opened rename on a
        # Recently Deleted or passkey-only row, for a set the daemon always refuses.
        self.assertIn('return !!s && (!!s.recently_deleted || s.kind === "passkey");',
                      function_body("selectedReadOnly"))
        title = CODE[CODE.index("HoverHandler { id: hTitle }"):]
        area = title[title.index("MouseArea {"):]
        area = area[:area.index("root.renaming = true;")]
        self.assertIn("enabled: !root.selectedReadOnly()", area)
        self.assertIn("onClicked: if (!root.selectedReadOnly()) root.withGrant(", area)
        hint = title[title.index('text: "rename"'):][:400]
        self.assertIn("opacity: hTitle.hovered && !root.selectedReadOnly() ? 1 : 0", hint)

    def test_read_only_notes_only_reveal(self):
        # Audit #2: the second "show notes" opened the notes editor (polkit #2, then a refusal).
        act = function_body("fieldAction")
        self.assertIn('else if (key === "notes")\n            root.loadNotes(root.notesLoaded && '
                      '!root.selectedReadOnly()\n                           ? function () { '
                      'root.openEditor("notes"); } : null);', act)
        self.assertLess(act.index('if (root.selectedReadOnly() && (key === "change" || '
                                  'key.indexOf("edit") === 0)) return;'),
                        act.index("root.withGrant("))

    def test_the_drop_down_spans_the_list_column(self):
        # The selected row's highlight and its icons showed right of a narrower drop-down.
        box = element_of("search")
        self.assertIn("panel.width: parent.width - search.x - search.panel.x", box)

    def test_passkeys_and_deleted_wait_for_their_flags(self):
        js = qmlscan.read(CATS_JS)
        self.assertRegex(js, r'key: "passkeys",[^\n]*flag: "passkeys"')
        self.assertRegex(js, r'key: "deleted",[^\n]*flag: "apple_deleted"')
        self.assertRegex(js, r'key: "codes",[^\n]*flag: ""')
        self.assertRegex(js, r'key: "wifi",[^\n]*flag: ""')
        # Security, Shared Groups and the Family card are not offered at all.
        for word in ("Security", "Shared", "Family", "security", "shared"):
            self.assertNotIn(word, qmlscan.strip_comments(js), word)


class TagsRowTests(unittest.TestCase):
    """5b.7: chips from tier-1 Meta, the editor behind withGrant, the dim sentence."""

    def test_the_tags_row_reads_meta_only(self):
        rows = function_body("fieldRows")
        part = rows[rows.index("const tags = s.tags || [];"):]
        self.assertIn('label: "Tags"', part)
        self.assertNotRegex(part, r"notesText|send\(|reveal")
        self.assertIn("chips: root.tagEditing ? [] : tags", part)

    def test_editing_tags_needs_the_grant_and_is_one_set(self):
        self.assertIn('else if (key === "edittags") root.withGrant(function () { root.openTagEditor(); });',
                      function_body("fieldAction"))
        save = function_body("saveTags")
        self.assertIn("root.setFields({ tags: tags }, null,", save)
        self.assertIn("root.withGrant(", function_body("setFields"))
        # The editor goes with the grant (lock, another account, time up).
        self.assertIn("root.tagEditing = false;", function_body("forgetSecrets"))
        ran = function_body("grantRanOut")
        self.assertLess(ran.index("tags: root.tagDraft.slice()"), ran.index("root.endGrant()"))
        for fn in ("select", "clearSelection", "lockApp"):
            self.assertIn("root.tagKept = null;", function_body(fn), fn)
        self.assertIn("kept.id === root.selectedId", function_body("openTagEditor"))

    def test_the_editor_says_tags_are_not_secret(self):
        editor = CODE[CODE.index("visible: root.tagEditing\n"):]
        editor = editor[:editor.index("visible: root.changing || root.confirming")]
        # The owner's short form; docs/security.md keeps the full sentence (test_docs_claims).
        sentence = ('text: "Tags show after the first unlock, like names and usernames \u2014 '
                    'don\'t put secrets in them."')
        self.assertIn(sentence, editor)
        self.assertIn("color: Theme.dim", editor[editor.index("Tags show after"):][:300])

    def test_the_create_form_says_why_tags_stop_add(self):
        hint = CODE[CODE.index("text: root.tagsProblem(crTags.text)") - 300:][:600]
        self.assertIn("visible: root.createMore && text !== \"\"", hint)
        self.assertIn("Layout.row: 9; Layout.column: 1", hint)
        body = function_body("tagsProblem")
        self.assertIn('"a tag is 1 to 32 letters, digits, - or _"', body)
        self.assertIn('"at most 16 tags"', body)

    def test_wifi_tags_show_read_only(self):
        # A Wi-Fi network has no notes Apple syncs, so no "edit" and no "Add tags"; the
        # daemon refuses set {tags} for it (test_wifi_details_refused.py).
        rows = function_body("fieldRows")
        wifi = rows[rows.index("if (s.is_wifi) {"):]
        wifi = wifi[:wifi.index("const sites = root.allSites();")]
        self.assertIn('rows.push({ key: "tags", label: "Tags", value: "#" + wifiTags.join("  #"),',
                      wifi)
        self.assertIn("chips: wifiTags, actions: [] });", wifi)
        self.assertIn("if (wifiTags.length)", wifi)
        self.assertNotIn("edittags", wifi)

    def test_the_detail_tags_wrap_and_are_never_cut(self):
        flow = element_of("chipFlow")
        self.assertIn("Layout.fillWidth: true", flow)
        self.assertNotIn("clip:", flow)
        self.assertIn("implicitHeight: chipFlow.visible ? Math.max(48, chipFlow.implicitHeight + 22) : 48",
                      CODE)
        self.assertRegex(CODE[CODE.rfind("{", 0, CODE.index("id: chipFlow")) - 8:], r"^\s*Flow \{")

    def test_the_tag_field_takes_the_grammars_characters_only(self):
        field = element_of("tagInput")
        self.assertIn(r"regularExpression: /^#?[\p{L}\p{M}\p{N}_-]{0,32}$/", field)
        commit = function_body("commitTagInput")
        self.assertIn("tagInput.acceptableInput", commit)
        self.assertIn("Cat.canonTag(raw)", commit)
        self.assertIn("root.tagDraft.length >= 16", commit)


class ReadOnlyRowTests(unittest.TestCase):
    """Rows Apple keeps read-only offer no edit, so no approval dialog is raised for one the
    daemon would refuse; a passkey-only row has no password to reveal or copy."""

    def test_read_only_rows_lose_their_edits(self):
        rows = function_body("fieldRows")
        self.assertIn('const readOnly = !!s.recently_deleted || s.kind === "passkey";', rows)
        self.assertEqual(rows.count("readOnly ? root.withoutEdits(rows) : rows"), 2)
        strip = function_body("withoutEdits")
        self.assertIn('a.key !== "change" && a.key.indexOf("edit") !== 0', strip)

    def test_passkey_only_rows_never_ask_for_a_password(self):
        for fn in ("doReveal", "copyField"):
            body = function_body(fn)
            guard = body.index("has_password === false")
            self.assertLess(guard, body.index("withGrant") if "withGrant" in body
                            else body.index("root.send("), fn)


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

# Made-up entries, shaped like the wire's (tier-1 Meta only). Expected counts with the flags off:
# All 6 (everything but e4), Codes 1 (e1; e4 is deleted), Wi-Fi 1, finance 1, side-project 1,
# work 3 (e1, e2, and e7's fullwidth spelling folds to the same key; e4 is deleted).
# With both flags on: Passkeys 2 (e5 has one, e6 is passkey-only), Deleted 1.
FIXTURE = """[
    { id: "e1", primary: "GitHub", title: "GitHub", secondary: "me", domain: "github.com",
      has_totp: true, tags: ["work", "finance"] },
    { id: "e2", primary: "Slack", title: "Slack", secondary: "me", domain: "slack.com",
      tags: ["Work"] },
    { id: "e3", primary: "Home", title: "Home", secondary: "", domain: "", is_wifi: true },
    { id: "e4", primary: "Old", title: "Old", secondary: "x", domain: "old.example",
      has_totp: true, recently_deleted: true, tags: ["work"] },
    { id: "e5", primary: "Bank", title: "Bank", secondary: "y", domain: "bank.example",
      has_passkey: true, tags: ["side-project"] },
    { id: "e6", primary: "Shop", title: "Shop", secondary: "z", domain: "shop.example",
      kind: "passkey", has_password: false },
    { id: "e7", primary: "Mail", title: "Mail", secondary: "w", domain: "mail.example",
      tags: ["\\uff57\\uff4f\\uff52\\uff4b"] }
]"""

TEST_QML = """import QtQuick
import QtQuick.Controls
import QtTest
import "categories.js" as Cat

Item {
    id: host
    width: 700; height: 600
    property var entries: %(fixture)s
    property var features: ({})
    property var catTag: null
    property var picked: []
    property int moved: 0
    property int tabs: 0
    property int copies: 0
    property int escapes: 0
    property int listTaps: 0
    property int wheels: 0
    property var baseEntries: %(fixture)s

    // What the window shows for a tag: its applyFilter with an empty query.
    function shown(tag) {
        return host.entries.filter(function (e) { return Cat.matches(e, tag); }).length;
    }

    Item {
        id: outer
        anchors.fill: parent
        Keys.onPressed: function (ev) { if (ev.key === Qt.Key_Escape) host.escapes++; }
        // The account list under the drop-down, taken by TapHandler and WheelHandler as in shell.qml.
        Item {
            id: under
            x: 0; y: 58; width: 700; height: 542
            TapHandler { onTapped: host.listTaps++ }
            WheelHandler { onWheel: host.wheels++ }
        }
        CategorySearch {
            id: search
            x: 14; y: 0; width: 300; height: 58
            focus: true
            entries: host.entries
            features: host.features
            tag: host.catTag
            onTagPicked: function (t) { host.picked = host.picked.concat([t]); host.catTag = t; }
            onMoveRequested: function (d) { host.moved += d; }
            onTabbed: host.tabs++
            onCopyRequested: host.copies++
        }
        TextField { id: other; x: 400; y: 500; width: 100; height: 30 }
    }

    TestCase {
        name: "CategoryTag"; when: windowShown

        function init() {
            host.features = ({}); host.catTag = null; host.picked = [];
            host.moved = 0; host.tabs = 0; host.copies = 0; host.escapes = 0;
            host.listTaps = 0; host.wheels = 0;
            host.entries = host.baseEntries;
            search.available = true;
            search.enabled = true;
            search.text = "";
            search.closeCats();
            mouseMove(host, 650, 580);
            wait(350);
            search.forceActiveFocus();
        }
        function rowIndex(kind, key) {
            for (var i = 0; i < search.catRows.length; i++)
                if (search.catRows[i].kind === kind && search.catRows[i].key === key) return i;
            return -1;
        }
        function rowY(i) {
            var y = 6;
            for (var j = 0; j < i; j++) y += search.catRows[j].kind === "divider" ? 11 : 34;
            return y + 17;
        }
        function clickRow(i) { mouseClick(search.panel, 40, rowY(i)); }
        function labels() {
            return search.catRows.map(function (r) { return r.kind === "divider" ? "-" : r.label; });
        }

        // ---- rows and counts
        function test_rows_and_counts() {
            compare(labels(), ["All", "Codes", "Wi-Fi", "-", "finance", "side-project", "work"]);
            var counts = search.catRows.filter(function (r) { return r.kind !== "divider"; })
                                       .map(function (r) { return r.count; });
            compare(counts, [6, 1, 1, 1, 1, 3]);
            for (var i = 0; i < search.catRows.length; i++) {
                var r = search.catRows[i];
                if (r.kind === "divider") continue;
                compare(r.count, shown(Cat.tagOf(r)), r.label);
            }
        }
        function test_flags_add_passkeys_and_deleted() {
            host.features = { passkeys: true, apple_deleted: true };
            compare(labels(), ["All", "Passkeys", "Codes", "Wi-Fi", "Deleted", "-", "finance",
                               "side-project", "work"]);
            compare(search.catRows[rowIndex("cat", "passkeys")].count, 2);
            compare(search.catRows[rowIndex("cat", "deleted")].count, 1);
            for (var i = 0; i < search.catRows.length; i++) {
                var r = search.catRows[i];
                if (r.kind !== "divider") compare(r.count, shown(Cat.tagOf(r)), r.label);
            }
            host.features = { passkeys: true };
            compare(rowIndex("cat", "deleted"), -1);
        }
        function test_a_category_with_none_is_still_listed() {
            var keep = host.entries;
            host.entries = keep.filter(function (e) { return !e.is_wifi; });
            compare(search.catRows[rowIndex("cat", "wifi")].count, 0);
            host.entries = keep;
        }
        function test_a_tag_nobody_has_is_dropped() {
            var t = { kind: "tag", key: "finance", label: "finance" };
            verify(Cat.stillValid(host.entries, host.features, t));
            var gone = host.entries.map(function (e) {
                return Object.assign({}, e, { tags: (e.tags || []).filter(function (x) { return x !== "finance"; }) });
            });
            verify(!Cat.stillValid(gone, host.features, t));
            verify(Cat.stillValid(gone, host.features, { kind: "cat", key: "wifi", label: "Wi-Fi" }));
            verify(!Cat.stillValid(gone, {}, { kind: "cat", key: "passkeys", label: "Passkeys" }));
        }

        // ---- hover
        function test_hover_opens_after_200ms() {
            mouseMove(search, 60, 20);
            wait(120);
            verify(!search.catOpen, "opened before 200 ms");
            wait(160);
            verify(search.catOpen, "not open after 280 ms");
            compare(search.catCursor, -1);
        }
        function test_a_pass_through_does_not_open() {
            mouseMove(search, 60, 20);
            wait(120);
            mouseMove(host, 650, 580);
            wait(300);
            verify(!search.catOpen);
        }
        function test_grace_across_field_and_list() {
            mouseMove(search, 60, 20);
            tryCompare(search, "catOpen", true, 1000);
            mouseMove(search.panel, 60, 30);          // field -> list
            wait(450);
            verify(search.catOpen, "closed while over the list");
            mouseMove(search, 80, 30);                // and back
            wait(450);
            verify(search.catOpen, "closed while over the field");
            mouseMove(host, 650, 580);                // away from both
            wait(150);
            verify(search.catOpen, "closed before the 300 ms grace");
            wait(250);
            verify(!search.catOpen, "still open after the grace");
        }
        function test_nothing_opens_without_entries_or_when_locked() {
            search.enabled = false;
            mouseMove(search, 60, 20);
            wait(300);
            verify(!search.catOpen);
            keyClick(Qt.Key_Down, Qt.AltModifier);
            verify(!search.catOpen);
            search.enabled = true;
            var keep = host.entries;
            host.entries = [];
            mouseMove(host, 650, 580);
            mouseMove(search, 70, 20);
            wait(300);
            verify(!search.catOpen);
            host.entries = keep;
        }

        // ---- keyboard
        function test_alt_down_and_routing() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            verify(search.catOpen);
            compare(search.catCursor, 0);             // All: no tag yet
            keyClick(Qt.Key_Down); keyClick(Qt.Key_Down);
            compare(search.catCursor, 2);             // Wi-Fi
            keyClick(Qt.Key_Down);
            compare(search.catCursor, 4);             // the divider is skipped
            keyClick(Qt.Key_Down); keyClick(Qt.Key_Down); keyClick(Qt.Key_Down);
            compare(search.catCursor, 6);             // clamped at the end, no wrap
            keyClick(Qt.Key_Up); keyClick(Qt.Key_Up); keyClick(Qt.Key_Up);
            compare(search.catCursor, 2);
            compare(host.moved, 0, "Up/Down reached the list while the drop-down was open");
            keyClick(Qt.Key_Return);
            verify(!search.catOpen);
            compare(host.catTag.kind, "cat");
            compare(host.catTag.key, "wifi");
            compare(host.copies, 0, "Enter copied a password");
            verify(search.activeFocus);
            // Opened again, the cursor starts on the tag that is set.
            keyClick(Qt.Key_Down, Qt.AltModifier);
            compare(search.catCursor, 2);
            keyClick(Qt.Key_Up); keyClick(Qt.Key_Space);
            compare(host.catTag.key, "codes");
            compare(search.text, "");
        }
        function test_esc_closes_and_stays_in_the_field() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            keyClick(Qt.Key_Escape);
            verify(!search.catOpen);
            compare(host.escapes, 0, "Esc reached the window");
            keyClick(Qt.Key_Escape);                   // closed: the window's again
            compare(host.escapes, 1);
        }
        function test_tab_closes_and_goes_to_the_panel() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            keyClick(Qt.Key_Tab);
            verify(!search.catOpen);
            compare(host.tabs, 1);
        }
        function test_closed_keys_keep_their_meanings() {
            keyClick(Qt.Key_Down); keyClick(Qt.Key_Down); keyClick(Qt.Key_Up);
            compare(host.moved, 1);
            keyClick(Qt.Key_Return);
            compare(host.copies, 1);
            keyClick(Qt.Key_Tab);
            compare(host.tabs, 1);
            verify(!search.catOpen);
        }
        function test_a_leading_hash_opens_and_filters() {
            keyClick("#");
            verify(search.catOpen);
            verify(search.catTyping);
            compare(search.text, "", "the # went into the query");
            keyClick("w");
            compare(labels(), ["Wi-Fi", "-", "work"]);
            keyClick("o");
            compare(labels(), ["work"]);
            compare(search.text, "");
            keyClick(Qt.Key_Return);
            compare(host.catTag.kind, "tag");
            compare(host.catTag.key, "work");
            verify(!search.catOpen);
            // Backspace on an empty filter closes; a '#' with a tag set is just text.
            host.catTag = null;
            keyClick("#");
            verify(search.catOpen);
            keyClick(Qt.Key_Backspace);
            verify(!search.catOpen);
            host.catTag = { kind: "cat", key: "wifi", label: "Wi-Fi" };
            keyClick("#");
            verify(!search.catOpen);
            compare(search.text, "#");
        }
        function test_a_resting_pointer_never_takes_a_typed_key() {
            mouseMove(search, 60, 20);
            tryCompare(search, "catOpen", true, 1000);
            mouseMove(search.panel, 40, rowY(1));
            compare(search.catCursor, 1);
            keyClick(Qt.Key_Space);
            compare(host.picked.length, 0);
            compare(search.text, " ");
            keyClick(Qt.Key_Return);
            compare(host.picked.length, 0);
            compare(host.copies, 1);
        }

        function test_a_leading_hash_works_while_hover_opened() {
            mouseMove(search, 60, 20);
            tryCompare(search, "catOpen", true, 1000);
            keyClick("#");
            verify(search.catTyping, "the # did not start the filter");
            compare(search.text, "", "the # went into the query");
            keyClick("w"); keyClick("o");
            compare(labels(), ["work"]);
            compare(search.text, "");
            keyClick(Qt.Key_Return);
            compare(host.catTag.key, "work");
            compare(host.copies, 0, "Enter copied a password");
        }
        function test_filter_keys_never_copy_or_type() {
            keyClick("#"); keyClick("z"); keyClick("z");
            compare(search.catRows.length, 0);
            keyClick(Qt.Key_Return);
            compare(host.copies, 0, "Enter with nothing matching copied a password");
            compare(host.picked.length, 0);
            keyClick(Qt.Key_Space);
            compare(search.text, "", "Space went into the query");
            keyClick(Qt.Key_Backspace); keyClick(Qt.Key_Backspace); keyClick(Qt.Key_Backspace);
            verify(!search.catOpen);
            keyClick("#"); keyClick("w");
            keyClick(Qt.Key_Space);                    // a match under the cursor: Space chooses
            compare(host.catTag.key, "wifi");
            compare(search.text, "");
            compare(host.copies, 0);
        }
        function test_the_panel_takes_its_own_presses_and_wheel() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            mouseClick(search.panel, 3, search.panel.height - 3);   // the margin
            mouseClick(search.panel, 40, rowY(3) - 12);             // the divider (11 px)
            compare(host.listTaps, 0, "a press on the drop-down reached the list under it");
            verify(search.catOpen);
            mouseWheel(search.panel, 40, rowY(1), 0, -120);
            compare(host.wheels, 0, "the wheel reached the list under the drop-down");
            clickRow(rowIndex("cat", "codes"));                     // a row: chosen, and only that
            compare(host.catTag.key, "codes");
            compare(host.listTaps, 0, "a click on a row also tapped the list under it");
            host.catTag = null;
            keyClick("#");                                          // the filter line
            mouseClick(search.panel, 40, 12);
            compare(host.listTaps, 0, "a press on the filter line reached the list");
            keyClick(Qt.Key_Escape);
            mouseClick(under, 300, 400);                            // closed: the list's again
            compare(host.listTaps, 1);
        }
        function test_nothing_opens_behind_a_sheet() {
            search.available = false;
            mouseMove(search, 60, 20);
            wait(300);
            verify(!search.catOpen, "hover opened it behind a sheet");
            keyClick(Qt.Key_Down, Qt.AltModifier);
            verify(!search.catOpen, "Alt+Down opened it behind a sheet");
            keyClick("#");
            verify(!search.catOpen, "# opened it behind a sheet");
            search.text = "";
            search.available = true;
            keyClick(Qt.Key_Down, Qt.AltModifier);
            verify(search.catOpen);
            search.available = false;                               // a sheet opening closes it
            verify(!search.catOpen);
        }
        function test_many_tags_scroll_inside_the_window() {
            var many = [];
            for (var i = 0; i < 30; i++)
                many.push({ id: "m" + i, primary: "A" + i, title: "A" + i, secondary: "", domain: "",
                            tags: ["t" + (i < 10 ? "0" : "") + i] });
            host.entries = many;
            keyClick(Qt.Key_Down, Qt.AltModifier);
            tryCompare(search.panel, "height", search.rowsView.height + 12);   // the Column's layout
            var bottom = search.panel.mapToItem(null, 0, search.panel.height).y;
            verify(bottom <= host.height, "the drop-down runs off the window: " + bottom);
            var last = search.catRows.length - 1;
            for (var k = 0; k < 40; k++) keyClick(Qt.Key_Down);
            compare(search.catCursor, last);
            var row = search.rowsView.itemAtIndex(last);
            verify(row !== null, "the last row was never scrolled into view");
            var p = row.mapToItem(search.panel, 40, row.height / 2);
            verify(p.y > 0 && p.y < search.panel.height - 6, "the last row is not visible: " + p.y);
            mouseClick(search.panel, p.x, p.y);
            compare(host.catTag.key, "t29");
        }
        function test_typing_closes_a_hover_opened_list() {
            mouseMove(search, 60, 20);
            tryCompare(search, "catOpen", true, 1000);
            keyClick("g");
            verify(!search.catOpen, "the hover list stayed over the results");
            compare(search.text, "g");
            keyClick(Qt.Key_Down);
            compare(host.moved, 1, "Down went to the drop-down, not the list");
            keyClick(Qt.Key_Return);
            compare(host.copies, 1);
            compare(host.picked.length, 0);
            // Opened from the keyboard it stays while the query changes.
            keyClick(Qt.Key_Down, Qt.AltModifier);
            search.text = "gi";
            verify(search.catOpen);
        }

        // ---- choosing
        function test_choosing_replaces_and_all_clears() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            clickRow(rowIndex("cat", "wifi"));
            compare(host.catTag.key, "wifi");
            verify(!search.catOpen);
            keyClick(Qt.Key_Down, Qt.AltModifier);
            clickRow(rowIndex("tag", "work"));
            compare(host.catTag.kind, "tag");          // replaced, not added
            compare(host.catTag.key, "work");
            compare(host.picked.length, 2);
            keyClick(Qt.Key_Down, Qt.AltModifier);
            clickRow(rowIndex("tag", "work"));         // the active row: nothing changes
            compare(host.picked.length, 2);
            verify(!search.catOpen);
            keyClick(Qt.Key_Down, Qt.AltModifier);
            clickRow(rowIndex("all", ""));
            compare(host.catTag, null);
            compare(host.picked.length, 3);
            verify(search.activeFocus);
        }
        function test_choosing_keeps_the_caret() {
            search.text = "abc"; search.cursorPosition = 1;
            keyClick(Qt.Key_Down, Qt.AltModifier);
            clickRow(rowIndex("cat", "codes"));
            compare(host.catTag.key, "codes");
            compare(search.cursorPosition, 1, "the click reached the text field");
            compare(search.text, "abc");
            keyClick(Qt.Key_Down, Qt.AltModifier);
            mouseClick(search.panel, 3, search.panel.height - 3);   // the panel's own margin
            verify(search.catOpen, "a press on the list itself closed it");
            compare(search.cursorPosition, 1, "the click reached the text field");
        }
        function test_a_press_outside_closes_and_goes_through() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            mouseClick(other, 10, 10);
            verify(!search.catOpen);
            verify(other.activeFocus, "the press did not reach what was under it");
        }
        function test_focus_leaving_closes() {
            keyClick(Qt.Key_Down, Qt.AltModifier);
            other.forceActiveFocus();
            verify(!search.catOpen);
        }

        // ---- the chip
        function test_chip_sits_before_the_query() {
            compare(search.leftPadding, search.padding);
            verify(!search.chipItem.visible);
            host.catTag = { kind: "tag", key: "work", label: "work" };
            verify(search.chipItem.visible);
            compare(search.leftPadding, search.padding + search.chipItem.width + 8);
            search.text = "git";
            search.cursorPosition = 0;
            verify(search.cursorRectangle.x >= search.chipItem.x + search.chipItem.width,
                   "the caret starts under the chip: " + search.cursorRectangle.x + " < "
                   + (search.chipItem.x + search.chipItem.width));
            compare(search.text, "git");               // the chip is never text
            compare(Cat.chipText(host.catTag), "#work");
            compare(Cat.chipText({ kind: "cat", key: "wifi", label: "Wi-Fi" }), "Wi-Fi");
            host.catTag = null;
            compare(search.leftPadding, search.padding);
        }
        function test_mini_x_clears_and_keeps_the_query() {
            host.catTag = { kind: "cat", key: "codes", label: "Codes" };
            search.text = "git";
            mouseClick(search.chipClearItem);
            compare(host.catTag, null);
            compare(search.text, "git");
        }
        function test_backspace_rule() {
            host.catTag = { kind: "cat", key: "codes", label: "Codes" };
            keyClick(Qt.Key_Backspace);                // empty query: the tag goes
            compare(host.catTag, null);
            host.catTag = { kind: "cat", key: "codes", label: "Codes" };
            search.text = "ab"; search.cursorPosition = 2;
            keyClick(Qt.Key_Backspace);                // a character to delete: it goes
            compare(search.text, "a");
            verify(host.catTag !== null);
            search.text = "ab"; search.cursorPosition = 0;
            keyClick(Qt.Key_Backspace);                // caret at 0: the tag goes, query kept
            compare(host.catTag, null);
            compare(search.text, "ab");
            host.catTag = { kind: "cat", key: "codes", label: "Codes" };
            search.select(0, 1);
            keyClick(Qt.Key_Backspace);                // a selection: default Backspace
            compare(search.text, "b");
            verify(host.catTag !== null);
            search.text = "ab";
            search.select(1, 0);                       // a selection with the caret at 0
            compare(search.cursorPosition, 0);
            keyClick(Qt.Key_Backspace);                // still the selection that goes
            compare(search.text, "b");
            verify(host.catTag !== null);
        }

        // ---- the tags grammar the window's editor uses
        function test_canon_and_fold() {
            compare(Cat.canonTag("#Work"), "work");
            compare(Cat.canonTag("cafe\\u0301"), "caf\\u00e9");
            compare(Cat.canonTag("a b"), "");
            compare(Cat.canonTag("a,b"), "");
            compare(Cat.canonTag("a:b"), "");
            compare(Cat.canonTag("##a"), "");
            compare(Cat.canonTag("x".repeat(32)), "x".repeat(32));
            compare(Cat.canonTag("x".repeat(33)), "");
            // Code points, as the daemon counts them: 20 Deseret letters are 40 UTF-16 units.
            compare(Cat.canonTag("\\ud801\\udc28".repeat(20)), "\\ud801\\udc28".repeat(20));
            compare(Cat.canonTag("\\ud801\\udc28".repeat(32)).length, 64);
            compare(Cat.canonTag("\\ud801\\udc28".repeat(33)), "");
            compare(Cat.fold("Stra\\u00dfe"), Cat.fold("STRASSE"));
            compare(Cat.fold("\\uff57\\uff4f\\uff52\\uff4b"), "work");
        }
    }
}
"""


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class RuntimeTests(unittest.TestCase):
    def test_the_real_search_field(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(SEARCH_QML, d)
            shutil.copy(CATS_JS, d)
            shutil.copy(os.path.join(qmlscan.APP, "AppScrollBar.qml"), d)
            with open(os.path.join(d, "Theme.qml"), "w") as f:
                f.write(THEME)
            with open(os.path.join(d, "qmldir"), "w") as f:
                f.write("singleton Theme 1.0 Theme.qml\nCategorySearch 1.0 CategorySearch.qml\n"
                        "AppScrollBar 1.0 AppScrollBar.qml\n")
            path = os.path.join(d, "tst_categorytag.qml")
            with open(path, "w") as f:
                f.write(TEST_QML.replace("%(fixture)s", FIXTURE))
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d, "QT_QUICK_CONTROLS_STYLE": "Basic"}
            r = subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True, text=True,
                               timeout=180, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        passed = re.findall(r"^PASS   : qmltestrunner::CategoryTag::(test_\w+)\(\)", r.stdout, re.M)
        self.assertEqual(len(passed), TEST_QML.count("        function test_"), r.stdout)


    def test_fold_is_the_daemons(self):
        """categories.js's fold is tagline.fold (NFKC, then str.casefold) for every code point
        that has a case mapping, and for strings where a whole-string lower case would differ
        (final sigma) - so the drop-down groups tags exactly as the daemon de-duplicates them."""
        import json
        import unicodedata
        from icp.keychain import tagline
        cps = [c for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF
               and unicodedata.category(chr(c)) != "Cn"
               and (chr(c).casefold() != chr(c) or chr(c).upper() != chr(c)
                    or chr(c).lower() != chr(c))]
        words = ["ΟΔΟΣ", "ὈΔΥΣΣΕΎΣ", "Straße", "ẞIG", "ＷＯＲＫ", "ǅemal", "İstanbul", "ıi",
                 "ᏣᎳᎩ", "ꮳꮃꭹ", "ﬁle", "café", "cafe\u0301", "Ⅻ", "①", "ﬀ"]
        samples = [chr(c) for c in cps] + words
        data = json.dumps([[t, tagline.fold(t)] for t in samples])
        qml = ('import QtQuick\nimport QtTest\nimport "categories.js" as Cat\n'
               'TestCase { name: "Fold"\n'
               '    function test_fold() {\n'
               '        const d = ' + data + ';\n'
               '        const bad = [];\n'
               '        for (let i = 0; i < d.length; i++) if (Cat.fold(d[i][0]) !== d[i][1]) bad.push(d[i][0]);\n'
               '        compare(bad.length, 0, "fold differs for " + JSON.stringify(bad.slice(0, 20)));\n'
               '        verify(d.length > 2900);\n'
               '    }\n}\n')
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(CATS_JS, d)
            path = os.path.join(d, "tst_fold.qml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(qml)
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d}
            r = subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True, text=True,
                               timeout=180, env=env)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("PASS   : qmltestrunner::Fold::test_fold()", r.stdout)



def function_text(name: str) -> str:
    m = re.search(rf"\bfunction {re.escape(name)}\s*\([^)]*\)\s*\{{", CODE)
    return m.group(0)[:-1] + qmlscan.element_body(CODE, m.end() - 1)


EDITOR_QML = """import QtQuick
import QtTest
import "categories.js" as Cat

Item {
    id: root
    width: 500; height: 200
    property bool tagEditing: true
    property var tagDraft: []
    property bool tagBusy: false
    property string tagError: ""
    property var saved: []
    function setFields(fields, extra, done) { root.saved = root.saved.concat([fields]); done({}); }
    function errorWords(d) { return d.error; }
    function showFlash(t) {}
    %(functions)s
    Flow {
        id: tagFlow
        width: 480
        %(input)s
    }
    TestCase {
        name: "TagEditor"; when: windowShown
        function type(s) { for (var i = 0; i < s.length; i++) keyClick(s[i]); }
        function test_editor() {
            tagInput.forceActiveFocus();
            type("Work"); keyClick(Qt.Key_Space);
            compare(root.tagDraft, ["work"]);
            compare(tagInput.text, "");
            type("#Finance"); keyClick(Qt.Key_Comma);
            compare(root.tagDraft, ["work", "finance"]);
            type("WORK"); keyClick(Qt.Key_Return);              // the same fold key: no second
            compare(root.tagDraft, ["work", "finance"]);
            type("a!b:c");                                       // not the grammar's characters
            compare(tagInput.text, "abc");
            keyClick(Qt.Key_Return);
            compare(root.tagDraft, ["work", "finance", "abc"]);
            type("x".repeat(40));
            compare(tagInput.text.length, 32);
            tagInput.text = "";
            keyClick(Qt.Key_Backspace);                          // empty: the last chip goes
            compare(root.tagDraft, ["work", "finance"]);
            root.tagDraft = Array.apply(null, Array(16)).map(function (_, i) { return "t" + i; });
            type("z"); keyClick(Qt.Key_Return);
            compare(root.tagDraft.length, 16);
            compare(root.tagError, "at most 16 tags");
            tagInput.text = "";
            root.tagDraft = ["work"];
            keyClick(Qt.Key_Return);                             // empty field: Enter saves
            compare(root.saved, [{ tags: ["work"] }]);
            compare(root.tagEditing, false);
            root.tagEditing = true;
            tagInput.forceActiveFocus();
            tagInput.text = "café";                               // (keyClick is ASCII only)
            root.saveTags();                                     // Save commits what is typed
            compare(root.saved[1], { tags: ["café"] });
            root.tagEditing = true;
            tagInput.forceActiveFocus();
            keyClick(Qt.Key_Escape);
            compare(root.tagEditing, false);
        }
        function test_create_form_tags_problem() {
            compare(root.tagsProblem(""), "");
            compare(root.tagsProblem("work #family, side-project"), "");
            var bad = "a tag is 1 to 32 letters, digits, - or _";
            compare(root.tagsProblem("x".repeat(33)), bad);
            compare(root.tagsProblem("a#b"), bad);
            compare(root.tagsProblem("##x"), bad);
            var many = [];
            for (var i = 0; i < 17; i++) many.push("t" + i);
            compare(root.tagsProblem(many.join(" ")), "at most 16 tags");
            compare(root.tagsProblem("\\ud801\\udc28".repeat(20)), "");   // 20 code points
            compare(root.parseTags("\\ud801\\udc28".repeat(20)), ["\\ud801\\udc28".repeat(20)]);
        }
    }
}
"""


ROWS_QML = """import QtQuick
import QtTest

Item {
    id: root
    property var selected: null
    property string selectedId: "e.1"
    property string revealed: ""
    property bool notesLoaded: false
    property string notesText: ""
    property string totpCode: ""
    property bool tagEditing: false
    property var calls: []
    function note(what) { root.calls = root.calls.concat([what]); }
    function withGrant(fn) { root.note("grant"); }
    function loadNotes(then) { root.note(then ? "load+edit" : "load"); }
    function openEditor(mode) { root.note("editor " + mode); }
    function copyField(f) { root.note("copy " + f); }
    function copyPassword() { root.note("copy password"); }
    function doReveal() { root.note("reveal"); }
    function loadTotp() { root.note("totp"); }
    function openDomain(d) { root.note("open " + d); }
    %(functions)s
    TestCase {
        name: "Rows"
        function keys(rows) { return rows.map(function (r) { return r.key; }); }
        function tagsRow(rows) { return rows.filter(function (r) { return r.label === "Tags"; })[0]; }
        function test_read_only_rows_never_open_an_editor() {
            const ro = [{ recently_deleted: true, kind: "login", has_notes: true, tags: ["a"] },
                        { recently_deleted: false, kind: "passkey", has_notes: true, has_password: false }];
            for (let i = 0; i < ro.length; i++) {
                root.selected = Object.assign({ username: "me", domain: "x.example", sites: [] }, ro[i]);
                verify(root.selectedReadOnly());
                root.notesLoaded = true; root.notesText = "body";
                root.calls = [];
                root.fieldAction("notes");                 // the second "show notes"
                for (const k of ["editnotes", "edittags", "editsites", "edittotp", "change"])
                    root.fieldAction(k);
                compare(root.calls, ["load"], JSON.stringify(ro[i]));
            }
            root.selected = { username: "me", domain: "x.example", sites: [], has_notes: true, kind: "login" };
            verify(!root.selectedReadOnly());
            root.calls = [];
            root.fieldAction("notes");
            compare(root.calls, ["load+edit"]);
        }
        function test_wifi_tags_show_without_an_edit() {
            root.notesLoaded = false;
            root.selected = { is_wifi: true, username: "Home", domain: "AirPort", kind: "login",
                              tags: ["home", "family"] };
            const t = tagsRow(root.fieldRows());
            verify(t !== undefined, "no Tags row for Wi-Fi");
            compare(t.chips, ["home", "family"]);
            compare(t.actions, []);
            compare(t.key, "tags");
            root.selected = { is_wifi: true, username: "Home", domain: "AirPort", kind: "login", tags: [] };
            compare(tagsRow(root.fieldRows()), undefined);
            compare(keys(root.fieldRows()), ["username", "password"]);
        }
    }
}
"""


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class FieldRowsRuntimeTests(unittest.TestCase):
    """fieldRows, withoutEdits, selectedReadOnly and fieldAction from shell.qml, under Qt."""

    def test_rows_and_actions(self):
        funcs = "\n    ".join(function_text(n) for n in
                              ("fieldRows", "withoutEdits", "allSites", "selectedReadOnly",
                               "fieldAction"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tst_rows.qml")
            with open(path, "w") as f:
                f.write(ROWS_QML % {"functions": funcs})
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d}
            r = subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True, text=True,
                               timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for t in ("test_read_only_rows_never_open_an_editor", "test_wifi_tags_show_without_an_edit"):
            self.assertIn(f"PASS   : qmltestrunner::Rows::{t}()", r.stdout)


@unittest.skipUnless(QMLTESTRUNNER, "qmltestrunner (qt6-declarative) not installed")
class TagEditorRuntimeTests(unittest.TestCase):
    """The tag field and its functions from shell.qml, run under Qt."""

    def test_the_tag_field(self):
        funcs = "\n    ".join(function_text(n) for n in
                              ("commitTagInput", "removeDraftTag", "saveTags", "closeTagEditor",
                               "parseTags", "tagsProblem"))
        m = re.search(r"\bid: tagInput\n", CODE)
        start = CODE.rfind("{", 0, m.start())
        field = "TextInput " + qmlscan.element_body(CODE, start)
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(CATS_JS, d)
            with open(os.path.join(d, "Theme.qml"), "w") as f:
                f.write(THEME)
            with open(os.path.join(d, "qmldir"), "w") as f:
                f.write("singleton Theme 1.0 Theme.qml\n")
            path = os.path.join(d, "tst_tageditor.qml")
            with open(path, "w") as f:
                f.write(EDITOR_QML % {"functions": funcs, "input": field})
            env = {"PATH": "/usr/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": d,
                   "XDG_RUNTIME_DIR": d, "QT_QUICK_CONTROLS_STYLE": "Basic"}
            r = subprocess.run([QMLTESTRUNNER, "-input", path], capture_output=True, text=True,
                               timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS   : qmltestrunner::TagEditor::test_editor()", r.stdout)
        self.assertIn("PASS   : qmltestrunner::TagEditor::test_create_form_tags_problem()", r.stdout)


if __name__ == "__main__":
    unittest.main()
