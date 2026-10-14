"""The real window against the real daemon: app/shell.qml under quickshell (offscreen) talks over
a unix socket to the real Server, Registry and handlers, with only polkit (FakeAuthority, which
approves), the store (FakeStore) and iCloud (a FakeApple that keeps the notes' tag line the way
apple.push_set does) standing in. pear-exec is a stand-in too: its `clip` role connects back as
pear-clip does, redeems the ticket and reports a paste.

One scripted session, driven inside the window with QtTest's event helpers: unlock, hover the
search field, choose Codes, the chip, Backspace, choose a tag and narrow it with a query, edit
an entry's tags under its grant, Copy a selection in the notes editor (copy-text, a clip ticket,
a paste), turn Recently Deleted on and run the keychain check from Settings, create an entry
with tags, and lock. Every op name, field and reply shape the window relies on is then the
daemon's own, and the test checks what reached the daemon and which dialogs were raised.
"""

import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace

import qmlscan
from daemon_fakes import FakeApple, FakeAuthority, Harness, meta, secrets

from icp.daemon import paths
from icp.keychain import tagline

QUICKSHELL = "/usr/bin/quickshell"
OMARCHY_SHELL = "/usr/share/omarchy/shell"
RUNNABLE = (os.access(QUICKSHELL, os.X_OK) and os.path.isdir(os.path.join(OMARCHY_SHELL, "Ui"))
            and os.path.isdir(os.path.join(OMARCHY_SHELL, "Commons")))

NOTES_BODY = "recovery codes are in the safe"
GH, SL, BK, WF, RD = "e.gh", "e.sl", "e.bk", "e.wf", "e.rd"


class WindowApple(FakeApple):
    """FakeApple, plus what apple.push_set does to the notes: `notes` is the body (the tag line
    stays), `tags` replaces only that line; meta follows, as the sync after a push would."""

    def __init__(self):
        super().__init__()
        self.created = None
        self.shape = {("keys", "com.apple.webkit.webauthn"):
                      {"count": 2, "keys": {"agrp", "class", "labl"}, "inner_keys": set()}}

    def push_set(self, ctx, id, fields):
        super().push_set(ctx, id, fields)
        st = ctx.store
        raw = st.secrets[id].notes
        if "notes" in fields:
            raw = tagline.replace_body(raw, fields["notes"])
        if "tags" in fields:
            raw = tagline.replace_tags(raw, tagline.canon_list(fields["tags"]))
        body, tags = tagline.split(raw)
        st.secrets[id] = replace(st.secrets[id], notes=raw)
        st.metas[id] = replace(st.metas[id], tags=tags, has_notes=bool(body.strip()))

    def create(self, ctx, fields):
        self.created = dict(fields)
        return super().create(ctx, fields)


FAKE_PEAR_EXEC = r'''#!%(python)s
# pear-exec, for the test: `clip` reads its ticket, redeems it as pear-clip would, says
# {"event":"offered"} on stdout a little later and reports one paste. What it got goes to a file
# the test reads (made-up data only). The third run fails the way pear-exec refused the clip
# role on the VM (exit 77, a reason on stderr, nothing on stdout); the fourth reports an error
# line as pear-clip does when the compositor has no data-control protocol.
import json, os, socket, sys, time
if sys.argv[1:] != ["clip"]:
    sys.exit(64)
n = 1
if os.path.exists(%(count)r):
    n = int(open(%(count)r).read()) + 1
open(%(count)r, "w").write(str(n))
ticket = sys.stdin.readline().strip()
if n == 3:
    sys.stderr.write("pear-exec: WAYLAND_DISPLAY must be a socket name like wayland-1\n")
    sys.exit(77)
if n == 4:
    print(json.dumps({"event": "error", "reason": "the compositor offers no data-control protocol"}),
          flush=True)
    print(json.dumps({"event": "done", "outcome": "failed"}), flush=True)
    sys.exit(0)
s = socket.socket(socket.AF_UNIX)
s.connect(%(sock)r)
f = s.makefile("rwb")
def call(**req):
    f.write(json.dumps(req).encode() + b"\n"); f.flush()
    return json.loads(f.readline())
out = {"hello": call(op="hello", rid=0, role="clip", proto=2, ticket=ticket)}
out["redeem"] = call(op="redeem", rid=1)
time.sleep(0.8)                      # the window must not say "copied" before this
print(json.dumps({"event": "offered"}), flush=True)
time.sleep(0.4)
out["result"] = call(op="clip-result", rid=2, outcome="pasted")
print(json.dumps({"event": "done", "outcome": "pasted"}), flush=True)
with open(%(out)r, "a") as log:
    log.write(json.dumps(out) + "\n")
'''

# Runs inside ShellRoot, so it sees the window's ids (root, search, tagInput, edArea, ...).
DRIVER = r'''
    TestCase { id: flowTc; name: "Flow"; when: false }
    Timer {
        interval: 100; running: true
        onTriggered: {
            let step = "start";
            const tc = flowTc;
            const check = function (ok, what) { if (!ok) throw new Error(what); };
            const waitFor = function (fn, ms, what) {
                const t0 = Date.now();
                while (!fn()) {
                    if (Date.now() - t0 > ms) throw new Error("timed out: " + what);
                    tc.wait(20);
                }
            };
            const rowIndex = function (kind, key) {
                for (let i = 0; i < search.catRows.length; i++)
                    if (search.catRows[i].kind === kind && search.catRows[i].key === key) return i;
                return -1;
            };
            const clickRow = function (i) {
                check(i >= 0, "no such row");
                let y = 6;
                for (let j = 0; j < i; j++) y += search.catRows[j].kind === "divider" ? 11 : 34;
                tc.mouseClick(search.panel, 40, y + 17);
            };
            const entry = function (id) {
                for (const e of root.entries) if (e.id === id) return e;
                return null;
            };
            const say = function (s) { console.info("FLOW-STEP " + s); };
            try {
                step = "hello";
                waitFor(function () { return root.phase === "ready" && root.vaultState === "locked"; },
                        15000, "hello");
                step = "unlock";
                root.authenticate();
                waitFor(function () { return root.appUnlocked && !root.syncing; }, 15000, "unlock and sync");
                check(root.entries.length === 4, "entries " + root.entries.length);
                check(JSON.stringify(entry("e.sl").tags) === '["work","finance"]', "wire tags");
                check(!root.features.passkeys && !root.features.apple_deleted, "flags start off");
                say(step);

                step = "hover";
                tc.mouseMove(search, 60, 20);
                tc.wait(120);
                check(!search.catOpen, "open before 200 ms");
                waitFor(function () { return search.catOpen; }, 1000, "hover opens the drop-down");
                check(JSON.stringify(search.catRows.map(function (r) { return r.kind === "divider" ? "-" : r.label + " " + r.count; }))
                      === '["All 4","Codes 1","Wi-Fi 1","-","finance 1","work 2"]',
                      "rows " + JSON.stringify(search.catRows));
                say(step);

                step = "choose Codes";
                clickRow(rowIndex("cat", "codes"));
                check(!search.catOpen, "still open");
                check(root.catTag && root.catTag.kind === "cat" && root.catTag.key === "codes", "tag");
                check(root.filtered.length === 1 && root.filtered[0].id === "e.gh", "filtered");
                check(search.chipItem.visible, "chip hidden");
                check(search.leftPadding >= search.chipItem.width, "query starts under the chip");
                check(search.placeholderText === "Search 1 Codes", search.placeholderText);
                say(step);

                step = "Backspace";
                search.forceActiveFocus();
                tc.keyClick(Qt.Key_Backspace);
                check(root.catTag === null, "Backspace left the tag");
                check(!search.chipItem.visible, "chip still shown");
                check(root.filtered.length === 4, "filtered " + root.filtered.length);
                say(step);

                step = "choose a tag";
                tc.keyClick(Qt.Key_Down, Qt.AltModifier);
                check(search.catOpen, "Alt+Down");
                clickRow(rowIndex("tag", "work"));
                check(root.catTag && root.catTag.kind === "tag" && root.catTag.key === "work", "tag work");
                check(root.filtered.length === 2, "work rows " + root.filtered.length);
                search.forceActiveFocus();
                for (const ch of "slackx") tc.keyClick(ch);
                tc.keyClick(Qt.Key_Backspace);            // mid-query: a character, not the chip
                check(search.text === "slack" && root.catTag && root.catTag.key === "work",
                      "Backspace in the query: " + search.text + " / " + JSON.stringify(root.catTag));
                check(root.filtered.length === 1 && root.filtered[0].id === "e.sl", "the query narrows the tag");
                search.text = "";
                say(step);

                step = "edit tags";
                root.select(entry("e.gh"));
                root.fieldAction("edittags");
                waitFor(function () { return root.tagEditing; }, 10000, "the tag editor behind the grant");
                check(root.grantId === "e.gh", "grant " + root.grantId);
                tc.wait(50);
                check(tagInput.activeFocus, "tag field focus");
                for (const ch of "travel") tc.keyClick(ch);
                tc.keyClick(Qt.Key_Return);
                check(JSON.stringify(root.tagDraft) === '["work","travel"]', "draft " + JSON.stringify(root.tagDraft));
                tc.keyClick(Qt.Key_Return);
                waitFor(function () { const e = entry("e.gh"); return !root.tagEditing && !root.tagBusy && e
                                      && JSON.stringify(e.tags) === '["work","travel"]'; }, 10000, "tags saved and listed");
                check(root.tagError === "", root.tagError);
                say(step);

                step = "copy-text";
                root.fieldAction("editnotes");
                waitFor(function () { return root.editorOpen && root.editorMode === "notes"; }, 10000, "notes editor");
                check(edArea.text === "recovery codes are in the safe", "the editor got the body only: " + JSON.stringify(edArea.text));
                edArea.forceActiveFocus();
                edArea.select(0, 8);
                root.flash = "";
                tc.keyClick("c", Qt.ControlModifier);
                // "copied" only once pear-clip says the clipboard has it.
                tc.wait(400);
                check(root.flash.indexOf("copied") === -1, "copied before offered: " + root.flash);
                check(!clipCountdown.visible, "a countdown before offered");
                waitFor(function () { return root.flash === "Selection copied — clears after one paste or 30 s"; },
                        10000, "the copied toast after offered (flash: " + root.flash + ")");
                // The toast holds the status bar's slot; once it goes, the countdown of the
                // live offer takes it until pear-clip's "done".
                check(!clipCountdown.visible, "the countdown over the copied toast");
                root.flash = "";
                check(clipCountdown.visible && /^Selection on clipboard · (30|29|28) s$/.test(clipCountdown.text),
                      "no countdown while offered: " + clipCountdown.visible + " " + clipCountdown.text);
                waitFor(function () { return root.flash.indexOf("Selection pasted") === 0; }, 10000,
                        "the clip event for the selection (flash: " + root.flash + ")");
                waitFor(function () { return !clipCountdown.visible; }, 3000, "the countdown after done");
                // The context menu's Copy takes the same way.
                root.flash = "";
                edArea.select(9, 14);
                tc.mouseClick(edArea, 30, 12, Qt.RightButton);
                waitFor(function () { return secretMenu.opened; }, 3000, "the context menu");
                check(secretMenu.source === "notes-edit" && secretMenu.target === edArea, "menu aimed elsewhere");
                const copyItem = secretMenu.itemAt(0);
                check(copyItem.text === "Copy" && copyItem.enabled, "no enabled Copy");
                check(secretMenu.count === 3 && secretMenu.itemAt(1).text === "Paste"
                      && secretMenu.itemAt(2).text === "Select All", "menu items");
                tc.mouseClick(copyItem);
                waitFor(function () { return root.flash.indexOf("Selection pasted") === 0; }, 10000,
                        "the clip event for the menu's Copy (flash: " + root.flash + ")");
                // Neither reached Qt's own clipboard (only pear-clip ever holds the text).
                const probe = Qt.createQmlObject("import QtQuick; TextInput {}", root);
                probe.paste();
                check(probe.text === "", "the window's clipboard holds " + JSON.stringify(probe.text));
                probe.text = "control"; probe.selectAll(); probe.copy(); probe.text = "";
                probe.paste();
                check(probe.text === "control", "the probe cannot see the clipboard");
                probe.destroy();
                say(step);

                step = "copy fails";
                // pear-exec refuses the clip role: it exits before "offered".
                root.flash = "";
                root.copyText("notes-edit", "recovery");
                waitFor(function () { return root.flash !== ""; }, 10000, "a toast for the refused copy");
                check(root.flash === "Couldn't copy — WAYLAND_DISPLAY must be a socket name like wayland-1",
                      "early exit: " + root.flash);
                // pear-clip reports an error line instead of "offered".
                root.flash = "";
                root.copyText("notes-edit", "codes");
                waitFor(function () { return root.flash !== ""; }, 10000, "a toast for the failed copy");
                check(root.flash === "Couldn't copy — the compositor offers no data-control protocol",
                      "error line: " + root.flash);
                tc.wait(300);
                check(root.flash.indexOf("copied") === -1, "copied after a failure: " + root.flash);
                root.closeEditor();
                say(step);

                step = "features";
                root.settingsOpen = true;
                tc.wait(100);
                root.setFeature("apple_deleted", true);
                waitFor(function () { return root.features.apple_deleted && root.entries.length === 5; }, 10000,
                        "Recently Deleted on and listed");
                check(rowIndex("cat", "deleted") >= 0, "Deleted row");
                check(search.catRows[rowIndex("cat", "deleted")].count === 1, "Deleted count");
                check(search.catRows[0].count === 4, "All leaves the deleted copy out");
                root.runDiag();
                waitFor(function () { return !root.diagBusy && root.diagText !== ""; }, 10000, "diag-items");
                check(root.diagText.indexOf("2 × keys  com.apple.webkit.webauthn") === 0, root.diagText);
                root.settingsOpen = false;
                say(step);

                step = "create";
                root.openEditor("create");
                root.createMore = true;
                crName.text = "New Site"; crSite.text = "new.example"; crUser.text = "kim";
                crPass.text = "made-up-pw"; crTags.text = "Work, #travel";
                check(root.editorReady(), "create not ready");
                root.editorSave();
                waitFor(function () { return !root.editorOpen; }, 10000, "create (" + root.editorError + ")");
                // The tags field takes the grammar's characters only, and Add waits for valid tags.
                root.openEditor("create");
                root.createMore = true;
                crName.text = "x"; crPass.text = "made-up-pw";
                tc.wait(50);                                  // openEditor focuses the name later
                crTags.forceActiveFocus();
                for (const ch of "ab!:c") tc.keyClick(ch);
                check(crTags.text === "abc", "typed " + crTags.text);
                crTags.text = "a!b";
                check(!root.editorReady(), "Add with a tag the daemon would refuse");
                crTags.text = Array.apply(null, Array(17)).map(function (_, i) { return "t" + i; }).join(" ");
                check(!root.editorReady(), "Add with 17 tags");
                root.closeEditor();
                say(step);

                step = "lock";
                root.setCatTag({ kind: "cat", key: "deleted", label: "Deleted" });
                root.lockNow();
                waitFor(function () { return !root.appUnlocked; }, 10000, "lock");
                check(root.catTag === null && !root.features.apple_deleted && root.diagText === "", "lock leftovers");
                say(step);
                console.info("FLOW-DONE");
            } catch (e) {
                console.info("FLOW-FAIL at " + step + ": " + e.message);
            }
            Qt.quit();
        }
    }
'''


def window_copy(d, sock, pear_exec):
    """The app directory with the socket and pear-exec paths pointed at the test's, and the
    driver added to the ShellRoot."""
    app = os.path.join(d, "app")
    shutil.copytree(qmlscan.APP, app)
    os.symlink(os.path.join(OMARCHY_SHELL, "Ui"), os.path.join(app, "Ui"))
    os.symlink(os.path.join(OMARCHY_SHELL, "Commons"), os.path.join(app, "Commons"))
    path = os.path.join(app, "shell.qml")
    src = qmlscan.read(path)
    for prop, value in (("socketPath", sock), ("pearExec", pear_exec)):
        src, n = re.subn(rf'(readonly property string {prop}: )"[^"]*"', rf'\g<1>"{value}"', src)
        assert n == 1, prop
    src = src.replace("import Quickshell\n", "import Quickshell\nimport QtTest\n", 1)
    end = src.rstrip().rfind("}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src[:end] + DRIVER + "}\n")
    return app


def seed(h):
    st = h.store()
    st.exists = True
    st.keys = False
    st.session = {"dsid": "fake"}
    rows = [
        (GH, meta(GH, title="GitHub", domain="github.com", username="me", has_totp=True,
                  has_notes=True, tags=["work"]),
         secrets(notes=NOTES_BODY + "\n\nTags: #work", seed=b"12345678901234567890")),
        (SL, meta(SL, title="Slack", domain="slack.com", username="me", tags=["work", "finance"]),
         secrets(notes="Tags: #work #finance")),
        (BK, meta(BK, title="Bank", domain="bank.example", username="me"), secrets()),
        (WF, meta(WF, title="Home", domain="AirPort", username="Home"), secrets()),
        (RD, meta(RD, title="Old", domain="old.example", username="me", recently_deleted=True),
         secrets()),
    ]
    for id, m, sec in rows:
        st.metas[id] = m
        st.secrets[id] = sec
    return st


@unittest.skipUnless(RUNNABLE, "quickshell or Omarchy's shell modules are not installed")
class WindowFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pear-flow-")
        self.authority = FakeAuthority()
        self.apple = WindowApple()
        self.h = await Harness(authority=self.authority, apple=self.apple).start()

    async def asyncTearDown(self):
        await self.h.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def run_window(self, app, timeout=150):
        run = os.path.join(self.tmp, "run")
        os.makedirs(run, mode=0o700)
        env = {"PATH": "/usr/bin", "HOME": self.tmp, "XDG_RUNTIME_DIR": run,
               "QT_QPA_PLATFORM": "offscreen", "QML_DISABLE_DISK_CACHE": "1"}
        proc = await asyncio.create_subprocess_exec(
            QUICKSHELL, "-p", app, env=env, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            out, _ = await proc.communicate()
            self.fail("the window never finished:\n" + out.decode(errors="replace")[-4000:])
        return re.sub(r"\x1b\[[0-9;]*m", "", out.decode(errors="replace"))

    async def test_the_window_and_the_daemon_agree(self):
        st = seed(self.h)
        clips = os.path.join(self.tmp, "clips.jsonl")
        fake = os.path.join(self.tmp, "pear-exec")
        with open(fake, "w") as f:
            f.write(FAKE_PEAR_EXEC % {"python": sys.executable, "sock": self.h.path, "out": clips,
                                      "count": os.path.join(self.tmp, "clip-runs")})
        os.chmod(fake, 0o755)
        app = window_copy(self.tmp, self.h.path, fake)
        ui = self.h.peer()
        # The window, then the two pear-clip processes it starts.
        self.h.peers.extend([ui, self.h.peer(ppid=ui.pid), self.h.peer(ppid=ui.pid)])

        out = await self.run_window(app)
        steps = re.findall(r"FLOW-STEP (.+)", out)
        self.assertIn("FLOW-DONE", out, f"steps done: {steps}\n" + out[-4000:])
        self.assertEqual(steps, ["unlock", "hover", "choose Codes", "Backspace", "choose a tag",
                                 "edit tags", "copy-text", "copy fails", "features", "create",
                                 "lock"])

        # The dialogs: the list, the one account, then .manage for turning a category on, the
        # keychain check and the new entry. Copy-text and the drop-down raise none.
        self.assertEqual(self.authority.actions(),
                         [paths.ACTION_UNLOCK, paths.ACTION_REVEAL, paths.ACTION_MANAGE,
                          paths.ACTION_MANAGE, paths.ACTION_MANAGE])
        self.assertIn("GitHub", self.authority.calls[1][2]["account"])   # the one it opened

        # set {tags}: spliced onto the notes, the body untouched.
        self.assertIn(("push_set", GH, ["tags"]), self.apple.calls)
        self.assertEqual(st.secrets[GH].notes, NOTES_BODY + "\n\nTags: #work #travel")
        # copy-text: one ticket, redeemed by pear-clip, holding exactly the selection.
        with open(clips) as f:
            got = [json.loads(line) for line in f]
        self.assertEqual(len(got), 2, got)
        for g in got:
            self.assertNotIn("error", g["hello"], g)
            self.assertIs(g["redeem"]["sensitive"], True)
            self.assertEqual(g["result"].get("ok"), True)
        self.assertEqual([g["redeem"]["value"] for g in got], [NOTES_BODY[:8], NOTES_BODY[9:14]])
        # create: the tags field reached the daemon canonical.
        self.assertEqual(self.apple.created["tags"], ["work", "travel"])
        self.assertEqual({k: self.apple.created[k] for k in ("domain", "username", "title")},
                         {"domain": "new.example", "username": "kim", "title": "New Site"})
        # Settings turned Recently Deleted on, and the store remembers it.
        self.assertIs(st.load_settings().get("features", {}).get("apple_deleted"), True)


if __name__ == "__main__":
    unittest.main()
