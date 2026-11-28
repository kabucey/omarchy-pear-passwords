"""The window's account-grant flow (app/shell.qml), checked on its source.

The window cannot be run here without a compositor, so these read the QML with comments
removed and pin the rules the reviews found broken:

- an unlock never starts a sign-in on its own (a second dialog nobody asked for);
- a reply for an account that is no longer selected, or whose grant ended, is dropped;
- a one-use grant keeps what its one request returned (the grant-expired event that request
  causes must not wipe it);
- a grant running out discards unsaved secret edits;
- the fields that hold secrets in plain text ask the input method for nothing.
"""

import re
import json
import shutil
import subprocess
import unittest

import qmlscan

SHELL = qmlscan.read(qmlscan.os.path.join(qmlscan.APP, "shell.qml"))
CODE = qmlscan.strip_comments(SHELL)


def function_body(name: str) -> str:
    m = re.search(rf"\bfunction {re.escape(name)}\s*\([^)]*\)\s*\{{", CODE)
    if not m:
        raise AssertionError(f"shell.qml has no function {name}")
    return qmlscan.element_body(CODE, m.end() - 1)


def case_body(label: str) -> str:
    start = CODE.index(f'case "{label}":')
    end = CODE.index("return;", start)
    nxt = CODE.find("case ", start + 5)
    # the case runs to its last `return;` before the next case label
    while nxt != -1 and CODE.find("return;", end + 1) != -1 and CODE.find("return;", end + 1) < nxt:
        end = CODE.find("return;", end + 1)
    return CODE[start:end]


class NoUnsolicitedSigninTests(unittest.TestCase):
    def test_the_unlock_reply_never_starts_a_signin(self):
        # clipboard_ui-3: "signin" raises .manage; after the unlock dialog it was a second
        # dialog without a click.
        body = function_body("authenticate")
        self.assertNotIn("startSignin", body)
        self.assertNotRegex(body, r'send\(\s*"(signin|grant|create|delete|signout|reset)"')
        self.assertNotIn("firstRunShown", CODE)

    def test_hello_never_starts_a_signin(self):
        self.assertNotIn("startSignin", function_body("onHello"))


class StaleReplyTests(unittest.TestCase):
    def test_secret_replies_are_dropped_unless_their_grant_is_still_open(self):
        # clipboard_ui-4
        stillopen = function_body("stillOpen")
        self.assertIn("root.selectedId", stillopen)
        self.assertIn("root.grantId", stillopen)
        for fn, op in (("doReveal", "reveal"), ("loadNotes", "reveal"),
                       ("loadHistory", "history"), ("loadTotp", "totp")):
            body = function_body(fn)
            m = re.search(rf'send\(\s*"{op}"\s*,\s*\{{\s*id:\s*id\b.*?function\s*\(d\)\s*\{{\s*'
                          r'if \(!root\.stillOpen\(id\)\) return;', body, re.S)
            self.assertIsNotNone(m, f"{fn}: the reply is not checked against its grant first")
            self.assertRegex(body, r"const id = root\.selectedId;", fn)


class SingleUseGrantTests(unittest.TestCase):
    def test_grant_expired_of_a_single_use_grant_keeps_what_it_returned(self):
        # clipboard_ui-5: the request that spends a one-use grant is answered first, then its
        # grant-expired event arrives; that event must not wipe the answer.
        body = case_body("grant-expired")
        single = body[body.index("if (root.grantSingleUse)"):]
        single = single[:single.index("return;")]
        self.assertNotIn("endGrant", single)
        self.assertNotIn("forgetSecrets", single)
        self.assertIn('root.grantId = ""', single)


class GrantRunsOutTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the window's JavaScript")
    def test_expiry_discards_secret_edits_and_closes_the_editor(self):
        # Execute the real expiry and cleanup functions, rather than asserting their spelling.
        funcs = {name: function_body(name) for name in
                 ("grantRanOut", "endGrant", "forgetSecrets", "hideSecrets", "stopGenerating")}
        script = "const funcs = " + json.dumps(funcs) + ";" + r'''
const root = {editorOpen: true, editorMode: "notes", selectedId: "entry",
    changing: true, notesText: "secret notes", notesLoaded: true,
    tagEditing: false, tagDraft: [], editDraft: null,
    showFlash: function () {}};
const edArea = {text: "unsaved secret notes"}, edSetup = {text: "seed"},
    newPw = {text: "new password"}, tagInput = {text: ""};
for (const [name, body] of Object.entries(funcs))
    root[name] = new Function("root", "edArea", "edSetup", "newPw", "tagInput", body)
        .bind(null, root, edArea, edSetup, newPw, tagInput);
root.grantRanOut();
process.stdout.write(JSON.stringify({editorOpen: root.editorOpen, changing: root.changing,
    notes: root.notesText, draft: root.editDraft,
    fields: [edArea.text, edSetup.text, newPw.text]}));
'''
        result = subprocess.run(["node"], input=script, text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout), {"editorOpen": False, "changing": False,
                          "notes": "", "draft": None, "fields": ["", "", ""]})


class RepeatedPressTests(unittest.TestCase):
    """A second Copy while the account is still opening (a sync holds the store for seconds)
    must not ask again: the daemon cancels the first grant, so the wait started over."""

    def run_js(self, script_tail: str) -> dict:
        body = function_body("withGrant")
        script = "const body = " + json.dumps(body) + ";" + r'''
const sent = [];
const root = {selected: {primary: "Example"}, selectedId: "e.1", unlocked: false, syncing: true,
    granting: false, grantAfter: null, grantSeq: 0, grantRid: -1, status: "", grantId: "",
    send: function (op, args, cb) { sent.push({op: op, args: args, cb: cb}); return sent.length; }};
root.withGrant = new Function("root", "after", body).bind(null, root);
const reply = {id: "e.1", expires: 0, single_use: false};
''' + script_tail
        out = subprocess.run(["node"], input=script, text=True, capture_output=True, check=True)
        return json.loads(out.stdout)

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the window's JavaScript")
    def test_two_presses_send_one_grant_and_run_the_newest_action_once(self):
        r = self.run_js(r'''
const ran = [];
root.withGrant(function () { ran.push("first"); });
const statusWhileSyncing = root.status;
root.withGrant(function () { ran.push("second"); });
sent[0].cb(reply);
process.stdout.write(JSON.stringify({grants: sent.filter(s => s.op === "grant").length,
    ran: ran, status: statusWhileSyncing, granting: root.granting, grantId: root.grantId}));
''')
        self.assertEqual(r["grants"], 1)
        self.assertEqual(r["ran"], ["second"])
        self.assertIn("once the sync finishes", r["status"])
        self.assertEqual((r["granting"], r["grantId"]), (False, "e.1"))

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the window's JavaScript")
    def test_a_reply_for_a_replaced_request_runs_nothing(self):
        r = self.run_js(r'''
const ran = [];
root.withGrant(function () { ran.push("old"); });
// select() moved on: a new account, a new request.
root.granting = false; root.grantAfter = null; root.grantSeq++;
root.selectedId = "e.2"; reply.id = "e.2";
root.withGrant(function () { ran.push("new"); });
sent[0].cb({id: "e.1"});                  // the old request answers late
const releasesAfterStale = sent.filter(s => s.op === "release").length;
sent[1].cb(reply);
process.stdout.write(JSON.stringify({ran: ran, releases: releasesAfterStale, grantId: root.grantId}));
''')
        self.assertEqual(r["ran"], ["new"])
        self.assertEqual(r["releases"], 0)        # the newer grant was on its way
        self.assertEqual(r["grantId"], "e.2")


class CopyPressTests(unittest.TestCase):
    """A second Copy while the first is still on its way does nothing, and a buffer that ran
    out at that moment is opened again and copied without another press."""

    def run_js(self, tail: str) -> dict:
        funcs = {n: function_body(n) for n in ("copyField", "withGrant")}
        script = "const funcs = " + json.dumps(funcs) + ";" + r'''
const sent = [];
const timer = {restart: function () {}};
const clipComponent = {createObject: function (p, o) { return {ticket: o.ticket}; }};
const root = {selected: {primary: "Bank", has_password: true}, selectedId: "e.1", unlocked: true,
    syncing: false, granting: false, grantAfter: null, grantSeq: 0, grantRid: -1, status: "",
    grantId: "e.1", copyPending: "", clipLatest: null, ended: 0,
    clipWords: function (f) { return f; }, showFlash: function () {},
    whenFocused: function (fn) { fn(); },
    endGrant: function () { root.ended++; root.grantId = ""; root.unlocked = false; },
    send: function (op, args, cb) { sent.push({op: op, args: args, cb: cb}); return sent.length; }};
root.copyField = new Function("root", "copyPendingTimer", "clipComponent", "field", "retried",
                              funcs.copyField).bind(null, root, timer, clipComponent);
root.withGrant = new Function("root", "after", funcs.withGrant).bind(null, root);
''' + tail
        out = subprocess.run(["node"], input=script, text=True, capture_output=True, check=True)
        return json.loads(out.stdout)

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the window's JavaScript")
    def test_a_second_press_while_copying_does_nothing(self):
        r = self.run_js(r'''
root.copyField("password");
root.copyField("password");
sent[0].cb({ticket: "t1"});
const afterOffer = sent.length;
process.stdout.write(JSON.stringify({copies: sent.filter(s => s.op === "copy").length,
    latest: root.clipLatest && root.clipLatest.ticket, pending: root.copyPending}));
''')
        self.assertEqual(r["copies"], 1)
        self.assertEqual(r["latest"], "t1")
        self.assertEqual(r["pending"], "e.1/password")      # until pear-clip offers it

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the window's JavaScript")
    def test_an_expired_buffer_is_opened_again_and_copied(self):
        r = self.run_js(r'''
root.copyField("password");
sent[0].cb({error: "grant-expired"});           // ran out between the two clocks
const grant = sent[1];
grant.cb({id: "e.1", expires: 0, single_use: false});
const copy2 = sent[2];
copy2.cb({ticket: "t2"});
process.stdout.write(JSON.stringify({ops: sent.map(s => s.op), ended: root.ended,
    latest: root.clipLatest && root.clipLatest.ticket, status: root.status}));
''')
        self.assertEqual(r["ops"], ["copy", "grant", "copy"])
        self.assertEqual(r["ended"], 1)
        self.assertEqual(r["latest"], "t2")
        self.assertEqual(r["status"], "")

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the window's JavaScript")
    def test_it_retries_once_only(self):
        r = self.run_js(r'''
root.copyField("password");
sent[0].cb({error: "grant-expired"});
sent[1].cb({id: "e.1", expires: 0, single_use: false});
sent[2].cb({error: "grant-expired"});
process.stdout.write(JSON.stringify({ops: sent.map(s => s.op), status: root.status}));
''')
        self.assertEqual(r["ops"], ["copy", "grant", "copy"])
        self.assertEqual(r["status"], "that account closed — open it again")


class SecretFieldTests(unittest.TestCase):
    def test_plain_text_secret_fields_ask_the_input_method_for_nothing(self):
        # clipboard_ui-2 (defence in depth; pear-exec also disables the protocols)
        for ident in ("edArea", "edSetup", "crNotes", "crSetup", "newPw"):
            m = re.search(rf"\bid: {ident}\n", CODE)
            self.assertIsNotNone(m, ident)
            body = CODE[m.end():m.end() + 1200]
            self.assertRegex(body, r"inputMethodHints: Qt\.ImhSensitiveData \| "
                                   r"Qt\.ImhNoPredictiveText", ident)


class TpmMoveWindowTests(unittest.TestCase):
    def test_the_move_onto_the_chip_is_only_ever_a_click(self):
        # audit: the PTT rotation ran on its own at unlock. It is now a Settings button.
        self.assertRegex(function_body("moveToTpm"), r'send\(\s*"tpm-move"')
        self.assertIn("root.tpmMove = !!d.tpm_move", function_body("authenticate"))
        for fn in ("authenticate", "onHello", "onEvent"):
            self.assertNotIn("tpm-move", function_body(fn), fn)
            self.assertNotIn("moveToTpm", function_body(fn), fn)
        self.assertEqual(CODE.count("root.moveToTpm()"), 1)
        button = CODE[CODE.index("root.moveToTpm()") - 400:CODE.index("root.moveToTpm()")]
        self.assertIn("onClicked:", button[-40:])


class MigrationScreenTests(unittest.TestCase):
    def test_a_pending_migration_is_offered_again(self):
        # function-migration-never-reoffered
        hello = function_body("onHello")
        self.assertIn("root.migrationPending = !!m.migration_pending", hello)
        self.assertRegex(hello, r'if \(root\.vaultState === "empty" \|\| root\.migrationPending\) '
                                r'\{ v1Check\.check\(\); return; \}')
        screen = CODE[CODE.index("readonly property string screen:"):]
        screen = screen[:screen.index("\n    }\n")]
        self.assertRegex(screen, r'root\.migrationPending && root\.vaultState === "locked"')
        self.assertIn("root.migrationPending = false", function_body("migrateFinish"))

    def test_a_keyring_vault_moves_with_no_terminal_step_and_no_pear_prompt(self):
        # audit: the keyring-vault screen sent users to 1.3.2's terminal passphrase prompt.
        # Now the importer reads the key from the keyring. A locked keyring is never asked
        # to unlock (round 2 audit, problem 4: that dialog was a second password prompt);
        # the window says so and "Check again" only reads again.
        self.assertIn('vaultFile.path = root.v1Dir + "/vault.enc"', CODE)
        self.assertIn("root.v1Present = vault;", CODE)
        self.assertIn("root.v1KeyringOnly = vault && !(kdf && check_)", CODE)
        for gone in ("icp passphrase", "migrate-keyring", "keyringStartFresh"):
            self.assertNotIn(gone, CODE, gone)
        line = function_body("onMigrateLine")
        branch = line[line.index('if (m.need === "keyring-locked")'):]
        branch = branch[:branch.index("return;")]
        self.assertIn('root.migrateStep = "keyring"', branch)
        self.assertNotIn("write(", branch)                    # nothing is sent on its own
        self.assertIn('check_keyring: true', function_body("migrateCheckKeyring"))
        self.assertEqual(CODE.count("root.migrateCheckKeyring()"), 1)
        self.assertIn('else if (root.migrateStep === "keyring") root.migrateCheckKeyring();', CODE)
        self.assertIn('root.migrateStep === "keyring" ? "Check again"', CODE)
        for gone in ("unlock_keyring", "keyring-unlock", "Unlock keyring",
                     "Unlock your login keyring", "keyring's own dialog"):
            self.assertNotIn(gone, CODE, gone)
        self.assertIn('m.error === "no-key"', line)

    def test_only_a_confirmed_missing_vault_abandons_the_import(self):
        # Round 2 audit, problem 3: any FileView load failure (unreadable, not a file) used
        # to count as "no 1.x vault" and dropped the pending import on its own.
        settle = function_body("settle")
        calls = [m.start() for m in re.finditer(r"root\.abandonMigration\(", settle)]
        self.assertEqual(len(calls), 1)
        guard = settle[:calls[0]]
        guard = guard[guard.rindex("if ("):]
        self.assertIn("vaultMissing", guard)
        vault_view = CODE[CODE.index("id: vaultFile"):]
        vault_view = vault_view[:vault_view.index("FileView {")]
        failed = vault_view[vault_view.index("onLoadFailed"):]
        self.assertIn("v1Check.vaultMissing = error === FileViewError.FileNotFound", failed)
        self.assertNotRegex(CODE, r"vaultMissing\s*=\s*true")
        # Cannot tell: the window says so and keeps the record.
        self.assertIn("vaultError", settle)

    def test_a_pending_import_with_no_vault_left_is_not_a_dead_end(self):
        # audit: migration_pending dead end. With ~/.config/icp gone the window cleared only
        # its own flag; every "Sign in to iCloud" then failed with migration-pending.
        settle = function_body("settle")
        branch = settle[settle.index("if (root.migrationPending && !root.v1Present && vaultMissing)"):]
        self.assertIn("root.abandonMigration(", branch[:branch.index("\n            }")])
        self.assertNotRegex(branch[:200], r"root\.migrationPending = false;")
        abandon = function_body("abandonMigration")
        self.assertRegex(abandon, r'send\(\s*"migrate-abandon"')
        self.assertIn("root.migrationPending = false", abandon)
        # "Start fresh instead" over an unfinished move abandons it too.
        fresh = CODE[CODE.index('text: "Start fresh instead"'):]
        fresh = fresh[:fresh.index("AppButton")]
        self.assertIn("if (root.migrationPending) root.abandonMigration(", fresh)
        # Its own words, and Start over (reset, .manage) as the way out if that fails.
        screen = CODE[CODE.index("readonly property string screen:"):]
        screen = screen[:screen.index("\n    }\n")]
        self.assertIn('"migration-pending"', screen)
        self.assertIn('case "migration-pending"', function_body("stateTitle"))
        self.assertIn('case "migration-pending"', function_body("stateBody"))
        self.assertIn('case "migration-pending"', function_body("errorWords"))
        self.assertRegex(CODE, r'root\.screen === "tpm-cleared" \|\| root\.screen === "damaged"\s*'
                               r'\|\| root\.screen === "migration-pending"')
        self.assertIn("root.migrationPending = false", function_body("startOver"))

    def test_units_that_were_not_stopped_are_shown_with_the_command(self):
        # function-legacy-units-not-stopped
        self.assertIn("migrateResult.units_not_stopped", CODE)
        self.assertIn('"systemctl --user disable --now "', CODE)
        self.assertNotIn("The old background services are stopped and turned off", CODE)


if __name__ == "__main__":
    unittest.main()
