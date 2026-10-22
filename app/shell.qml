//@ pragma UseQApplication
import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui as O
import "categories.js" as Cat

// Pear Passwords 2: the window.
//
// It runs as `pear-exec ui` from the root-owned copy in /usr/local/lib/pear-passwords/app, with
// effective gid pear-client, non-dumpable, and an environment pear-exec built from scratch. It
// holds no key and reads no vault file. Everything comes from pear-passwordsd over one socket
// (docs/protocol.md), and that one connection is the unlocked session: close the window and
// the daemon locks.
//
// Rules this file keeps (backend/tests/test_qml_*.py check them):
//   - no Quickshell IPC handler element, here or in any Omarchy Ui component it instantiates
//     (Ui/Panel has one, so Panel is never used);
//   - every Text and TextArea is PlainText, so nothing from Apple or a site is ever markup;
//   - no console.log, of anything;
//   - child processes only from the fixed list below: hyprctl (window rules, focus, opening a
//     link through Hyprland so the browser does not inherit our group), pear-exec clip and
//     migrate, the touchpad watcher and `systemctl show` for diagnostics; plus, through
//     Omarchy's Style singleton, `hyprctl -j getoption` (rounding, gaps) and `fc-match
//     monospace`, which also re-run when your fonts.conf or the window-gaps toggle changes
//     (test_qml_process_allowlist.py pins both lists, and Omarchy's reads from your home).
// A secret (password, notes, history, code) enters this process only after an explicit
// action inside that account's grant, is shown for at most `hide_after` seconds or until the
// window loses focus, then the property is overwritten. QML strings cannot be zeroed; that
// residue is the documented limit of a QML window.
ShellRoot {
    id: root

    // ---------------------------------------------------------------- fixed paths and commands
    readonly property string socketPath: "/run/pear-passwords/client.sock"
    readonly property string pearExec: "/usr/local/lib/pear-passwords/libexec/pear-exec"
    readonly property string touchWatchPath: decodeURIComponent(
        Qt.resolvedUrl("touch_watch.py").toString().replace(/^file:\/\//, ""))
    readonly property string qrScanPath: decodeURIComponent(
        Qt.resolvedUrl("qr_scan.py").toString().replace(/^file:\/\//, ""))
    readonly property string home: Quickshell.env("HOME")
    // pear-exec points XDG_CONFIG_HOME and XDG_STATE_HOME at an empty directory, so the two
    // files of yours this window looks at are named from HOME, exactly where 1.x and Omarchy
    // keep them.
    readonly property string v1Dir: home + "/.config/icp"
    readonly property string clipHistoryPath: home + "/.local/state/omarchy/clipboard-history.json"
    // Registered before the window maps (it stays hidden until this has run). The layout
    // rules once per Hyprland session; no_screen_share on every start, outside that guard, so
    // a global set beforehand cannot keep it from being added (a config reload still drops it
    // until Pear starts again). It keeps the window out of screen sharing and most capture
    // tools; it is best effort, a revealed password can still be photographed, and a program
    // that controls Hyprland can remove it (README, "What a program running as you can do").
    // Floating or regular is the "Open as" setting: a global the open handler reads, set on
    // every launch before the window maps. The handler is registered once per Hyprland
    // session; a regular window also undoes an older session's float rule. enable/disable,
    // never set/unset: Hyprland reads those as a toggle, so "regular" floated every newly
    // tiled window. v4 because a v3 handler (the toggling one) may still be registered.
    readonly property bool windowFloating: root.settings.window_mode !== "regular"
    readonly property string windowRulesLua: "_G.__pear_passwords_float = "
        + (root.windowFloating ? "true " : "false ")
        + "hl.window_rule({ match = { class = [[^org\\.quickshell$]], "
        + "title = [[^Pear Passwords$]] }, no_screen_share = true }) "
        + "if not _G.__pear_passwords_rules_v4 then "
        + "local m = { class = [[^org\\.quickshell$]], title = [[^Pear Passwords$]] } "
        + "hl.window_rule({ match = m, tag = [[-default-opacity]] }) "
        + "hl.window_rule({ match = m, opacity = [[1 override 1 override]] }) "
        + "hl.on([[window.open]], function(w) "
        + "if w.class ~= [[org.quickshell]] or w.title ~= [[Pear Passwords]] then return end "
        + "if _G.__pear_passwords_float == false then "
        + "hl.dispatch(hl.dsp.window.float({ action = [[disable]], window = w })) "
        + "else "
        + "hl.dispatch(hl.dsp.window.float({ action = [[enable]], window = w })) "
        + "hl.dispatch(hl.dsp.window.center({ window = w })) "
        + "end end) "
        + "_G.__pear_passwords_rules_v4 = true end"
    // The same choice for the window that is already open, when it changes in Settings.
    readonly property string windowModeLua: "_G.__pear_passwords_float = "
        + (root.windowFloating
           ? "true hl.dispatch(hl.dsp.window.float({ action = [[enable]], window = [[title:^Pear Passwords$]] })) "
             + "hl.dispatch(hl.dsp.window.center({ window = [[title:^Pear Passwords$]] }))"
           : "false hl.dispatch(hl.dsp.window.float({ action = [[disable]], window = [[title:^Pear Passwords$]] }))")
    readonly property string focusLua: "hl.dsp.focus({ window = \"title:^Pear Passwords$\" })"
    // What a site may look like before it is handed to Hyprland to open: a lowercase host of
    // two or more labels, an optional port and a plain path. Nothing that could end the Lua
    // string or reach a shell (no quotes, spaces, $, backslashes or semicolons).
    readonly property var urlPattern: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?(\/[A-Za-z0-9._~\/%-]*)?$/
    // The importer reports the 1.x extension's id when it found that extension's old
    // connection file; the command then needs only to be pasted. It is never run for you.
    readonly property string registerCommand:
        "pear-passwords-autofill register --browser zen \\\n    --extension-id "
        + (/^\{[0-9a-f-]{36}\}$/.test(root.migrateResult.extension_id || "")
           ? "'" + root.migrateResult.extension_id + "'" : "<your extension's id>")
    readonly property var legacyUnits: ["icp-host.service", "icp-sync.timer", "icp-sync.service",
                                        "pear-passwords-sync.timer", "pear-passwords-sync.service"]

    // ---------------------------------------------------------------- what the daemon said
    // phase: can we talk to the daemon at all. vaultState: what it said about the store.
    property string phase: "connecting"        // connecting ready not-installed launcher daemon-failed abi-mismatch
    property string daemonDetail: ""
    property string vaultState: ""             // empty locked unlocked tpm-missing tpm-cleared damaged
    property string lockReason: ""             // why the last unlock did not open the list
    property bool signedIn: false
    property string sealedWith: ""
    // A usable TPM and host-sealed keys: Settings offers the one-time move onto the chip.
    // Never automatic - it opens every entry inside the daemon - so it waits for a click.
    property bool tpmMove: false
    property bool tpmMoving: false
    property var settings: ({ grant_s: 120, idle_lock_s: 300, clip_timeout_s: 30, window_mode: "floating" })
    // Browser autofill: off until turned on here (one .manage dialog); how many hosts are on.
    property bool autofillEnabled: false
    property int autofillHosts: 0
    property var oldCopy: null
    property real syncedAt: 0
    property bool syncing: false
    property bool v1Present: false
    property bool v1Checked: false
    // A 1.x vault keyed by the login keyring (1.x's default): vault.enc but no kdf.json or
    // check.enc. The importer reads its key from the unlocked keyring; no passphrase exists.
    property bool v1KeyringOnly: false
    // migrate-begin made keys but the import never committed (the window was closed at the
    // passphrase step): the daemon says so at hello, and the move is offered again.
    property bool migrationPending: false
    property bool everConnected: false

    // The screen follows from the above; nothing else decides it.
    readonly property string screen: {
        if (root.phase !== "ready") return root.phase;
        if (root.migrateStep !== "") return "migrate";
        if (root.appUnlocked) return "list";
        if (root.migrationPending && root.vaultState === "locked")
            return !root.v1Checked ? "connecting" : (root.v1Present ? "migrate" : "migration-pending");
        switch (root.vaultState) {
        case "empty": return !root.v1Checked ? "connecting" : root.v1Present ? "migrate" : "empty";
        case "tpm-missing": case "tpm-cleared": case "damaged": return root.vaultState;
        }
        if (root.lockReason === "no-agent" || root.lockReason === "busy") return "no-agent";
        return "locked";
    }

    // ---------------------------------------------------------------- the list
    property var entries: []
    property var filtered: []
    property int cursor: -1
    property var selected: null
    property string selectedId: ""
    property bool appUnlocked: false
    property bool autoAuthTried: false
    property bool authing: false
    property int authRid: -1
    property bool authRetry: false
    property bool startOverConfirm: false
    property bool needsLogin: false
    // The search field's one tag (categories.js): null is All. List metadata only, so it
    // survives syncs and grants; a lock clears it.
    property var catTag: null
    // From the unlock reply: rows that wait for a live check stay hidden until it passes.
    property var features: ({ passkeys: false, apple_deleted: false })

    // ---------------------------------------------------------------- the one account grant
    // At most one account is open at a time, for settings.grant_s seconds (0 = one use).
    property string grantId: ""
    property real grantExpires: 0              // 0 with a single-use grant
    property bool grantSingleUse: false
    property int grantLeft: 0
    property bool granting: false
    property int grantRid: -1
    readonly property bool unlocked: root.grantId !== "" && root.grantId === root.selectedId
                                     && (root.grantSingleUse || root.grantLeft > 0)

    // ---------------------------------------------------------------- secrets on screen
    property string revealed: ""
    property var historyRows: []
    property var revealedHistory: ({})
    property bool historyLoaded: false
    property string totpCode: ""
    property int totpLeft: 0
    property string notesText: ""
    property bool notesLoaded: false
    property int hideAfter: 20
    // A passkey-only row (features spec 1) has nothing to reveal or copy: said, never asked for.
    readonly property string noPassword: "This account has no password — it signs in with a passkey"

    property string status: ""
    property string flash: ""
    property bool busy: false
    property bool confirming: false
    // Delete: said in full in the window first, then the daemon's .manage dialog (fingerprint).
    property bool deleteConfirm: false
    // A dialog over the main view (an editor, Settings, sign-in over an unlocked vault): the view
    // behind it darkens and blurs, easing in and out together.
    readonly property bool dialogOpen: root.editorOpen || root.settingsOpen
                                       || (root.signinOpen && root.signedIn)
    property real dialogT: root.dialogOpen ? 1 : 0
    Behavior on dialogT { NumberAnimation { duration: 260; easing.type: Easing.OutCubic } }
    property bool deleting: false
    readonly property bool canDelete: !!root.selected && root.appUnlocked
        && !root.selected.recently_deleted && root.selected.kind !== "passkey"
        && !root.selected.is_wifi
    property bool generateNew: false
    property bool renaming: false
    property bool changing: false
    // ---- editor sheet: websites / notes / verification code / new entry
    property bool editorOpen: false
    property string editorMode: ""               // sites | notes | totp | create
    property bool editorBusy: false
    property string editorError: ""
    property var totpPreview: ({})
    property bool createMore: false
    property bool createGenerate: false
    // ---- tags: an inline chip editor in the detail pane, inside the account's grant
    property bool tagEditing: false
    property var tagDraft: []
    property bool tagBusy: false
    property string tagError: ""
    // Tags are list metadata; an unfinished tag edit may survive its account closing.
    property var tagKept: null
    property bool panelFocus: false
    property int detailIndex: 0
    readonly property int fieldCount: root.fieldRows().length
    // ---- sign-in sheet: draws only what the daemon's sign-in stream says
    property bool signinOpen: false
    property string signinMode: "login"          // login | relogin
    property bool signinRunning: false
    property int signinRid: -1
    property int signinAskId: -1
    property string signinStage: ""
    property string signinNeed: ""               // text | secret | confirm | choice - "" while working
    property string signinKind: ""
    property string signinDefault: ""
    property string signinDetail: ""
    property var signinOptions: []
    property var signinDetails: []
    property var signinDevice: ({})
    property int signinChoice: -1
    property string signinVia: "trusted"
    property int signinCount: -1
    property bool signinVerified: false
    property string signinError: ""
    property var signinWarnings: []
    property var signinLog: []
    property bool signinShowDetails: false
    property string signinOutcome: ""            // "" | ok | error | cancelled
    // ---- migration sheet
    property string migrateStep: ""              // "" intro running passphrase done error
    property bool migrateManifests: true
    property string migrateStage: ""
    property bool migrateRetry: false
    property var migrateResult: ({})
    property string migrateError: ""
    // ---- settings sheet
    property bool settingsOpen: false
    property string historyCheck: ""             // result line of the clipboard-history check
    property bool historyChecking: false
    property bool featureBusy: false
    property bool diagBusy: false
    property string diagText: ""                 // the keychain check: counts and names only
    property bool purging: false
    property bool windowReady: false
    property bool connectGrace: false

    readonly property bool debugWheel: false
    // Development only (pear-exec drops every variable, so the installed window never sees
    // these): PEAR_PASSWORDS_SNAPSHOT renders the window to a PNG and quits;
    // PEAR_PASSWORDS_PREVIEW=<screen> fills it with made-up data and never connects.
    readonly property string snapshotPath: Quickshell.env("PEAR_PASSWORDS_SNAPSHOT") || ""
    readonly property string previewMode: Quickshell.env("PEAR_PASSWORDS_PREVIEW") || ""
    readonly property bool headless: Quickshell.env("QT_QPA_PLATFORM") === "offscreen"

    // ---------------------------------------------------------------- the daemon socket
    property int nextRid: 1
    property var pending: ({})                   // rid -> function(reply)

    Socket {
        id: daemon
        path: root.socketPath
        parser: SplitParser {
            splitMarker: "\n"
            onRead: function (line) { root.onLine(line); }
        }
        onConnectionStateChanged: {
            if (daemon.connected) {
                root.everConnected = true;
                root.pending = ({});
                root.nextRid = 1;
                daemon.write(JSON.stringify({ op: "hello", rid: 0, role: "ui", proto: 2 }) + "\n");
                daemon.flush();
            } else if (root.phase === "ready") {
                // The daemon went away (restart, crash, uninstall). Whatever was open is gone
                // with it; say so instead of showing a list that can no longer do anything.
                root.lockApp("");
                root.phase = "daemon-failed";
                root.daemonDetail = "The connection to Pear's background service was lost.";
                diagnose.running = true;
            }
        }
        onError: function (error) {
            if (root.phase === "ready") return;
            // 1 = not found (no socket: not installed, or the socket unit is off),
            // 2 = refused, 0/3 = access (started without pear-exec)
            if (error === 3 || error === 0) { root.phase = "launcher"; return; }
            diagnose.running = true;
        }
    }

    function send(op, fields, done) {
        if (!daemon.connected) { if (done) done({ error: "daemon" }); return -1; }
        const rid = root.nextRid++;
        if (done) {
            const p = root.pending;
            p[rid] = done;
            root.pending = p;
        }
        daemon.write(JSON.stringify(Object.assign({ op: op, rid: rid }, fields || {})) + "\n");
        daemon.flush();
        return rid;
    }

    function onLine(line) {
        if (!line || !line.length) return;
        let m = null;
        try { m = JSON.parse(line); } catch (e) { return; }
        if (!m || typeof m !== "object") return;
        if (m.event !== undefined) { root.onEvent(m); return; }
        if (m.rid === 0 && root.phase !== "ready") { root.onHello(m); return; }
        const cb = root.pending[m.rid];
        if (cb) {
            const p = root.pending;
            delete p[m.rid];
            root.pending = p;
            cb(m);
        }
    }

    function onHello(m) {
        if (m.error === "already-running") { Qt.quit(); return; }    // the other window raises itself
        if (m.error) {
            root.phase = "daemon-failed";
            root.daemonDetail = "The background service refused this window (" + m.error + ").";
            return;
        }
        root.phase = "ready";
        root.vaultState = m.state || "";
        root.signedIn = !!m.signed_in;
        root.sealedWith = m.sealed_with || "";
        if (m.settings) root.settings = m.settings;
        root.startWindowRules();
        root.autofillEnabled = !!(m.autofill && m.autofill.enabled);
        root.autofillHosts = (m.autofill && m.autofill.hosts) || 0;
        root.oldCopy = m.old_copy || null;
        root.migrationPending = !!m.migration_pending;
        // A migration that never committed is offered again (no unlock, no sign-in first).
        if (root.vaultState === "empty" || root.migrationPending) { v1Check.check(); return; }
        // Opening the window is the request to see it: ask once, straight away. Never for a
        // window nobody can see (an offscreen load), and never again on our own after that.
        if (root.vaultState === "locked" && !root.autoAuthTried && !root.headless) {
            root.autoAuthTried = true;
            root.authenticate();
        }
        if (root.snapshotPath) snapshotTimer.start();
    }

    function onEvent(m) {
        switch (m.event) {
        case "locked":
            root.lockApp(m.reason || "");
            return;
        case "synced":
            root.syncing = false;
            root.syncedAt = m.synced_at || 0;
            root.needsLogin = false;
            // The list follows the flags it was made with (a flag changed in Settings, too).
            if (m.features) root.takeFeatures(m.features);
            root.setEntries(m.entries || []);
            return;
        case "sync-failed":
            root.syncing = false;
            if (m.reason === "needs-login") root.needsLogin = true;
            root.showFlash(m.reason === "anisette-unavailable" ? "Sync failed — the local sign-in helper isn't running"
                         : m.reason === "network" ? "Sync failed — iCloud couldn't be reached"
                         : m.reason === "needs-login" ? "Sync paused — iCloud wants you to sign in again"
                         : "Sync failed");
            return;
        case "needs-login":
            root.needsLogin = true;
            return;
        case "grant-expired":
            if (m.id !== root.grantId) return;
            if (root.grantSingleUse) {
                // The one use was the request that just answered: keep what it returned until
                // hide_after, focus loss or lock (the usual timers), and drop only the grant.
                root.grantId = ""; root.grantExpires = 0; root.grantLeft = 0;
                root.grantSingleUse = false;
                return;
            }
            root.grantRanOut();
            return;
        case "clip":
            if (m.outcome === "failed" && Date.now() - root.clipFailAt < 5000) return;
            root.showFlash(root.clipWords(m.field) + (m.outcome === "pasted" ? " pasted — now cleared"
                         : m.outcome === "expired" ? " cleared from the clipboard"
                         : m.outcome === "replaced" ? " replaced by something you copied"
                         : m.outcome === "withdrawn" ? " taken back off the clipboard"
                         : " couldn't be put on the clipboard"));
            return;
        case "autofill":
            root.showFlash(m.outcome === "filled" ? "Filled a password on " + (m.origin || "a site")
                         : m.outcome === "failed" ? "A browser fill failed"
                         : "A browser fill was not approved");
            return;
        case "autofill-hosts":
            root.autofillHosts = m.count || 0;
            return;
        case "migrated":
            root.migrateResult = Object.assign({}, root.migrateResult, { counts: m.counts || {} });
            return;
        case "focus":
            focusProc.running = true;
            return;
        case "stage": case "out": case "ask":
            if (m.rid === root.signinRid) root.onSigninEvent(m);
            return;
        }
    }

    // Couldn't connect: work out which of the error screens it is.
    Process {
        id: diagnose
        running: false
        command: ["/usr/bin/systemctl", "show", "-p", "LoadState,ActiveState,Result,ExecMainStatus", "pear-passwordsd.service"]
        stdout: StdioCollector {
            onStreamFinished: {
                const v = {};
                for (const line of this.text.split("\n")) {
                    const i = line.indexOf("=");
                    if (i > 0) v[line.slice(0, i)] = line.slice(i + 1);
                }
                if (root.snapshotPath) snapshotTimer.start();
                if (v.LoadState === "not-found") { root.phase = "not-installed"; return; }
                if (v.ExecMainStatus === "78") { root.phase = "abi-mismatch"; return; }
                root.phase = "daemon-failed";
                if (!root.daemonDetail)
                    root.daemonDetail = v.Result && v.Result !== "success"
                        ? "It stopped with \"" + v.Result + "\"." : "";
            }
        }
    }

    function reconnect() {
        root.phase = "connecting";
        root.daemonDetail = "";
        daemon.connected = false;
        daemon.connected = true;
    }

    // ---------------------------------------------------------------- is there a 1.x vault?
    // Only whether kdf.json and check.enc exist matters (both are non-secret or ciphertext);
    // the importer, not this window, reads the vault.
    QtObject {
        id: v1Check
        property int pendingChecks: 0
        property bool kdf: false
        property bool check_: false
        property bool vault: false
        // Only a load that failed because vault.enc does not exist says there is no 1.x
        // vault; unreadable or not a file is "cannot tell", and nothing is abandoned on it.
        property bool vaultMissing: false
        property string vaultError: ""
        function check() {
            kdf = false; check_ = false; vault = false; vaultMissing = false; vaultError = "";
            pendingChecks = 3;
            kdfFile.path = ""; kdfFile.path = root.v1Dir + "/kdf.json";
            checkFile.path = ""; checkFile.path = root.v1Dir + "/check.enc";
            vaultFile.path = ""; vaultFile.path = root.v1Dir + "/vault.enc";
        }
        function settle() {
            if (--pendingChecks > 0) return;
            // Either kind of 1.x vault can be moved: a passphrase vault (kdf.json + check.enc)
            // or one keyed by the login keyring (vault.enc alone).
            root.v1Present = vault;
            root.v1KeyringOnly = vault && !(kdf && check_);
            root.v1Checked = true;
            if (root.v1Present && root.migrateStep === "") root.migrateStep = "intro";
            if (root.migrationPending && !root.v1Present && !vaultMissing && vaultError)
                root.status = "Pear cannot read " + root.v1Dir + "/vault.enc (" + vaultError
                    + "), so the move from 1.x waits. Fix that and reopen Pear, or Start over.";
            if (root.migrationPending && !root.v1Present && vaultMissing) {
                // Nothing left to import (the 1.x vault is gone): the daemon drops its record
                // of the unfinished move (no dialog), and this is an ordinary store again.
                root.abandonMigration(function () {
                    if (root.vaultState === "locked" && !root.autoAuthTried && !root.headless) {
                        root.autoAuthTried = true;
                        root.authenticate();
                    }
                });
            }
            if (root.snapshotPath) snapshotTimer.start();
        }
    }
    FileView {
        id: vaultFile
        printErrors: false
        // Only whether it exists; its contents are never used here. Large, so not watched.
        onLoaded: { v1Check.vault = true; v1Check.settle(); }
        onLoadFailed: (error) => {
            v1Check.vaultMissing = error === FileViewError.FileNotFound;
            if (!v1Check.vaultMissing) v1Check.vaultError = FileViewError.toString(error);
            v1Check.settle();
        }
    }
    FileView {
        id: kdfFile
        printErrors: false
        onLoaded: { v1Check.kdf = true; v1Check.settle(); }
        onLoadFailed: v1Check.settle()
    }
    FileView {
        id: checkFile
        printErrors: false
        onLoaded: { v1Check.check_ = true; v1Check.settle(); }
        onLoadFailed: v1Check.settle()
    }

    // ---------------------------------------------------------------- Hyprland
    property bool rulesStarted: false
    function startWindowRules() {
        if (root.rulesStarted || root.previewMode) return;
        root.rulesStarted = true;
        rulesProc.running = true;
    }
    Process {
        id: rulesProc
        running: false
        command: ["/usr/bin/hyprctl", "eval", root.windowRulesLua]
        onExited: root.windowReady = true
    }
    Timer {
        // No hello yet (the service is starting): open with the default rather than wait.
        interval: 700; running: !root.rulesStarted && !root.previewMode
        onTriggered: root.startWindowRules()
    }
    Process {
        id: windowModeProc
        running: false
        command: ["/usr/bin/hyprctl", "eval", root.windowModeLua]
    }
    Timer {
        // Without Hyprland (or a hung hyprctl) the window must still appear.
        interval: 1500; running: !root.windowReady; onTriggered: root.windowReady = true
    }
    Timer { interval: 800; running: true; onTriggered: root.connectGrace = true }
    Process {
        id: focusProc
        running: false
        command: ["/usr/bin/hyprctl", "dispatch", root.focusLua]
    }
    // A link opens through Hyprland, so the browser is Hyprland's child, not ours: a child of
    // this window would inherit the pear-client group and could talk to the daemon.
    Process {
        id: opener
        property string lua: ""
        running: false
        command: ["/usr/bin/hyprctl", "dispatch", opener.lua]
    }

    // ---------------------------------------------------------------- QR scan
    // "Scan QR code" next to a setup-key field: you drag over the code, qr_scan.py reads it
    // (slurp, grim into memory, zbarimg) and only what the code holds comes back, into the
    // field you would otherwise paste into.
    property bool qrScanning: false
    property var qrTarget: null
    function scanQr(field) {
        if (root.qrScanning || !field) return;
        root.qrTarget = field;
        root.qrScanning = true;
        qrProc.running = true;
        root.showFlash("Draw a box around the QR code — Esc cancels");
    }
    Process {
        id: qrProc
        running: false
        command: ["/usr/bin/python3", "-I", root.qrScanPath]
        stdout: SplitParser {
            onRead: function (line) {
                let m = null;
                try { m = JSON.parse(line); } catch (e) { return; }
                if (m && m.ok === true && typeof m.text === "string" && root.qrTarget)
                    root.qrTarget.text = m.text;
                else if (m && m.reason === "no-code")
                    root.showFlash("No QR code in that area — try again, around the whole code");
                else if (m && m.reason === "failed")
                    root.showFlash("Couldn't read the screen for a QR code");
            }
        }
        onExited: { root.qrScanning = false; root.qrTarget = null; }
    }

    // ---------------------------------------------------------------- clocks
    Timer {
        interval: 1000; running: true; repeat: true
        onTriggered: {
            const now = Date.now() / 1000;
            if (root.grantId !== "" && !root.grantSingleUse) {
                root.grantLeft = Math.max(0, Math.ceil(root.grantExpires - now));
                if (root.grantLeft === 0) root.grantRanOut();
                else if (root.grantLeft <= 20 && root.editorOpen && root.editorMode !== "create")
                    root.editorError = "this account closes in " + root.grantLeft
                                     + " s — save now to keep your changes";
            }
            if (root.totpLeft > 0) {
                root.totpLeft -= 1;
                if (root.totpLeft === 0) root.totpCode = "";
            }
        }
    }
    Timer { id: flashTimer; interval: 3200; onTriggered: root.flash = "" }
    // Whatever secret is on screen goes after hide_after seconds.
    Timer { id: hideTimer; interval: root.hideAfter * 1000; onTriggered: root.hideSecrets() }
    // ...or as soon as the window is not the one you are looking at.
    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.application.state !== Qt.ApplicationActive) { root.hideSecrets(); search.closeCats(); }
        }
    }
    Timer {
        id: previewDebounce
        interval: 300
        property string text: ""
        onTriggered: root.previewTotp(text)
    }

    // Tells us when fingers touch the touchpad - the one event Qt's Wayland client never
    // delivers (see touch_watch.py). Runs only while unlocked, prints only "touch".
    Process {
        id: touchWatch
        running: root.appUnlocked && !root.previewMode
        command: ["/usr/bin/python3", "-I", root.touchWatchPath]
        stdout: SplitParser {
            splitMarker: "\n"
            onRead: function (line) { if (line === "touch") list.catchCoast(); }
        }
    }

    // ---------------------------------------------------------------- pear-exec children
    // Copy: the value never comes here. The daemon puts it in a ticket; pear-clip redeems it
    // and owns the clipboard. A component, because a second copy may start while the first
    // clip process is still being told to withdraw. "copied" is said only once pear-clip
    // reports {"event":"offered"} on stdout (the compositor has the selection); an error
    // line, or an exit before "offered" (pear-exec refusing it, a crash), says why it failed.
    Component {
        id: clipComponent
        Process {
            id: clipProc
            property string ticket: ""
            property string words: "Selection"
            property bool offered: false
            property bool failed: false
            property string refusal: ""          // pear-exec's or pear-clip's own stderr line
            running: false
            stdinEnabled: true
            command: [root.pearExec, "clip"]
            onStarted: { write(ticket + "\n"); ticket = ""; stdinEnabled = false; }
            function fail(reason) {
                if (clipProc.offered || clipProc.failed) return;
                clipProc.failed = true;
                root.clipFailed(reason);
            }
            stdout: SplitParser {
                splitMarker: "\n"
                onRead: function (line) {
                    let m = null;
                    try { m = JSON.parse(line); } catch (e) { return; }
                    if (!m) return;
                    if (m.event === "offered" && !clipProc.failed && !clipProc.offered) {
                        clipProc.offered = true;
                        root.clipFailAt = 0;
                        root.showFlash(clipProc.words + " copied — clears after one paste or "
                                       + (root.settings.clip_timeout_s || 30) + " s");
                        root.clipOffered(clipProc, clipProc.words);
                    } else if (m.event === "error") {
                        clipProc.fail(typeof m.reason === "string" && m.reason ? m.reason
                                      : "the clipboard didn't take it");
                    } else if (m.event === "done") {
                        root.clipDone(clipProc);
                    }
                }
            }
            stderr: SplitParser {
                splitMarker: "\n"
                onRead: function (line) {
                    const r = line.match(/^pear-(?:exec|clip): (.+)$/);
                    if (r) clipProc.refusal = r[1].slice(0, 160);
                }
            }
            onExited: function (code) {
                clipProc.fail(clipProc.refusal ? clipProc.refusal
                              : code === 77 ? "the clipboard helper was refused (pear-exec 77)"
                              : "the clipboard helper stopped (exit " + code + ")");
                root.clipDone(clipProc);
                destroy();
            }
        }
    }
    // A copy that never reached the clipboard. The daemon's own "couldn't be put on the
    // clipboard" for the same copy, if it follows, adds nothing and is not shown over this.
    property double clipFailAt: 0
    function clipFailed(reason) {
        root.clipFailAt = Date.now();
        root.showFlash("Couldn't copy — " + reason);
    }

    // The live offer in the status bar, "Password on clipboard · 27 s", from pear-clip's
    // "offered" until its "done" (pasted, expired, replaced, withdrawn or failed), when the
    // outcome toast takes over. Only the clip process that offered can end it, so the previous
    // offer's "done", arriving behind a new copy, leaves the new countdown alone. Not
    // clickable: the window has no way to withdraw an offer early (a new copy or a lock does,
    // through the daemon).
    property QtObject clipOwner: null
    readonly property bool clipLive: clipOwner !== null
    property string clipLabel: ""
    property double clipUntil: 0
    property int clipLeft: 0
    function clipOffered(owner, words) {
        root.clipOwner = owner;
        root.clipLabel = words;
        root.clipUntil = Date.now() + (root.settings.clip_timeout_s || 30) * 1000;
        root.clipTick();
    }
    function clipDone(owner) {
        if (root.clipOwner !== owner) return;
        root.clipOwner = null;
        root.clipLabel = "";
        root.clipUntil = 0;
        root.clipLeft = 0;
    }
    function clipTick() {
        root.clipLeft = Math.max(0, Math.ceil((root.clipUntil - Date.now()) / 1000));
    }
    Timer { id: clipTimer; interval: 250; repeat: true; running: root.clipLive; onTriggered: root.clipTick() }

    // The importer: line 1 the ticket, line 2 the options, later only an answer it asks for.
    Process {
        id: migrateProc
        property string ticket: ""
        property string options: ""
        property bool purge: false
        running: false
        stdinEnabled: true
        command: [root.pearExec, "migrate"]
        onStarted: {
            write(ticket + "\n" + (purge ? "" : options + "\n"));
            ticket = "";
            if (purge) stdinEnabled = false;
        }
        stdout: SplitParser {
            splitMarker: "\n"
            onRead: function (line) {
                let m = null;
                try { m = JSON.parse(line); } catch (e) { return; }
                if (migrateProc.purge) root.onPurgeLine(m); else root.onMigrateLine(m);
            }
        }
        onExited: function (code) {
            stdinEnabled = true;
            if (migrateProc.purge) { root.purging = false; return; }
            if (root.migrateStep === "running" || root.migrateStep === "passphrase"
                || root.migrateStep === "keyring") {
                if (code !== 4) {
                    root.migrateStep = "error";
                    if (!root.migrateError) root.migrateError = "The importer stopped unexpectedly. Nothing was changed.";
                } else root.migrateStep = "intro";
            }
        }
    }

    // ---------------------------------------------------------------- unlock and lock
    function authenticate() {
        if (root.authing) return;
        root.authing = true;
        root.lockReason = "";
        root.status = "waiting for your fingerprint or password…";
        root.authRid = root.send("unlock", {}, function (d) {
            root.authing = false;
            root.authRid = -1;
            if (root.authRetry) { root.authRetry = false; root.authenticate(); return; }
            if (d.locked) {
                root.status = "";
                root.lockReason = d.reason || "";
                if (d.reason === "tpm-missing" || d.reason === "tpm-cleared" || d.reason === "damaged"
                    || d.reason === "empty") root.vaultState = d.reason;
                if (d.reason === "dismissed") root.status = "cancelled";
                else if (d.reason === "denied") root.status = "not approved";
                else if (d.reason === "rate-limited")
                    root.status = "too many tries — wait " + (d.retry_after || 60) + " s";
                return;
            }
            if (d.error) { root.status = root.errorWords(d); return; }
            root.status = "";
            root.appUnlocked = true;
            root.vaultState = "unlocked";
            root.syncedAt = d.synced_at || 0;
            root.needsLogin = !!d.needs_login;
            root.tpmMove = !!d.tpm_move;
            root.takeFeatures(d.features);
            root.syncing = true;
            root.setEntries(d.entries || []);
            // No sign-in started from here: "signin" raises its own .manage dialog, and a
            // dialog may follow only a click. The empty list offers "Sign in to iCloud".
        });
    }

    // "Nothing appeared? Retry": withdraw the dialog that never showed and ask again.
    function retryAuth() {
        if (!root.authing) { root.authenticate(); return; }
        root.authRetry = true;
        root.send("cancel", { target: root.authRid }, null);
    }

    function lockNow() { root.send("lock", {}, null); }

    // Ctrl+C / Ctrl+X (and Ctrl+Insert, Shift+Delete) in a field that holds a secret would put
    // it on the regular clipboard, past pear-clip's one paste or 30 s and into clipboard
    // history, so Qt never sees them here. Copy in a field with a `source` (docs/protocol.md,
    // copy-text) sends the selection to the daemon, and pear-clip puts it on the clipboard
    // like any other copy; without one (the Apple ID password, the 2FA code, the 1.x
    // passphrase) it does nothing. Cut is swallowed everywhere.
    function guardSecretKeys(event, source, field) {
        if (event.matches(StandardKey.Copy)) {
            event.accepted = true;
            if (source && field && field.selectedText !== "") root.copyText(source, field.selectedText);
        } else if (event.matches(StandardKey.Cut)) event.accepted = true;
    }

    // Selected text from a secret field, through the daemon and pear-clip: no dialog (the text
    // is already in this window), and the edit sources only inside that account's grant.
    function copyText(source, text) {
        if (!text) return;
        if (text.length > 16384) { root.showFlash("That selection is too long to copy"); return; }
        const bound = source === "notes-edit" || source === "totp-setup-edit" || source === "new-password";
        const id = root.selectedId;
        const go = function () {
            root.send("copy-text", bound ? { source: source, id: id, text: text }
                                         : { source: source, text: text }, function (d) {
                if (d.error) { root.showFlash(root.errorWords(d)); return; }
                clipComponent.createObject(root, { ticket: d.ticket, words: "Selection", running: true });
            });
        };
        if (bound) root.withGrant(go); else go();
    }

    // An import that never committed, with nothing left to import or "Start fresh instead"
    // chosen: tell the daemon, which otherwise refuses a fresh sign-in (migration-pending).
    // No dialog. If it fails, the migration-pending screen offers Start over (reset).
    function abandonMigration(then) {
        root.send("migrate-abandon", {}, function (d) {
            if (d.error) { root.status = root.errorWords(d); return; }
            root.migrationPending = false;
            if (then) then();
        });
    }

    // After tpm-cleared, damaged or an unfinished move: new keys, then sign in again
    // (startOverNote says what happens to the old files).
    function startOver() {
        root.send("reset", {}, function (d) {
            root.startOverConfirm = false;
            if (d.error) { root.status = root.errorWords(d); return; }
            root.migrationPending = false;
            root.vaultState = d.state || "empty";
            root.lockReason = "";
            root.status = "";
            v1Check.check();
        });
    }

    // "Move your keys onto the security chip": one .manage dialog, then the daemon rotates to
    // new keys sealed with the TPM. Only ever on this click.
    function moveToTpm() {
        if (root.tpmMoving) return;
        root.tpmMoving = true;
        root.send("tpm-move", {}, function (d) {
            root.tpmMoving = false;
            if (d.error) { root.showFlash(root.errorWords(d)); return; }
            root.sealedWith = d.sealed_with || "host+tpm2";
            root.tpmMove = false;
            root.showFlash("your keys are now sealed to this computer and its security chip");
        });
    }

    function signOut() {
        root.send("signout", {}, function (d) {
            if (d.error) { root.showFlash(root.errorWords(d)); return; }
            root.settingsOpen = false;
        });
    }

    // Back to the locked window, with nothing in it. Never re-prompts on its own.
    function lockApp(reason) {
        root.tagKept = null;
        root.endGrant();
        root.appUnlocked = false;
        root.autoAuthTried = true;
        root.authing = false;
        root.vaultState = root.vaultState === "unlocked" ? "locked" : root.vaultState;
        root.entries = []; root.filtered = [];
        root.selected = null; root.selectedId = "";
        root.editorOpen = false;
        edArea.text = ""; edSetup.text = "";
        crPass.text = ""; crNotes.text = ""; crSetup.text = "";
        root.totpPreview = ({});
        signinField.text = ""; codeField.text = ""; oldPass.text = "";
        root.settingsOpen = false;
        root.historyCheck = "";
        if (root.signinOpen && root.signinMode === "relogin") root.signinOpen = false;
        search.closeCats();
        root.catTag = null;
        root.takeFeatures(null);
        root.diagText = "";
        search.text = "";
        root.lockReason = "";
        root.status = reason === "screen-locked" ? "locked because the screen locked"
                    : reason === "sleep" ? "locked for sleep"
                    : reason === "idle" ? "locked after a while without use"
                    : reason === "signout" ? "signed out of iCloud"
                    : reason === "reset" ? ""
                    : reason === "error" ? "locked after an error" : "";
        if (reason === "signout") root.signedIn = false;
    }

    function setEntries(list_) {
        const keep = root.selectedId;
        // A tag nobody has any more (its last entry lost it on another device) goes.
        if (!Cat.stillValid(list_, root.features, root.catTag)) root.catTag = null;
        root.entries = list_;
        root.applyFilter(keep);
        if (root.snapshotPath) snapshotTimer.start();
    }

    function syncNow() {
        if (root.syncing) return;
        root.send("sync", {}, function (d) {
            if (d.queued) root.syncing = true;
            else if (d.skipped === "signed-out") root.showFlash("Not signed in to iCloud");
            else if (d.skipped === "needs-login") { root.needsLogin = true; root.showFlash("iCloud wants you to sign in again"); }
        });
    }

    // ---------------------------------------------------------------- the account grant
    // Everything that shows or changes a secret runs through here: if this account is not
    // open, the daemon opens its temporary buffer using this window's unlocked session.
    function withGrant(after) {
        if (!root.selected) return;
        if (root.unlocked) { if (after) after(); return; }
        const id = root.selectedId;
        const name = root.selected.primary;
        root.granting = true;
        root.status = "opening " + name + "…";
        root.grantRid = root.send("grant", { id: id }, function (d) {
            root.granting = false;
            root.grantRid = -1;
            if (d.error) {
                root.status = d.error === "cancelled" || d.error === "locked" ? "" : d.error;
                return;
            }
            root.status = "";
            if (id !== root.selectedId) { root.send("release", {}, null); return; }
            root.grantId = id;
            root.grantSingleUse = !!d.single_use;
            root.grantExpires = d.expires || 0;
            root.grantLeft = root.grantSingleUse ? 0 : Math.max(0, Math.ceil(root.grantExpires - Date.now() / 1000));
            if (after) after();
        });
    }

    // The grant ran out or was dropped: everything that came from it goes.
    function endGrant() {
        root.grantId = ""; root.grantExpires = 0; root.grantLeft = 0; root.grantSingleUse = false;
        root.forgetSecrets();
    }

    // Buffer expiry discards secret edits. Tags are list metadata and may be kept.
    function grantRanOut() {
        const kept = root.tagEditing && root.selectedId !== ""
            ? { id: root.selectedId, tags: root.tagDraft.slice(), typed: tagInput.text } : null;
        root.endGrant();
        root.tagKept = kept;
    }

    function hideSecrets() {
        root.revealed = "";
        root.totpCode = ""; root.totpLeft = 0;
        root.notesText = root.editorOpen && root.editorMode === "notes" ? root.notesText : "";
        root.notesLoaded = root.editorOpen && root.editorMode === "notes" ? root.notesLoaded : false;
        root.historyRows = []; root.revealedHistory = ({}); root.historyLoaded = false;
    }

    function forgetSecrets() {
        root.hideSecrets();
        root.notesText = ""; root.notesLoaded = false;
        root.confirming = false; root.changing = false; root.generateNew = false;
        root.renaming = false;
        if (!root.deleting) root.deleteConfirm = false;
        if (root.editorMode !== "create") {
            root.editorOpen = false;
            edArea.text = ""; edSetup.text = "";
            root.totpPreview = ({});
        }
        newPw.text = "";
        root.tagEditing = false; root.tagBusy = false; root.tagDraft = []; root.tagError = "";
        tagInput.text = "";
    }

    function secretShown() { hideTimer.restart(); }

    // ---------------------------------------------------------------- list
    function applyFilter(keep) {
        const q = search.text.trim().toLowerCase();
        // "2fa", "notes", "websites", "wifi": filter by kind rather than by those letters.
        const kind = root.searchKind(q);
        const out = [];
        for (const e of root.entries) {
            // The chip narrows first, with the same predicate its count in the drop-down uses.
            if (!Cat.matches(e, root.catTag)) continue;
            const hay = (e.primary + " " + e.title + " " + e.secondary + " " + e.domain
                         + " " + (e.sites || []).join(" ")
                         + ((e.tags || []).length ? " #" + e.tags.join(" #") : "")).toLowerCase();
            if (kind ? kind(e) : (!q || hay.indexOf(q) !== -1))
                out.push(e);
        }
        root.filtered = out;
        if (keep) {
            for (let i = 0; i < out.length; i++) {
                if (out[i].id === keep) {
                    root.cursor = i;
                    root.selected = out[i];
                    return;
                }
            }
        }
        root.cursor = out.length ? 0 : -1;
        if (out.length) root.select(out[0]); else root.clearSelection();
    }

    // From the drop-down, the chip's x or Backspace: the list follows at once, the query stays.
    function setCatTag(t) {
        root.catTag = t;
        root.applyFilter(root.selectedId);
    }

    function searchKind(q) {
        if (/^(2fa|mfa|otp|totp|(2fa|mfa|otp) codes?|codes?|verification codes?|two[- ]factor|2[- ]factor)$/.test(q))
            return function (e) { return e.has_totp; };
        if (/^(notes?|with notes|has notes)$/.test(q))
            return function (e) { return e.has_notes; };
        if (/^(websites?|sites?|urls?|with websites?)$/.test(q))
            return function (e) { return !e.is_wifi && (!e.no_site || (e.sites || []).length > 0); };
        if (/^(wi-?fi|wi fi|wlan|wireless|networks?|wi-?fi (passwords?|networks?)|airport)$/.test(q))
            return function (e) { return e.is_wifi; };
        return null;
    }

    function clearSelection() {
        if (root.grantId !== "" || root.granting) root.send("release", {}, null);
        root.tagKept = null;
        root.selected = null; root.selectedId = "";
        root.endGrant();
        root.detailIndex = 0;
    }

    // Selecting another account drops the open one: the daemon wipes its grant (and cancels a
    // dialog still waiting for it) and this window forgets what it showed.
    function select(e) {
        if (!e || e.id === root.selectedId) return;
        if (root.grantId !== "" || root.granting) root.send("release", {}, null);
        root.granting = false;
        root.tagKept = null;
        root.selected = e; root.selectedId = e.id;
        root.endGrant();
        root.detailIndex = 0;
    }

    function moveCursor(delta) {
        if (!root.filtered.length) return;
        root.cursor = Math.max(0, Math.min(root.filtered.length - 1, root.cursor + delta));
        root.select(root.filtered[root.cursor]);
        list.stopPhysics();
        list.positionViewAtIndex(root.cursor, ListView.Contain);
    }

    // ---------------------------------------------------------------- copy, reveal, codes
    function clipWords(field) {
        return field === "password" ? "Password" : field === "code" ? "Code"
             : field === "notes" ? "Notes" : field === "domain" ? "Website"
             : field === "text" ? "Selection" : "Username";
    }

    function copyField(field) {
        if (!root.selected) return;
        if (field === "password" && root.selected.has_password === false) { root.showFlash(root.noPassword); return; }
        const id = root.selectedId;
        const go = function () {
            root.send("copy", { id: id, field: field }, function (d) {
                if (d.error) { root.status = d.error === "no-grant" || d.error === "grant-expired"
                                   ? "that account closed — open it again" : d.error; return; }
                clipComponent.createObject(root, { ticket: d.ticket, words: root.clipWords(field),
                                                   running: true });
            });
        };
        if (field === "password" || field === "code" || field === "notes") root.withGrant(go); else go();
    }
    function copyPassword() { root.copyField("password"); }

    // A reply for an account you have since left, or whose buffer has since closed, is
    // dropped: a secret is shown only inside its own account's grant.
    function stillOpen(id) { return id === root.selectedId && root.grantId === id; }

    function doReveal() {
        if (root.selected && root.selected.has_password === false) { root.showFlash(root.noPassword); return; }
        root.withGrant(function () {
            if (root.revealed) { root.revealed = ""; return; }
            const id = root.selectedId;
            root.send("reveal", { id: id, field: "password" }, function (d) {
                if (!root.stillOpen(id)) return;
                if (d.error) { root.status = d.error; return; }
                root.revealed = d.value || "";
                root.hideAfter = d.hide_after || 20;
                root.secretShown();
            });
        });
    }

    function loadNotes(after) {
        root.withGrant(function () {
            if (root.notesLoaded || !root.selected.has_notes) { root.notesLoaded = true; if (after) after(); return; }
            const id = root.selectedId;
            root.send("reveal", { id: id, field: "notes" }, function (d) {
                if (!root.stillOpen(id)) return;
                if (d.error) { root.status = d.error; return; }
                root.notesText = d.value || ""; root.notesLoaded = true;
                root.hideAfter = d.hide_after || 20;
                root.secretShown();
                if (after) after();
            });
        });
    }

    function loadHistory() {
        root.withGrant(function () {
            const id = root.selectedId;
            root.send("history", { id: id }, function (d) {
                if (!root.stillOpen(id)) return;
                if (d.error) { root.status = d.error; return; }
                root.historyRows = d.items || [];
                root.historyLoaded = true;
                root.secretShown();
            });
        });
    }

    function loadTotp() {
        root.withGrant(function () {
            const id = root.selectedId;
            root.send("totp", { id: id }, function (d) {
                if (!root.stillOpen(id)) return;
                if (d.error) { root.status = d.error; return; }
                root.totpCode = d.code || "";
                root.totpLeft = Math.max(1, Math.round((d.valid_until || 0) - Date.now() / 1000));
                root.secretShown();
            });
        });
    }

    // ---------------------------------------------------------------- edits
    function setFields(fields, extra, done) {
        const id = root.selectedId;
        root.withGrant(function () {
            root.send("set", Object.assign({ id: id, fields: fields }, extra || {}), done);
        });
    }

    function saveNickname(value) {
        root.status = "renaming…";
        root.setFields({ nickname: value }, null, function (d) {
            root.status = "";
            if (d.error) { root.status = root.errorWords(d); return; }
            root.renaming = false;
            root.showFlash(!value ? (d.synced ? "name cleared on all your devices" : "name cleared")
                           : (d.synced ? "renamed on all your devices" : "renamed on this computer only"));
        });
    }

    // The new password is either typed here or generated by the daemon; a generated one never
    // comes to this window unless you reveal it afterwards.
    // Deletes the selected entry from iCloud Keychain, everywhere. Only after the inline
    // confirmation; the daemon then raises its own dialog (fingerprint or password).
    function deleteSelected() {
        if (!root.canDelete || !root.deleteConfirm || root.deleting) return;
        const id = root.selectedId;
        const name = root.selected.primary;
        root.deleting = true;
        root.send("delete", { id: id }, function (d) {
            root.deleting = false;
            if (d.error) {
                // Dismissing the dialog keeps the question up; anything else says why.
                if (d.error !== "dismissed" && d.error !== "cancelled") {
                    root.deleteConfirm = false;
                    root.showFlash(root.errorWords(d));
                }
                return;
            }
            root.deleteConfirm = false;
            if (root.selectedId === id) root.selectedId = "";
            root.showFlash("Deleted " + name + " from iCloud Keychain");
        });
    }

    function commitChange() {
        const pw = newPw.text;
        const gen = root.generateNew;
        root.confirming = false;
        root.status = "pushing to iCloud…";
        root.setFields(gen ? {} : { password: pw }, gen ? { generate: {} } : null, function (d) {
            root.status = "";
            newPw.text = ""; root.revealed = ""; root.historyRows = []; root.historyLoaded = false;
            root.changing = false; root.generateNew = false;
            if (d.error) { root.status = root.errorWords(d); return; }
            root.showFlash(gen ? "changed to a new generated password on all your devices — reveal it to see it"
                               : "changed on all your devices");
        });
    }

    function errorWords(d) {
        switch (d.error) {
        case "not-signed-in": return "not signed in to iCloud";
        case "needs-login": root.needsLogin = true; return "iCloud wants you to sign in again";
        case "anisette-unavailable": return "the local sign-in helper isn't running";
        case "network": return "iCloud couldn't be reached";
        case "apple": return "iCloud refused it" + (d.detail ? ": " + d.detail : "");
        case "busy-sync": return "a sync is running — try again in a moment";
        case "seal-unavailable": return "the system key service didn't answer — try again in a moment";
        case "seal-refused":
            return d.reason === "pcr-policy"
                ? "this computer has a signed boot policy (tpm2-pcr-public-key.pem), and systemd would tie new keys "
                  + "to it, so a boot without that signature could never open them. Pear refuses: nothing was saved. "
                  + "See \"TPM\" in the README"
                : "systemd sealed the keys in a way Pear doesn't recognise, so nothing was saved. "
                  + "See \"TPM\" in the README";
        case "migration-pending": return "the move from 1.x isn't finished — finish it or start fresh first";
        case "invalid":
            if (d.detail === "not-utf8")
                return "these notes aren't plain UTF-8 text, so Pear won't rewrite them to change the tags";
            return "that " + (d.field || "value") + " isn't valid";
        case "dismissed": case "cancelled": return "cancelled";
        case "denied": return "not approved";
        case "no-grant": case "grant-expired": return "that account closed — open it again";
        case "rate-limited": return "too many tries — wait " + (d.retry_after || 60) + " s";
        }
        return d.error || "failed";
    }

    function agoShort(unix) {
        const s = Math.max(0, Date.now() / 1000 - unix);
        if (s < 90) return "just now";
        if (s < 3600) return Math.round(s / 60) + " min ago";
        if (s < 86400) return Math.round(s / 3600) + " h ago";
        return Math.round(s / 86400) + " d ago";
    }

    function showFlash(text) {
        root.flash = text;
        flashTimer.restart();
    }

    // ---------------------------------------------------------------- sign-in
    // Driven entirely by the daemon's sign-in stream: it says what stage it is at and asks
    // typed questions; this draws them and answers. A step Apple adds later needs no change.
    function startSignin(mode) {
        root.signinMode = mode;
        root.signinOpen = true;
        root.signinRunning = true;
        root.signinStage = ""; root.signinNeed = ""; root.signinKind = "";
        root.signinDefault = ""; root.signinDetail = ""; root.signinOptions = [];
        root.signinChoice = -1; root.signinVia = "trusted"; root.signinCount = -1;
        root.signinVerified = false; root.signinError = ""; root.signinWarnings = [];
        root.signinLog = []; root.signinShowDetails = false; root.signinOutcome = "";
        root.signinDevice = ({}); root.signinAskId = -1;
        signinField.text = ""; codeField.text = "";
        root.signinRid = root.send("signin", { mode: mode }, function (d) {
            root.signinRunning = false;
            root.signinNeed = "";
            if (d.error === "cancelled") { root.signinOutcome = "cancelled"; root.signinOpen = false; return; }
            if (d.error) {
                root.signinOutcome = "error";
                if (!root.signinError) root.signinError = root.errorWords(d);
                return;
            }
            root.signinOutcome = "ok";
            root.signedIn = true;
            root.needsLogin = false;
            // A sign-in leaves the store unlocked on this connection: fetch the list (no
            // second dialog, the daemon knows this window is already in).
            root.authenticate();
        });
    }

    function onSigninEvent(m) {
        if (m.event === "ask") {
            root.signinAskId = m.ask_id;
            root.signinNeed = m.need || "text";
            root.signinKind = m.kind || "";
            root.signinDefault = m.default || "";
            root.signinDetail = m.detail || "";
            root.signinOptions = m.options || [];
            root.signinDetails = m.details || [];
            root.signinChoice = (m.options && m.options.length === 1) ? 0 : -1;
            signinField.text = root.signinKind === "apple_id" ? root.signinDefault : "";
            codeField.text = "";
            Qt.callLater(root.focusSignin);
            return;
        }
        if (m.event === "stage") {
            const info = m.info || {};
            if (m.stage === "device_chosen") {
                root.signinDevice = { name: info.name || "", model: info.model || "", secret: info.secret || "" };
                return;
            }
            root.signinStage = m.stage || "";
            if (info.via) root.signinVia = info.via;
            if (info.count !== undefined) root.signinCount = info.count;
            return;
        }
        // out: progress lines, shown only under "Details" if it fails
        if (m.kind === "err") root.signinError = m.text || "";
        if (m.kind === "warn") root.signinWarnings = root.signinWarnings.concat([m.text || ""]);
        root.signinLogPush(m.kind || "out", m.text || "");
    }

    function signinSend(value) {
        if (!root.signinRunning || root.signinNeed === "") return;
        if (root.signinKind === "code") root.signinVerified = true;
        root.send("answer", { ask_id: root.signinAskId, value: String(value) }, null);
        root.signinNeed = "";
        signinField.text = "";
        codeField.text = "";
    }

    function signinCancel() {
        if (root.signinRunning) {
            if (root.signinNeed !== "") root.send("answer", { ask_id: root.signinAskId, cancel: true }, null);
            else root.send("cancel", { target: root.signinRid }, null);
        }
        root.signinOpen = false;
        signinField.text = ""; codeField.text = "";
    }

    function signinLogPush(kind, text) {
        root.signinLog = root.signinLog.slice(-40).concat([{ kind: kind, text: text }]);
    }

    // ---------------------------------------------------------------- migration
    function migrateBegin() {
        root.migrateError = "";
        root.migrateStage = "";
        root.migrateRetry = false;
        root.migrateResult = ({});
        root.migrateStep = "running";
        root.send("migrate-begin", {}, function (d) {
            if (d.error) {
                root.migrateStep = "intro";
                root.migrateError = d.error === "dismissed" || d.error === "cancelled" ? ""
                                  : root.errorWords(d);
                return;
            }
            migrateProc.purge = false;
            migrateProc.ticket = d.ticket;
            migrateProc.options = JSON.stringify({ move_manifests: root.migrateManifests });
            migrateProc.running = true;
        });
    }

    function onMigrateLine(m) {
        if (!m) return;
        if (m.stage) { root.migrateStage = m.stage; root.migrateStep = "running"; return; }
        if (m.need === "keyring-locked") {
            // A keyring-keyed 1.x vault and a locked login keyring. Pear never asks the
            // keyring to unlock (that would be a second password dialog): the user unlocks it
            // the usual way and clicks "Check again", which only reads again.
            root.migrateRetry = !!m.retry;
            root.migrateStep = "keyring";
            return;
        }
        if (m.need === "passphrase") {
            root.migrateRetry = !!m.retry;
            root.migrateStep = "passphrase";
            oldPass.text = "";
            Qt.callLater(function () { oldPass.forceActiveFocus(); });
            return;
        }
        if (m.done) {
            root.migrateResult = Object.assign({}, root.migrateResult, m);
            root.migrateStep = "done";
            migrateProc.stdinEnabled = false;
            return;
        }
        if (m.error) {
            root.migrateError = m.error === "wrong-passphrase" ? "That passphrase didn't open your old vault."
                : m.error === "mismatch" ? "The converted copy didn't match your old vault, so nothing was changed. Your 1.x passwords are untouched."
                : m.error === "unsafe-file" ? "A file in ~/.config/icp isn't safe to read (" + (m.detail || "") + "). Nothing was changed."
                : m.error === "no-v1" ? "No 1.x vault was found to move."
                : m.error === "no-key" ? "Your 1.x vault's key isn't in your login keyring, so it can't be opened here. "
                                         + "Nothing was changed. You can start fresh instead: sign in to iCloud and your "
                                         + "passwords come back (local history and nicknames stay in the old vault)."
                : "Something went wrong" + (m.detail ? ": " + m.detail : ".");
            if (root.migrateStep !== "done") root.migrateStep = "error";
        }
    }

    function migratePassphrase() {
        if (!oldPass.text.length) return;
        migrateProc.write(JSON.stringify({ passphrase: oldPass.text }) + "\n");
        oldPass.text = "";
        root.migrateStep = "running";
    }

    function migrateCheckKeyring() {
        migrateProc.write(JSON.stringify({ check_keyring: true }) + "\n");
        root.migrateStep = "running";
        root.migrateStage = "keyring";
    }

    function migrateCancel() {
        if (migrateProc.running) migrateProc.write(JSON.stringify({ cancel: true }) + "\n");
        root.migrateStep = "intro";
    }

    function migrateFinish() {
        root.migrateStep = "";
        root.v1Present = false;
        root.migrationPending = false;
        root.signedIn = true;
        // migrate-begin opened the list on this connection; fetch it without a dialog.
        root.authenticate();
    }

    // ---------------------------------------------------------------- settings and cleanup
    function setSetting(key, value) {
        const s = {};
        s[key] = value;
        root.send("settings", { set: s }, function (d) {
            if (d.error) { root.showFlash("Couldn't change that setting"); return; }
            root.settings = d.settings;
            if (key === "window_mode" && !root.previewMode) windowModeProc.running = true;
        });
    }

    // On asks once (.manage); Off never asks and disconnects every autofill host.
    function setAutofill(on) {
        root.send("autofill-enable", { enabled: on }, function (d) {
            if (d.error) { root.showFlash(root.errorWords(d)); return; }
            root.autofillEnabled = !!(d.autofill && d.autofill.enabled);
            root.autofillHosts = (d.autofill && d.autofill.hosts) || 0;
        });
    }

    function purgeOldCopy() {
        root.purging = true;
        root.send("purge-old-copy", {}, function (d) {
            if (d.error) { root.purging = false; root.showFlash(root.errorWords(d)); return; }
            migrateProc.purge = true;
            migrateProc.ticket = d.ticket;
            migrateProc.running = true;
        });
    }

    function onPurgeLine(m) {
        if (!m) return;
        if (m.done) {
            root.oldCopy = null;
            const kept = (m.kept || []).length;
            root.showFlash(kept ? "Old copy deleted, except " + kept + " file(s) that changed since the move"
                                : "Old encrypted copy deleted");
        } else if (m.error) root.showFlash("Couldn't delete the old copy");
    }

    // The clipboard-history check, only on request: read Omarchy's history file, keep the
    // entries that could be a password, and let the daemon compare them by keyed hash. The
    // answer is positions only; nothing is removed from here.
    function checkClipboardHistory() {
        root.historyChecking = true;
        root.historyCheck = "";
        clipHistoryFile.path = "";
        clipHistoryFile.path = root.clipHistoryPath;
    }

    // ---- categories that wait for a check (Passkeys, Recently Deleted)
    // The unlock reply and every `synced` carry the flags; reading them never asks, so
    // Settings reads them again when it opens (it can be open while locked).
    function takeFeatures(f) {
        root.features = { passkeys: !!(f && f.passkeys), apple_deleted: !!(f && f.apple_deleted) };
    }
    function loadFeatures() {
        root.send("features", { get: true }, function (d) {
            if (!d.error) root.takeFeatures(d.features);
        });
    }
    // Either way is a change, and a change is a .manage dialog: the window alone never turns
    // one on. The daemon sends the list again with or without those rows.
    function setFeature(key, on) {
        const f = {};
        f[key] = on;
        root.featureBusy = true;
        root.send("features", { set: f }, function (d) {
            root.featureBusy = false;
            if (d.error) { root.showFlash(root.errorWords(d)); return; }
            root.takeFeatures(d.features);
        });
    }
    // What the last sync decrypted, as counts and attribute names (never a value), to check
    // the passkey and Recently Deleted names once before turning those on.
    function runDiag() {
        root.diagBusy = true;
        root.diagText = "";
        root.send("diag-items", {}, function (d) {
            root.diagBusy = false;
            if (d.error) { root.diagText = root.errorWords(d); return; }
            if (!d.available) {
                root.diagText = "Nothing to check yet: sync once since unlocking, then check again.";
                return;
            }
            root.diagText = (d.items || []).map(function (it) {
                return it.count + " × " + it["class"] + "  " + it.agrp
                     + "\n    names: " + (it.keys || []).join(", ")
                     + ((it.inner_keys || []).length ? "\n    inside: " + it.inner_keys.join(", ") : "");
            }).join("\n");
        });
    }
    onSettingsOpenChanged: if (root.settingsOpen && root.phase === "ready") root.loadFeatures()

    FileView {
        id: clipHistoryFile
        printErrors: false
        onLoaded: {
            let items = [], index = [];
            try {
                const h = JSON.parse(text());
                let size = 0;
                for (let i = 0; i < h.length && items.length < 1000; i++) {
                    const t = h[i] && h[i].type === "text" ? h[i].text : null;
                    // Passwords are one line without spaces; everything else is skipped, which
                    // also keeps the request under the daemon's line limit.
                    if (typeof t !== "string" || t.length < 4 || t.length > 256 || /\s/.test(t)) continue;
                    size += t.length + 8;
                    if (size > 56000) break;
                    items.push(t); index.push(i + 1);
                }
            } catch (e) {}
            clipHistoryFile.path = "";
            if (!items.length) {
                root.historyChecking = false;
                root.historyCheck = "Nothing in your clipboard history looks like a saved password.";
                return;
            }
            root.send("clip-history-check", { items: items }, function (d) {
                root.historyChecking = false;
                items = [];
                if (d.error) { root.historyCheck = d.error === "dismissed" ? "" : root.errorWords(d); return; }
                const pos = (d.matches || []).map(function (k) { return index[k]; });
                root.historyCheck = !pos.length ? "None of your saved passwords are in your clipboard history."
                    : pos.length + (pos.length === 1 ? " entry" : " entries")
                      + " in your clipboard history " + (pos.length === 1 ? "is" : "are")
                      + " a saved password (number " + pos.join(", ")
                      + " from the newest). Delete " + (pos.length === 1 ? "it" : "them")
                      + " in Omarchy's clipboard history.";
            });
        }
        onLoadFailed: {
            clipHistoryFile.path = "";
            root.historyChecking = false;
            root.historyCheck = "There's no clipboard history to check.";
        }
    }

    // ---------------------------------------------------------------- editor sheet
    function openEditor(mode) {
        root.editorMode = mode; root.editorError = ""; root.totpPreview = ({});
        root.editorBusy = false; root.createMore = false; root.createGenerate = false;
        edArea.text = mode === "sites" ? (root.selected ? (root.selected.sites || []).join("\n") : "")
                    : mode === "notes" ? root.notesText : "";
        edSetup.text = "";
        if (mode === "create") {
            crName.text = ""; crSite.text = ""; crUser.text = ""; crPass.text = "";
            crNotes.text = ""; crSetup.text = ""; crTags.text = "";
        }
        root.editorOpen = true;
        Qt.callLater(function () {
            if (mode === "create") crName.forceActiveFocus();
            else if (mode === "totp") edSetup.forceActiveFocus();
            else edArea.forceActiveFocus();
        });
    }
    function closeEditor() {
        if (root.editorBusy) return;
        root.editorOpen = false;
        edArea.text = ""; crPass.text = "";
    }

    function editorTitle() {
        switch (root.editorMode) {
        case "sites": return "Websites";
        case "notes": return "Notes";
        case "totp": return root.selected && root.selected.has_totp ? "Verification code" : "Set up a verification code";
        case "create": return "New password";
        }
        return "";
    }
    function editorReady() {
        if (root.editorBusy) return false;
        if (root.editorMode === "totp") return !!root.totpPreview.code;
        if (root.editorMode === "create")
            return (crPass.text.length > 0 || root.createGenerate)
                   && (crSite.text.trim().length > 0 || crName.text.trim().length > 0)
                   && (!crSetup.text.trim() || !!root.totpPreview.code)
                   && crTags.acceptableInput && root.parseTags(crTags.text) !== null;
        return true;
    }

    function editorSave() {
        if (!root.editorReady()) return;
        root.editorError = "";
        const mode = root.editorMode;
        const done = function (d) {
            root.editorBusy = false;
            if (d.error) { root.editorError = root.errorWords(d); return; }
            if (mode === "notes") { root.notesText = edArea.text.replace(/^\n+|\n+$/g, ""); root.notesLoaded = true; }
            if (mode === "totp") root.totpCode = "";
            root.editorOpen = false;
            edArea.text = ""; crPass.text = "";
            root.showFlash(mode === "create" ? "Added to iCloud Keychain" : "Saved to iCloud — on all your devices");
        };
        root.editorBusy = true;
        if (mode === "sites") {
            root.setFields({ sites: edArea.text.split("\n").map(function (s) { return s.trim(); })
                                         .filter(function (s) { return s; }) }, null, done);
        } else if (mode === "notes") {
            root.setFields({ notes: edArea.text }, null, done);
        } else if (mode === "totp") {
            root.setFields({ totp: { setup: edSetup.text } }, null, done);
        } else {
            const f = { title: crName.text, domain: crSite.text.trim(), username: crUser.text };
            if (crNotes.text) f.notes = crNotes.text;
            if (crSetup.text.trim()) f.totp = { setup: crSetup.text.trim() };
            const tags = root.parseTags(crTags.text) || [];
            if (tags.length) f.tags = tags;
            if (!root.createGenerate) f.password = crPass.text;
            root.send("create", root.createGenerate ? { fields: f, generate: {} } : { fields: f },
                      function (d) {
                          if (!d.error && d.id) root.selectedId = "";
                          done(d);
                      });
        }
    }
    function removeTotp() {
        root.editorError = ""; root.editorBusy = true;
        root.setFields({ totp: { remove: true } }, null, function (d) {
            root.editorBusy = false;
            if (d.error) { root.editorError = root.errorWords(d); return; }
            root.editorOpen = false; root.totpCode = "";
            root.showFlash("Verification code removed");
        });
    }
    function previewTotp(text) {
        if (!text.trim()) { root.totpPreview = ({}); return; }
        root.send("totp-preview", { setup: text }, function (d) {
            root.totpPreview = d && d.code ? d : ({ error: "" });
        });
    }
    function groupCode(c) { return c && c.length === 6 ? c.slice(0, 3) + " " + c.slice(3) : (c || ""); }

    // ---------------------------------------------------------------- links
    function openDomain(d) {
        if (!d) return;
        const url = String(d).replace(/^https?:\/\//, "").toLowerCase();
        if (!root.urlPattern.test(url)) { root.showFlash("That website can't be opened from here"); return; }
        opener.lua = "hl.dsp.exec_cmd(\"xdg-open https://" + url + "\")";
        opener.running = true;
    }

    function focusSignin() {
        if (root.signinKind === "code") codeField.forceActiveFocus();
        else if (root.signinNeed === "text" || root.signinNeed === "secret") {
            signinField.forceActiveFocus();
            signinField.selectAll();
        } else sheetKeys.forceActiveFocus();
    }

    function signinTitle() {
        if (root.signinOutcome === "ok" && root.signinStage === "not_joined") return "Signed in, not joined yet";
        if (root.signinOutcome === "ok") return root.signinMode === "relogin" ? "You're reconnected" : "You're signed in";
        if (root.signinOutcome === "error") return "Couldn't finish signing in";
        switch (root.signinKind) {
        case "code": return "Enter the verification code";
        case "device": return "Choose a device";
        case "join_confirm": return root.secretWord() === "password" ? "Join with your Mac's password"
                                                                     : "Join with a device passcode";
        case "device_passcode": return root.secretWord() === "password" ? "Enter your Mac's login password"
                                                                        : "Enter the device passcode";
        }
        if (root.signinNeed === "" && root.signinStep() === 2) return "Trusting this computer";
        if (root.signinNeed === "" && root.signinStage === "syncing") return "Syncing";
        return root.signinMode === "relogin" ? "Confirm it's you" : "Sign in to iCloud";
    }
    function signinSubtitle() {
        if (root.signinOutcome === "ok" && root.signinStage === "not_joined")
            return "No attempt was used. Sign in again when you're ready to join this computer to your keychain.";
        if (root.signinOutcome === "ok")
            return root.signinVerified ? "This computer is now trusted, so regular syncs shouldn't need a code."
                                       : "Your passwords are up to date.";
        if (root.signinOutcome === "error") return root.signinErrorText();
        if (root.signinNeed === "") return root.signinStatus();
        switch (root.signinKind) {
        case "apple_id":
        case "password":
            return root.signinMode === "relogin" ? "Your session expired. Sign in again to keep your passwords syncing."
                                              : "Pear Passwords uses your Apple Account to read your iCloud Keychain.";
        case "code":
            return root.signinVia === "sms" ? "A code was sent to your phone by text message."
                                            : "A code was sent to your other Apple devices.";
        case "device":
            return "Pick a device whose passcode (iPhone, iPad) or login password (Mac) you know. "
                 + "It's used once so this computer can join your keychain.";
        case "join_confirm":
            return "You'll be asked for the " + (root.secretWord() === "password" ? "login password" : root.secretWord())
                 + " of " + root.deviceName() + (root.signinDevice.model ? ", " + root.signinDevice.model : "") + ".";
        case "device_passcode":
            return root.signinDevice.model || "";
        }
        return "";
    }
    function signinPrimaryLabel() {
        if (root.signinOutcome === "ok") return "Done";
        if (root.signinOutcome === "error") return "Try again";
        if (root.signinNeed === "confirm") return "Continue";
        if (root.signinKind === "device_passcode") return "Join";
        if (root.signinKind === "password") return "Sign In";
        if (root.signinNeed !== "") return "Continue";
        return "";
    }
    function signinPrimaryReady() {
        if (root.signinOutcome !== "") return true;
        if (root.signinKind === "code") return codeField.text.length === 6;
        if (root.signinNeed === "choice") return root.signinChoice >= 0;
        if (root.signinNeed === "text" || root.signinNeed === "secret") return signinField.text.length > 0;
        return root.signinNeed === "confirm";
    }
    function signinPrimary() {
        if (root.signinOutcome === "ok") { root.signinOpen = false; return; }
        if (root.signinOutcome === "error") { root.startSignin(root.signinMode); return; }
        if (!root.signinPrimaryReady()) return;
        if (root.signinKind === "code") root.signinSend(codeField.text);
        else if (root.signinNeed === "choice") root.signinSend(root.signinChoice);
        else if (root.signinNeed === "confirm") root.signinSend("yes");
        else root.signinSend(signinField.text);
    }


    // The word follows the device: a Mac escrows with its login password, iPhone/iPad a passcode.
    function deviceName() { return root.signinDevice.name || root.signinDetail; }
    function secretWord() {
        // This is interpolated into the escrow warning, and signinDevice.secret comes off an
        // Apple API response rather than from here, so it is clamped to the words the rest of
        // this file branches on instead of being rendered as whatever arrives.
        const named = ["password", "passcode", "PIN"];
        if (named.indexOf(root.signinDevice.secret) >= 0) return root.signinDevice.secret;
        const d = root.signinDetail;
        if (/mac/i.test(d)) return "password";
        if (/iphone|ipad|ipod|vision|watch/i.test(d)) return "passcode";
        return "passcode or password";
    }
    function signinSteps() {
        return root.signinMode === "relogin" ? ["Verify", "Sync"] : ["Account", "Verify", "Trust", "Sync"];
    }
    // Which step of the indicator the current stage or question belongs to.
    function signinStep() {
        const k = root.signinKind, s = root.signinStage;
        if (root.signinStage === "not_joined") return 2;
        if (root.signinOutcome === "ok") return root.signinSteps().length;
        if (root.signinMode === "relogin") return (s === "syncing" || s === "synced") ? 1 : 0;
        if (s === "syncing" || s === "synced") return 3;
        if (s === "finding_devices" || s === "joining"
            || k === "device" || k === "join_confirm" || k === "device_passcode") return 2;
        if (s === "verify" || k === "code") return 1;
        return 0;
    }
    function signinStatus() {
        switch (root.signinStage) {
        case "signing_in": return "Signing in…";
        case "verify": return root.signinVia === "sms" ? "Sending a code by text message…"
                                                       : "Sending a code to your devices…";
        case "finding_devices": return "Finding your devices…";
        case "joining": return "Establishing trust — this can take a moment…";
        case "syncing": return "Syncing your passwords…";
        case "synced": return root.signinCount >= 0 ? "Synced " + root.signinCount + " passwords" : "Synced";
        default: return "Connecting…";
        }
    }
    function fieldLabel() {
        switch (root.signinKind) {
        case "apple_id": return "Apple Account";
        case "password": return "Password";
        case "device_passcode": return (root.secretWord() === "password" ? "Login password for "
                                                                         : "Lock screen passcode for ") + root.deviceName();
        default: return root.signinDetail || "";
        }
    }
    function fieldHelper() {
        switch (root.signinKind) {
        case "apple_id": return "The email or phone number you use with iCloud.";
        case "password": return "Saved encrypted on this computer so Pear Passwords can stay signed in.";
        case "device_passcode": return root.secretWord() === "password"
            ? "The password you log in to that Mac with right now - not your Apple Account password."
            : "The code you type to unlock that device right now - not the verification code.";
        default: return "";
        }
    }
    // The raw error, said plainly where we recognise it; the original stays under Details.
    function signinErrorText() {
        const e = root.signinError || "";
        if (/2FA rejected|code was rejected/i.test(e)) return "That code wasn't accepted. Try again to get a new one.";
        if (/no recoverable escrow bottle/i.test(e)) return "None of your devices can be used to join the keychain from here.";
        if (/join failed/i.test(e)) return "Couldn't join your iCloud Keychain. No attempt was used unless a passcode was entered.";
        if (/anisette|6969|connection refused/i.test(e)) return "Couldn't reach the local sign-in helper. Check that anisette is running.";
        return e.length ? e : "Sign-in didn't finish.";
    }

    // Only facts not already shown elsewhere in the pane.
    function metaLine() {
        if (!root.selected) return "";
        const parts = [];
        if (root.selected.mdat) parts.push("changed " + root.ago(root.selected.mdat));
        if (root.unlocked) parts.push(root.grantSingleUse ? "open for one use" : "open " + root.clock(root.grantLeft));
        return parts.join("   ·   ");
    }

    function fieldRows() {
        const s = root.selected;
        if (!s) return [];
        // Apple keeps these read-only (the daemon refuses a `set` on them): no edit is offered,
        // so an account buffer is not opened for an action that cannot happen.
        const readOnly = !!s.recently_deleted || s.kind === "passkey";
        const rows = [{ key: "username", label: s.is_wifi ? "Network" : "Username", value: s.username || "—",
                        quiet: !s.username, actions: [{ key: "username", label: "copy" }] },
                      { key: "password", label: "Password",
                        value: root.revealed ? root.revealed : "••••••••••••",
                        quiet: !root.revealed,
                        actions: [{ key: "view", label: root.revealed ? "hide" : "view" },
                                  { key: "change", label: "change" },
                                  { key: "password", label: "copy" }] }];
        if (s.has_password === false)
            rows[1] = { key: "none", label: "Password", value: "none — this account uses a passkey",
                        quiet: true, actions: [] };
        // Wi-Fi: Apple keeps no notes for a network (no details record in the WiFi zone), so
        // tags it carries (from a 1.x import) show read-only, and the daemon refuses to set them.
        if (s.is_wifi) {
            const wifiTags = s.tags || [];
            if (wifiTags.length)
                rows.push({ key: "tags", label: "Tags", value: "#" + wifiTags.join("  #"),
                            quiet: false, chips: wifiTags, actions: [] });
            return readOnly ? root.withoutEdits(rows) : rows;
        }
        const sites = root.allSites();
        if (!sites.length)
            rows.push({ key: "editsites", label: "Website", value: "Add a website", quiet: true, actions: [] });
        for (let i = 0; i < sites.length; i++)
            rows.push({ key: "open:" + i, label: i === 0 ? (sites.length > 1 ? "Websites" : "Website") : "",
                        value: sites[i],
                        actions: [{ key: "open:" + i, label: "open ↗" }].concat(
                            i === 0 ? [{ key: "editsites", label: "edit" }] : []) });
        if (s.has_totp)
            rows.push({ key: "totp", label: "Code",
                        value: root.totpCode ? root.totpCode : "show code",
                        quiet: !root.totpCode, actions: [{ key: "edittotp", label: "edit" }] });
        else
            rows.push({ key: "edittotp", label: "Code", value: "Set up verification code",
                        quiet: true, actions: [] });
        if (s.has_notes)
            rows.push({ key: "notes", label: "Notes",
                        value: root.notesLoaded ? (root.notesText.split("\n")[0] || "—") + (root.notesText.indexOf("\n") !== -1 ? "  …" : "") : "show notes",
                        quiet: !root.notesLoaded, actions: [{ key: "editnotes", label: "edit" }] });
        else
            rows.push({ key: "editnotes", label: "Notes", value: "Add notes", quiet: true, actions: [] });
        // Tags: list metadata (the notes' final "Tags:" line, read by the daemon at sync), so
        // they show without the account's grant; editing them is an edit and needs it.
        // Rows Apple keeps read-only (recently deleted, passkey-only) show them, nothing more.
        const tags = s.tags || [];
        rows.push({ key: readOnly ? "tags" : "edittags", label: "Tags",
                    value: root.tagEditing ? "editing below" : tags.length ? "#" + tags.join("  #")
                         : readOnly ? "—" : "Add tags",
                    quiet: !tags.length || root.tagEditing, chips: root.tagEditing ? [] : tags,
                    actions: tags.length && !readOnly ? [{ key: "edittags", label: "edit" }] : [] });
        return readOnly ? root.withoutEdits(rows) : rows;
    }
    function withoutEdits(rows) {
        for (let i = 0; i < rows.length; i++) {
            rows[i].actions = rows[i].actions.filter(function (a) {
                return a.key !== "change" && a.key.indexOf("edit") !== 0;
            });
            if (rows[i].key.indexOf("edit") === 0) { rows[i].key = "none"; rows[i].value = "—"; }
        }
        return rows;
    }

    // The entry's websites: the record's own site first (when it has one), then the extras.
    function allSites() {
        const s = root.selected;
        if (!s) return [];
        return (s.no_site ? [] : [s.domain]).concat(s.sites || []);
    }

    // Rows Apple keeps read-only (the daemon refuses a `set` on them): Recently Deleted copies
    // and passkey-only rows. Nothing on them may open an editor for an edit that cannot happen.
    function selectedReadOnly() {
        const s = root.selected;
        return !!s && (!!s.recently_deleted || s.kind === "passkey");
    }

    function fieldAction(key) {
        if (root.selectedReadOnly() && (key === "change" || key.indexOf("edit") === 0)) return;
        if (key === "username") root.copyField("username");
        else if (key === "password") root.copyPassword();
        else if (key === "view") root.doReveal();
        else if (key === "change")
            root.withGrant(function () {
                root.changing = true; root.generateNew = false;
                newPw.forceActiveFocus();
            });
        else if (key === "website") root.openDomain(root.selected.domain);
        else if (key.indexOf("open:") === 0) root.openDomain(root.allSites()[parseInt(key.slice(5))]);
        else if (key === "totp") root.loadTotp();
        else if (key === "editsites") root.withGrant(function () { root.openEditor("sites"); });
        else if (key === "edittotp") root.withGrant(function () { root.openEditor("totp"); });
        else if (key === "notes")
            root.loadNotes(root.notesLoaded && !root.selectedReadOnly()
                           ? function () { root.openEditor("notes"); } : null);
        else if (key === "editnotes") root.loadNotes(function () { root.openEditor("notes"); });
        else if (key === "edittags") root.withGrant(function () { root.openTagEditor(); });
    }

    // ---- tags --------------------------------------------------------------------------
    function openTagEditor() {
        if (!root.selected) return;
        const kept = root.tagKept;
        const fromKept = !!kept && kept.id === root.selectedId;
        root.tagKept = null;
        root.tagDraft = fromKept ? kept.tags : (root.selected.tags || []).slice();
        tagInput.text = fromKept ? kept.typed || "" : "";
        root.tagError = ""; root.tagBusy = false;
        root.tagEditing = true;
        Qt.callLater(function () { tagInput.forceActiveFocus(); });
    }
    function closeTagEditor() {
        if (root.tagBusy) return;
        root.tagEditing = false; root.tagDraft = []; root.tagError = "";
        tagInput.text = "";
    }
    // What is typed becomes a chip: the field only lets the grammar's characters in (letters,
    // marks, digits, - and _), this checks the rest; the daemon checks every tag again.
    function commitTagInput() {
        const raw = tagInput.text;
        if (raw === "" || raw === "#") { tagInput.text = ""; return true; }
        const t = Cat.canonTag(raw);
        if (!tagInput.acceptableInput || !t) { root.tagError = "a tag is 1 to 32 letters, digits, - or _"; return false; }
        const k = Cat.fold(t);
        for (const x of root.tagDraft)
            if (Cat.fold(x) === k) { tagInput.text = ""; return true; }
        if (root.tagDraft.length >= 16) { root.tagError = "at most 16 tags"; return false; }
        root.tagDraft = root.tagDraft.concat([t]);
        tagInput.text = "";
        root.tagError = "";
        return true;
    }
    // "work #family, side-project" -> canonical tags, or null when one breaks the grammar or
    // there are more than 16 (the daemon checks them again).
    function parseTags(text) {
        const out = [];
        for (const raw of String(text).split(/[\s,]+/)) {
            if (raw === "" || raw === "#") continue;
            const t = Cat.canonTag(raw);
            if (!t) return null;
            if (!out.some(function (x) { return Cat.fold(x) === Cat.fold(t); })) out.push(t);
        }
        return out.length > 16 ? null : out;
    }
    // What is wrong with the create form's Tags text, in commitTagInput's words; "" when nothing.
    function tagsProblem(text) {
        if (String(text).trim() === "" || root.parseTags(text) !== null) return "";
        for (const raw of String(text).split(/[\s,]+/))
            if (raw !== "" && raw !== "#" && !Cat.canonTag(raw)) return "a tag is 1 to 32 letters, digits, - or _";
        return "at most 16 tags";
    }
    function removeDraftTag(i) {
        const d = root.tagDraft.slice();
        d.splice(i, 1);
        root.tagDraft = d;
    }
    function saveTags() {
        if (root.tagBusy || !root.commitTagInput()) return;
        const tags = root.tagDraft.slice();
        root.tagBusy = true;
        root.tagError = "";
        root.setFields({ tags: tags }, null, function (d) {
            root.tagBusy = false;
            if (d.error) { root.tagError = root.errorWords(d); return; }
            root.tagEditing = false; root.tagDraft = [];
            root.showFlash("Tags saved to iCloud — on all your devices");
        });
    }

    // ---- keyboard: the detail panel -------------------------------------------------------
    // Stops, in order: every field row, then either each history row (loaded) or the single
    // "show" line, so a keyboard user can open history as well as read it.
    function panelStops() {
        return root.fieldCount + (root.historyLoaded ? root.historyRows.length : 1);
    }
    function enterPanel(at) {
        if (!root.selected || !root.appUnlocked) return;
        root.panelFocus = true;
        root.detailIndex = at === undefined ? 0 : Math.max(0, Math.min(at, root.panelStops() - 1));
        detailKeys.forceActiveFocus();
    }
    function searchFollowsPointer() {
        if (!listHover.hovered || search.activeFocus || !root.appUnlocked) return;
        if (root.editorOpen || root.settingsOpen || root.tagEditing || root.renaming
                || root.confirming || root.deleteConfirm) return;
        root.panelFocus = false;
        search.forceActiveFocus();
    }

    // A key nobody else took, with the pointer over the search field or the list: it continues
    // the search. Only printable text and Backspace, never with Ctrl/Alt/Super, and never while
    // an editor, Settings or a question is open.
    function typeToSearch(ev) {
        if (!listHover.hovered || search.activeFocus || !root.appUnlocked) return false;
        if (root.editorOpen || root.settingsOpen || root.tagEditing || root.renaming
                || root.confirming || root.deleteConfirm) return false;
        if (ev.modifiers & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)) return false;
        const backspace = ev.key === Qt.Key_Backspace;
        if (!backspace && !(ev.text.length === 1 && ev.text.charCodeAt(0) >= 32
                            && ev.text.charCodeAt(0) !== 127)) return false;
        root.leavePanel();
        search.cursorPosition = search.text.length;
        if (backspace) search.remove(Math.max(0, search.text.length - 1), search.text.length);
        else search.insert(search.cursorPosition, ev.text);
        return true;
    }

    function leavePanel() {
        root.panelFocus = false;
        search.forceActiveFocus();
    }
    function panelMove(delta) {
        const n = root.panelStops();
        const next = root.detailIndex + delta;
        if (next < 0 || next >= n) return false;       // let the caller decide what an edge means
        root.detailIndex = next;
        if (next >= root.fieldCount && root.historyLoaded)
            historyList.positionViewAtIndex(next - root.fieldCount, ListView.Contain);
        return true;
    }
    function toggleHistory(h) {
        const m = Object.assign({}, root.revealedHistory);
        m[h] = !m[h];
        root.revealedHistory = m;
        root.secretShown();
    }
    // Enter does exactly what a click on the row does.
    function panelActivate() {
        const rows = root.fieldRows(), k = root.detailIndex;
        if (k < rows.length) { root.fieldAction(rows[k].key); return; }
        if (!root.historyLoaded) { root.loadHistory(); return; }
        root.toggleHistory(k - rows.length);
    }
    // Space shows: the password on its row, a former password on a history row.
    function panelShow() {
        const rows = root.fieldRows(), k = root.detailIndex;
        if (k < rows.length && rows[k].key === "password") { root.doReveal(); return; }
        if (k >= rows.length && root.historyLoaded) { root.toggleHistory(k - rows.length); return; }
        root.panelActivate();
    }
    function fieldFocused(i) { return root.panelFocus && root.detailIndex === i; }


    // ---------------------------------------------------------------- helpers
    function clock(seconds) {
        const s = Math.max(0, seconds);
        return Math.floor(s / 60) + ":" + ("0" + (s % 60)).slice(-2);
    }

    function monogram(e) {
        const s = (e.primary || "").replace(/^www\./, "");
        const letters = s.replace(/[^A-Za-z0-9]/g, "");
        return (letters.substring(0, 2) || "?").toUpperCase();
    }
    function chipColor(e) {
        let h = 0;
        const s = e.primary || "";
        for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffff;
        return Qt.hsla((h % 360) / 360, 0.32, 0.42, 1.0);
    }
    function ago(unix) {
        if (!unix) return "";
        const days = (Date.now() / 1000 - unix) / 86400;
        if (days < 1) return "today";
        if (days < 30) return Math.round(days) + "d ago";
        if (days < 365) return Math.round(days / 30) + "mo ago";
        return Math.round(days / 365) + "y ago";
    }
    function isRecent(unix) { return unix && (Date.now() / 1000 - unix) < 30 * 86400; }

    FloatingWindow {
        id: win
        title: "Pear Passwords"
        implicitWidth: 960
        implicitHeight: 640
        color: Theme.bg
        // Hidden until the rules are in and the daemon has answered (or a moment has passed),
        // so a second launch that only raises the first window never flashes on screen.
        visible: root.windowReady && (root.phase !== "connecting" || root.connectGrace)
        onClosed: Qt.quit()

        Rectangle { anchors.fill: parent; color: Theme.bg }

        FocusScope {
            id: scope
            anchors.fill: parent
            focus: true

            // Painted inside the scope rather than beside it, so a grab of the scope (the
            // offscreen snapshot) includes the real background instead of transparency.
            Rectangle { anchors.fill: parent; color: Theme.bg; z: -1 }

            Keys.onPressed: function (ev) {
                if (ev.key === Qt.Key_Escape) {
                    if (root.confirming) { root.confirming = false; }
                    else if (root.revealed) { root.revealed = ""; }
                    else if (root.settingsOpen) { root.settingsOpen = false; }
                    else if (search.text.length) { search.text = ""; }
                    else if (root.catTag) { root.setCatTag(null); }
                    else Qt.quit();
                    ev.accepted = true;
                } else if (ev.key === Qt.Key_Down) { root.moveCursor(1); ev.accepted = true; }
                else if (ev.key === Qt.Key_Up) { root.moveCursor(-1); ev.accepted = true; }
                else if (ev.key === Qt.Key_PageDown) { root.moveCursor(10); ev.accepted = true; }
                else if (ev.key === Qt.Key_PageUp) { root.moveCursor(-10); ev.accepted = true; }
                else if (ev.key === Qt.Key_Return || ev.key === Qt.Key_Enter) {
                    if (root.confirming) root.commitChange(); else root.copyPassword();
                    ev.accepted = true;
                } else if (ev.key === Qt.Key_Space && ev.modifiers & Qt.ControlModifier) {
                    root.doReveal(); ev.accepted = true;
                } else if (ev.key === Qt.Key_L && ev.modifiers & Qt.ControlModifier) {
                    root.lockNow(); ev.accepted = true;
                } else if (root.typeToSearch(ev)) {
                    ev.accepted = true;
                }
            }

            ColumnLayout {
                id: mainColumn
                anchors.fill: parent
                spacing: 0
                // Blurred behind a dialog; rendered to a layer only while it is. The software
                // renderer has no shader effects (the layer would draw nothing), so there it
                // stays plainly dimmed.
                layer.enabled: root.dialogT > 0.001 && GraphicsInfo.api !== GraphicsInfo.Software
                layer.effect: MultiEffect {
                    blurEnabled: true
                    blur: root.dialogT
                    blurMax: 40
                    autoPaddingEnabled: false
                }

                // Any program of yours can run the autofill role once autofill is on, so the
                // window says when one is connected: a dialog for a fill you did not ask your
                // browser for is then one to deny.
                Rectangle {
                    Layout.fillWidth: true
                    visible: root.autofillHosts > 0
                    implicitHeight: 30
                    color: Theme.panel
                    Text {
                        textFormat: Text.PlainText
                        anchors.fill: parent
                        anchors.leftMargin: 14
                        anchors.rightMargin: 10
                        verticalAlignment: Text.AlignVCenter
                        text: "A browser autofill host is connected. Approve a fill only when you just asked your browser for one."
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        elide: Text.ElideRight
                    }
                }

                // Apple wants an interactive sign-in. This used to be a desktop notification
                // telling you to run a terminal command, which is a dead end with nowhere to
                // type the code.
                Rectangle {
                    Layout.fillWidth: true
                    visible: root.appUnlocked && (root.needsLogin || (!root.signedIn && root.entries.length > 0)) && !root.signinOpen
                    implicitHeight: 38
                    color: Theme.panel
                    Rectangle { anchors.left: parent.left; anchors.top: parent.top
                                anchors.bottom: parent.bottom; width: 3; color: Theme.danger }
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 14
                        anchors.rightMargin: 10
                        spacing: 10
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.signedIn ? "Apple needs you to sign in again — your passwords are not syncing"
                                                : "Not signed in to iCloud — these are the passwords saved on this computer"
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            elide: Text.ElideRight
                        }
                        AppButton {
                            text: "Sign in"
                            onClicked: root.startSignin(root.signedIn ? "relogin" : "login")
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: 0

                    // ------------------------------------------------ list
                    ColumnLayout {
                        id: listColumn
                        Layout.fillWidth: false
                        // 380, not 340: at 340 7% of usernames elided; at 380 none do. The list
                        // is where the time goes - the panel mostly confirms what was picked.
                        Layout.preferredWidth: 380
                        Layout.minimumWidth: 380
                        Layout.maximumWidth: 380
                        Layout.fillHeight: true
                        spacing: 0
                        // Typing while the pointer is over the search field or the list goes into
                        // the search field, wherever the keyboard focus was (the window's Keys).
                        HoverHandler {
                            id: listHover
                            // The pointer moving over the search field or the list hands the keyboard
                            // to the search field, so whatever had it before, typing lands there.
                            onHoveredChanged: if (hovered) root.searchFollowsPointer()
                            onPointChanged: root.searchFollowsPointer()
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: 58
                            // Above the list, so the search's drop-down draws over it.
                            z: 2
                            color: Theme.panel
                            // Plain text in the corner, no box: a search that looks like a form
                            // field makes the whole window read as a dialog.
                            // New entry: a word in the corner, like the search it sits beside.
                            Text {
                                textFormat: Text.PlainText
                                id: newButton
                                anchors.right: parent.right
                                anchors.rightMargin: 16
                                anchors.verticalCenter: parent.verticalCenter
                                visible: root.appUnlocked && root.signedIn
                                text: "+ New"
                                color: hNew.hovered ? Theme.fg : Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                HoverHandler { id: hNew; cursorShape: Qt.PointingHandCursor }
                                TapHandler { onTapped: root.openEditor("create") }
                            }
                            // Hover it (or Alt+Down, or a leading '#') for the categories and
                            // tags; the chosen one sits before the query as a chip
                            // (CategorySearch.qml). Down/Up/Enter/Tab keep their list meanings.
                            CategorySearch {
                                id: search
                                anchors.fill: parent
                                anchors.leftMargin: 14
                                anchors.rightMargin: newButton.visible ? newButton.width + 28 : 14
                                enabled: root.appUnlocked
                                opacity: root.appUnlocked ? 1 : 0.6
                                // Nothing drops down behind a sheet (their dim takes no hover).
                                available: !root.editorOpen && !root.settingsOpen && !root.signinOpen
                                // The status bar under the window (24 px): the rows scroll above it.
                                bottomReserve: statusBar.height
                                // The drop-down keeps its left edge by the avatars and reaches the
                                // list column's right edge, so no row's highlight or icons show
                                // beside it.
                                panel.width: parent.width - search.x - search.panel.x
                                entries: root.entries
                                features: root.features
                                tag: root.catTag
                                placeholderText: !root.appUnlocked ? "Locked"
                                    : root.entries.length === 0 ? "No passwords"
                                    : root.catTag ? "Search " + Cat.count(root.entries, root.catTag) + " "
                                                    + Cat.chipText(root.catTag)
                                    : "Search " + Cat.count(root.entries, null) + " passwords"
                                color: Theme.fg
                                placeholderTextColor: Theme.dim
                                background: Rectangle { color: "transparent" }
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                focus: true
                                onTextChanged: root.applyFilter(root.selectedId)
                                onTagPicked: (t) => root.setCatTag(t)
                                onMoveRequested: (delta) => root.moveCursor(delta)
                                onCopyRequested: root.copyPassword()
                                onTabbed: root.enterPanel(0)
                            }
                        }

                        ListView {
                            id: list
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: root.appUnlocked
                            clip: true
                            // Scrolling is ours, not Flickable's. A mouse notch glides instead of
                            // jumping; a touchpad follows the fingers 1:1 and stretches past the
                            // ends with resistance, then springs back when the fingers lift.
                            // interactive:false is what hands wheel events to the handler below -
                            // with it on, Flickable took them too and scrolled twice.
                            interactive: false
                            readonly property real minY: originY
                            readonly property real maxY: Math.max(originY, originY + contentHeight - height)

                            // ---- Apple's scroll physics --------------------------------------------
                            // decelRate: UIScrollView.DecelerationRate.normal, per millisecond. Speed
                            //   decays exponentially, v = v0 * 0.998^t - fast start, long smooth tail.
                            // bandC: the rubber-band constant from UIScrollView,
                            //   f(x) = (1 - 1/(x*c/d + 1)) * d - the further past an end, the less it gives.
                            // springOmega: bounce-back is a critically damped spring (damping 1.0, as in
                            //   WWDC "Designing Fluid Interfaces"), 0.4 s response, carrying the flick's speed.
                            // accelMax: the one part that is NOT Apple's published curve. macOS accelerates
                            //   fast scrolls in the OS and hasn't documented how; libinput deliberately
                            //   doesn't accelerate touchpad scrolling at all. Slow stays 1:1, fast gains up
                            //   to (1 + accelMax)x. If sensitivity feels off, this is the knob.
                            readonly property real decelRate: 0.998
                            readonly property real bandC: 0.55
                            readonly property real springOmega: 2 * Math.PI / 400
                            readonly property real accelMax: 1.6

                            property string mode: "idle"      // idle | drag | coast | bounce
                            property real vel: 0              // px/ms along contentY
                            property real rawY: 0             // where the fingers put it, before the band
                            property real bounceTarget: 0
                            property var samples: []
                            property real lastT: 0
                            property real glideTo: 0

                            function band(x) { const d = list.height; return (1 - 1 / (x * list.bandC / d + 1)) * d; }
                            function unband(y) {
                                const d = list.height;
                                return y >= d * 0.999 ? y * 50 : y * d / (list.bandC * (d - y));
                            }
                            function banded(raw) {
                                if (raw < list.minY) return list.minY - list.band(list.minY - raw);
                                if (raw > list.maxY) return list.maxY + list.band(raw - list.maxY);
                                return raw;
                            }
                            function unbanded(y) {
                                if (y < list.minY) return list.minY - list.unband(list.minY - y);
                                if (y > list.maxY) return list.maxY + list.unband(y - list.maxY);
                                return y;
                            }

                            // Continuous input (touchpad) is tracked through the physics above; a
                            // discrete mouse notch glides to an accumulating target. A value that isn't a
                            // multiple of 120 is continuous even when pixelDelta is empty.
                            WheelHandler {
                                acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
                                onWheel: function (ev) {
                                    const px = ev.pixelDelta.y, ad = ev.angleDelta.y;
                                    // The lift carries no movement, so catch it before "did it move".
                                    if (ev.phase === Qt.ScrollEnd) { list.letGo(); return; }
                                    if (px !== 0 || ad % 120 !== 0) {
                                        glide.stop();
                                        list.pushBy(px !== 0 ? -px : -ad / 120 * 60);
                                        endTimer.restart();
                                    } else if (ad !== 0) {
                                        list.mode = "idle";
                                        const base = glide.running ? list.glideTo : list.contentY;
                                        list.glideTo = Math.max(list.minY, Math.min(list.maxY, base - ad / 120 * 110));
                                        glide.to = list.glideTo;
                                        glide.restart();
                                    }
                                }
                            }
                            NumberAnimation { id: glide; target: list; property: "contentY"
                                              duration: 240; easing.type: Easing.OutCubic }
                            // Fingers lifted, for input paths that never send ScrollEnd.
                            Timer { id: endTimer; interval: 90; onTriggered: list.letGo() }
                            // Integrated per frame, not fitted to an easing curve: exact at any refresh rate.
                            FrameAnimation {
                                running: list.mode === "coast" || list.mode === "bounce"
                                onRunningChanged: list.movingFor = 0
                                onTriggered: {
                                    const dt = Math.min(frameTime * 1000, 34);
                                    list.movingFor += dt;
                                    // Momentum is a flick's tail, never a state: after 3 s, settle in bounds.
                                    if (list.movingFor > 3000) { list.settle(); return; }
                                    list.step(dt);
                                }
                            }
                            property real movingFor: 0

                            function pushBy(dy) {
                                const now = Date.now();
                                if (list.mode !== "drag") {     // fingers down: take over from any coast
                                    list.mode = "drag";
                                    list.vel = 0;
                                    list.rawY = list.unbanded(list.contentY);
                                    list.samples = [];
                                    list.lastT = now;
                                }
                                const dt = Math.max(1, now - list.lastT);
                                list.lastT = now;
                                const speed = Math.abs(dy) / dt;                      // px/ms
                                const gain = 1 + list.accelMax * Math.max(0, Math.min(1, (speed - 0.35) / 2.2));
                                const moved = dy * gain;
                                list.samples = list.samples.filter(function (s) { return now - s.t < 160; })
                                                           .concat([{ t: now, dy: moved }]);
                                list.rawY += moved;
                                list.contentY = list.banded(list.rawY);
                            }

                            function letGo() {
                                endTimer.stop();
                                if (list.mode !== "drag") return;
                                const s = list.samples;
                                list.samples = [];
                                let v = 0;
                                if (s.length >= 3) {
                                    // speed between the first and last movement, never to "now"
                                    const last = s[s.length - 1].t;
                                    const w = s.filter(function (x) { return last - x.t <= 110; });
                                    if (w.length >= 3) {
                                        let travelled = 0;
                                        for (let k = 1; k < w.length; k++) travelled += w[k].dy;
                                        v = travelled / Math.max(8, last - w[0].t);
                                    }
                                }
                                list.vel = Math.max(-8, Math.min(8, v));
                                if (list.contentY < list.minY || list.contentY > list.maxY) list.startBounce();
                                else list.mode = Math.abs(list.vel) > 0.02 ? "coast" : "idle";
                            }

                            function startBounce() {
                                list.bounceTarget = list.contentY < list.minY ? list.minY : list.maxY;
                                list.mode = "bounce";
                            }

                            function step(dt) {
                                if (list.mode === "coast") {
                                    const decay = Math.pow(list.decelRate, dt);
                                    list.contentY += list.vel * (decay - 1) / Math.log(list.decelRate);
                                    list.vel *= decay;
                                    if (list.contentY < list.minY || list.contentY > list.maxY) list.startBounce();
                                    else if (Math.abs(list.vel) < 0.01) { list.vel = 0; list.mode = "idle"; }
                                    return;
                                }
                                if (list.mode === "bounce") {
                                    // ListView only estimates contentHeight for a long list and corrects it
                                    // as rows are made, so the ends move: aim at where they are now, and
                                    // stop once back inside (a stale target was chased for ever).
                                    if (list.contentY >= list.minY && list.contentY <= list.maxY
                                            && Math.abs(list.vel) < 0.05) {
                                        list.vel = 0;
                                        list.mode = "idle";
                                        return;
                                    }
                                    list.bounceTarget = list.contentY < list.minY ? list.minY
                                                      : list.contentY > list.maxY ? list.maxY : list.bounceTarget;
                                    // exact critically damped step: x(t) = (x0 + (v0 + w*x0) t) e^(-wt)
                                    const w = list.springOmega;
                                    const x0 = list.contentY - list.bounceTarget, v0 = list.vel;
                                    const e = Math.exp(-w * dt), B = v0 + w * x0;
                                    const x = (x0 + B * dt) * e;
                                    list.vel = (v0 - w * B * dt) * e;
                                    list.contentY = list.bounceTarget + x;
                                    if (Math.abs(x) < 0.3 && Math.abs(list.vel) < 0.02) {
                                        list.contentY = list.bounceTarget;
                                        list.vel = 0;
                                        list.mode = "idle";
                                    }
                                }
                            }

                            // Fingers landed mid-coast (touch_watch.py): stop dead. A bounce is let
                            // through, or it would strand the list stretched past an end.
                            function catchCoast() {
                                glide.stop();
                                if (list.mode === "coast") {
                                    list.vel = 0;
                                    if (list.contentY < list.minY || list.contentY > list.maxY) list.startBounce();
                                    else list.mode = "idle";
                                }
                            }

                            function stopPhysics() {
                                glide.stop();
                                list.vel = 0;
                                list.mode = "idle";
                            }
                            // Stop and put the view inside its bounds as they are now.
                            function settle() {
                                list.stopPhysics();
                                list.contentY = Math.max(list.minY, Math.min(list.maxY, list.contentY));
                            }
                            // New rows (a sync, a delete, a filter): whatever was moving was moving over
                            // the old list, so it stops here.
                            onModelChanged: list.settle()
                            model: root.filtered
                            currentIndex: root.cursor
                            ScrollBar.vertical: AppScrollBar {}

                            delegate: Rectangle {
                                required property var modelData
                                required property int index
                                width: list.width
                                height: 58
                                color: index === root.cursor ? Theme.selected
                                     : hov.hovered ? Qt.darker(Theme.hover, 1.3) : "transparent"

                                HoverHandler { id: hov }
                                TapHandler {
                                    onTapped: { root.leavePanel(); root.cursor = index; root.select(modelData); }
                                    onDoubleTapped: root.copyPassword()
                                }

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 10
                                    anchors.rightMargin: 10
                                    spacing: 10

                                    // identity chip: deterministic from the name, never a
                                    // fetched favicon - that would tell every one of these
                                    // sites that you hold an account there.
                                    Rectangle {
                                        Layout.preferredWidth: 34
                                        Layout.preferredHeight: 34
                                        radius: Theme.radius
                                        color: root.chipColor(modelData)
                                        Text {
                                            textFormat: Text.PlainText
                                            anchors.centerIn: parent
                                            text: root.monogram(modelData)
                                            color: "#ffffff"
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                            font.bold: true
                                        }
                                    }

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 1
                                        RowLayout {
                                            Layout.fillWidth: true
                                            spacing: 6
                                            Text {
                                                textFormat: Text.PlainText
                                                Layout.fillWidth: true
                                                text: modelData.primary
                                                color: Theme.fg
                                                font.family: Theme.uiFont
                                                font.pixelSize: Theme.fBody
                                                elide: Text.ElideRight
                                            }
                                            Rectangle {
                                                visible: root.isRecent(modelData.mdat)
                                                width: 6; height: 6; radius: Theme.radius
                                                color: Theme.accent
                                            }
                                        }
                                        Text {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            visible: text.length > 0
                                            // The account first; "no website" only when there is nothing else to say.
                                            text: modelData.is_wifi ? "Wi-Fi network"
                                                : modelData.no_site && !modelData.secondary
                                                ? ((modelData.sites || []).length ? modelData.sites[0] : "no website")
                                                : modelData.ambiguous
                                                    ? modelData.secondary + " · " + root.ago(modelData.mdat)
                                                    : modelData.secondary
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                            elide: Text.ElideRight
                                        }
                                    }

                                    Text {
                                        textFormat: Text.PlainText
                                        visible: modelData.has_totp
                                        text: "⧗"
                                        color: Theme.dim
                                        font.pixelSize: Theme.fBody
                                    }
                                }
                            }
                        }

                        // Locked: rows with no content. Widths come from the row index, never
                        // from the entries - the backend has not sent any.
                        Column {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: !root.appUnlocked
                            topPadding: 6
                            spacing: 0
                            Repeater {
                                model: 13
                                delegate: Item {
                                    required property int index
                                    width: parent ? parent.width : 0
                                    height: 58
                                    Rectangle {
                                        x: 14; anchors.verticalCenter: parent.verticalCenter
                                        width: 34; height: 34; radius: Theme.radius
                                        color: Theme.selected
                                    }
                                    Rectangle {
                                        x: 62; y: 18; height: 11; radius: 2
                                        width: 70 + (index * 47) % 130
                                        color: Theme.selected
                                    }
                                    Rectangle {
                                        x: 62; y: 34; height: 9; radius: 2
                                        width: 50 + (index * 71) % 100
                                        color: Qt.rgba(Theme.selected.r, Theme.selected.g,
                                                       Theme.selected.b, Theme.selected.a * 0.6)
                                    }
                                }
                            }
                        }
                    }

                    Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.line }

                    // ------------------------------------------------ detail
                    //
                    // One rule governs this pane: say each thing once. The name lives in the
                    // header, the username in its row, the site in its row. Rows are flat and
                    // only light up under the pointer - what you can do with a row is shown
                    // when you point at it, not painted permanently on every one.
                    Item {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        Item {
                            id: detailKeys
                            Keys.onPressed: function (ev) {
                                const shift = ev.modifiers & Qt.ShiftModifier;
                                const k = ev.key;
                                if (k === Qt.Key_Down || (k === Qt.Key_Tab && !shift)) {
                                    // Tab past the last row wraps back to the list; Down just stops.
                                    if (!root.panelMove(1) && k === Qt.Key_Tab) root.leavePanel();
                                } else if (k === Qt.Key_Up || k === Qt.Key_Backtab || (k === Qt.Key_Tab && shift)) {
                                    if (!root.panelMove(-1) && k !== Qt.Key_Up) root.leavePanel();
                                } else if (k === Qt.Key_Escape || k === Qt.Key_Left) {
                                    root.leavePanel();
                                } else if (k === Qt.Key_Return || k === Qt.Key_Enter) {
                                    root.panelActivate();
                                } else if (k === Qt.Key_Space) {
                                    root.panelShow();
                                } else if (ev.text.length === 1 && ev.text.trim().length === 1
                                           && !(ev.modifiers & (Qt.ControlModifier | Qt.AltModifier))) {
                                    // typing always means search - don't strand the keyboard here
                                    root.leavePanel();
                                    search.insert(search.cursorPosition, ev.text);
                                } else {
                                    return;                        // let the window handle the rest
                                }
                                ev.accepted = true;
                            }
                        }

                        ColumnLayout {
                            anchors.centerIn: parent
                            width: Math.min(parent.width - 80, 420)
                            visible: !root.appUnlocked
                            spacing: 14
                            // Everything here is greyed except the one thing you can do. A locked
                            // screen shouldn't shout its own state louder than the way out of it.
                            Text {
                                textFormat: Text.PlainText
                                Layout.alignment: Qt.AlignHCenter
                                text: root.screen === "no-agent" ? "The unlock dialog isn't available"
                                                                 : "Pear Passwords is locked"
                                color: Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fHeading
                            }
                            Text {
                                textFormat: Text.PlainText
                                Layout.fillWidth: true
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.Wrap
                                text: root.screen === "no-agent"
                                    ? "Your desktop shell may be restarting. Try again in a moment, or run "
                                      + "omarchy restart shell."
                                    : root.authing
                                    ? "Waiting for your fingerprint or password. Nothing appeared? Retry"
                                    : "Click anywhere, or press Unlock, and use your fingerprint or password"
                                color: Theme.dim
                                opacity: 0.65
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                            }
                            // Never disabled. If a prompt is pending and nothing appeared, this is
                            // the way out - so it has to stay pressable and say so.
                            AppButton {
                                Layout.alignment: Qt.AlignHCenter
                                Layout.topMargin: 6
                                text: root.authing ? "Retry" : root.screen === "no-agent" ? "Try again" : "Unlock"
                                onClicked: root.authing ? root.retryAuth() : root.authenticate()
                            }
                        }

                        // First run: nothing to show yet, and the one thing to do about it.
                        ColumnLayout {
                            anchors.centerIn: parent
                            width: Math.min(parent.width - 80, 360)
                            visible: root.appUnlocked && root.entries.length === 0
                            spacing: 10
                            Text {
                                textFormat: Text.PlainText
                                Layout.alignment: Qt.AlignHCenter
                                text: "No passwords yet"
                                color: Theme.fg
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fHeading
                            }
                            Text {
                                textFormat: Text.PlainText
                                Layout.fillWidth: true
                                horizontalAlignment: Text.AlignHCenter
                                text: root.signedIn
                                    ? "Your iCloud Keychain has nothing saved in it yet."
                                    : "Sign in to iCloud to bring in the passwords saved on your iPhone, iPad and Mac."
                                color: Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                lineHeight: 1.15
                                wrapMode: Text.Wrap
                            }
                            AppButton {
                                Layout.alignment: Qt.AlignHCenter
                                Layout.topMargin: 10
                                visible: !root.signedIn
                                active: true
                                text: "Sign in to iCloud"
                                onClicked: root.startSignin("login")
                            }
                        }

                        Text {
                            textFormat: Text.PlainText
                            anchors.centerIn: parent
                            visible: root.appUnlocked && !root.selected && root.entries.length > 0
                            text: "Select an entry"
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                        }

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 28
                            anchors.rightMargin: 28
                            anchors.topMargin: 26
                            anchors.bottomMargin: 16
                            spacing: 0
                            visible: !!root.selected

                            // ---- identity: the chip, the name, one quiet line of facts
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: false
                                spacing: 14

                                Rectangle {
                                    Layout.preferredWidth: 42
                                    Layout.preferredHeight: 42
                                    Layout.alignment: Qt.AlignTop
                                    radius: Theme.radius
                                    color: root.selected ? root.chipColor(root.selected) : "transparent"
                                    Text {
                                        textFormat: Text.PlainText
                                        anchors.centerIn: parent
                                        text: root.selected ? root.monogram(root.selected) : ""
                                        color: "#ffffff"
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fBody
                                        font.bold: true
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 10
                                        Text {
                                            textFormat: Text.PlainText
                                            visible: !root.renaming
                                            Layout.fillWidth: true
                                            text: root.selected ? root.selected.primary : ""
                                            color: Theme.fg
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fHeading
                                            elide: Text.ElideRight
                                            HoverHandler { id: hTitle }
                                            // No rename on a read-only row: the edit always fails.
                                            MouseArea {
                                                anchors.fill: parent
                                                enabled: !root.selectedReadOnly()
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: if (!root.selectedReadOnly()) root.withGrant(function () {
                                                    nickField.text = root.selected.nickname
                                                        || root.selected.title;
                                                    root.renaming = true;
                                                    nickField.forceActiveFocus();
                                                    nickField.selectAll();
                                                })
                                            }
                                        }
                                        Text {
                                            textFormat: Text.PlainText
                                            visible: !root.renaming
                                            text: "rename"
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                            opacity: hTitle.hovered && !root.selectedReadOnly() ? 1 : 0
                                        }
                                        O.TextField {
                                            id: nickField
                                            visible: root.renaming
                                            Layout.fillWidth: true
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fHeading
                                            onAccepted: root.saveNickname(text)
                                            Keys.onEscapePressed: root.renaming = false
                                        }
                                        AppButton {
                                            visible: root.renaming
                                            text: "Save"
                                            onClicked: root.saveNickname(nickField.text)
                                        }
                                        Text {
                                            textFormat: Text.PlainText
                                            visible: root.renaming && root.selected && root.selected.nickname
                                            text: "reset"
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                            MouseArea {
                                                anchors.fill: parent
                                                anchors.margins: -6
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: root.saveNickname("")
                                            }
                                        }
                                    }

                                    // The facts that are not already shown elsewhere, as text -
                                    // no pills. "Unlocked" belongs here rather than as a badge
                                    // because it is state, not identity.
                                    Text {
                                        textFormat: Text.PlainText
                                        Layout.fillWidth: true
                                        text: root.metaLine()
                                        visible: text.length > 0
                                        color: Theme.dim
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fSmall
                                        elide: Text.ElideRight
                                    }
                                }
                            }

                            Item { Layout.preferredHeight: 26 }

                            // ---- fields: flat rows, the value is the action
                            Repeater {
                                model: root.fieldRows()
                                delegate: Item {
                                    id: frow
                                    required property var modelData
                                    required property int index
                                    readonly property bool keyed: root.fieldFocused(index)
                                    Layout.fillWidth: true
                                    // Grows with the tag chips when they wrap onto more lines.
                                    implicitHeight: chipFlow.visible ? Math.max(48, chipFlow.implicitHeight + 22) : 48

                                    HoverHandler { id: hRow }
                                    Rectangle {
                                        anchors.fill: parent
                                        anchors.leftMargin: -12
                                        anchors.rightMargin: -12
                                        radius: Theme.radius
                                        color: hRow.hovered || frow.keyed ? Theme.selected : "transparent"
                                        // Keyboard focus gets a mark of its own, so it stays findable
                                        // while the pointer is lighting up some other row.
                                        Rectangle {
                                            visible: frow.keyed
                                            x: 0; width: 2; radius: 1
                                            anchors.top: parent.top; anchors.bottom: parent.bottom
                                            anchors.topMargin: 10; anchors.bottomMargin: 10
                                            color: Theme.fg
                                        }
                                    }
                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: { root.enterPanel(frow.index); root.fieldAction(frow.modelData.key); }
                                    }
                                    RowLayout {
                                        anchors.fill: parent
                                        spacing: 18
                                        Text {
                                            textFormat: Text.PlainText
                                            Layout.preferredWidth: 88
                                            text: frow.modelData.label
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                        }
                                        Text {
                                            id: fieldValue
                                            // A revealed password or a TOTP code: never on
                                            // the accessibility bus (docs/security.md 3).
                                            Accessible.ignored: true
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            visible: !(frow.modelData.chips && frow.modelData.chips.length)
                                            text: frow.modelData.value
                                            color: frow.modelData.quiet ? Theme.dim : Theme.fg
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            elide: Text.ElideRight
                                        }
                                        // Tags as chips, the way the search field shows one. They wrap
                                        // onto more lines (up to 16 tags): none is ever cut off.
                                        Flow {
                                            id: chipFlow
                                            visible: !!frow.modelData.chips && frow.modelData.chips.length > 0
                                            Layout.fillWidth: true
                                            spacing: 6
                                            Repeater {
                                                model: frow.modelData.chips || []
                                                delegate: Rectangle {
                                                    required property var modelData
                                                    width: tagChip.implicitWidth + 16
                                                    height: tagChip.implicitHeight + 6
                                                    radius: 9
                                                    color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
                                                    Text {
                                                        id: tagChip
                                                        textFormat: Text.PlainText
                                                        anchors.centerIn: parent
                                                        text: "#" + modelData
                                                        color: Theme.fg
                                                        font.family: Theme.uiFont
                                                        font.pixelSize: Theme.fBody - 1
                                                    }
                                                }
                                            }
                                        }
                                        // Secondary actions: declared on top, so a click on one
                                        // is taken here and never reaches the row's own action.
                                        Repeater {
                                            model: frow.modelData.actions
                                            delegate: Text {
                                                textFormat: Text.PlainText
                                                required property var modelData
                                                text: modelData.label
                                                color: hAct.hovered ? Theme.fg : Theme.dim
                                                font.family: Theme.uiFont
                                                font.pixelSize: Theme.fSmall
                                                opacity: hRow.hovered || frow.keyed || modelData.sticky ? 1 : 0
                                                HoverHandler { id: hAct }
                                                MouseArea {
                                                    anchors.fill: parent
                                                    anchors.margins: -8
                                                    cursorShape: Qt.PointingHandCursor
                                                    onClicked: root.fieldAction(modelData.key)
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // other sites this login is offered on, as plain links
                            Flow {
                                Layout.fillWidth: true
                                Layout.topMargin: 2
                                spacing: 0
                                visible: root.selected && root.selected.aliases && root.selected.aliases.length > 0
                                Text {
                                    textFormat: Text.PlainText
                                    text: "also on   "
                                    color: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                }
                                Repeater {
                                    model: root.selected ? root.selected.aliases : []
                                    delegate: Text {
                                        textFormat: Text.PlainText
                                        required property var modelData
                                        required property int index
                                        text: (index > 0 ? "  ·  " : "") + modelData
                                        color: hAl.hovered ? Theme.fg : Theme.dim
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fSmall
                                        font.underline: hAl.hovered
                                        HoverHandler { id: hAl }
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.openDomain(modelData)
                                        }
                                    }
                                }
                            }

                            // ---- tags: chips you can remove, and a field for new ones (the grant
                            // is open while this shows; Save is one `set`, pushed to iCloud)
                            ColumnLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: false
                                Layout.topMargin: 12
                                spacing: 8
                                visible: root.tagEditing

                                Rectangle {
                                    Layout.fillWidth: true
                                    implicitHeight: tagFlow.implicitHeight + 16
                                    radius: Theme.radius
                                    color: "transparent"
                                    border.width: 1
                                    border.color: tagInput.activeFocus ? Theme.accent : Theme.line
                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.IBeamCursor
                                        onClicked: tagInput.forceActiveFocus()
                                    }
                                    Flow {
                                        id: tagFlow
                                        x: 8; y: 8
                                        width: parent.width - 16
                                        spacing: 6
                                        Repeater {
                                            model: root.tagDraft
                                            delegate: Rectangle {
                                                required property var modelData
                                                required property int index
                                                width: draftRow.width + 16
                                                height: 26
                                                radius: 9
                                                color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
                                                Row {
                                                    id: draftRow
                                                    x: 8
                                                    anchors.verticalCenter: parent.verticalCenter
                                                    spacing: 5
                                                    Text {
                                                        textFormat: Text.PlainText
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        text: "#" + modelData
                                                        color: Theme.fg
                                                        font.family: Theme.uiFont
                                                        font.pixelSize: Theme.fBody - 1
                                                    }
                                                    Text {
                                                        textFormat: Text.PlainText
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        text: "×"
                                                        color: hDraftX.hovered ? Theme.fg : Theme.dim
                                                        font.family: Theme.uiFont
                                                        font.pixelSize: Theme.fBody
                                                        HoverHandler { id: hDraftX; cursorShape: Qt.PointingHandCursor }
                                                        TapHandler { onTapped: root.removeDraftTag(index) }
                                                    }
                                                }
                                            }
                                        }
                                        TextInput {
                                            id: tagInput
                                            width: Math.max(140, Math.min(contentWidth + 12, tagFlow.width))
                                            height: 26
                                            verticalAlignment: TextInput.AlignVCenter
                                            color: Theme.fg
                                            selectionColor: Theme.selected
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            // The grammar's characters only (features spec 5b.2);
                                            // Space, comma and Enter end a tag instead.
                                            validator: RegularExpressionValidator {
                                                regularExpression: /^#?[\p{L}\p{M}\p{N}_-]{0,32}$/
                                            }
                                            onTextChanged: root.tagError = ""
                                            Keys.onPressed: function (ev) {
                                                const k = ev.key;
                                                if (k === Qt.Key_Escape) root.closeTagEditor();
                                                else if (k === Qt.Key_Return || k === Qt.Key_Enter) {
                                                    if (tagInput.text !== "") root.commitTagInput();
                                                    else root.saveTags();
                                                } else if (k === Qt.Key_Space || k === Qt.Key_Comma || ev.text === ",")
                                                    root.commitTagInput();
                                                else if (k === Qt.Key_Backspace && tagInput.text === "" && root.tagDraft.length)
                                                    root.removeDraftTag(root.tagDraft.length - 1);
                                                else return;
                                                ev.accepted = true;
                                            }
                                            Text {
                                                textFormat: Text.PlainText
                                                anchors.verticalCenter: parent.verticalCenter
                                                visible: tagInput.text === ""
                                                text: root.tagDraft.length ? "add a tag" : "work, family, side-project…"
                                                color: Theme.dim
                                                font.family: Theme.uiFont
                                                font.pixelSize: Theme.fBody
                                            }
                                        }
                                    }
                                }
                                // What a tag is not, in short: docs/security.md 2 has the full sentence.
                                Text {
                                    textFormat: Text.PlainText
                                    Layout.fillWidth: true
                                    text: "Tags show after the first unlock, like names and usernames — don't put secrets in them."
                                    color: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    wrapMode: Text.Wrap
                                }
                                Text {
                                    textFormat: Text.PlainText
                                    Layout.fillWidth: true
                                    visible: root.tagBusy || root.tagError !== ""
                                    text: root.tagBusy ? "Saving to iCloud and checking it arrived…" : root.tagError
                                    color: root.tagBusy ? Theme.dim : Theme.danger
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    wrapMode: Text.Wrap
                                }
                                RowLayout {
                                    spacing: 8
                                    AppButton {
                                        active: true
                                        text: "Save"
                                        enabled: !root.tagBusy
                                        onClicked: root.saveTags()
                                    }
                                    AppButton {
                                        text: "Cancel"
                                        enabled: !root.tagBusy
                                        onClicked: root.closeTagEditor()
                                    }
                                }
                            }

                            // ---- change password: hidden until asked for
                            ColumnLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: false
                                Layout.topMargin: 16
                                spacing: 10
                                visible: root.changing || root.confirming

                                RowLayout {
                                    Layout.fillWidth: true
                                    visible: !root.confirming
                                    spacing: 8
                                    O.TextField {
                                        id: newPw
                                        Accessible.ignored: true
                                        // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                                        // clipboard history): Ctrl+C and the menu's Copy go through root.copyText; Ctrl+X does nothing.
                                        Keys.onPressed: (event) => root.guardSecretKeys(event, "new-password", newPw)
                                        ContextMenu.menu: secretMenu
                                        ContextMenu.onRequested: secretMenu.aim(newPw, "new-password")
                                        // No IME learning, no prediction (pear-exec also keeps input methods and the
                                        // primary selection away from the window).
                                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                                        Layout.fillWidth: true
                                        visible: !root.generateNew
                                        placeholderText: "New password"
                                        password: true
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fBody
                                        onAccepted: if (text.length) root.confirming = true
                                    }
                                    // A generated password is made by the daemon and never comes
                                    // here unless you reveal it afterwards.
                                    Text {
                                        textFormat: Text.PlainText
                                        Layout.fillWidth: true
                                        visible: root.generateNew
                                        text: "Pear will generate a strong password in Apple's style"
                                        color: Theme.fg
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fBody
                                        elide: Text.ElideRight
                                    }
                                    AppButton {
                                        text: root.generateNew ? "Type one" : "Generate"
                                        onClicked: { root.generateNew = !root.generateNew; newPw.text = ""; }
                                    }
                                    AppButton {
                                        text: "Change…"
                                        enabled: (newPw.text.length > 0 || root.generateNew) && !root.busy
                                        onClicked: root.confirming = true
                                    }
                                    Text {
                                        textFormat: Text.PlainText
                                        text: "cancel"
                                        color: Theme.dim
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fSmall
                                        MouseArea {
                                            anchors.fill: parent
                                            anchors.margins: -8
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: { root.changing = false; newPw.text = ""; root.generateNew = false; }
                                        }
                                    }
                                }

                                // confirmation: this writes to every Apple device you own
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    visible: root.confirming
                                    spacing: 10
                                    Text {
                                        textFormat: Text.PlainText
                                        Layout.fillWidth: true
                                        text: "Change this password on every device signed into your iCloud account?"
                                        color: Theme.fg
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fBody
                                        wrapMode: Text.Wrap
                                    }
                                    Text {
                                        textFormat: Text.PlainText
                                        Layout.fillWidth: true
                                        text: "current password   →   " + (root.generateNew ? "a generated password" : "the one you typed")
                                        color: Theme.dim
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fSmall
                                        elide: Text.ElideRight
                                    }
                                    RowLayout {
                                        spacing: 8
                                        AppButton { text: "Change it"; onClicked: root.commitChange() }
                                        AppButton { text: "Cancel"; onClicked: root.confirming = false }
                                    }
                                }
                            }

                            // ---- history: the one locked section, so it carries the lock
                            // (out of the way while the tag editor takes its room)
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: false
                                Layout.topMargin: 30
                                visible: !root.tagEditing
                                spacing: 10
                                Text {
                                    textFormat: Text.PlainText
                                    text: "History"
                                    color: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    font.letterSpacing: 0.6
                                }
                                Item { Layout.fillWidth: true }
                                Text {
                                    textFormat: Text.PlainText
                                    visible: !root.historyLoaded && !!root.selected && root.selected.history_count > 0
                                    text: "show"
                                    readonly property bool keyed: root.panelFocus && !root.historyLoaded
                                                                  && root.detailIndex === root.fieldCount
                                    color: hUnlock.hovered || keyed ? Theme.fg : Theme.dim
                                    font.underline: keyed
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    HoverHandler { id: hUnlock }
                                    MouseArea {
                                        anchors.fill: parent
                                        anchors.margins: -8
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: root.loadHistory()
                                    }
                                }
                            }

                            Text {
                                textFormat: Text.PlainText
                                Layout.fillWidth: true
                                Layout.topMargin: 10
                                visible: !!root.selected && !root.tagEditing && (root.selected.history_count === 0
                                         || (root.historyLoaded && root.historyRows.length === 0))
                                text: "No changes recorded yet."
                                color: Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                            }

                            Item {
                                Layout.fillHeight: true
                                visible: !(root.historyLoaded && root.historyRows.length > 0) || root.tagEditing
                            }

                            // The list is widened 12px each side and its text inset by the same,
                            // so a hovered row's fill bleeds past the column exactly like the
                            // field rows above while the text stays aligned with them. It can't
                            // just bleed outward like those: the list clips its own bounds.
                            Item {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.topMargin: 6
                                visible: root.historyLoaded && root.historyRows.length > 0 && !root.tagEditing
                            ListView {
                                id: historyList
                                anchors.fill: parent
                                anchors.leftMargin: -12
                                anchors.rightMargin: -12
                                clip: true
                                model: root.historyRows
                                ScrollBar.vertical: AppScrollBar {}
                                // Masked per row: this is a list of former passwords, so it
                                // must not be less protected than the live one. Click a row
                                // to see it - no button column.
                                delegate: Item {
                                    id: hrow
                                    required property var modelData
                                    required property int index
                                    readonly property bool keyed: root.fieldFocused(root.fieldCount + index)
                                    width: ListView.view ? ListView.view.width : 0
                                    height: 52
                                    HoverHandler { id: hH }
                                    Rectangle {
                                        anchors.fill: parent
                                        radius: Theme.radius
                                        color: hH.hovered || hrow.keyed ? Theme.selected : "transparent"
                                        Rectangle {
                                            visible: hrow.keyed
                                            x: 0; width: 2; radius: 1
                                            anchors.top: parent.top; anchors.bottom: parent.bottom
                                            anchors.topMargin: 10; anchors.bottomMargin: 10
                                            color: Theme.fg
                                        }
                                    }
                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: root.toggleHistory(hrow.index)
                                    }
                                    ColumnLayout {
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.leftMargin: 12
                                        anchors.rightMargin: 12
                                        anchors.verticalCenter: parent.verticalCenter
                                        spacing: 3
                                        Text {
                                            textFormat: Text.PlainText
                                            text: Qt.formatDateTime(new Date(hrow.modelData.date), "d MMM yyyy") + "   "
                                                  + (hrow.modelData.source === "local" ? "seen changing here" : "from Apple")
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                        }
                                        Text {
                                            id: historyValue
                                            Accessible.ignored: true
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            text: root.revealedHistory[hrow.index]
                                                ? (hrow.modelData.value || "")
                                                : "••••••••••••"
                                            color: root.revealedHistory[hrow.index] ? Theme.fg : Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            elide: Text.ElideRight
                                        }
                                    }
                                }
                            }
                            }

                            // ---- delete: the whole consequence in words, then the dialog
                            ColumnLayout {
                                Layout.fillWidth: true
                                Layout.topMargin: 14
                                spacing: 10
                                visible: root.canDelete && !root.tagEditing
                                Text {
                                    textFormat: Text.PlainText
                                    visible: !root.deleteConfirm
                                    text: "Delete…"
                                    color: hDelete.hovered ? Theme.danger : Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    HoverHandler { id: hDelete; cursorShape: Qt.PointingHandCursor }
                                    TapHandler { onTapped: root.deleteConfirm = true }
                                }
                                Text {
                                    textFormat: Text.PlainText
                                    visible: root.deleteConfirm
                                    Layout.fillWidth: true
                                    wrapMode: Text.WordWrap
                                    text: "Delete " + (root.selected ? root.selected.primary : "")
                                          + " from iCloud Keychain on all your devices? Its password history goes"
                                          + " with it, and it won't be in Recently Deleted on your Apple devices."
                                    color: Theme.fg
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                }
                                RowLayout {
                                    visible: root.deleteConfirm
                                    spacing: 8
                                    AppButton {
                                        text: root.deleting ? "Deleting…" : "Delete"
                                        enabled: !root.deleting
                                        onClicked: root.deleteSelected()
                                    }
                                    AppButton {
                                        text: "Cancel"
                                        enabled: !root.deleting
                                        onClicked: root.deleteConfirm = false
                                    }
                                }
                            }
                        }
                    }
                }

                // ------------------------------------------------ status bar
                Rectangle {
                    id: statusBar
                    Layout.fillWidth: true
                    implicitHeight: 24
                    color: root.flash ? Theme.hover : Theme.panel
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 12
                        anchors.rightMargin: 12
                        spacing: 14
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            visible: !clipCountdown.visible
                            text: root.flash ? root.flash
                                : root.status ? root.status
                                : !root.appUnlocked ? "locked"
                                : root.entries.length === 0 ? ""
                                : root.filtered.length + " of " + Cat.count(root.entries, null) + " shown"
                            color: root.flash ? Theme.accent : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            elide: Text.ElideRight
                            opacity: root.appUnlocked || root.flash ? 1 : 0.45
                        }
                        // The live clipboard offer and how long it stays: "Password on clipboard · 27 s".
                        // It takes the main slot rather than a slot of its own (a narrow window has
                        // no room for both), once the "copied" toast, which says the same, is gone.
                        Text {
                            id: clipCountdown
                            textFormat: Text.PlainText
                            visible: root.clipLive && !root.flash
                            Layout.fillWidth: true
                            text: root.clipLabel + " on clipboard · " + root.clipLeft + " s"
                            color: Theme.accent
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            elide: Text.ElideLeft
                        }
                        // The one open account and how long it stays open: "GitHub open 1:58".
                        Text {
                            textFormat: Text.PlainText
                            visible: root.unlocked
                            Layout.maximumWidth: 260
                            text: (root.selected ? root.selected.primary : "")
                                  + (root.grantSingleUse ? " open for one use" : " open " + root.clock(root.grantLeft))
                            color: Theme.accent
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            elide: Text.ElideMiddle
                        }
                        Text {
                            textFormat: Text.PlainText
                            visible: root.appUnlocked && root.signedIn
                            text: root.syncing ? "syncing…"
                                : root.syncedAt > 0 ? "synced " + root.agoShort(root.syncedAt) : "sync now"
                            color: hSync.hovered ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hSync.hovered && !root.syncing
                            HoverHandler { id: hSync; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.syncNow() }
                        }
                        // Only while unlocked: signing in raises a dialog of its own and needs the
                        // window to be the authenticated one.
                        Text {
                            textFormat: Text.PlainText
                            visible: root.appUnlocked && (!root.signedIn || root.needsLogin)
                            text: "sign in…"
                            color: hSign.hovered ? Theme.accent : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hSign.hovered
                            HoverHandler { id: hSign; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.startSignin(root.signedIn ? "relogin" : "login") }
                        }
                        Text {
                            textFormat: Text.PlainText
                            visible: root.appUnlocked
                            text: "settings"
                            color: hSettings.hovered ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hSettings.hovered
                            HoverHandler { id: hSettings; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.settingsOpen = true }
                        }
                        Text {
                            textFormat: Text.PlainText
                            visible: root.appUnlocked
                            text: "lock"
                            color: hLockNow.hovered ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hLockNow.hovered
                            HoverHandler { id: hLockNow; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.lockNow() }
                        }
                        Text {
                            textFormat: Text.PlainText
                            visible: root.entries.length > 0 && !root.unlocked
                            text: root.panelFocus
                                ? "↑↓ move   ⏎ copy / open   ␣ show   esc list"
                                : "↑↓ move   ⏎ copy   ⇥ details   esc back"
                            opacity: root.appUnlocked ? 1 : 0.45
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                        }
                    }
                }
            }
        }

        // Copy, Paste and Select All for the fields that hold a secret and may be copied (the
        // Apple ID password, the 2FA code and the 1.x passphrase have no menu at all). Copy is
        // root.copyText: the daemon and pear-clip, never Qt's clipboard. There is no Cut.
        // Drawn like the category drop-down: Theme font and colours, padded rows, the accent
        // under the row the pointer or keyboard is on, a hairline border.
        Menu {
            id: secretMenu
            parent: scope
            property Item target: null
            property string source: ""
            function aim(field, source_) { secretMenu.target = field; secretMenu.source = source_; }
            padding: 6
            font.family: Theme.uiFont
            font.pixelSize: Theme.fBody
            background: Rectangle {
                implicitWidth: 200
                color: Theme.bg
                border.width: 1
                border.color: Theme.line
                radius: Theme.radius
            }
            delegate: MenuItem {
                id: secretItem
                implicitWidth: 188
                implicitHeight: 34
                leftPadding: 10
                rightPadding: 10
                font: secretMenu.font
                indicator: null
                arrow: null
                contentItem: Text {
                    textFormat: Text.PlainText
                    text: secretItem.text
                    font: secretItem.font
                    color: secretItem.enabled ? Theme.fg : Theme.dim
                    verticalAlignment: Text.AlignVCenter
                    elide: Text.ElideRight
                }
                background: Rectangle {
                    radius: Theme.radius
                    color: secretItem.highlighted && secretItem.enabled
                        ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.24)
                        : "transparent"
                }
            }
            Action {
                text: "Copy"
                enabled: !!secretMenu.target && secretMenu.source !== ""
                         && secretMenu.target.selectedText !== ""
                onTriggered: root.copyText(secretMenu.source, secretMenu.target.selectedText)
            }
            Action {
                text: "Paste"
                enabled: !!secretMenu.target && secretMenu.target.canPaste
                onTriggered: secretMenu.target.paste()
            }
            Action {
                text: "Select All"
                enabled: !!secretMenu.target && secretMenu.target.length > 0
                onTriggered: secretMenu.target.selectAll()
            }
        }

        // Locked: the whole window is the way back in. Under the sheets (z 90/100) so a
        // sign-in or an editor still takes its own clicks.
        MouseArea {
            parent: scope
            z: 50
            anchors.fill: parent
            enabled: root.screen === "locked" && !root.authing && !root.signinOpen && !root.editorOpen
            visible: enabled
            cursorShape: Qt.PointingHandCursor
            onClicked: root.authenticate()
        }

        // ---------------------------------------------------------------- dialog backdrop
        // Shared by the sheets below (they are transparent now): it darkens as the view blurs.
        Rectangle {
            parent: scope
            z: 87
            anchors.fill: parent
            visible: root.dialogT > 0.001
            color: Qt.rgba(0, 0, 0, 0.55 * root.dialogT)
        }

        // ---------------------------------------------------------------- editor sheet
        // Websites, notes, verification code and new entries: one card in the sign-in sheet's
        // style. Every save goes to iCloud and is read back before the sheet closes.
        Rectangle {
            parent: scope
            z: 90
            anchors.fill: parent
            visible: root.editorOpen
            color: "transparent"
            MouseArea { anchors.fill: parent; onClicked: root.closeEditor() }

            Rectangle {
                id: editorCard
                anchors.centerIn: parent
                width: Math.min(parent.width - 80, 520)
                height: Math.min(edSheet.implicitHeight + 60, parent.height - 40)
                radius: Theme.radius
                color: Theme.bg
                border.width: 1
                border.color: Theme.line
                clip: true
                MouseArea { anchors.fill: parent }          // clicks inside don't close it

                Keys.onPressed: function (ev) {
                    if (ev.key === Qt.Key_Escape) { root.closeEditor(); ev.accepted = true; }
                    else if ((ev.key === Qt.Key_Return || ev.key === Qt.Key_Enter)
                             && (ev.modifiers & Qt.ControlModifier)) { root.editorSave(); ev.accepted = true; }
                }

                ColumnLayout {
                    id: edSheet
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: 30
                    spacing: 0

                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        text: root.editorTitle()
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Math.round(Theme.fHeading * 1.25)
                        font.weight: Font.DemiBold
                        wrapMode: Text.Wrap
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 6
                        visible: text !== ""
                        text: root.editorMode === "create" ? "Saved to your iCloud Keychain, so it reaches your other devices."
                            : root.editorMode === "totp" ? "Paste the setup key or otpauth:// link from the site's two-factor settings, or scan its QR code."
                            : root.selected ? root.selected.primary : ""
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fBody
                        wrapMode: Text.Wrap
                        lineHeight: 1.15
                    }

                    // ---- websites / notes: one text area
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 22
                        spacing: 8
                        visible: root.editorMode === "sites" || root.editorMode === "notes"
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            visible: root.editorMode === "sites" && root.selected && !root.selected.no_site
                            text: "Main website   " + (root.selected ? root.selected.domain : "")
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            elide: Text.ElideRight
                        }
                        Text {
                            textFormat: Text.PlainText
                            text: root.editorMode === "sites"
                                  ? (root.selected && !root.selected.no_site ? "Other websites" : "Websites") : "Notes"
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: root.editorMode === "notes" ? 170 : 120
                            radius: Theme.radius
                            color: "transparent"
                            border.width: 1
                            border.color: edArea.activeFocus ? Theme.accent : Theme.line
                            ScrollView {
                                anchors.fill: parent
                                anchors.margins: 1
                                TextArea {
                                    textFormat: TextArea.PlainText
                                    id: edArea
                                    Accessible.ignored: true
                                    // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                                    // clipboard history): Ctrl+C and the menu's Copy go through root.copyText; Ctrl+X does nothing.
                                    Keys.onPressed: (event) => root.guardSecretKeys(event, root.editorMode === "notes" ? "notes-edit" : "", edArea)
                                    ContextMenu.menu: root.editorMode === "notes" ? secretMenu : null
                                    ContextMenu.onRequested: secretMenu.aim(edArea, "notes-edit")
                                    // No IME learning, no prediction (pear-exec also keeps input methods and the
                                    // primary selection away from the window).
                                    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                                    wrapMode: TextEdit.Wrap
                                    color: Theme.fg
                                    selectionColor: Theme.selected
                                    placeholderText: root.editorMode === "sites" ? "example.com" : "Anything you want to keep with this password"
                                    placeholderTextColor: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fBody
                                    padding: 12
                                    background: null
                                }
                            }
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.editorMode === "sites"
                                  ? "One per line. The password is offered on each of these."
                                  : "Synced to your other devices. Ctrl+Enter saves."
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- verification code
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 22
                        spacing: 10
                        visible: root.editorMode === "totp"
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10
                            O.TextField {
                                id: edSetup
                                Accessible.ignored: true
                                // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                                // clipboard history): Ctrl+C and the menu's Copy go through root.copyText; Ctrl+X does nothing.
                                Keys.onPressed: (event) => root.guardSecretKeys(event, "totp-setup-edit", edSetup)
                                ContextMenu.menu: secretMenu
                                ContextMenu.onRequested: secretMenu.aim(edSetup, "totp-setup-edit")
                                // No IME learning, no prediction (pear-exec also keeps input methods and the
                                // primary selection away from the window).
                                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                                Layout.fillWidth: true
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                verticalPadding: 10
                                placeholderText: "Setup key or otpauth:// link"
                                onTextChanged: { previewDebounce.text = text; previewDebounce.restart(); }
                                onAccepted: root.editorSave()
                            }
                            AppButton {
                                text: root.qrScanning ? "Scanning…" : "Scan QR code"
                                enabled: !root.qrScanning
                                onClicked: root.scanQr(edSetup)
                            }
                        }
                        // What the code will be, before anything is saved: type it into the
                        // site to prove the pairing works.
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.topMargin: 6
                            visible: !!root.totpPreview.code
                            implicitHeight: previewCol.implicitHeight + 28
                            radius: Theme.radius
                            color: Theme.panel
                            ColumnLayout {
                                id: previewCol
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.margins: 16
                                spacing: 4
                                Text {
                                    textFormat: Text.PlainText
                                    text: root.groupCode(root.totpPreview.code)
                                    color: Theme.fg
                                    font.family: Theme.uiFont
                                    font.pixelSize: Math.round(Theme.fHeading * 1.6)
                                    font.letterSpacing: 2
                                }
                                Text {
                                    textFormat: Text.PlainText
                                    Layout.fillWidth: true
                                    text: [root.totpPreview.issuer, root.totpPreview.account].filter(function (x) { return x; }).join("  ·  ")
                                          || "Enter this code on the site to finish setting it up."
                                    color: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    elide: Text.ElideRight
                                }
                            }
                        }
                        Text {
                            textFormat: Text.PlainText
                            visible: root.editorMode === "totp" && root.selected && root.selected.has_totp && !root.editorBusy
                            text: "Remove verification code"
                            color: hRemove.hovered ? Theme.danger : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hRemove.hovered
                            HoverHandler { id: hRemove; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.removeTotp() }
                        }
                    }

                    // ---- new entry
                    GridLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 22
                        visible: root.editorMode === "create"
                        columns: 2
                        columnSpacing: 16
                        rowSpacing: 10
                        Repeater {
                            model: [{ l: "Name", f: "name" }, { l: "Website", f: "site" },
                                    { l: "Username", f: "user" }, { l: "Password", f: "pass" }]
                            delegate: Text {
                                textFormat: Text.PlainText
                                required property var modelData
                                required property int index
                                Layout.row: index
                                Layout.column: 0
                                Layout.preferredWidth: 88
                                text: modelData.l
                                color: Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                            }
                        }
                        O.TextField {
                            id: crName
                            Layout.row: 0; Layout.column: 1; Layout.fillWidth: true
                            font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                            placeholderText: "Optional"
                            KeyNavigation.tab: crSite
                        }
                        O.TextField {
                            id: crSite
                            Layout.row: 1; Layout.column: 1; Layout.fillWidth: true
                            font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                            placeholderText: "example.com"
                            KeyNavigation.tab: crUser
                        }
                        O.TextField {
                            id: crUser
                            Layout.row: 2; Layout.column: 1; Layout.fillWidth: true
                            font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                            placeholderText: "Email or username"
                            KeyNavigation.tab: crPass
                        }
                        RowLayout {
                            Layout.row: 3; Layout.column: 1; Layout.fillWidth: true
                            spacing: 10
                            O.TextField {
                                id: crPass
                                Accessible.ignored: true
                                // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                                // clipboard history): Ctrl+C and the menu's Copy go through root.copyText; Ctrl+X does nothing.
                                Keys.onPressed: (event) => root.guardSecretKeys(event, "create-password", crPass)
                                ContextMenu.menu: secretMenu
                                ContextMenu.onRequested: secretMenu.aim(crPass, "create-password")
                                Layout.fillWidth: true
                                visible: !root.createGenerate
                                password: true
                                font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                                placeholderText: "Required"
                                onAccepted: root.editorSave()
                            }
                            Text {
                                textFormat: Text.PlainText
                                Layout.fillWidth: true
                                visible: root.createGenerate
                                text: "Pear will generate one"
                                color: Theme.fg; font.family: Theme.uiFont; font.pixelSize: Theme.fBody
                            }
                            AppButton {
                                text: root.createGenerate ? "Type one" : "Generate"
                                onClicked: { root.createGenerate = !root.createGenerate; crPass.text = ""; }
                            }
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.row: 4; Layout.column: 1
                            Layout.topMargin: 4
                            visible: !root.createMore
                            text: "Add notes or a verification code"
                            color: hMore.hovered ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hMore.hovered
                            HoverHandler { id: hMore; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.createMore = true }
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.row: 5; Layout.column: 0
                            visible: root.createMore
                            text: "Notes"
                            color: Theme.dim; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
                        }
                        O.TextField {
                            id: crNotes
                            Accessible.ignored: true
                            // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                            // clipboard history): Ctrl+C and the menu's Copy go through root.copyText; Ctrl+X does nothing.
                            Keys.onPressed: (event) => root.guardSecretKeys(event, "create-notes", crNotes)
                            ContextMenu.menu: secretMenu
                            ContextMenu.onRequested: secretMenu.aim(crNotes, "create-notes")
                            // No IME learning, no prediction (pear-exec also keeps input methods and the
                            // primary selection away from the window).
                            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                            Layout.row: 5; Layout.column: 1; Layout.fillWidth: true
                            visible: root.createMore
                            font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                            placeholderText: "Optional"
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.row: 6; Layout.column: 0
                            visible: root.createMore
                            text: "Code"
                            color: Theme.dim; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
                        }
                        RowLayout {
                            Layout.row: 6; Layout.column: 1; Layout.fillWidth: true
                            visible: root.createMore
                            spacing: 10
                            O.TextField {
                                id: crSetup
                                Accessible.ignored: true
                                // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                                // clipboard history): Ctrl+C and the menu's Copy go through root.copyText; Ctrl+X does nothing.
                                Keys.onPressed: (event) => root.guardSecretKeys(event, "create-totp-setup", crSetup)
                                ContextMenu.menu: secretMenu
                                ContextMenu.onRequested: secretMenu.aim(crSetup, "create-totp-setup")
                                // No IME learning, no prediction (pear-exec also keeps input methods and the
                                // primary selection away from the window).
                                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                                Layout.fillWidth: true
                                font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                                placeholderText: "Setup key or link (optional)"
                                onTextChanged: { previewDebounce.text = text; previewDebounce.restart(); }
                            }
                            AppButton {
                                text: root.qrScanning ? "Scanning…" : "Scan QR code"
                                enabled: !root.qrScanning
                                fontSize: Theme.fSmall
                                onClicked: root.scanQr(crSetup)
                            }
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.row: 7; Layout.column: 1
                            visible: root.createMore && !!root.totpPreview.code
                            text: "Code now: " + root.groupCode(root.totpPreview.code)
                            color: Theme.dim; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.row: 8; Layout.column: 0
                            visible: root.createMore
                            text: "Tags"
                            color: Theme.dim; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
                        }
                        // List metadata, not a secret (the notes' last line): an ordinary field.
                        O.TextField {
                            id: crTags
                            Layout.row: 8; Layout.column: 1; Layout.fillWidth: true
                            visible: root.createMore
                            font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                            placeholderText: "work family (optional)"
                            // The grammar's characters, and the spaces, commas and '#' between tags.
                            validator: RegularExpressionValidator { regularExpression: /^[#\p{L}\p{M}\p{N}_, -]*$/ }
                        }
                        // Why Add is off when the Tags field is what stops it: the chip editor's words.
                        Text {
                            textFormat: Text.PlainText
                            Layout.row: 9; Layout.column: 1; Layout.fillWidth: true
                            visible: root.createMore && text !== ""
                            text: root.tagsProblem(crTags.text)
                            color: Theme.danger; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- working / error
                    Item {
                        Layout.fillWidth: true
                        Layout.topMargin: 20
                        implicitHeight: 2
                        visible: root.editorBusy
                        clip: true
                        Rectangle { anchors.fill: parent; color: Theme.line }
                        Rectangle {
                            id: edSweep
                            width: parent.width * 0.3
                            height: parent.height
                            color: Theme.accent
                            NumberAnimation on x {
                                running: root.editorBusy
                                loops: Animation.Infinite
                                from: -edSweep.width
                                to: edSweep.parent.width
                                duration: 1300
                                easing.type: Easing.InOutQuad
                            }
                        }
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 10
                        visible: root.editorBusy || root.editorError !== ""
                        text: root.editorBusy ? "Saving to iCloud and checking it arrived…" : root.editorError
                        color: root.editorBusy ? Theme.dim : Theme.danger
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        wrapMode: Text.Wrap
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 26
                        spacing: 10
                        Item { Layout.fillWidth: true }
                        AppButton {
                            text: "Cancel"
                            enabled: !root.editorBusy
                            onClicked: root.closeEditor()
                        }
                        AppButton {
                            active: true
                            text: root.editorMode === "create" ? "Add" : "Save"
                            enabled: root.editorReady()
                            onClicked: root.editorSave()
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------- sign-in sheet
        // One card, one question at a time. The step bar and the status line come from the
        // backend's stage events; the body is whichever question it is asking right now.
        Rectangle {
            parent: scope            // inside the focus scope (keys) and the snapshot's grab
            z: 100
            anchors.fill: parent
            visible: root.signinOpen
            color: root.signedIn ? "transparent" : Theme.bg
            MouseArea { anchors.fill: parent }   // swallow clicks to the list behind

            Rectangle {
                id: signinCard
                anchors.centerIn: parent
                width: Math.min(parent.width - 80, 480)
                height: sheet.implicitHeight + 64
                radius: Theme.radius
                color: Theme.bg
                border.width: 1
                border.color: Theme.line
                Behavior on height { NumberAnimation { duration: 180; easing.type: Easing.OutCubic } }
                clip: true

                // Enter / Esc / arrows for everything that isn't a text field.
                Item {
                    id: sheetKeys
                    focus: root.signinOpen
                    Keys.onPressed: function (ev) {
                        if (ev.key === Qt.Key_Escape) {
                            if (root.signinRunning) root.signinCancel(); else root.signinOpen = false;
                            ev.accepted = true;
                        } else if (ev.key === Qt.Key_Return || ev.key === Qt.Key_Enter) {
                            root.signinPrimary();
                            ev.accepted = true;
                        } else if (root.signinNeed === "choice" && root.signinOptions.length) {
                            const n = root.signinOptions.length;
                            if (ev.key === Qt.Key_Down) { root.signinChoice = (root.signinChoice + 1) % n; ev.accepted = true; }
                            if (ev.key === Qt.Key_Up) { root.signinChoice = (root.signinChoice - 1 + n) % n; ev.accepted = true; }
                        }
                    }
                }

                ColumnLayout {
                    id: sheet
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: 32
                    spacing: 0

                    // ---- steps: thin segments, labels under
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 6
                        visible: root.signinOutcome !== "error"
                        Repeater {
                            model: root.signinSteps()
                            delegate: ColumnLayout {
                                required property var modelData
                                required property int index
                                readonly property int state: index < root.signinStep() ? 2
                                                           : index === root.signinStep() ? 1 : 0
                                Layout.fillWidth: true
                                Layout.preferredWidth: 1
                                spacing: 6
                                Rectangle {
                                    Layout.fillWidth: true
                                    implicitHeight: 3
                                    radius: 1.5
                                    color: parent.state > 0 ? Theme.accent : Theme.line
                                    Behavior on color { ColorAnimation { duration: 200 } }
                                }
                                Text {
                                    textFormat: Text.PlainText
                                    text: modelData
                                    color: parent.state === 1 ? Theme.fg : Theme.dim
                                    opacity: parent.state === 0 ? 0.6 : 1
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fCaption
                                }
                            }
                        }
                    }

                    // ---- outcome glyph
                    Rectangle {
                        Layout.topMargin: root.signinOutcome === "error" ? 0 : 28
                        visible: root.signinOutcome === "ok" || root.signinOutcome === "error"
                        implicitWidth: 44; implicitHeight: 44
                        radius: 22
                        color: "transparent"
                        border.width: 2
                        border.color: root.signinOutcome === "ok" ? Theme.accent : Theme.danger
                        Text {
                            textFormat: Text.PlainText
                            anchors.centerIn: parent
                            text: root.signinOutcome === "ok" ? "✓" : "!"
                            color: parent.border.color
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fHeading
                            font.bold: true
                        }
                    }

                    // ---- title + subtitle
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: root.signinOutcome === "" ? 28 : 18
                        text: root.signinTitle()
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Math.round(Theme.fHeading * 1.25)
                        font.weight: Font.DemiBold
                        wrapMode: Text.Wrap
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 8
                        visible: text !== ""
                        text: root.signinSubtitle()
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fBody
                        lineHeight: 1.15
                        wrapMode: Text.Wrap
                    }

                    // ---- working: an indeterminate sweep under the status
                    Item {
                        Layout.fillWidth: true
                        Layout.topMargin: 22
                        implicitHeight: 2
                        visible: root.signinRunning && root.signinNeed === ""
                        clip: true
                        Rectangle { anchors.fill: parent; color: Theme.line }
                        Rectangle {
                            id: sweep
                            width: parent.width * 0.3
                            height: parent.height
                            color: Theme.accent
                            NumberAnimation on x {
                                running: sweep.parent.visible && root.signinOpen
                                loops: Animation.Infinite
                                from: -sweep.width
                                to: sweep.parent.width
                                duration: 1300
                                easing.type: Easing.InOutQuad
                            }
                        }
                    }

                    // ---- a text or secret answer
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 24
                        spacing: 8
                        visible: (root.signinNeed === "text" || root.signinNeed === "secret")
                                 && root.signinKind !== "code"
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                            visible: text !== ""
                            text: root.fieldLabel()
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                        }
                        O.TextField {
                            id: signinField
                            Accessible.ignored: true
                            // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                            // clipboard history): an account credential, not vault data, so nothing copies from here (no Ctrl+C, Ctrl+X or menu).
                            Keys.onPressed: (event) => root.guardSecretKeys(event)
                            ContextMenu.menu: null
                            Layout.fillWidth: true
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            verticalPadding: 10
                            password: root.signinNeed === "secret"
                            placeholderText: root.signinKind === "apple_id" ? "name@example.com"
                                           : root.signinKind === "password" ? "Required" : ""
                            onAccepted: root.signinPrimary()
                            Keys.onEscapePressed: root.signinCancel()
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            visible: text !== ""
                            text: root.fieldHelper()
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- six-digit code: boxes over one hidden input
                    Item {
                        Layout.fillWidth: true
                        Layout.topMargin: 26
                        implicitHeight: 60
                        visible: root.signinNeed !== "" && root.signinKind === "code"
                        TextInput {
                            id: codeField
                            Accessible.ignored: true
                            // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                            // clipboard history): an account credential, not vault data, so nothing copies from here (no Ctrl+C, Ctrl+X or menu).
                            Keys.onPressed: (event) => root.guardSecretKeys(event)
                            ContextMenu.menu: null
                            width: 1; height: 1; opacity: 0
                            maximumLength: 6
                            inputMethodHints: Qt.ImhDigitsOnly
                            validator: RegularExpressionValidator { regularExpression: /[0-9]{0,6}/ }
                            onTextChanged: if (text.length === 6) root.signinSend(text)
                            Keys.onEscapePressed: root.signinCancel()
                        }
                        Row {
                            anchors.horizontalCenter: parent.horizontalCenter
                            spacing: 10
                            Repeater {
                                model: 6
                                delegate: Rectangle {
                                    required property int index
                                    readonly property bool current: codeField.activeFocus
                                        && index === Math.min(codeField.text.length, 5)
                                    width: 50; height: 60
                                    radius: Theme.radius
                                    color: "transparent"
                                    border.width: current ? 2 : 1
                                    border.color: current ? Theme.accent : Theme.line
                                    Text {
                                        textFormat: Text.PlainText
                                        anchors.centerIn: parent
                                        text: codeField.text.charAt(index)
                                        color: Theme.fg
                                        font.family: Theme.uiFont
                                        font.pixelSize: Math.round(Theme.fHeading * 1.5)
                                    }
                                    // caret
                                    Rectangle {
                                        anchors.centerIn: parent
                                        visible: parent.current && codeField.text.length <= index
                                        width: 2; height: 24
                                        color: Theme.accent
                                        SequentialAnimation on opacity {
                                            loops: Animation.Infinite
                                            running: parent.visible
                                            NumberAnimation { to: 0; duration: 500 }
                                            NumberAnimation { to: 1; duration: 500 }
                                        }
                                    }
                                }
                            }
                        }
                        MouseArea { anchors.fill: parent; onClicked: codeField.forceActiveFocus() }
                    }

                    // ---- which device
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 20
                        spacing: 2
                        visible: root.signinNeed === "choice"
                        Repeater {
                            model: root.signinOptions
                            delegate: Rectangle {
                                required property var modelData
                                required property int index
                                readonly property bool chosen: root.signinChoice === index
                                readonly property string detail: root.signinDetails[index] || ""
                                Layout.fillWidth: true
                                implicitHeight: Math.max(46, deviceText.implicitHeight + 22)
                                radius: Theme.radius
                                color: chosen || deviceHover.containsMouse ? Theme.hover : "transparent"
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 14
                                    anchors.rightMargin: 14
                                    spacing: 14
                                    Rectangle {
                                        implicitWidth: 18; implicitHeight: 18; radius: 9
                                        color: "transparent"
                                        border.width: 2
                                        border.color: parent.parent.chosen ? Theme.accent : Theme.dim
                                        Rectangle {
                                            anchors.centerIn: parent
                                            width: 8; height: 8; radius: 4
                                            color: Theme.accent
                                            visible: parent.parent.parent.chosen
                                        }
                                    }
                                    ColumnLayout {
                                        id: deviceText
                                        Layout.fillWidth: true
                                        spacing: 3
                                        Text {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            text: modelData
                                            color: parent.parent.parent.chosen ? Theme.selectedText : Theme.fg
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            elide: Text.ElideRight
                                        }
                                        Text {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            visible: text !== ""
                                            text: parent.parent.parent.detail
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                            wrapMode: Text.Wrap
                                        }
                                    }
                                }
                                MouseArea {
                                    id: deviceHover
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.signinChoice = parent.index
                                    onDoubleClicked: { root.signinChoice = parent.index; root.signinPrimary(); }
                                }
                            }
                        }
                    }

                    // ---- the irreversible step, said exactly
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.topMargin: 22
                        visible: root.signinNeed === "confirm" && root.signinKind === "join_confirm"
                        implicitHeight: warnText.implicitHeight + 32
                        radius: Theme.radius
                        color: Qt.rgba(Theme.danger.r, Theme.danger.g, Theme.danger.b, 0.08)
                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 3
                            color: Theme.danger
                        }
                        Text {
                            id: warnText
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.leftMargin: 20
                            anchors.rightMargin: 16
                            text: "This can't be undone. Each wrong " + root.secretWord() + " uses 1 of about 10 attempts. "
                                + "After the 10th wrong attempt, the escrow record for this device is destroyed permanently."
                            textFormat: Text.PlainText
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            lineHeight: 1.15
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- done: the facts, then quiet warnings
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 14
                        visible: root.signinOutcome === "ok" && root.signinCount >= 0
                        text: root.signinCount.toLocaleString(Qt.locale(), "f", 0) + " passwords synced"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fBody
                    }
                    Repeater {
                        model: root.signinOutcome === "ok" ? root.signinWarnings : []
                        delegate: Text {
                            textFormat: Text.PlainText
                            required property var modelData
                            Layout.fillWidth: true
                            Layout.topMargin: 6
                            text: modelData
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- error: what it said, verbatim, on request
                    Text {
                        textFormat: Text.PlainText
                        Layout.topMargin: 14
                        visible: root.signinOutcome === "error" && root.signinLog.length > 0
                        text: (root.signinShowDetails ? "Hide details" : "Show details")
                        color: detailsHover.containsMouse ? Theme.fg : Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        font.underline: detailsHover.containsMouse
                        MouseArea {
                            id: detailsHover
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.signinShowDetails = !root.signinShowDetails
                        }
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.topMargin: 8
                        visible: root.signinOutcome === "error" && root.signinShowDetails
                        implicitHeight: Math.min(logText.implicitHeight + 20, 160)
                        radius: Theme.radius
                        color: Theme.panel
                        clip: true
                        Text {
                            textFormat: Text.PlainText
                            id: logText
                            anchors.fill: parent
                            anchors.margins: 10
                            text: root.signinLog.map(l => l.text).join("\n")
                            color: Theme.dim
                            font.family: "monospace"
                            font.pixelSize: Theme.fCaption
                            wrapMode: Text.WrapAnywhere
                        }
                    }

                    // ---- actions
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 30
                        spacing: 10
                        Item { Layout.fillWidth: true }
                        AppButton {
                            visible: root.signinOutcome !== "ok"
                            text: root.signinRunning
                                  ? (root.signinKind === "join_confirm" && root.signinNeed === "confirm" ? "Not now" : "Cancel")
                                  : "Close"
                            onClicked: {
                                if (root.signinRunning && root.signinNeed === "confirm") root.signinSend("no");
                                else if (root.signinRunning) root.signinCancel();
                                else root.signinOpen = false;
                            }
                        }
                        AppButton {
                            visible: root.signinPrimaryLabel() !== ""
                            active: true
                            enabled: root.signinPrimaryReady()
                            text: root.signinPrimaryLabel()
                            onClicked: root.signinPrimary()
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------- state screens
        // Everything that is not the list: can't reach the service, nothing to show yet, or a
        // problem with the keys. Under the sheets, so a sign-in started here draws on top.
        Rectangle {
            parent: scope
            z: 85
            anchors.fill: parent
            color: Theme.bg
            visible: ["connecting", "not-installed", "launcher", "daemon-failed", "abi-mismatch",
                      "empty", "migration-pending", "tpm-missing", "tpm-cleared",
                      "damaged"].indexOf(root.screen) >= 0
            MouseArea { anchors.fill: parent }

            ColumnLayout {
                anchors.centerIn: parent
                width: Math.min(parent.width - 120, 500)
                spacing: 14

                Text {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: root.stateTitle()
                    color: Theme.fg
                    font.family: Theme.uiFont
                    font.pixelSize: Math.round(Theme.fHeading * 1.25)
                    font.weight: Font.DemiBold
                    wrapMode: Text.Wrap
                }
                Text {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    visible: text !== ""
                    text: root.stateBody()
                    color: Theme.dim
                    font.family: Theme.uiFont
                    font.pixelSize: Theme.fBody
                    lineHeight: 1.15
                    wrapMode: Text.Wrap
                }
                // A command to run, selectable so it can be copied.
                Rectangle {
                    Layout.fillWidth: true
                    visible: root.stateCommand() !== ""
                    implicitHeight: cmdText.implicitHeight + 20
                    radius: Theme.radius
                    color: Theme.panel
                    TextEdit {
                        id: cmdText
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.margins: 12
                        textFormat: TextEdit.PlainText
                        readOnly: true
                        selectByMouse: true
                        wrapMode: TextEdit.WrapAnywhere
                        text: root.stateCommand()
                        color: Theme.fg
                        selectionColor: Theme.selected
                        font.family: "monospace"
                        font.pixelSize: Theme.fSmall
                    }
                }
                // Start over: said in full before it is offered, and asked twice.
                Text {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    visible: root.startOverConfirm
                    text: root.startOverNote(root.screen)
                    color: Theme.danger
                    font.family: Theme.uiFont
                    font.pixelSize: Theme.fSmall
                    wrapMode: Text.Wrap
                }
                RowLayout {
                    Layout.topMargin: 10
                    spacing: 10
                    AppButton {
                        visible: root.screen === "tpm-cleared" || root.screen === "damaged"
                                 || root.screen === "migration-pending"
                        text: root.startOverConfirm ? "Yes, start over" : "Start over…"
                        onClicked: root.startOverConfirm ? root.startOver() : root.startOverConfirm = true
                    }
                    AppButton {
                        visible: root.stateButton() !== ""
                        active: true
                        text: root.stateButton()
                        onClicked: root.stateAction()
                    }
                }
            }
        }

        // ---------------------------------------------------------------- migration
        Rectangle {
            parent: scope
            z: 86
            anchors.fill: parent
            color: Theme.bg
            visible: root.screen === "migrate"
            MouseArea { anchors.fill: parent }

            Rectangle {
                anchors.centerIn: parent
                width: Math.min(parent.width - 80, 560)
                height: Math.min(migSheet.implicitHeight + 64, parent.height - 40)
                radius: Theme.radius
                color: Theme.bg
                border.width: 1
                border.color: Theme.line
                clip: true

                ColumnLayout {
                    id: migSheet
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: 32
                    spacing: 0

                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        text: root.migrateStep === "running" ? "Moving your passwords…"
                            : root.migrateStep === "passphrase" ? "Your old Pear Passwords passphrase"
                            : root.migrateStep === "keyring" ? "Your login keyring is locked"
                            : root.migrateStep === "done" ? "Your passwords are here"
                            : root.migrateStep === "error" ? "The move didn't finish"
                            : "Move your passwords into Pear Passwords 2"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Math.round(Theme.fHeading * 1.25)
                        font.weight: Font.DemiBold
                        wrapMode: Text.Wrap
                    }

                    // ---- intro
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 12
                        spacing: 12
                        visible: root.migrateStep === "intro" || root.migrateStep === ""
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: "Pear Passwords 2 keeps your passwords in a system service under its own account, "
                                + "so nothing in your home folder can decrypt them any more. This moves your 1.x vault "
                                + "across once. It's checked against the original before anything changes; then "
                                + "~/.config/icp is renamed to a dated backup you can delete later from Settings."
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            lineHeight: 1.15
                            wrapMode: Text.Wrap
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.v1KeyringOnly
                                ? "Your 1.x vault's key is in your login keyring, so there's no passphrase to type: Pear "
                                  + "reads it from the keyring, which needs to be unlocked."
                                : "For the smoothest move, open and unlock Pear Passwords 1.3.2 within 15 minutes "
                                  + "before this step. Otherwise you'll be asked for your old passphrase, this one last time."
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            lineHeight: 1.15
                            wrapMode: Text.Wrap
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: "The old background services will be stopped and turned off: " + root.legacyUnits.join(", ") + "."
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                        // consent: the old browser-extension connection files
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 12
                            Rectangle {
                                Layout.alignment: Qt.AlignTop
                                implicitWidth: 18; implicitHeight: 18
                                radius: Theme.radius
                                color: root.migrateManifests ? Theme.accent : "transparent"
                                border.width: 1
                                border.color: root.migrateManifests ? Theme.accent : Theme.dim
                                Text {
                                    textFormat: Text.PlainText
                                    anchors.centerIn: parent
                                    visible: root.migrateManifests
                                    text: "✓"
                                    color: Theme.bg
                                    font.pixelSize: Theme.fSmall
                                }
                            }
                            Text {
                                textFormat: Text.PlainText
                                Layout.fillWidth: true
                                text: "Also move the old browser-extension connection files (org.icp.native.json) "
                                    + "into the backup. Only files that are exactly the old ones are moved; ~/icp is left alone."
                                color: Theme.fg
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                                wrapMode: Text.Wrap
                            }
                            TapHandler { onTapped: root.migrateManifests = !root.migrateManifests }
                            HoverHandler { cursorShape: Qt.PointingHandCursor }
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            visible: root.migrateError !== ""
                            text: root.migrateError
                            color: Theme.danger
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- running
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 12
                        spacing: 16
                        visible: root.migrateStep === "running"
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.migrateStage === "reading" ? "Reading your 1.x vault…"
                                : root.migrateStage === "peek" ? "Getting the key from Pear Passwords 1.3.2…"
                                : root.migrateStage === "keyring" ? "Getting the key from your login keyring…"
                                : root.migrateStage === "converting" ? "Converting and checking every entry…"
                                : root.migrateStage === "cleanup" ? "Tidying up the old install…"
                                : "Waiting for your approval…"
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                        }
                        Item {
                            Layout.fillWidth: true
                            implicitHeight: 2
                            clip: true
                            Rectangle { anchors.fill: parent; color: Theme.line }
                            Rectangle {
                                id: migSweep
                                width: parent.width * 0.3
                                height: parent.height
                                color: Theme.accent
                                NumberAnimation on x {
                                    running: root.migrateStep === "running"
                                    loops: Animation.Infinite
                                    from: -migSweep.width
                                    to: migSweep.parent.width
                                    duration: 1300
                                    easing.type: Easing.InOutQuad
                                }
                            }
                        }
                    }

                    // ---- a locked login keyring (keyring-keyed vault)
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 12
                        visible: root.migrateStep === "keyring"
                        text: (root.migrateRetry ? "The keyring is still locked. " : "")
                            + "Your 1.x vault's key is in your login keyring, which is locked. Unlock it the way "
                            + "you usually do (for example in Passwords and Keys), then choose Check again. "
                            + "Pear never asks for the keyring's password, and there is no Pear passphrase to type."
                        color: root.migrateRetry ? Theme.danger : Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fBody
                        lineHeight: 1.15
                        wrapMode: Text.Wrap
                    }

                    // ---- the old passphrase, once
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 12
                        spacing: 10
                        visible: root.migrateStep === "passphrase"
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.migrateRetry ? "That passphrase didn't open your old vault. Try again."
                                : "Pear Passwords 1.3.2 wasn't unlocked recently, so the old vault needs its "
                                  + "passphrase — this one last time. It goes to the service in memory and is never stored."
                            color: root.migrateRetry ? Theme.danger : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            lineHeight: 1.15
                            wrapMode: Text.Wrap
                        }
                        O.TextField {
                            id: oldPass
                            Accessible.ignored: true
                            // A secret leaves this window only through pear-clip (one paste or 30 s, never in
                            // clipboard history): an account credential, not vault data, so nothing copies from here (no Ctrl+C, Ctrl+X or menu).
                            Keys.onPressed: (event) => root.guardSecretKeys(event)
                            ContextMenu.menu: null
                            Layout.fillWidth: true
                            password: true
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            verticalPadding: 10
                            placeholderText: "Old passphrase"
                            onAccepted: root.migratePassphrase()
                            Keys.onEscapePressed: root.migrateCancel()
                        }
                    }

                    // ---- done
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 12
                        spacing: 12
                        visible: root.migrateStep === "done"
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.migrateSummary()
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fBody
                            lineHeight: 1.15
                            wrapMode: Text.Wrap
                        }
                        // What the importer could not stop is said, with the command: the old
                        // services would keep serving 1.x and could pop its old dialogs.
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            visible: (root.migrateResult.units_not_stopped || []).length > 0
                            text: "These old background services could not be stopped from here. Run this in a terminal:"
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                        TextEdit {
                            Layout.fillWidth: true
                            visible: (root.migrateResult.units_not_stopped || []).length > 0
                            readOnly: true
                            selectByMouse: true
                            textFormat: TextEdit.PlainText
                            wrapMode: TextEdit.WrapAnywhere
                            text: "systemctl --user disable --now "
                                + (root.migrateResult.units_not_stopped || []).join(" ")
                            color: Theme.fg
                            font.family: "monospace"
                            font.pixelSize: Theme.fSmall
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: "Browser autofill is off until you turn it on in Settings. If you use a Pear "
                                + "Passwords browser extension, turn it on there and register the extension once:"
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: regText.implicitHeight + 20
                            radius: Theme.radius
                            color: Theme.panel
                            TextEdit {
                                id: regText
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.margins: 12
                                textFormat: TextEdit.PlainText
                                readOnly: true
                                selectByMouse: true
                                wrapMode: TextEdit.WrapAtWordBoundaryOrAnywhere
                                text: root.registerCommand
                                color: Theme.fg
                                selectionColor: Theme.selected
                                font.family: "monospace"
                                font.pixelSize: Theme.fSmall
                            }
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            visible: (root.migrateResult.kept_manifests || []).length > 0
                            text: "Left in place (not the old files, or you chose to keep them): "
                                + (root.migrateResult.kept_manifests || []).join(", ")
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.WrapAnywhere
                        }
                    }

                    // ---- error
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 12
                        visible: root.migrateStep === "error"
                        text: root.migrateError
                        color: Theme.danger
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fBody
                        wrapMode: Text.Wrap
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 28
                        spacing: 10
                        Text {
                            textFormat: Text.PlainText
                            visible: root.migrateStep === "intro"
                            text: "Start fresh instead"
                            color: hFresh.hovered ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hFresh.hovered
                            HoverHandler { id: hFresh; cursorShape: Qt.PointingHandCursor }
                            TapHandler {
                                onTapped: {
                                    root.migrateStep = ""; root.v1Present = false;
                                    if (root.migrationPending) root.abandonMigration(null);
                                }
                            }
                        }
                        Item { Layout.fillWidth: true }
                        AppButton {
                            visible: root.migrateStep === "passphrase" || root.migrateStep === "keyring"
                            text: "Cancel"
                            onClicked: root.migrateCancel()
                        }
                        AppButton {
                            visible: root.migrateStep !== "running"
                            active: true
                            enabled: root.migrateStep !== "passphrase" || oldPass.text.length > 0
                            text: root.migrateStep === "done" ? "Done"
                                : root.migrateStep === "error" ? "Back"
                                : root.migrateStep === "keyring" ? "Check again" : "Continue"
                            onClicked: {
                                if (root.migrateStep === "done") root.migrateFinish();
                                else if (root.migrateStep === "keyring") root.migrateCheckKeyring();
                                else if (root.migrateStep === "error") { root.migrateStep = "intro"; }
                                else if (root.migrateStep === "passphrase") root.migratePassphrase();
                                else root.migrateBegin();
                            }
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------- settings
        Rectangle {
            parent: scope
            z: 88
            anchors.fill: parent
            visible: root.settingsOpen
            color: "transparent"
            MouseArea { anchors.fill: parent; onClicked: root.settingsOpen = false }

            Rectangle {
                anchors.centerIn: parent
                width: Math.min(parent.width - 80, 600)
                height: Math.min(setSheet.implicitHeight + 60, parent.height - 40)
                radius: Theme.radius
                color: Theme.bg
                border.width: 1
                border.color: Theme.line
                clip: true
                MouseArea { anchors.fill: parent }
                Keys.onEscapePressed: root.settingsOpen = false

                Flickable {
                    id: setFlick
                    anchors.fill: parent
                    anchors.margins: 30
                    contentHeight: setSheet.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: AppScrollBar {}

                ColumnLayout {
                    id: setSheet
                    width: parent.width
                    spacing: 0

                    Text {
                        textFormat: Text.PlainText
                        text: "Settings"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Math.round(Theme.fHeading * 1.25)
                        font.weight: Font.DemiBold
                    }

                    Repeater {
                        model: [
                            { key: "grant_s", label: "An account you open stays open for",
                              choices: [[0, "one use"], [30, "30 s"], [60, "1 min"], [120, "2 min"], [300, "5 min"], [600, "10 min"]] },
                            { key: "idle_lock_s", label: "Lock when not used for",
                              choices: [[0, "never"], [300, "5 min"], [900, "15 min"], [1800, "30 min"]] },
                            { key: "clip_timeout_s", label: "A copied password clears after one paste or",
                              choices: [[10, "10 s"], [15, "15 s"], [30, "30 s"], [45, "45 s"], [60, "60 s"]] },
                            { key: "window_mode", label: "Open as",
                              choices: [["floating", "floating window"], ["regular", "regular window"]] }
                        ]
                        delegate: ColumnLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            Layout.topMargin: 20
                            spacing: 8
                            Text {
                                textFormat: Text.PlainText
                                text: parent.modelData.label
                                color: Theme.fg
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                            }
                            Flow {
                                Layout.fillWidth: true
                                spacing: 6
                                Repeater {
                                    model: parent.parent.modelData.choices
                                    delegate: AppButton {
                                        required property var modelData
                                        readonly property string key: parent.parent.modelData.key
                                        text: modelData[1]
                                        active: root.settings[key] === modelData[0]
                                        fontSize: Theme.fSmall
                                        onClicked: root.setSetting(key, modelData[0])
                                    }
                                }
                            }
                        }
                    }

                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 24
                        text: root.sealedWith === "host+tpm2"
                            ? "Your keys are sealed to this computer and its security chip."
                            : root.tpmMove
                              ? "Your keys are sealed to this computer. This laptop's security chip is on: moving "
                                + "your keys onto it makes new keys sealed with the chip and re-encrypts every "
                                + "password inside Pear's service (one dialog). A backup taken before still opens "
                                + "the passwords as they were then."
                              : "Your keys are sealed to this computer. Turning on the security chip (PTT) in the "
                                + "BIOS lets Pear tie them to this laptop too; it then offers the move here."
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        wrapMode: Text.Wrap
                    }

                    AppButton {
                        Layout.topMargin: 8
                        visible: root.sealedWith !== "host+tpm2" && root.tpmMove
                        text: root.tpmMoving ? "Moving…" : "Move your keys onto the security chip"
                        fontSize: Theme.fSmall
                        onClicked: root.moveToTpm()
                    }

                    // ---- browser autofill
                    Text {
                        textFormat: Text.PlainText
                        Layout.topMargin: 24
                        text: "Browser autofill"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 6
                        text: "Lets a browser extension you registered with pear-passwords-autofill ask for a password. "
                            + "Every fill is its own dialog. While this is on, any program running as you can ask the same "
                            + "way, so approve a fill only right after you asked your browser for one."
                            + (root.autofillHosts > 0 ? " Connected now: " + root.autofillHosts + "." : "")
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        wrapMode: Text.Wrap
                    }
                    RowLayout {
                        Layout.topMargin: 8
                        spacing: 6
                        AppButton {
                            text: "Off"
                            active: !root.autofillEnabled
                            fontSize: Theme.fSmall
                            onClicked: if (root.autofillEnabled) root.setAutofill(false)
                        }
                        AppButton {
                            text: "On"
                            active: root.autofillEnabled
                            fontSize: Theme.fSmall
                            onClicked: if (!root.autofillEnabled) root.setAutofill(true)
                        }
                    }

                    // ---- clipboard history
                    Text {
                        textFormat: Text.PlainText
                        Layout.topMargin: 24
                        text: "Clipboard history"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 6
                        text: "Passwords copied before Pear Passwords 2 may still be in Omarchy's clipboard history. "
                            + "This compares the two without showing either, and needs your approval."
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        wrapMode: Text.Wrap
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 8
                        spacing: 12
                        AppButton {
                            text: root.historyChecking ? "Checking…" : "Check clipboard history"
                            enabled: !root.historyChecking
                            fontSize: Theme.fSmall
                            onClicked: root.checkClipboardHistory()
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: root.historyCheck
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- categories that wait for a check (features spec 1)
                    Text {
                        id: featHead
                        textFormat: Text.PlainText
                        Layout.topMargin: 24
                        text: "Passkeys and Recently Deleted"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 6
                        text: "Pear reads both from your iCloud Keychain, but how Apple names them has not been checked "
                            + "on a real keychain yet, so they stay out of the list until you turn them on. Check the "
                            + "names first (counts and names only, never a value), compare the counts with the Passwords "
                            + "app, then turn them on. Each change needs your approval; both stay read-only."
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        wrapMode: Text.Wrap
                    }
                    Repeater {
                        model: [{ key: "passkeys", label: "Passkeys" }, { key: "apple_deleted", label: "Recently Deleted" }]
                        delegate: RowLayout {
                            id: featRow
                            required property var modelData
                            Layout.topMargin: 8
                            spacing: 6
                            Text {
                                textFormat: Text.PlainText
                                Layout.preferredWidth: 140
                                text: featRow.modelData.label
                                color: Theme.fg
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                            }
                            AppButton {
                                text: "Off"
                                active: !root.features[featRow.modelData.key]
                                enabled: !root.featureBusy
                                fontSize: Theme.fSmall
                                onClicked: if (root.features[featRow.modelData.key]) root.setFeature(featRow.modelData.key, false)
                            }
                            AppButton {
                                text: "On"
                                active: !!root.features[featRow.modelData.key]
                                enabled: !root.featureBusy
                                fontSize: Theme.fSmall
                                onClicked: if (!root.features[featRow.modelData.key]) root.setFeature(featRow.modelData.key, true)
                            }
                        }
                    }
                    AppButton {
                        Layout.topMargin: 8
                        visible: root.appUnlocked
                        text: root.diagBusy ? "Checking…" : "Check the keychain's item names"
                        enabled: !root.diagBusy
                        fontSize: Theme.fSmall
                        onClicked: root.runDiag()
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.topMargin: 8
                        visible: root.diagText !== ""
                        implicitHeight: diagOut.implicitHeight + 16
                        radius: Theme.radius
                        color: Theme.panel
                        // Names and counts only; selectable, so they can be pasted into a report.
                        TextEdit {
                            id: diagOut
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.margins: 10
                            textFormat: TextEdit.PlainText
                            readOnly: true
                            selectByMouse: true
                            wrapMode: TextEdit.WrapAnywhere
                            text: root.diagText
                            color: Theme.fg
                            selectionColor: Theme.selected
                            font.family: "monospace"
                            font.pixelSize: Theme.fCaption
                        }
                    }

                    // ---- the 1.x backup
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 24
                        spacing: 8
                        visible: !!root.oldCopy
                        Text {
                            textFormat: Text.PlainText
                            text: "Old 1.x copy"
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                        }
                        Text {
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            text: "The encrypted 1.x vault is still in " + (root.oldCopy ? root.oldCopy.dir : "")
                                + ". It is sealed with your old passphrase only; once everything looks right here, delete it."
                            color: root.oldCopyStale() ? Theme.fg : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            wrapMode: Text.Wrap
                        }
                        AppButton {
                            text: root.purging ? "Deleting…" : "Delete the old encrypted copy"
                            enabled: !root.purging
                            fontSize: Theme.fSmall
                            onClicked: root.purgeOldCopy()
                        }
                    }

                    // ---- autofill
                    Text {
                        textFormat: Text.PlainText
                        Layout.topMargin: 24
                        text: "Browser autofill"
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        Layout.topMargin: 6
                        text: "Off unless you register an extension of your own. Every fill then asks for your "
                            + "approval, and the browser holds that one password afterwards. To turn it on:"
                        color: Theme.dim
                        font.family: Theme.uiFont
                        font.pixelSize: Theme.fSmall
                        wrapMode: Text.Wrap
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.topMargin: 8
                        implicitHeight: setReg.implicitHeight + 16
                        radius: Theme.radius
                        color: Theme.panel
                        TextEdit {
                            id: setReg
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.margins: 10
                            textFormat: TextEdit.PlainText
                            readOnly: true
                            selectByMouse: true
                            wrapMode: TextEdit.WrapAtWordBoundaryOrAnywhere
                            text: root.registerCommand
                            color: Theme.fg
                            selectionColor: Theme.selected
                            font.family: "monospace"
                            font.pixelSize: Theme.fCaption
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: 28
                        spacing: 10
                        AppButton {
                            visible: root.signedIn
                            text: "Sign out of iCloud…"
                            fontSize: Theme.fSmall
                            onClicked: root.signOut()
                        }
                        Item { Layout.fillWidth: true }
                        AppButton { text: "Lock now"; onClicked: { root.settingsOpen = false; root.lockNow(); } }
                        AppButton { active: true; text: "Close"; onClicked: root.settingsOpen = false }
                    }
                }
                }
            }
        }
    }

    // ---------------------------------------------------------------- screen texts
    function stateTitle() {
        switch (root.screen) {
        case "connecting": return "Pear Passwords";
        case "not-installed": return "One more step";
        case "launcher": return "Open Pear Passwords from its launcher";
        case "daemon-failed": return "Pear's background service didn't start";
        case "abi-mismatch": return "Python was upgraded";
        case "empty": return "No passwords yet";
        case "migration-pending": return "The move from 1.x didn't finish";
        case "tpm-missing": return "The security chip is switched off";
        case "tpm-cleared": return "The security chip refused the keys";
        case "damaged": return "Pear Passwords can't read its data";
        }
        return "";
    }
    function stateBody() {
        switch (root.screen) {
        case "connecting": return "Connecting…";
        case "not-installed":
            return "Pear Passwords 2 keeps your passwords in a small system service, which needs a one-time "
                 + "step as an administrator. Run ./install.sh from the plugin folder, then paste the command it prints.";
        case "launcher":
            return "This window was started directly, so it can't prove it's the real app. Close it and "
                 + "open Pear Passwords from the app launcher.";
        case "daemon-failed":
            return (root.daemonDetail ? root.daemonDetail + " " : "")
                 + "Its log says why:";
        case "abi-mismatch":
            return "Pear's system part was built for the previous Python. Re-run the system step: run "
                 + "./install.sh from the plugin folder, then paste the command it prints.";
        case "empty":
            return "Sign in to iCloud to bring in the passwords saved on your iPhone, iPad and Mac."
                 + (root.v1KeyringOnly ? " Your 1.x vault in ~/.config/icp stays where it is, and its history and "
                                         + "nicknames are not brought over." : "");
        case "migration-pending":
            return "An earlier move from Pear Passwords 1.x stopped before it finished, and there is no 1.x "
                 + "vault in ~/.config/icp to finish it from. Nothing was imported. Starting over makes new "
                 + "keys, and then you sign in to iCloud to bring in your passwords.";
        case "tpm-missing":
            return "The security chip (PTT) is switched off. Turn it back on in the BIOS and your "
                 + "passwords come back.";
        case "tpm-cleared":
            return "A working security chip refused the keys: it was most likely reset (\"Clear TPM\") or "
                 + "replaced, and then the keys can't be recovered. If you changed nothing, try again after "
                 + "a restart first. Starting over makes new keys "
                 + "and signs you in to iCloud again. If this computer's place in your keychain was lost too, "
                 + "that needs your Apple Account password, a verification code and one device-passcode attempt "
                 + "(out of about 10). Local password history and nicknames are lost.";
        case "damaged":
            return "Pear's keys or its stored data no longer open on this computer. Nothing has been deleted; "
                 + "the files are kept for diagnosis. Starting over moves them aside, makes new keys and signs "
                 + "you in to iCloud again. If this computer's place in your keychain was lost too, that needs "
                 + "your Apple Account password, a verification code and one device-passcode attempt (out of "
                 + "about 10). Local password history and nicknames are lost.";
        }
        return "";
    }
    function stateCommand() {
        return root.screen === "daemon-failed" ? "journalctl -b -u pear-passwordsd"
             : "";
    }
    function stateButton() {
        switch (root.screen) {
        case "not-installed": case "daemon-failed": case "abi-mismatch": return "Try again";
        case "launcher": return "Close";
        case "empty": return "Sign in to iCloud";
        case "tpm-missing": case "tpm-cleared": case "damaged": return "Try again";
        }
        return "";
    }
    // reset keeps the old files after tpm-cleared or damaged; a store that opens normally and
    // keeps nothing (an unfinished move that saved nothing) is deleted (docs/protocol.md, reset).
    function startOverNote(screen) {
        const head = "Start over? New keys are made and you sign in to iCloud again. Local password "
                   + "history and nicknames can't be brought back. ";
        if (screen === "tpm-cleared" || screen === "damaged")
            return head + "The old files are moved aside, not deleted.";
        return head + "If the unfinished move saved nothing yet, its files are deleted; otherwise "
             + "they are moved aside.";
    }
    function stateAction() {
        switch (root.screen) {
        case "not-installed": case "daemon-failed": case "abi-mismatch": root.reconnect(); return;
        case "launcher": Qt.quit(); return;
        case "empty": root.startSignin("login"); return;
        case "tpm-missing": case "tpm-cleared": case "damaged": root.authenticate(); return;
        }
    }
    function migrateSummary() {
        const c = root.migrateResult.counts || {};
        const n = function (k, one, many) { const v = c[k] || 0; return v + " " + (v === 1 ? one : many); };
        return n("credentials", "password", "passwords") + ", " + n("history", "history entry", "history entries")
             + " and " + n("nicknames", "nickname", "nicknames") + " moved and checked. The old encrypted copy is in "
             + (root.migrateResult.backup_dir || "a backup folder") + "; delete it from Settings once everything looks right.";
    }
    function oldCopyStale() {
        return !!root.oldCopy && root.oldCopy.migrated_at && (Date.now() / 1000 - root.oldCopy.migrated_at) > 7 * 86400;
    }

    // ---------------------------------------------------------------- development previews
    Timer {
        id: snapshotTimer
        interval: 1500
        onTriggered: scope.grabToImage(function (r) {
            r.saveToFile(root.snapshotPath);
            Qt.quit();
        })
    }

    // Made-up data only. Nothing is read from or sent to the daemon.
    function applyPreview(mode) {
        const now = Date.now() / 1000;
        const mk = function (n, user, sites, totp, notes, noSite, domain) {
            return { id: "demo" + n, domain: domain || ("example-" + n + ".com"), username: user,
                     title: "Example Account " + n, primary: "Example Account " + n, nickname: "",
                     apple_title: "Example Account " + n, secondary: user, no_site: !!noSite,
                     mdat: now - n * 86400 * 3, has_totp: totp, aliases: [], sites: sites,
                     has_notes: notes, ambiguous: false, is_wifi: false, history_count: n === 1 ? 2 : 0 };
        };
        root.phase = "ready";
        root.windowReady = true;
        root.signedIn = true;
        root.sealedWith = "host";
        root.syncedAt = now - 240;
        root.vaultState = "locked";
        if (["not-installed", "daemon-failed", "abi-mismatch", "launcher"].indexOf(mode) >= 0) {
            root.phase = mode;
            if (mode === "daemon-failed") root.daemonDetail = "It stopped with \"exit-code\".";
        } else if (["tpm-missing", "tpm-cleared", "damaged"].indexOf(mode) >= 0) {
            root.vaultState = mode;
        } else if (mode === "empty") {
            root.vaultState = "empty"; root.v1Checked = true; root.signedIn = false;
        } else if (mode === "no-agent") {
            root.lockReason = "no-agent";
        } else if (mode.indexOf("migrate") === 0) {
            root.vaultState = "empty"; root.v1Checked = true; root.v1Present = true;
            root.migrateStep = mode === "migrate" ? "intro" : mode.slice(8);
            root.migrateStage = "converting";
            root.migrateResult = { counts: { credentials: 554, history: 31, nicknames: 12 },
                                   backup_dir: root.home + "/.config/icp.v1-backup-20261008",
                                   kept_manifests: [] };
        } else if (mode !== "locked") {
            root.appUnlocked = true;
            root.vaultState = "unlocked";
            root.oldCopy = { dir: root.home + "/.config/icp.v1-backup-20261008", migrated_at: now - 9 * 86400 };
            const list_ = [mk(1, "dummyuser1", ["login.example-1.com"], true, true, false),
                           mk(2, "dummyuser2", [], false, true, false),
                           mk(3, "alex@example.com", [], true, false, false),
                           mk(4, "sam@example.com", [], false, false, true)];
            if (["cats", "cats-flags", "chip", "tags", "tageditor"].indexOf(mode) >= 0) {
                list_[0].tags = ["work", "finance"];
                list_[1].tags = ["work"];
                list_[2].tags = ["side-project"];
                const wifi = mk(5, "", [], false, false, true, "Home Network");
                wifi.primary = "Home Network"; wifi.title = "Home Network"; wifi.is_wifi = true;
                const gone = mk(6, "old@example.com", [], false, false, false);
                gone.recently_deleted = true;
                list_.push(wifi, gone);
            }
            if (mode === "cats-flags") root.takeFeatures({ passkeys: true, apple_deleted: true });
            root.setEntries(list_);
            if (mode === "cats" || mode === "cats-flags") search.openCats(true, false);
            if (mode === "chip") {
                root.setCatTag({ kind: "tag", key: "work", label: "work" });
                search.text = "acc";
            }
            if (mode === "tageditor") {
                root.grantId = "demo1"; root.grantExpires = now + 118; root.grantLeft = 118;
                root.openTagEditor();
                tagInput.text = "taxes";
            }
            if (mode === "detail") {
                root.grantId = "demo1"; root.grantExpires = now + 118; root.grantLeft = 118;
                root.revealed = "correct-horse-battery";
                root.totpCode = "482913"; root.totpLeft = 21;
                root.historyRows = [{ date: "2026-09-01T10:00:00Z", value: "old-one", source: "apple" },
                                    { date: "2026-08-01T10:00:00Z", value: "older-one", source: "local" }];
                root.historyLoaded = true;
            }
            if (mode === "settings") root.settingsOpen = true;
            if (mode === "settings-checked") {
                root.settingsOpen = true;
                root.takeFeatures({ passkeys: true, apple_deleted: false });
                root.diagText = "22 × keys  com.apple.webkit.webauthn\n    names: agrp, cdat, class, klbl, labl, mdat\n"
                              + "3 × inet  com.apple.password-manager-recently-deleted\n    names: acct, agrp, class, srvr";
            }
            if (mode === "create-tags") {
                root.openEditor("create");
                root.createMore = true;
                crName.text = "Example"; crSite.text = "example.com"; crUser.text = "me@example.com";
                crTags.text = "work #family";
            }
            if (mode === "settings-checked") Qt.callLater(function () { setFlick.contentY = featHead.y - 10; });
            if (mode === "copied") root.showFlash("Password copied — clears after one paste or 30 s");
            if (mode === "clip-countdown") {
                root.clipOffered(root, "Password");
                root.clipUntil -= 3000;
                root.clipTick();
            }
        }
        if (root.snapshotPath) snapshotTimer.start();
    }

    Component.onCompleted: {
        if (root.previewMode) { root.applyPreview(root.previewMode); return; }
        daemon.connected = true;
    }
}
