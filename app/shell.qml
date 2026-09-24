//@ pragma UseQApplication
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui as O

ShellRoot {
    id: root

    property var entries: []
    property var filtered: []
    property int cursor: -1
    property var selected: null
    property string selectedId: ""

    // Two clocks, both restarted by a fingerprint and both app-wide (the backend owns them;
    // these are only what the window counts down). `unlocked` = the scan still counts, so
    // revealing, copying and editing work. When it lapses the list stays readable and the next
    // such action asks again. When `sessionLeft` runs out the whole window locks.
    property real fullUntil: 0
    property real sessionUntil: 0
    property int unlockLeft: 0
    property int sessionLeft: 0
    readonly property bool unlocked: unlockLeft > 0

    property string revealed: ""
    property var historyRows: []
    property var revealedHistory: ({})
    property string totpCode: ""
    property int totpLeft: 0
    property string status: ""
    property string flash: ""
    property bool busy: false
    property bool confirming: false
    property bool generated: false
    property bool renaming: false
    property bool historyLoaded: false
    property bool changing: false
    // Notes are read only under the per-entry unlock (people keep recovery answers there).
    property string notesText: ""
    property bool notesLoaded: false
    // ---- editor sheet: websites / notes / verification code / new entry
    property bool editorOpen: false
    property string editorMode: ""               // sites | notes | totp | create
    property bool editorBusy: false
    property bool editorScanning: false
    property string editorError: ""
    property var totpPreview: ({})
    property bool createMore: false
    // Two keyboard zones: the list (search field has focus) and the detail panel (detailKeys has
    // focus). Tab crosses between them; inside the panel the arrows walk the rows.
    property bool panelFocus: false
    property int detailIndex: 0
    readonly property int fieldCount: root.fieldRows().length
    // The app opens locked. Until the fingerprint/password check passes the backend sends no
    // names at all - these are only the window's view of that.
    property bool appUnlocked: false
    property bool autoAuthTried: false
    property bool needsLogin: false
    property bool signedIn: true
    property bool firstRunShown: false
    // ---- sign-in sheet. It draws only what the backend says it is doing (stage events) and
    // asking for (typed prompts); it holds no idea of Apple's sequence of its own.
    property bool signinOpen: false
    property string signinMode: "login"          // login | sync
    property bool signinRunning: false
    property string signinStage: ""              // account signing_in verify finding_devices joining syncing synced
    property string signinNeed: ""               // text | secret | confirm | choice - "" while working
    property string signinKind: ""               // apple_id password code device join_confirm device_passcode
    property string signinDefault: ""
    property string signinDetail: ""
    property var signinOptions: []
    property var signinDetails: []
    property var signinDevice: ({})            // {name, model, secret} once a device is picked
    property int signinChoice: -1
    property string signinVia: "trusted"
    property int signinCount: -1
    property bool signinVerified: false          // a code was asked for and accepted
    property string signinError: ""
    property var signinWarnings: []
    property var signinLog: []                   // raw lines, shown only under "Details" on failure
    property bool signinShowDetails: false
    property string signinOutcome: ""            // "" | ok | error | cancelled

    // The backend CLI, where install.sh puts it. PEAR_PASSWORDS_ICP overrides it for development.
    readonly property string icp: Quickshell.env("PEAR_PASSWORDS_ICP")
        || (Quickshell.env("HOME") + "/.local/share/pear-passwords/venv/bin/icp")
    readonly property bool debugWheel: Quickshell.env("PEAR_PASSWORDS_DEBUG_WHEEL") === "1"

    // Development only. With PEAR_PASSWORDS_SNAPSHOT set, the window renders itself to that PNG
    // and quits - run under QT_QPA_PLATFORM=offscreen and nothing ever appears on screen, so
    // a visual change can be checked without a window landing on top of whatever you're doing.
    readonly property string snapshotPath: Quickshell.env("PEAR_PASSWORDS_SNAPSHOT") || ""
    readonly property string snapshotQuery: Quickshell.env("PEAR_PASSWORDS_SNAPSHOT_QUERY") || ""

    // ---------------------------------------------------------------- process plumbing
    property var queue: []
    // A command may outlive the view that asked for it (a sync can take minutes). Every
    // callback captures the generation that was current when it was requested. Expiry and
    // selection changes advance it, so a late reply can finish in the child process without
    // putting old secrets back into this window.
    property int callbackGeneration: 0
    property int editorGeneration: 0
    property bool clipboardClearPending: false
    property bool clipboardClearRequested: false
    property bool clipboardMustStayClear: false
    property int clipboardRetryCount: 0
    readonly property int clipboardRetryLimit: 3

    function invalidateAppCallbacks() {
        root.callbackGeneration += 1;
        // Do not stop a process that may already be writing remotely. Its callback is dropped,
        // while queued work (which has not started) and its secret-bearing closures are released.
        root.queue = [];
        proc.handler = null;
        // If it has not started, this is still the command's plaintext stdin. If it has started,
        // onStarted already handed it to the child and cleared the property; clearing it here
        // therefore never interrupts an in-flight remote write.
        proc.pending = "";
        proc.output = "";
        // A FailedToStart transition emits runningChanged without onExited. There is no child
        // left to finish, so release the attempt and its busy marker immediately when that
        // transition has already happened. A running child is deliberately left alone: an
        // in-flight remote write still owns its framed stdin.
        if (!proc.running) { proc.attemptActive = false; root.busy = false; }
    }

    function invalidateEditorCallbacks() {
        root.editorGeneration += 1;
        // An editor write may still be in flight. Dropping only the UI handler lets that write
        // finish with the payload already handed to edProc, without reopening the sheet or
        // copying its result into a new editor.
        edProc.handler = null;
        edProc.pending = "";
        edProc.output = "";
        if (!edProc.running) edProc.attemptActive = false;
        previewDebounce.stop();
    }

    function failProcStart(attempt) {
        if (proc.running || !proc.attemptActive || proc.attempt !== attempt) return;
        proc.attemptActive = false;
        proc.handler = null;
        proc.pending = "";
        proc.output = "";
        root.busy = false;
        // A failed start can have been carrying an editor payload through the shared process.
        // Use the same fail-closed path as the clock boundary, then expose only a generic
        // status; no callback is allowed to repopulate a secret-bearing control.
        root.forgetSecrets();
        root.status = "couldn't start icp";
    }

    function failEditorStart(attempt) {
        if (edProc.running || !edProc.attemptActive || edProc.attempt !== attempt) return;
        edProc.attemptActive = false;
        root.invalidateEditorCallbacks();
        root.editorOpen = false;
        root.editorMode = "";
        root.clearEditorFields();
        root.status = "couldn't start icp";
    }

    function clearClipboard() {
        root.clipboardClearRequested = true;
        if (clipboardProc.running || root.clipboardClearPending) return;
        root.clipboardClearRequested = false;
        root.clipboardClearPending = true;
        clipboardProc.attempt += 1;
        clipboardProc.running = true;
    }

    function scheduleClipboardRetry() {
        if (!root.clipboardMustStayClear || root.clipboardRetryCount >= root.clipboardRetryLimit)
            return false;
        root.clipboardRetryCount += 1;
        clipboardRetryTimer.restart();
        return true;
    }

    function failClipboardStart(attempt) {
        if (clipboardProc.running || !root.clipboardClearPending
            || clipboardProc.attempt !== attempt) return;
        root.clipboardClearPending = false;
        if (root.scheduleClipboardRetry()) return;
        root.status = "clipboard could not be cleared";
    }

    function startRun(q) {
        proc.handler = q.handler;
        // Newline-terminated: the backend reads exactly one line. It used to read to EOF,
        // and since this pipe stays open the process waited in read() forever.
        proc.stdinEnabled = true;
        proc.pending = q.stdinText && q.stdinText.length ? q.stdinText + "\n" : "";
        proc.output = "";
        proc.command = [root.icp].concat(q.args);
        proc.attempt += 1;
        proc.attemptActive = true;
        root.busy = true;
        proc.running = true;
    }

    function run(args, stdinText, done) {
        const generation = root.callbackGeneration;
        const handler = function (d) {
            if (generation !== root.callbackGeneration) return;
            if (done) done(d);
        };
        const q = { args: args, stdinText: stdinText, handler: handler, generation: generation };
        if (proc.running) {
            root.queue = root.queue.concat([q]);
            return;
        }
        root.startRun(q);
    }

    function drain() {
        if (!root.queue.length || proc.running) return;
        const q = root.queue[0];
        root.queue = root.queue.slice(1);
        // Expiry/selection normally removes these before drain runs. Keep this guard for the
        // event-loop turn where a child exits at the same time as the clock transition.
        if (q.generation !== root.callbackGeneration) { Qt.callLater(root.drain); return; }
        root.startRun(q);
    }

    Process {
        id: proc
        property var handler: null
        property string pending: ""
        // SplitParser does not expose the process reader's persistent buffer. This accumulator
        // exists only between the first output chunk and onExited, and is cleared on both paths.
        property string output: ""
        property int attempt: 0
        property bool attemptActive: false
        running: false
        stdinEnabled: true
        onRunningChanged: {
            if (running || !proc.attemptActive) return;
            // Quickshell emits onExited before the normal running=false transition. A
            // FailedToStart has no onExited, so defer one event-loop turn and distinguish the
            // two cases by the attempt flag instead of dropping a valid reply.
            const attempt = proc.attempt;
            Qt.callLater(function () {
                if (!proc.running && proc.attemptActive && proc.attempt === attempt)
                    root.failProcStart(attempt);
            });
        }
        onStarted: {
            if (pending.length) { write(pending); pending = ""; }
            stdinEnabled = false;
        }
        stdout: SplitParser {
            // App commands emit one JSON object without a required trailing newline. Empty
            // splitting forwards each chunk and leaves no parser-side plaintext buffer behind.
            splitMarker: ""
            onRead: function (data) {
                // Expiry clears the handler before any late stream event can run. Do not let
                // that event repopulate the short-lived accumulator.
                if (!proc.handler) return;
                proc.output += data;
            }
        }
        onExited: {
            proc.attemptActive = false;
            root.busy = false;
            const handler = proc.handler;
            const output = proc.output;
            proc.handler = null;
            proc.output = "";
            // A handler of null means expiry/selection invalidated this reply. Do not even
            // update status in that case: the old command no longer owns the window.
            if (handler) {
                let d = null;
                try { d = JSON.parse(output); } catch (e) {}
                if (!d) root.status = "no reply from icp";
                else if (d.ok === false) root.status = d.error || "failed";
                else { root.status = ""; handler(d); }
            }
            Qt.callLater(root.drain);
            // A copy command may have been inside proc when the clock expired. Its callback is
            // intentionally dropped, but the backend can still finish and create a new Pear
            // clipboard owner after the first clear attempt. Queue one dedicated retry so that
            // a completed remote write cannot repopulate the clipboard past the boundary.
            if (root.clipboardMustStayClear) root.clearClipboard();
        }
    }

    // Clipboard cleanup is deliberately outside proc/queue: expiry must not wait behind a
    // network write. The backend only terminates the foreground wl-copy process it owns; if a
    // different application replaced the selection, this action is a safe no-op.
    Process {
        id: clipboardProc
        property int attempt: 0
        command: [root.icp, "app-clipboard-clear"]
        running: false
        stdinEnabled: false
        onRunningChanged: {
            if (running) return;
            const attempt = clipboardProc.attempt;
            Qt.callLater(function () {
                if (!clipboardProc.running && root.clipboardClearPending
                    && clipboardProc.attempt === attempt)
                    root.failClipboardStart(attempt);
            });
        }
        onExited: function (exitCode, exitStatus) {
            root.clipboardClearPending = false;
            clipboardRetryTimer.stop();
            root.clipboardRetryCount = 0;
            if (exitCode !== 0) root.status = "clipboard could not be cleared";
            if (root.clipboardClearRequested) Qt.callLater(root.clearClipboard);
        }
    }

    Timer {
        id: clipboardRetryTimer
        interval: 100
        repeat: false
        onTriggered: {
            if (root.clipboardMustStayClear && !clipboardProc.running
                && !root.clipboardClearPending) root.clearClipboard();
        }
    }

    Timer {
        interval: 1000; running: true; repeat: true
        onTriggered: {
            const now = Date.now() / 1000;
            const wasUnlocked = root.unlockLeft > 0;
            root.unlockLeft = Math.max(0, Math.ceil(root.fullUntil - now));
            root.sessionLeft = Math.max(0, Math.ceil(root.sessionUntil - now));
            // The scan stopped counting: put the secrets away, keep the list.
            if (wasUnlocked && root.unlockLeft === 0) {
                root.clipboardMustStayClear = true;
                root.clearClipboard();
                root.forgetSecrets();
            }
            // And when the session runs out, the window locks and the backend stops sending.
            if (root.appUnlocked && root.sessionUntil > 0 && root.sessionLeft === 0) root.lockApp();
            if (root.totpLeft > 0) root.totpLeft -= 1;
        }
    }

    Timer { id: flashTimer; interval: 2600; onTriggered: root.flash = "" }

    Process {
        id: edProc
        property var handler: null
        property string pending: ""
        property string output: ""
        property int attempt: 0
        property bool attemptActive: false
        running: false
        stdinEnabled: true
        onRunningChanged: {
            if (running || !edProc.attemptActive) return;
            const attempt = edProc.attempt;
            Qt.callLater(function () {
                if (!edProc.running && edProc.attemptActive && edProc.attempt === attempt)
                    root.failEditorStart(attempt);
            });
        }
        onStarted: {
            if (pending.length) { write(pending); pending = ""; }
            stdinEnabled = false;
        }
        stdout: SplitParser {
            splitMarker: ""
            onRead: function (data) {
                if (!edProc.handler) return;
                edProc.output += data;
            }
        }
        onExited: {
            edProc.attemptActive = false;
            const handler = edProc.handler;
            const output = edProc.output;
            edProc.handler = null;
            edProc.output = "";
            if (handler) {
                let d = null;
                try { d = JSON.parse(output); } catch (e) {}
                handler(d || { ok: false, error: "no reply from the backend" });
            }
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
        running: root.appUnlocked
        command: ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("touch_watch.py").toString().replace(/^file:\/\//, ""))]
        stdout: SplitParser {
            splitMarker: "\n"
            onRead: function (line) { if (line === "touch") list.catchCoast(); }
        }
    }

    Process {
        id: authProc
        property bool restartAfterExit: false
        property int attempt: 0
        property bool attemptActive: false
        running: false
        command: [root.icp, "app-auth"]
        stdout: StdioCollector {
            onStreamFinished: {
                let d = null;
                try { d = JSON.parse(this.text); } catch (e) {}
                if (!d) return;                // killed for a retry - no verdict to act on
                if (d.authed) {
                    root.appUnlocked = true; root.status = ""; root.readClocks(d); root.refresh();
                }
                else if (d.ok === false) root.status = d.error || "authentication failed";
                else if (d.reason === "error")
                    root.status = "couldn't reach the authentication prompt - press Unlock to retry";
                else root.status = "cancelled";
            }
        }
        onRunningChanged: {
            if (running || !authProc.attemptActive) return;
            const attempt = authProc.attempt;
            Qt.callLater(function () {
                if (!authProc.running && authProc.attemptActive && authProc.attempt === attempt)
                    root.failAuthStart(attempt);
            });
        }
        onExited: {
            authProc.attemptActive = false;
            root.authing = false;
            if (restartAfterExit) {
                restartAfterExit = false;
                root.authing = true;
                authProc.attempt += 1;
                authProc.attemptActive = true;
                running = true;
            }
        }
    }

    Timer {
        id: snapshotTimer
        interval: 1500
        onTriggered: scope.grabToImage(function (r) {
            r.saveToFile(root.snapshotPath);
            Qt.quit();
        })
    }

    // Development only: PEAR_PASSWORDS_SIGNIN_PREVIEW=detail | editor_<mode> | search_2fa draws
    // the unlocked window with made-up entries. Nothing is read from or written to the vault.
    Timer {
        id: detailPreview
        interval: 700
        property string mode: ""
        onTriggered: {
            const now = Date.now() / 1000;
            const mk = function (n, user, sites, totp, notes, noSite, domain) {
                return { id: "demo" + n, domain: domain || ("EXAMPLE-" + n), username: user,
                         primary: "Example Account " + n, real_title: "Example Account " + n,
                         nickname: "Example Account " + n, apple_title: "Example Account " + n,
                         synced_name: true, secondary: user, no_site: !!noSite, mdat: now - n * 86400 * 3,
                         has_totp: totp, aliases: [], sites: sites, has_notes: notes, ambiguous: false };
            };
            root.entries = [mk(1, "dummyuser1", ["example.com", "login.example.com"], true, true, true),
                            mk(2, "dummyuser2", ["example.org"], false, true, true),
                            mk(3, "dummyuser3", ["app.example.net"], true, false, false, "example.net"),
                            mk(4, "alex@example.com", [], false, false, false, "example.dev"),
                            Object.assign(mk(5, "Example Home", [], false, false, false, "AirPort"),
                                          { primary: "Example Home", is_wifi: true, secondary: "" })];
            root.appUnlocked = true;
            const q = { search_2fa: "2FA codes", search_notes: "notes", search_websites: "websites", search_wifi: "wifi" }[mode];
            if (q) search.text = q;
            root.applyFilter();
            root.select(root.entries[0]);
            root.fullUntil = now + 95; root.sessionUntil = now + 275;
            root.unlockLeft = 95; root.sessionLeft = 275;
            root.notesText = "Recovery email: backup@example.com\nSecurity question: first pet — Pear";
            root.notesLoaded = true;
            root.totpCode = "482 913"; root.totpLeft = 21;
            if (mode.indexOf("editor_") === 0) {
                root.openEditor(mode.slice(7));
                if (mode === "editor_totp") { edSetup.text = "otpauth://totp/Example:dummyuser1?secret=JBSWY3DPEHPK3PXP&issuer=Example"; }
                if (mode === "editor_create") {
                    crName.text = "Example Account 5"; crSite.text = "example.io"; crUser.text = "sam@example.io";
                    crPass.text = "hutvab-6rixqo-Nocbam"; root.createMore = true;
                }
            }
        }
    }

    Timer {
        id: firstRunPreview
        interval: 700            // after the (locked) first refresh has landed
        onTriggered: { root.appUnlocked = true; root.entries = []; root.filtered = []; root.signedIn = false; }
    }

    Process {
        id: signin
        property int attempt: 0
        property bool attemptActive: false
        running: false
        stdinEnabled: true
        stdout: SplitParser {
            splitMarker: "\n"
            onRead: function (line) {
                if (!line || !line.trim().length) return;
                let m = null;
                try { m = JSON.parse(line); } catch (err) { return; }
                if (m.need) {
                    root.signinNeed = m.need;
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
                if (m.event === "stage" && m.stage === "device_chosen") {
                    root.signinDevice = { name: m.name || "", model: m.model || "", secret: m.secret || "" };
                    return;
                }
                if (m.event === "stage") {
                    root.signinStage = m.stage;
                    if (m.via) root.signinVia = m.via;
                    if (m.count !== undefined) root.signinCount = m.count;
                    return;
                }
                if (m.event === "done") {
                    root.signinRunning = false;
                    root.signinNeed = "";
                    signinField.text = ""; codeField.text = "";
                    root.signinOutcome = m.cancelled ? "cancelled" : (m.ok ? "ok" : "error");
                    if (m.cancelled) root.signinOpen = false;
                    if (m.ok) root.refresh();
                    return;
                }
                if (m.event === "err") root.signinError = m.text || "";
                if (m.event === "warn") root.signinWarnings = root.signinWarnings.concat([m.text || ""]);
                if (m.event) root.signinLogPush(m.event, m.text || "");
            }
        }
        onRunningChanged: {
            if (running || !signin.attemptActive) return;
            const attempt = signin.attempt;
            Qt.callLater(function () {
                if (!signin.running && signin.attemptActive && signin.attempt === attempt)
                    root.failSigninStart(attempt);
            });
        }
        onExited: {
            signin.attemptActive = false;
            root.signinRunning = false;
            signinField.text = ""; codeField.text = "";
            if (root.signinOutcome === "" && root.signinOpen) root.signinOutcome = "error";
        }
    }

    // ---------------------------------------------------------------- actions
    function refresh() {
        const keep = root.selectedId;
        run(["app-list"], "", function (d) {
            if (d.locked) {
                root.appUnlocked = false;
                root.entries = [];
                root.filtered = [];
                root.clearSelection();
                root.signedIn = d.signed_in !== false;
                const headless = Quickshell.env("QT_QPA_PLATFORM") === "offscreen";
                // Never signed in: the first thing a new user sees is the account sign-in, not
                // a fingerprint prompt guarding an empty vault.
                if (!root.signedIn) {
                    if (root.snapshotPath) snapshotTimer.start();
                    if (!root.firstRunShown && !headless && !root.signinOpen) {
                        root.firstRunShown = true;
                        root.startSignin("login");
                    }
                    return;
                }
                // Ask once, straight away - opening the app is the request to see it.
                // Never raise a fingerprint prompt for a window nobody can see: an offscreen
                // load (a test, or the snapshot hook) put a real prompt on screen once.
                if (root.snapshotPath) snapshotTimer.start();
                if (!root.autoAuthTried && !headless) {
                    root.autoAuthTried = true;
                    root.authenticate();
                }
                return;
            }
            root.appUnlocked = true;
            root.entries = d.entries || [];
            root.needsLogin = !!d.needs_login;
            root.signedIn = d.signed_in !== false;
            root.readClocks(d);
            if (root.snapshotPath && root.snapshotQuery) search.text = root.snapshotQuery;
            root.applyFilter();
            if (root.snapshotPath) snapshotTimer.start();
            if (keep) {
                for (let i = 0; i < root.filtered.length; i++) {
                    if (root.filtered[i].id === keep) {
                        root.cursor = i;
                        root.selected = root.filtered[i];
                        root.selectedId = keep;
                        break;
                    }
                }
            }
        });
    }

    // Unlock never goes through the shared command queue: a hung prompt used to hold the queue
    // busy, which disabled this button and parked every retry behind the stuck attempt. It gets
    // its own process, and pressing Unlock while one is pending kills it and starts over.
    property bool authing: false

    function failAuthStart(attempt) {
        if (authProc.running || !authProc.attemptActive || authProc.attempt !== attempt) return;
        authProc.attemptActive = false;
        authProc.restartAfterExit = false;
        root.authing = false;
        root.status = "couldn't start authentication";
    }

    function authenticate() {
        root.status = "waiting for authentication…";
        if (authProc.running) {
            authProc.restartAfterExit = true;
            authProc.running = false;          // backend tears its prompt down on SIGTERM
            return;
        }
        root.authing = true;
        authProc.attempt += 1;
        authProc.attemptActive = true;
        authProc.running = true;
    }

    function applyFilter() {
        const q = search.text.trim().toLowerCase();
        // "2fa", "mfa", "2fa codes", "verification codes", "otp"... list every entry that has
        // a verification code, rather than searching for those letters in names.
        // A few words filter by kind instead of matching text: "notes", "websites", "wifi".
        const kind = root.searchKind(q);
        const out = [];
        for (const e of root.entries) {
            const hay = (e.primary + " " + e.real_title + " " + e.secondary + " " + e.domain
                         + " " + (e.sites || []).join(" ")).toLowerCase();
            if (kind ? kind(e) : (!q || hay.indexOf(q) !== -1))
                out.push(e);
            if (out.length >= 600) break;
        }
        root.filtered = out;
        root.cursor = out.length ? 0 : -1;
        if (out.length) root.select(out[0]); else root.clearSelection();
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
        root.selected = null; root.selectedId = ""; root.relock();
    }

    // Every gated reply carries the clocks, so the window never has to guess.
    function readClocks(d) {
        if (!d || d.expires === undefined) return;
        root.fullUntil = d.full_until || 0;
        root.sessionUntil = d.expires || 0;
        const now = Date.now() / 1000;
        root.unlockLeft = Math.max(0, Math.ceil(root.fullUntil - now));
        root.sessionLeft = Math.max(0, Math.ceil(root.sessionUntil - now));
        if (root.unlockLeft > 0) {
            root.clipboardMustStayClear = false;
            root.clipboardClearRequested = false;
            root.clipboardRetryCount = 0;
            clipboardRetryTimer.stop();
        }
    }

    // Text controls keep their value even while their sheet is hidden. Clear every editor
    // before hiding it, including fields whose contents are only secret in some modes (notes,
    // setup links and the create form). Do not clear edProc.pending: a process that already
    // started may still need that exact payload to finish an in-flight remote write.
    function clearEditorFields() {
        previewDebounce.stop();
        edArea.text = ""; edSetup.text = "";
        crName.text = ""; crSite.text = ""; crUser.text = ""; crPass.text = "";
        crNotes.text = ""; crSetup.text = "";
        root.totpPreview = ({});
        root.editorError = "";
        root.editorBusy = false; root.editorScanning = false; root.createMore = false;
        previewDebounce.stop();
    }

    // The scan stopped counting. Everything on screen that came from it goes. In particular,
    // this path never waits for the command queue: the clock is a security boundary even while
    // a network write or a stuck helper is running.
    function forgetSecrets() {
        root.invalidateAppCallbacks();
        root.invalidateEditorCallbacks();
        root.revealed = ""; root.totpCode = ""; root.totpLeft = 0;
        root.notesText = ""; root.notesLoaded = false;
        root.historyRows = []; root.revealedHistory = ({}); root.historyLoaded = false;
        root.confirming = false; root.changing = false; root.generated = false;
        root.renaming = false;
        newPw.text = "";
        nickField.text = "";
        // Sign-in is a separate long-lived flow and remains open, but a password or code that
        // is waiting for the user is still a secret and must be re-entered after expiry.
        if (root.signinNeed === "secret" || root.signinKind === "password"
            || root.signinKind === "device_passcode")
            signinField.text = "";
        codeField.text = "";
        root.editorOpen = false; root.editorMode = "";
        root.clearEditorFields();
    }

    // Out of time: back to the locked window, with nothing in it.
    function lockApp() {
        root.clipboardMustStayClear = true;
        root.clearClipboard();
        root.forgetSecrets();
        root.appUnlocked = false;
        root.autoAuthTried = true;            // don't re-prompt on our own; the screen invites it
        root.fullUntil = 0; root.sessionUntil = 0; root.unlockLeft = 0; root.sessionLeft = 0;
        root.entries = []; root.filtered = [];
        root.selected = null; root.selectedId = ""; root.detailIndex = 0;
        search.text = "";
    }

    // Selecting another entry hides what was on screen for the last one. The clocks are the
    // app's, not the entry's, so they keep running.
    function relock() {
        root.forgetSecrets();
        root.detailIndex = 0;
    }

    function select(e) {
        if (!e || e.id === root.selectedId) return;
        root.selected = e; root.selectedId = e.id;
        root.relock();
    }

    function moveCursor(delta) {
        if (!root.filtered.length) return;
        root.cursor = Math.max(0, Math.min(root.filtered.length - 1, root.cursor + delta));
        root.select(root.filtered[root.cursor]);
        list.stopPhysics();
        list.positionViewAtIndex(root.cursor, ListView.Contain);
    }

    function unlockThen(after) {
        if (root.unlocked) { if (after) after(); return; }
        root.status = "waiting for fingerprint…";
        run(["app-unlock"], "", function (d) {
            root.readClocks(d);
            if (after) after();
            if (!root.selectedId) return;
            // Fetch history under the scan just given. Queued, so it cannot clobber
            // whatever `after` started.
            root.run(["app-history", root.selectedId], "", function (h) {
                root.historyRows = h.history || [];
                root.historyLoaded = true;
            });
        });
    }

    // Copy never brings the value into this process - icp puts it on the clipboard itself.
    function copyField(field, label) {
        if (!root.selected) return;
        const go = function () {
            run(["app-copy", root.selectedId, "--field", field], "", function (d) {
                root.flash = d.clears_in
                    ? label + " copied — clears in " + d.clears_in + "s"
                    : label + " copied";
                flashTimer.restart();
            });
        };
        if (field === "password") unlockThen(go); else go();
    }
    function copyPassword() { root.copyField("password", "Password"); }

    function generatePassword() {
        const generation = root.callbackGeneration;
        newPw.text = ""; root.generated = false;
        run(["app-generate"], "", function (d) {
            if (generation !== root.callbackGeneration || (!root.changing && !root.confirming)
                || newPw.text.length)
                return;
            newPw.text = d.password;
            root.generated = true;
            root.flash = "generated — " + d.entropy_bits + " bits, one digit, one capital";
            flashTimer.restart();
        });
    }

    function saveNickname(value) {
        unlockThen(function () {
            root.status = "renaming…";
            run(["app-set-nickname", root.selectedId], value, function (d) {
                root.renaming = false;
                // Say which it was. A name written to Apple's metadata record reaches every
                // device; one stored here does not, and the user should not have to guess.
                root.flash = !d.nickname
                    ? (d.synced ? "name cleared on all your devices" : "name cleared")
                    : (d.synced ? "renamed on all your devices" : "renamed on this machine only");
                flashTimer.restart();
                root.refresh();
            });
        });
    }

    // Sign-in is driven entirely by whatever the backend asks for: it emits a prompt, we
    // render it, we answer. The UI deliberately knows nothing about Apple's sequence, so a
    // step added later needs no change here.
    function failSigninStart(attempt) {
        if (signin.running || !signin.attemptActive || signin.attempt !== attempt) return;
        signin.attemptActive = false;
        root.signinRunning = false;
        root.signinStage = "";
        root.signinNeed = "";
        root.signinKind = "";
        root.signinDefault = "";
        root.signinDetail = "";
        root.signinOptions = [];
        root.signinDetails = [];
        root.signinDevice = ({});
        root.signinChoice = -1;
        root.signinVia = "trusted";
        root.signinCount = -1;
        root.signinVerified = false;
        root.signinError = "couldn't start sign-in";
        root.signinWarnings = [];
        root.signinLog = [];
        root.signinShowDetails = false;
        root.signinOutcome = "error";
        signinField.text = ""; codeField.text = "";
        root.status = "couldn't start sign-in";
    }

    function startSignin(mode) {
        root.signinMode = mode;
        root.signinOpen = true;
        root.signinRunning = true;
        root.signinStage = ""; root.signinNeed = ""; root.signinKind = "";
        root.signinDefault = ""; root.signinDetail = ""; root.signinOptions = [];
        root.signinChoice = -1; root.signinVia = "trusted"; root.signinCount = -1;
        root.signinVerified = false; root.signinError = ""; root.signinWarnings = [];
        root.signinLog = []; root.signinShowDetails = false; root.signinOutcome = "";
        root.signinDevice = ({});
        signinField.text = ""; codeField.text = "";
        signin.command = [root.icp, "app-signin", "--mode", mode];
        signin.attempt += 1;
        signin.attemptActive = true;
        signin.running = true;
    }

    function signinSend(value) {
        if (!root.signinRunning || root.signinNeed === "") return;
        if (root.signinKind === "code") root.signinVerified = true;
        signin.write(JSON.stringify({ value: String(value) }) + "\n");
        root.signinNeed = "";
        signinField.text = "";
        codeField.text = "";
    }

    function signinCancel() {
        if (root.signinRunning) signin.write(JSON.stringify({ cancel: true }) + "\n");
        signinField.text = ""; codeField.text = "";
        root.signinOpen = false;
    }

    function signinLogPush(kind, text) {
        root.signinLog = root.signinLog.slice(-40).concat([{ kind: kind, text: text }]);
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
        if (root.signinOutcome === "ok") return root.signinMode === "sync" ? "You're reconnected" : "You're signed in";
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
        return root.signinMode === "sync" ? "Confirm it's you" : "Sign in to iCloud";
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
            return root.signinMode === "sync" ? "Your session expired. Sign in again to keep your passwords syncing."
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
        else if (root.signinNeed === "confirm") root.signinSend("y");
        else root.signinSend(signinField.text);
    }

    // Development only: PEAR_PASSWORDS_SIGNIN_PREVIEW=<state> draws one sheet state with made-up
    // values and starts nothing, so each screen can be checked without talking to Apple.
    function applySigninPreview(state) {
        root.signinOpen = true;
        const set = (o) => { for (const k in o) root[k] = o[k]; };
        set({ signinMode: "login", signinRunning: true, signinNeed: "", signinKind: "",
              signinStage: "", signinOutcome: "", signinVia: "trusted" });
        switch (state) {
        case "apple_id": set({ signinStage: "account", signinNeed: "text", signinKind: "apple_id" });
            signinField.text = "name@example.com"; break;
        case "password": set({ signinStage: "account", signinNeed: "secret", signinKind: "password" });
            signinField.text = "xxxxxxxxxxxx"; break;
        case "signing_in": set({ signinStage: "signing_in" }); break;
        case "code": set({ signinStage: "verify", signinNeed: "text", signinKind: "code" });
            codeField.text = "314"; codeField.forceActiveFocus(); break;
        case "device": set({ signinStage: "finding_devices", signinNeed: "choice", signinKind: "device",
            signinOptions: ["Work Mac (MacBook Pro)", "My iPhone (iPhone 16 Pro)"],
            signinDetails: ["backed up 12 Aug 2026 · Mac login password · serial ending 4K2P",
                            "backed up 3 Sep 2026 · 6-digit passcode · serial ending 7XQ2"], signinChoice: 1 }); break;
        case "join_confirm": set({ signinStage: "finding_devices", signinNeed: "confirm", signinKind: "join_confirm",
            signinDetail: "My iPhone (iPhone 16 Pro)" }); break;
        case "device_passcode": set({ signinStage: "finding_devices", signinNeed: "secret", signinKind: "device_passcode",
            signinDetail: "My iPhone (iPhone 16 Pro)" }); signinField.text = "xxxxxx"; break;
        case "ipad_passcode": set({ signinStage: "finding_devices", signinNeed: "secret", signinKind: "device_passcode",
            signinDetail: "Alex’s iPad",
            signinDevice: { name: "Alex’s iPad", model: "iPad Pro (11-inch) (3rd generation)", secret: "passcode" } }); break;
        case "ipad_confirm": set({ signinStage: "finding_devices", signinNeed: "confirm", signinKind: "join_confirm",
            signinDetail: "Alex’s iPad",
            signinDevice: { name: "Alex’s iPad", model: "iPad Pro (11-inch) (3rd generation)", secret: "passcode" } }); break;
        case "ipad_device": set({ signinStage: "finding_devices", signinNeed: "choice", signinKind: "device",
            signinOptions: ["Alex’s MacBook Pro", "Alex’s iPad"],
            signinDetails: ["MacBook Pro (14-inch, 2023) · backed up 12 Aug 2026 · Mac login password · serial ending 4K2P",
                            "iPad Pro (11-inch) (3rd generation) · backed up 3 Sep 2026 · 6-digit passcode · serial ending 7XQ2"],
            signinChoice: 1 }); break;
        case "mac_confirm": set({ signinStage: "finding_devices", signinNeed: "confirm", signinKind: "join_confirm",
            signinDetail: "Work Mac (MacBook Pro)" }); break;
        case "mac_passcode": set({ signinStage: "finding_devices", signinNeed: "secret", signinKind: "device_passcode",
            signinDetail: "Work Mac (MacBook Pro)" }); signinField.text = "xxxxxxxxxx"; break;
        case "not_joined": set({ signinRunning: false, signinOutcome: "ok", signinStage: "not_joined" }); break;
        case "joining": set({ signinStage: "joining" }); break;
        case "sync_code": set({ signinMode: "sync", signinStage: "verify", signinNeed: "text", signinKind: "code" }); break;
        case "done": set({ signinRunning: false, signinOutcome: "ok", signinVerified: true, signinCount: 547,
            signinStage: "synced", signinWarnings: ["3 items could not be decrypted and were skipped."] }); break;
        case "error": set({ signinRunning: false, signinOutcome: "error", signinError: "2FA rejected (code was rejected)",
            signinLog: [{ kind: "step", text: "requesting code" }, { kind: "err", text: "2FA rejected (code was rejected)" }],
            signinShowDetails: true }); break;
        }
    }

    // The word follows the device: a Mac escrows with its login password, iPhone/iPad a passcode.
    function deviceName() { return root.signinDevice.name || root.signinDetail; }
    function secretWord() {
        if (root.signinDevice.secret) return root.signinDevice.secret;
        const d = root.signinDetail;
        if (/mac/i.test(d)) return "password";
        if (/iphone|ipad|ipod|vision|watch/i.test(d)) return "passcode";
        return "passcode or password";
    }
    function signinSteps() {
        return root.signinMode === "sync" ? ["Verify", "Sync"] : ["Account", "Verify", "Trust", "Sync"];
    }
    // Which step of the indicator the current stage or question belongs to.
    function signinStep() {
        const k = root.signinKind, s = root.signinStage;
        if (root.signinStage === "not_joined") return 2;
        if (root.signinOutcome === "ok") return root.signinSteps().length;
        if (root.signinMode === "sync") return (s === "syncing" || s === "synced") ? 1 : 0;
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
        if (root.unlocked) parts.push("unlocked " + root.clock(root.unlockLeft));
        return parts.join("   ·   ");
    }

    function fieldRows() {
        const s = root.selected;
        if (!s) return [];
        const rows = [{ key: "username", label: s.is_wifi ? "Network" : "Username", value: s.username || "—",
                        quiet: !s.username, actions: [{ key: "username", label: "copy" }] },
                      { key: "password", label: "Password",
                        value: root.revealed ? root.revealed : "••••••••••••",
                        quiet: !root.revealed,
                        actions: [{ key: "view", label: root.revealed ? "hide" : "view" },
                                  { key: "change", label: "change" },
                                  { key: "password", label: "copy" }] }];
        if (s.is_wifi) return rows;
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
        return rows;
    }

    // The entry's websites: the record's own site first (when it has one), then the extras.
    function allSites() {
        const s = root.selected;
        if (!s) return [];
        return (s.no_site ? [] : [s.domain]).concat(s.sites || []);
    }

    function fieldAction(key) {
        if (key === "username") root.copyField("username", "Username");
        else if (key === "password") root.copyPassword();
        else if (key === "view") root.doReveal();
        else if (key === "change")
            root.unlockThen(function () { root.changing = true; newPw.forceActiveFocus(); });
        else if (key === "website") root.openDomain(root.selected.domain);
        else if (key.indexOf("open:") === 0) root.openDomain(root.allSites()[parseInt(key.slice(5))]);
        else if (key === "totp") root.loadTotp();
        else if (key === "editsites") root.unlockThen(function () { root.openEditor("sites"); });
        else if (key === "edittotp") root.unlockThen(function () { root.openEditor("totp"); });
        else if (key === "notes") root.loadNotes(root.notesLoaded ? function () { root.openEditor("notes"); } : null);
        else if (key === "editnotes") root.loadNotes(function () { root.openEditor("notes"); });
    }

    // ---- keyboard: the detail panel -------------------------------------------------------
    // Stops, in order: every field row, then either each history row (unlocked) or the single
    // "unlock" line (locked), so a keyboard user can unlock history as well as read it.
    function panelStops() {
        return root.fieldCount + (root.unlocked ? root.historyRows.length : 1);
    }
    function enterPanel(at) {
        if (!root.selected || !root.appUnlocked) return;
        root.panelFocus = true;
        root.detailIndex = at === undefined ? 0 : Math.max(0, Math.min(at, root.panelStops() - 1));
        detailKeys.forceActiveFocus();
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
        if (next >= root.fieldCount && root.unlocked)
            historyList.positionViewAtIndex(next - root.fieldCount, ListView.Contain);
        return true;
    }
    function toggleHistory(h) {
        const m = Object.assign({}, root.revealedHistory);
        m[h] = !m[h];
        root.revealedHistory = m;
    }
    // Enter does exactly what a click on the row does.
    function panelActivate() {
        const rows = root.fieldRows(), k = root.detailIndex;
        if (k < rows.length) { root.fieldAction(rows[k].key); return; }
        if (!root.unlocked) { root.unlockThen(null); return; }
        root.toggleHistory(k - rows.length);
    }
    // Space shows: the password on its row, a former password on a history row.
    function panelShow() {
        const rows = root.fieldRows(), k = root.detailIndex;
        if (k < rows.length && rows[k].key === "password") { root.doReveal(); return; }
        if (k >= rows.length && root.unlocked) { root.toggleHistory(k - rows.length); return; }
        root.panelActivate();
    }
    function fieldFocused(i) { return root.panelFocus && root.detailIndex === i; }

    function openDomain(d) {
        if (!d) return;
        Qt.openUrlExternally(d.indexOf("://") === -1 ? "https://" + d : d);
    }

    function doReveal() {
        unlockThen(function () {
            if (root.revealed) { root.revealed = ""; return; }
            run(["app-reveal", root.selectedId], "", function (d) { root.revealed = d.password || ""; });
        });
    }

    function loadHistory() {
        unlockThen(function () {
            run(["app-history", root.selectedId], "", function (d) {
                root.historyRows = d.history || [];
            });
        });
    }

    function loadNotes(after) {
        unlockThen(function () {
            if (root.notesLoaded || !root.selected.has_notes) { root.notesLoaded = true; if (after) after(); return; }
            run(["app-details", root.selectedId], "", function (d) {
                root.notesText = d.notes || ""; root.notesLoaded = true;
                if (after) after();
            });
        });
    }

    function openEditor(mode) {
        root.invalidateEditorCallbacks();
        root.clearEditorFields();
        root.editorMode = mode; root.editorError = ""; root.totpPreview = ({});
        root.editorBusy = false; root.editorScanning = false; root.createMore = false;
        edArea.text = mode === "sites" ? (root.selected ? (root.selected.sites || []).join("\n") : "")
                    : mode === "notes" ? root.notesText : "";
        edSetup.text = "";
        if (mode === "create") {
            crName.text = ""; crSite.text = ""; crUser.text = ""; crPass.text = "";
            crNotes.text = ""; crSetup.text = "";
        }
        root.editorOpen = true;
        const generation = root.editorGeneration;
        Qt.callLater(function () {
            if (!root.editorOpen || generation !== root.editorGeneration || root.editorMode !== mode) return;
            if (mode === "create") crName.forceActiveFocus();
            else if (mode === "totp") edSetup.forceActiveFocus();
            else edArea.forceActiveFocus();
        });
    }
    function closeEditor() {
        if (root.editorBusy) return;
        root.editorOpen = false;
        root.invalidateEditorCallbacks();
        root.clearEditorFields();
        root.editorMode = "";
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
        if (root.editorBusy || root.editorScanning || edProc.running) return false;
        if (root.editorMode === "totp") return !!root.totpPreview.code;
        if (root.editorMode === "create")
            return crPass.text.length > 0 && (crSite.text.trim().length > 0 || crName.text.trim().length > 0)
                   && (!crSetup.text.trim() || !!root.totpPreview.code);
        return true;
    }

    function editorSave() {
        if (!root.editorReady()) return;
        root.editorError = "";
        const id = root.selectedId;
        let args, payload;
        if (root.editorMode === "sites") {
            args = ["app-set-details", id];
            payload = { sites: edArea.text.split("\n").map(function (s) { return s.trim(); }).filter(function (s) { return s; }) };
        } else if (root.editorMode === "notes") {
            args = ["app-set-details", id]; payload = { notes: edArea.text };
        } else if (root.editorMode === "totp") {
            args = ["app-set-totp", id]; payload = { setup: edSetup.text };
        } else {
            args = ["app-create"];
            payload = { title: crName.text, site: crSite.text, username: crUser.text,
                        password: crPass.text, notes: crNotes.text, setup: crSetup.text };
        }
        const mode = root.editorMode;
        const generation = root.editorGeneration;
        root.editorBusy = true;
        if (!root.edRun(args, JSON.stringify(payload), function (d) {
            if (!root.editorOpen || root.editorMode !== mode || root.editorGeneration !== generation
                || (mode !== "create" && root.selectedId !== id)) return;
            root.editorBusy = false;
            if (d.ok === false) { root.editorError = d.error || "Couldn't save"; return; }
            if (mode === "notes") { root.notesText = payload.notes.replace(/^\n+|\n+$/g, ""); root.notesLoaded = true; }
            if (mode === "totp") { root.totpCode = ""; }
            if (mode === "create" && d.id) { root.selectedId = d.id; root.selected = null; }
            root.editorOpen = false;
            root.invalidateEditorCallbacks();
            root.clearEditorFields();
            root.editorMode = "";
            root.flash = mode === "create" ? "Added to iCloud Keychain" : "Saved to iCloud — on all your devices";
            flashTimer.restart();
            root.refresh();
        })) {
            root.editorBusy = false;
            root.editorError = "An earlier save is still finishing — try again in a moment";
        }
    }
    function removeTotp() {
        if (root.editorBusy || root.editorScanning || edProc.running) return;
        const id = root.selectedId, generation = root.editorGeneration;
        root.editorError = ""; root.editorBusy = true;
        if (!root.edRun(["app-set-totp", id], JSON.stringify({ remove: true }), function (d) {
            if (!root.editorOpen || root.editorMode !== "totp" || root.editorGeneration !== generation
                || root.selectedId !== id) return;
            root.editorBusy = false;
            if (d.ok === false) { root.editorError = d.error || "Couldn't remove it"; return; }
            root.editorOpen = false; root.totpCode = "";
            root.invalidateEditorCallbacks();
            root.clearEditorFields();
            root.editorMode = "";
            root.flash = "Verification code removed"; flashTimer.restart();
            root.refresh();
        })) {
            root.editorBusy = false;
            root.editorError = "An earlier editor operation is still finishing — try again in a moment";
        }
    }
    function scanQr(field) {
        if (root.editorBusy || root.editorScanning || edProc.running) return;
        const mode = root.editorMode, generation = root.editorGeneration, target = field;
        root.editorScanning = true; root.editorError = "";
        if (!root.edRun(["app-scan-qr"], "", function (d) {
            if (!root.editorOpen || root.editorMode !== mode || root.editorGeneration !== generation
                || field !== target) return;
            root.editorScanning = false;
            if (d.cancelled) return;
            if (d.ok === false) { root.editorError = d.error || "No QR code found"; return; }
            field.text = d.text;
        })) {
            root.editorScanning = false;
            root.editorError = "An earlier editor operation is still finishing — try again in a moment";
        }
    }
    function previewTotp(text) {
        const mode = root.editorMode, generation = root.editorGeneration;
        const target = mode === "create" ? crSetup : edSetup;
        if (!text.trim()) {
            if (root.editorOpen && root.editorMode === mode && generation === root.editorGeneration
                && target.text === text) root.totpPreview = ({});
            return;
        }
        run(["app-totp-preview"], text, function (d) {
            if (!root.editorOpen || root.editorMode !== mode || root.editorGeneration !== generation
                || target.text !== text) return;
            root.totpPreview = d && d.code ? d : ({ error: "" });
        });
    }
    function groupCode(c) { return c && c.length === 6 ? c.slice(0, 3) + " " + c.slice(3) : (c || ""); }

    // Editor commands get their own process: a save fetches the zone, writes and re-syncs,
    // which takes long enough that it must not hold up the list's own queue.
    function edRun(args, stdinText, done) {
        if (edProc.running) return false;
        const callbackGeneration = root.callbackGeneration;
        const editorGeneration = root.editorGeneration;
        edProc.handler = function (d) {
            if (callbackGeneration !== root.callbackGeneration || editorGeneration !== root.editorGeneration)
                return;
            if (done) done(d);
        };
        edProc.stdinEnabled = true;
        edProc.pending = stdinText && stdinText.length ? stdinText + "\n" : "";
        edProc.output = "";
        edProc.command = [root.icp].concat(args);
        edProc.attempt += 1;
        edProc.attemptActive = true;
        edProc.running = true;
        return true;
    }

    function loadTotp() {
        unlockThen(function () {
            run(["app-totp", root.selectedId], "", function (d) {
                root.totpCode = d.code; root.totpLeft = d.seconds;
            });
        });
    }

    function commitChange() {
        const pw = newPw.text;
        root.confirming = false;
        root.status = "pushing to iCloud…";
        run(["app-set-password", root.selectedId], pw, function (d) {
            newPw.text = ""; root.revealed = ""; root.historyRows = [];
            root.flash = "changed on all your devices (" + d.records_written + " records)";
            flashTimer.restart();
            root.refresh();
        });
    }

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

    Component.onCompleted: {
        refresh();
        const preview = Quickshell.env("PEAR_PASSWORDS_SIGNIN_PREVIEW");
        if (preview === "first_run") { firstRunPreview.start(); return; }
        if (preview && (preview === "detail" || preview.indexOf("editor_") === 0 || preview.indexOf("search_") === 0)) {
            detailPreview.mode = preview; detailPreview.start(); return;
        }
        if (preview === "first_launch") { root.signedIn = false; Qt.callLater(() => root.applySigninPreview("apple_id")); return; }
        if (preview) Qt.callLater(() => root.applySigninPreview(preview));
    }

    FloatingWindow {
        id: win
        title: "Pear Passwords"
        implicitWidth: 960
        implicitHeight: 640
        color: Theme.bg
        visible: true
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
                    else if (search.text.length) { search.text = ""; }
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
                }
            }

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                // Apple wants an interactive sign-in. This used to be a desktop notification
                // telling you to run a terminal command, which is a dead end with nowhere to
                // type the code.
                Rectangle {
                    Layout.fillWidth: true
                    visible: (root.needsLogin || (!root.signedIn && root.entries.length > 0)) && !root.signinOpen
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
                            onClicked: root.startSignin(root.signedIn ? "sync" : "login")
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: 0

                    // ------------------------------------------------ list
                    ColumnLayout {
                        Layout.fillWidth: false
                        // 380, not 340: at 340 7% of usernames elided; at 380 none do. The list
                        // is where the time goes - the panel mostly confirms what was picked.
                        Layout.preferredWidth: 380
                        Layout.minimumWidth: 380
                        Layout.maximumWidth: 380
                        Layout.fillHeight: true
                        spacing: 0

                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: 58
                            color: Theme.panel
                            // Plain text in the corner, no box: a search that looks like a form
                            // field makes the whole window read as a dialog.
                            // New entry: a word in the corner, like the search it sits beside.
                            Text {
                                id: newButton
                                anchors.right: parent.right
                                anchors.rightMargin: 16
                                anchors.verticalCenter: parent.verticalCenter
                                visible: root.appUnlocked
                                text: "+ New"
                                color: hNew.hovered ? Theme.fg : Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                HoverHandler { id: hNew; cursorShape: Qt.PointingHandCursor }
                                TapHandler { onTapped: root.openEditor("create") }
                            }
                            TextField {
                                id: search
                                anchors.fill: parent
                                anchors.leftMargin: 14
                                anchors.rightMargin: newButton.visible ? newButton.width + 28 : 14
                                enabled: root.appUnlocked
                                opacity: root.appUnlocked ? 1 : 0.6
                                placeholderText: !root.signedIn && root.entries.length === 0 ? "No passwords"
                                    : !root.appUnlocked ? "Locked"
                                    : root.entries.length === 0 ? "No passwords"
                                    : "Search " + root.entries.length + " passwords"
                                color: Theme.fg
                                placeholderTextColor: Theme.dim
                                background: Rectangle { color: "transparent" }
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                focus: true
                                onTextChanged: root.applyFilter()
                                Keys.onDownPressed: root.moveCursor(1)
                                Keys.onTabPressed: root.enterPanel(0)
                                Keys.onUpPressed: root.moveCursor(-1)
                                Keys.onReturnPressed: root.copyPassword()
                                Keys.onEscapePressed: function (ev) { ev.accepted = false; }
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
                                    if (root.debugWheel)
                                        console.log("wheel t=" + Date.now() + " px=" + px + " angle=" + ad
                                                    + " phase=" + ev.phase);
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
                                onTriggered: list.step(Math.min(frameTime * 1000, 34))
                            }

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
                                if (root.debugWheel)
                                    console.log("release v=" + list.vel.toFixed(2) + " px/ms -> " + list.mode);
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
                                        visible: modelData.has_totp
                                        text: "⧗"
                                        color: Theme.dim
                                        font.pixelSize: Theme.fBody
                                    }
                                }
                            }
                        }

                        // Never signed in: no list and no placeholder rows - this keeps the search
                        // bar pinned to the top instead of floating to the middle of an empty column.
                        Item {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: !root.appUnlocked && !root.signedIn
                        }

                        // Locked: rows with no content. Widths come from the row index, never
                        // from the entries - the backend has not sent any.
                        Column {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: !root.appUnlocked && root.signedIn
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
                            visible: !root.appUnlocked && root.signedIn
                            spacing: 14
                            // Everything here is greyed except the one thing you can do. A locked
                            // screen shouldn't shout its own state louder than the way out of it.
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: "Pear Passwords is locked"
                                color: Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fHeading
                            }
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: root.authing
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
                                text: root.authing ? "Retry" : "Unlock"
                                onClicked: root.authenticate()
                            }
                        }

                        // First run: nothing to show yet, and the one thing to do about it.
                        ColumnLayout {
                            anchors.centerIn: parent
                            width: Math.min(parent.width - 80, 360)
                            visible: (root.appUnlocked && root.entries.length === 0) || (!root.appUnlocked && !root.signedIn)
                            spacing: 10
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: "No passwords yet"
                                color: Theme.fg
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fHeading
                            }
                            Text {
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
                                            visible: !root.renaming
                                            Layout.fillWidth: true
                                            text: root.selected ? root.selected.primary : ""
                                            color: Theme.fg
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fHeading
                                            elide: Text.ElideRight
                                            HoverHandler { id: hTitle }
                                            MouseArea {
                                                anchors.fill: parent
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: root.unlockThen(function () {
                                                    nickField.text = root.selected.nickname
                                                        || root.selected.real_title;
                                                    root.renaming = true;
                                                    nickField.forceActiveFocus();
                                                    nickField.selectAll();
                                                })
                                            }
                                        }
                                        Text {
                                            visible: !root.renaming
                                            text: "rename"
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                            opacity: hTitle.hovered ? 1 : 0
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
                                    implicitHeight: 48

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
                                            Layout.preferredWidth: 88
                                            text: frow.modelData.label
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            text: frow.modelData.value
                                            color: frow.modelData.quiet ? Theme.dim : Theme.fg
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            elide: Text.ElideRight
                                        }
                                        // Secondary actions: declared on top, so a click on one
                                        // is taken here and never reaches the row's own action.
                                        Repeater {
                                            model: frow.modelData.actions
                                            delegate: Text {
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
                                    text: "also on   "
                                    color: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                }
                                Repeater {
                                    model: root.selected ? root.selected.aliases : []
                                    delegate: Text {
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
                                        Layout.fillWidth: true
                                        placeholderText: "New password"
                                        // Generated passwords are shown in clear so they can be
                                        // read and rehearsed; typed ones stay masked.
                                        password: !root.generated
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fBody
                                        onTextEdited: root.generated = false
                                        onAccepted: if (text.length) root.confirming = true
                                    }
                                    AppButton { text: "Generate"; onClicked: root.generatePassword() }
                                    AppButton {
                                        text: "Change…"
                                        enabled: newPw.text.length > 0 && !root.busy
                                        onClicked: root.confirming = true
                                    }
                                    Text {
                                        text: "cancel"
                                        color: Theme.dim
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fSmall
                                        MouseArea {
                                            anchors.fill: parent
                                            anchors.margins: -8
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: { root.changing = false; newPw.text = ""; root.generated = false; }
                                        }
                                    }
                                }

                                // confirmation: this writes to every Apple device you own
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    visible: root.confirming
                                    spacing: 10
                                    Text {
                                        Layout.fillWidth: true
                                        text: "Change this password on every device signed into your iCloud account?"
                                        color: Theme.fg
                                        font.family: Theme.uiFont
                                        font.pixelSize: Theme.fBody
                                        wrapMode: Text.Wrap
                                    }
                                    Text {
                                        Layout.fillWidth: true
                                        text: (root.revealed ? root.revealed : "current password") + "   →   " + newPw.text
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
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: false
                                Layout.topMargin: 30
                                spacing: 10
                                Text {
                                    text: "History"
                                    color: Theme.dim
                                    font.family: Theme.uiFont
                                    font.pixelSize: Theme.fSmall
                                    font.letterSpacing: 0.6
                                }
                                Item { Layout.fillWidth: true }
                                Text {
                                    visible: !root.unlocked
                                    text: "unlock"
                                    readonly property bool keyed: root.panelFocus && !root.unlocked
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
                                        onClicked: root.unlockThen(null)
                                    }
                                }
                            }

                            Text {
                                Layout.fillWidth: true
                                Layout.topMargin: 10
                                visible: root.unlocked && root.historyLoaded && root.historyRows.length === 0
                                text: "No changes recorded yet."
                                color: Theme.dim
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fSmall
                            }

                            Item {
                                Layout.fillHeight: true
                                visible: !(root.unlocked && root.historyRows.length > 0)
                            }

                            // The list is widened 12px each side and its text inset by the same,
                            // so a hovered row's fill bleeds past the column exactly like the
                            // field rows above while the text stays aligned with them. It can't
                            // just bleed outward like those: the list clips its own bounds.
                            Item {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.topMargin: 6
                                visible: root.unlocked && root.historyRows.length > 0
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
                                        onClicked: {
                                            const m = Object.assign({}, root.revealedHistory);
                                            m[hrow.index] = !m[hrow.index];
                                            root.revealedHistory = m;
                                        }
                                    }
                                    ColumnLayout {
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.leftMargin: 12
                                        anchors.rightMargin: 12
                                        anchors.verticalCenter: parent.verticalCenter
                                        spacing: 3
                                        Text {
                                            text: Qt.formatDateTime(new Date(hrow.modelData.at * 1000), "d MMM yyyy") + "   "
                                                  + (hrow.modelData.source === "sync" ? "changed on another device"
                                                     : hrow.modelData.source === "local" ? "changed here" : "from Apple")
                                            color: Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fSmall
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            text: root.revealedHistory[hrow.index]
                                                ? ((hrow.modelData.old ? hrow.modelData.old + "   →   " : "") + (hrow.modelData.new || ""))
                                                : "••••••••   →   ••••••••"
                                            color: root.revealedHistory[hrow.index] ? Theme.fg : Theme.dim
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            elide: Text.ElideRight
                                        }
                                    }
                                }
                            }
                            }
                        }
                    }
                }

                // ------------------------------------------------ status bar
                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 24
                    color: root.flash ? Theme.hover : Theme.panel
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 12
                        anchors.rightMargin: 12
                        spacing: 10
                        Text {
                            Layout.fillWidth: true
                            text: root.flash ? root.flash
                                : root.status ? root.status
                                : root.busy ? "working…"
                                : !root.appUnlocked && root.signedIn ? "locked"
                                : root.entries.length === 0 ? ""
                                : root.filtered.length + " of " + root.entries.length + " shown"
                            color: root.flash ? Theme.accent : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            elide: Text.ElideRight
                            opacity: root.appUnlocked || root.flash ? 1 : 0.45
                        }
                        // Which of the two states the app is in, and how long is left of it.
                        // Click it to scan now rather than waiting to be asked mid-action.
                        Text {
                            visible: root.appUnlocked && root.sessionLeft > 0
                            text: root.unlocked ? "unlocked " + root.clock(root.unlockLeft)
                                                : "read-only · locks in " + root.clock(root.sessionLeft)
                            color: root.unlocked ? Theme.accent : (hLock.hovered ? Theme.fg : Theme.dim)
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hLock.hovered && !root.unlocked
                            HoverHandler { id: hLock; cursorShape: root.unlocked ? Qt.ArrowCursor : Qt.PointingHandCursor }
                            TapHandler { onTapped: if (!root.unlocked) root.unlockThen(null) }
                        }
                        // Always reachable - the banner only appears once Apple has already
                        // refused a sync, which is no help for a first sign-in.
                        Text {
                            text: "sign in…"
                            opacity: root.appUnlocked ? 1 : 0.45
                            color: hSign.hovered ? Theme.accent : Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            font.underline: hSign.hovered
                            HoverHandler { id: hSign }
                            TapHandler { onTapped: root.startSignin("login") }
                        }
                        Text {
                            visible: root.entries.length > 0
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

        // Locked: the whole window is the way back in. Under the sheets (z 90/100) so a
        // sign-in or an editor still takes its own clicks.
        MouseArea {
            parent: scope
            z: 50
            anchors.fill: parent
            enabled: !root.appUnlocked && root.signedIn && !root.signinOpen && !root.editorOpen
            visible: enabled
            cursorShape: Qt.PointingHandCursor
            onClicked: root.authenticate()
        }

        // ---------------------------------------------------------------- editor sheet
        // Websites, notes, verification code and new entries: one card in the sign-in sheet's
        // style. Every save goes to iCloud and is read back before the sheet closes.
        Rectangle {
            parent: scope
            z: 90
            anchors.fill: parent
            visible: root.editorOpen
            color: Qt.rgba(0, 0, 0, 0.55)
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
                        Layout.fillWidth: true
                        text: root.editorTitle()
                        color: Theme.fg
                        font.family: Theme.uiFont
                        font.pixelSize: Math.round(Theme.fHeading * 1.25)
                        font.weight: Font.DemiBold
                        wrapMode: Text.Wrap
                    }
                    Text {
                        Layout.fillWidth: true
                        Layout.topMargin: 6
                        visible: text !== ""
                        text: root.editorMode === "create" ? "Saved to your iCloud Keychain, so it reaches your other devices."
                            : root.editorMode === "totp" ? "Paste the setup key or link from the site's two-factor settings, or scan its QR code."
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
                            Layout.fillWidth: true
                            visible: root.editorMode === "sites" && root.selected && !root.selected.no_site
                            text: "Main website   " + (root.selected ? root.selected.domain : "")
                            color: Theme.dim
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            elide: Text.ElideRight
                        }
                        Text {
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
                                    id: edArea
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
                                Layout.fillWidth: true
                                font.family: Theme.uiFont
                                font.pixelSize: Theme.fBody
                                verticalPadding: 10
                                placeholderText: "Setup key or otpauth:// link"
                                onTextChanged: { previewDebounce.text = text; previewDebounce.restart(); }
                                onAccepted: root.editorSave()
                            }
                            AppButton {
                                text: root.editorScanning ? "Drag over the code…" : "Scan QR code"
                                enabled: !root.editorScanning && !root.editorBusy && !edProc.running
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
                                    text: root.groupCode(root.totpPreview.code)
                                    color: Theme.fg
                                    font.family: Theme.uiFont
                                    font.pixelSize: Math.round(Theme.fHeading * 1.6)
                                    font.letterSpacing: 2
                                }
                                Text {
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
                            visible: root.editorMode === "totp" && root.selected && root.selected.has_totp
                                     && !root.editorBusy && !edProc.running
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
                                Layout.fillWidth: true
                                font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                                placeholderText: "Required"
                                onAccepted: root.editorSave()
                            }
                            AppButton {
                                text: "Generate"
                                onClicked: {
                                    const generation = root.callbackGeneration;
                                    const editorGeneration = root.editorGeneration;
                                    crPass.text = "";
                                    root.run(["app-generate"], "", function (d) {
                                        if (!root.editorOpen || root.editorMode !== "create"
                                            || generation !== root.callbackGeneration
                                            || editorGeneration !== root.editorGeneration
                                            || crPass.text.length) return;
                                        crPass.text = d.password || "";
                                    });
                                }
                            }
                        }
                        Text {
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
                            Layout.row: 5; Layout.column: 0
                            visible: root.createMore
                            text: "Notes"
                            color: Theme.dim; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
                        }
                        O.TextField {
                            id: crNotes
                            Layout.row: 5; Layout.column: 1; Layout.fillWidth: true
                            visible: root.createMore
                            font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                            placeholderText: "Optional"
                        }
                        Text {
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
                                Layout.fillWidth: true
                                font.family: Theme.uiFont; font.pixelSize: Theme.fBody; verticalPadding: 9
                                placeholderText: "Setup key or link (optional)"
                                onTextChanged: { previewDebounce.text = text; previewDebounce.restart(); }
                            }
                            AppButton {
                                text: root.editorScanning ? "Drag…" : "Scan"
                                enabled: !root.editorScanning && !root.editorBusy && !edProc.running
                                onClicked: root.scanQr(crSetup)
                            }
                        }
                        Text {
                            Layout.row: 7; Layout.column: 1
                            visible: root.createMore && !!root.totpPreview.code
                            text: "Code now: " + root.groupCode(root.totpPreview.code)
                            color: Theme.dim; font.family: Theme.uiFont; font.pixelSize: Theme.fSmall
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
            color: root.signedIn ? Qt.rgba(0, 0, 0, 0.55) : Theme.bg
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
                                            Layout.fillWidth: true
                                            text: modelData
                                            color: parent.parent.parent.chosen ? Theme.selectedText : Theme.fg
                                            font.family: Theme.uiFont
                                            font.pixelSize: Theme.fBody
                                            elide: Text.ElideRight
                                        }
                                        Text {
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
                            text: "<b>This can't be undone.</b> Each wrong " + root.secretWord() + " uses 1 of about 10 attempts. "
                                + "After the 10th wrong attempt, the escrow record for this device is destroyed permanently."
                            textFormat: Text.StyledText
                            color: Theme.fg
                            font.family: Theme.uiFont
                            font.pixelSize: Theme.fSmall
                            lineHeight: 1.15
                            wrapMode: Text.Wrap
                        }
                    }

                    // ---- done: the facts, then quiet warnings
                    Text {
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
                                if (root.signinRunning && root.signinNeed === "confirm") root.signinSend("n");
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
    }
}
