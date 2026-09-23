"""Regression guards for the QML app's expiry boundary.

There is no Qt/QML test runner in the supported backend test environment (and this checkout has
no ``quickshell``, ``qml`` or ``qmltestrunner`` binary), so these tests pin the security-critical
source structure. They deliberately inspect only the expiry/process plumbing; UI copy and layout
are outside their scope.
"""

from pathlib import Path
import re
import unittest


SHELL = Path(__file__).resolve().parents[2] / "app" / "shell.qml"


def _function(source: str, name: str) -> str:
    """Return one QML function's body, up to the next top-level function/property block."""
    start = source.index(f"function {name}(")
    tail = source[start:]
    match = re.search(r"\n\s+(?:function|property|readonly property)\b", tail[len(f"function {name}("):])
    return tail if not match else tail[: len(f"function {name}(") + match.start()]


class ShellExpirySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SHELL.read_text()

    def test_clock_transitions_do_not_wait_for_busy_or_queue(self):
        timer = self.source[self.source.index("Timer {\n        interval: 1000"):]
        timer = timer[:timer.index("Timer { id: flashTimer")]
        self.assertRegex(timer, r"if \(wasUnlocked && root\.unlockLeft === 0\)\s*\{[\s\S]*?root\.forgetSecrets\(\);\s*\}")
        self.assertRegex(timer, r"if \(root\.appUnlocked && root\.sessionUntil > 0 && root\.sessionLeft === 0\) root\.lockApp\(\);")
        self.assertNotIn("!root.busy", timer)
        self.assertNotIn("root.queue.length", timer)

    def test_expiry_invalidates_callbacks_and_clears_every_editor_secret(self):
        forget = _function(self.source, "forgetSecrets")
        for call in ("root.invalidateAppCallbacks();", "root.invalidateEditorCallbacks();",
                     "root.editorOpen = false;", "root.clearEditorFields();"):
            self.assertIn(call, forget)

        clear = _function(self.source, "clearEditorFields")
        for field in ("edArea", "edSetup", "crName", "crSite", "crUser", "crPass", "crNotes", "crSetup"):
            self.assertRegex(clear, rf"{field}\.text = \"\";")
        self.assertIn("previewDebounce.stop();", clear)
        self.assertIn("newPw.text = \"\";", forget)
        self.assertIn("signinField.text = \"\";", forget)
        self.assertIn("codeField.text = \"\";", forget)

    def test_queued_and_active_commands_have_generation_guards(self):
        run = _function(self.source, "run")
        self.assertIn("const generation = root.callbackGeneration;", run)
        self.assertIn("generation !== root.callbackGeneration", run)
        self.assertIn("generation: generation", run)

        invalidate = _function(self.source, "invalidateAppCallbacks")
        self.assertIn("root.queue = [];", invalidate)
        self.assertIn("proc.handler = null;", invalidate)

        editor = _function(self.source, "edRun")
        self.assertIn("if (edProc.running) return false;", editor)
        self.assertIn("callbackGeneration !== root.callbackGeneration", editor)
        self.assertIn("editorGeneration !== root.editorGeneration", editor)

    def test_secret_processes_use_nonretaining_parsers_and_clear_buffers(self):
        proc = self.source[self.source.index("Process {\n        id: proc"):]
        proc = proc[:proc.index("Timer {\n        interval: 1000")]
        editor = self.source[self.source.index("Process {\n        id: edProc"):]
        editor = editor[:editor.index("Timer {\n        id: previewDebounce")]
        for name, process in (("proc", proc), ("edProc", editor)):
            self.assertIn("stdout: SplitParser", process)
            self.assertNotIn("StdioCollector", process)
            self.assertIn('splitMarker: ""', process)
            self.assertIn("write(pending); pending = \"\";", process)
            self.assertRegex(process, rf"if \(!{name}\.handler\) return;\s+{name}\.output \+= data;")
            self.assertRegex(process, rf"const output = {name}\.output;\s+{name}\.handler = null;\s+{name}\.output = \"\";")
            self.assertIn("try { d = JSON.parse(output); }", process)
        # Expiry must never kill a started process: the remote write owns its already-framed
        # stdin payload, while the UI handler and all not-yet-started payloads are released.
        self.assertNotRegex(self.source, r"(?:proc|edProc)\.running\s*=\s*false")

        invalidate_app = _function(self.source, "invalidateAppCallbacks")
        invalidate_editor = _function(self.source, "invalidateEditorCallbacks")
        for invalidate, name in ((invalidate_app, "proc"), (invalidate_editor, "edProc")):
            self.assertIn(f"{name}.pending = \"\";", invalidate)
            self.assertIn(f"{name}.output = \"\";", invalidate)

    def test_expiry_cannot_repopulate_process_output(self):
        for name, function in (("proc", "invalidateAppCallbacks"),
                               ("edProc", "invalidateEditorCallbacks")):
            invalidate = _function(self.source, function)
            self.assertIn(f"{name}.handler = null;", invalidate)
            process = self.source[self.source.index(f"Process {{\n        id: {name}"):]
            self.assertRegex(process, rf"if \(!{name}\.handler\) return;\s+{name}\.output \+= data;")

        # Completion consumes and clears the accumulator before invoking any callback, so a
        # callback that starts another command cannot inherit the prior command's plaintext.
        for name in ("proc", "edProc"):
            process = self.source[self.source.index(f"Process {{\n        id: {name}"):]
            self.assertRegex(process, rf"const output = {name}\.output;\s+{name}\.handler = null;\s+{name}\.output = \"\";")

    def test_auth_and_signin_processes_remain_separate_from_app_callback_invalidation(self):
        self.assertIn("id: authProc", self.source)
        self.assertIn("id: signin", self.source)
        self.assertIn("authProc.running = true;", self.source)
        self.assertIn("signin.running = true;", self.source)
        self.assertIn("if (root.signinRunning) signin.write", self.source)

    def test_failed_start_cleanup_is_distinct_from_normal_exit(self):
        for name, function in (("proc", "failProcStart"), ("edProc", "failEditorStart")):
            process = self.source[self.source.index(f"Process {{\n        id: {name}"):]
            self.assertIn("property int attempt: 0", process)
            self.assertIn("property bool attemptActive: false", process)
            self.assertIn("onRunningChanged:", process)
            self.assertIn("Qt.callLater", process)
            self.assertRegex(
                process,
                rf"if \(!{name}\.running && {name}\.attemptActive && {name}\.attempt === attempt\)\s+"
                rf"root\.{function}\(attempt\);",
            )
            exited = process[process.index("onExited:"):]
            self.assertIn(f"{name}.attemptActive = false;", exited)
        # A failed start drops all sensitive state, whereas an ordinary finish gets to parse its
        # reply first. This is why the cleanup is deferred instead of attached directly to the
        # first running=false notification.
        self.assertIn("root.forgetSecrets();", _function(self.source, "failProcStart"))
        editor_failure = _function(self.source, "failEditorStart")
        self.assertIn("root.clearEditorFields();", editor_failure)
        self.assertIn("root.invalidateEditorCallbacks();", editor_failure)

    def test_expiry_uses_dedicated_clipboard_cleanup_outside_the_command_queue(self):
        forget = _function(self.source, "forgetSecrets")
        timer = self.source[self.source.index("Timer {\n        interval: 1000"):]
        timer = timer[:timer.index("Timer { id: flashTimer")]
        self.assertRegex(timer, r"root\.clearClipboard\(\);\s+root\.forgetSecrets\(\);")
        self.assertRegex(_function(self.source, "lockApp"), r"root\.clearClipboard\(\);\s+root\.forgetSecrets\(\);")
        self.assertIn("property bool clipboardMustStayClear: false", self.source)
        self.assertIn("if (root.clipboardMustStayClear) root.clearClipboard();", self.source)
        clear = _function(self.source, "clearClipboard")
        self.assertIn("clipboardProc.running = true;", clear)
        self.assertNotIn("root.run(", clear)
        self.assertIn('id: clipboardProc', self.source)
        self.assertIn('command: [root.icp, "app-clipboard-clear"]', self.source)
        self.assertIn("root.clipboardClearPending = false;", self.source)

    def test_clipboard_failed_start_retries_with_a_bounded_timer(self):
        process = self.source[self.source.index("Process {\n        id: clipboardProc"):]
        process = process[:process.index("Timer {\n        id: clipboardRetryTimer")]
        self.assertIn("property int attempt: 0", process)
        self.assertIn("onRunningChanged:", process)
        self.assertIn("root.failClipboardStart(attempt);", process)
        self.assertIn("function scheduleClipboardRetry()", self.source)
        self.assertIn("root.clipboardRetryCount >= root.clipboardRetryLimit", self.source)
        self.assertIn("readonly property int clipboardRetryLimit: 3", self.source)
        self.assertRegex(
            self.source,
            r"Timer \{\n        id: clipboardRetryTimer[\s\S]*?interval: 100[\s\S]*?"
            r"root\.clipboardMustStayClear[\s\S]*?root\.clearClipboard\(\);",
        )

    def test_auth_and_signin_failed_starts_clear_state_and_end_busy_ui(self):
        for name, function in (("authProc", "failAuthStart"), ("signin", "failSigninStart")):
            process = self.source[self.source.index(f"Process {{\n        id: {name}"):]
            self.assertIn("property int attempt: 0", process)
            self.assertIn("property bool attemptActive: false", process)
            self.assertIn("onRunningChanged:", process)
            self.assertIn(f"root.{function}(attempt);", process)
            self.assertIn("Qt.callLater", process)
        auth_failure = _function(self.source, "failAuthStart")
        self.assertIn("root.authing = false;", auth_failure)
        signin_failure = _function(self.source, "failSigninStart")
        for field in ("signinField", "codeField"):
            self.assertIn(f"{field}.text = \"\";", signin_failure)
        for state in ("root.signinRunning = false;", 'root.signinNeed = "";',
                      'root.signinKind = "";', 'root.signinOutcome = "error";'):
            self.assertIn(state, signin_failure)


if __name__ == "__main__":
    unittest.main()
