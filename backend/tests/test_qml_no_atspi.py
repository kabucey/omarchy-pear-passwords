"""Nothing in the window reaches the accessibility bus (audit round 2, problem 1).

Any program of the user's can set org.a11y.Status IsEnabled=true on the session bus, without
privilege and even after the window has started. Qt then registers the window on the AT-SPI
bus, and the plain text of every field (a new password, notes being edited, setup keys, the
Apple ID password, the 2FA code, the 1.x passphrase) and every label (a revealed password, a
TOTP code, a history value) can be read, and the window's buttons pressed.

Two layers, each checked here:
- pear-exec gives the window a session-bus address nothing can listen on, so the bridge never
  starts (the C side is exercised in test_pear_exec_env.py; here, its constant and that the
  window itself needs no session bus);
- every secret-bearing item carries `Accessible.ignored: true`.
"""

import os
import re
import unittest

import qmlscan
from icp.daemon import paths

SHELL = qmlscan.read(os.path.join(qmlscan.APP, "shell.qml"))
CODE = qmlscan.strip_comments(SHELL)
PEAR_EXEC = os.path.join(os.path.dirname(qmlscan.APP), "native", "pear-exec.c")

# Fields that hold a secret while it is typed or edited.
SECRET_FIELDS = ("edArea", "edSetup", "crSetup", "crNotes", "newPw", "crPass", "oldPass",
                 "signinField", "codeField")
# Labels that show a secret once revealed: the detail rows (password, TOTP code, notes) and
# the password history.
SECRET_LABELS = ("fieldValue", "historyValue")
# Inputs that never hold a secret: the search box (catSearch is its root inside
# CategorySearch.qml), a nickname, a new entry's name, site, username and tags, a tag being
# typed (tags are list metadata), the keychain check's names and counts, and read-only shell
# commands to copy (one has no id). Only the session-bus layer keeps these off AT-SPI, which
# is enough: they hold nothing the unlocked list does not show.
NOT_SECRET = ("search", "catSearch", "nickField", "crName", "crSite", "crUser", "crTags",
              "tagInput", "diagOut", "cmdText", "regText", "setReg", None)


def element_of(ident: str) -> str:
    m = re.search(rf"\bid: {ident}\n", CODE)
    if m is None:
        raise AssertionError(f"shell.qml has no element with id {ident}")
    start = CODE.rfind("{", 0, m.start())
    return qmlscan.element_body(CODE, start)


def own_properties(body: str) -> str:
    """The element's own lines: nested elements' bodies removed, so a child's property does
    not count for its parent."""
    inner = body[body.index("{") + 1:]
    out, depth = [], 0
    for ch in inner:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


class SecretItemsAreIgnoredTests(unittest.TestCase):
    def test_every_secret_field_is_off_the_accessibility_tree(self):
        for ident in SECRET_FIELDS:
            self.assertRegex(own_properties(element_of(ident)),
                             r"\bAccessible\.ignored:\s*true\b", ident)

    def test_every_label_that_shows_a_secret_is_off_the_tree(self):
        for ident in SECRET_LABELS:
            props = own_properties(element_of(ident))
            self.assertRegex(props, r"\bAccessible\.ignored:\s*true\b", ident)
        # And they are the labels that show those values.
        self.assertIn("frow.modelData.value", own_properties(element_of("fieldValue")))
        self.assertIn("hrow.modelData.value", own_properties(element_of("historyValue")))

    def test_nothing_turns_accessibility_back_on(self):
        self.assertNotRegex(CODE, r"\bAccessible\.ignored:\s*(false|!)")

    def test_every_text_input_in_the_window_is_a_known_secret_field_or_ignored(self):
        # A new field that can hold a secret must join the list (or be marked ignored). Every
        # QML file of the window, not only shell.qml.
        found = 0
        for path in qmlscan.app_files((".qml",)):
            code = qmlscan.strip_comments(qmlscan.read(path))
            for m in re.finditer(r"^\s*(?:O\.)?(TextField|TextArea|TextInput|TextEdit)\s*\{",
                                 code, re.M):
                found += 1
                self.check_input(code, m)
        self.assertGreater(found, 15)

    def check_input(self, code, m):
        body = qmlscan.element_body(code, code.index("{", m.start()))
        props = own_properties(body)
        idm = re.search(r"\bid:\s*(\w+)", props)
        if re.search(r"\bAccessible\.ignored:\s*true\b", props):
            return
        if (idm.group(1) if idm else None) in NOT_SECRET:
            return
        self.fail(f"{m.group(1)} {idm.group(1) if idm else '(no id)'} is on the "
                  "accessibility tree; mark it Accessible.ignored or say why not")


class NoSessionBusTests(unittest.TestCase):
    def test_the_window_needs_no_session_bus(self):
        # Nothing in the window talks to the session bus: no D-Bus module, no dbus tools.
        for word in ("DBus", "dbus", "busctl", "gdbus", "notify-send", "openUrlExternally"):
            self.assertNotIn(word, CODE, word)

    def test_the_dead_address_lives_in_the_root_owned_empty_directory(self):
        with open(PEAR_EXEC) as f:
            src = f.read()
        m = re.search(r'^#define\s+PEAR_NO_SESSION_BUS\s+"([^"]*)"', src, re.M)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), f"unix:path={paths.EMPTY_DIR}/no-session-bus")
        self.assertIn('module == NULL ? PEAR_NO_SESSION_BUS : bus', src)


if __name__ == "__main__":
    unittest.main()
