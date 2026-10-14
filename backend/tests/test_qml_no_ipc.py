"""No IpcHandler in the window, or in any Omarchy Ui component it actually instantiates.

Quickshell exposes every IpcHandler of a running instance on its per-instance socket, which
any process running as you can talk to. The window has none, and must not pick one up through
Omarchy's kit: Ui/Panel.qml has a (gated) one, which is why the window never uses Panel. The
Omarchy files are checked where they are installed, following each component the window uses
into the components it uses in turn.
"""

import os
import re
import unittest

import qmlscan

UI = os.path.join(qmlscan.OMARCHY_SHELL, "Ui")
COMMONS = os.path.join(qmlscan.OMARCHY_SHELL, "Commons")


def used_ui_components() -> set[str]:
    """Names of Ui components instantiated by the app (as O.Name), followed transitively
    through Ui files (where siblings are referenced unqualified)."""
    seen: set[str] = set()
    todo = []
    for path in qmlscan.app_files((".qml",)):
        code = qmlscan.blank_strings(qmlscan.strip_comments(qmlscan.read(path)))
        todo += re.findall(r"(?<![\w.])O\.([A-Z]\w*)\s*\{", code)
    siblings = {f[:-4] for f in os.listdir(UI) if f.endswith(".qml")} if os.path.isdir(UI) else set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        path = os.path.join(UI, name + ".qml")
        if not os.path.exists(path):
            continue
        code = qmlscan.blank_strings(qmlscan.strip_comments(qmlscan.read(path)))
        for ref in re.findall(r"(?<![\w.])([A-Z]\w*)\s*\{", code):
            if ref in siblings:
                todo.append(ref)
    return seen


class NoIpcTests(unittest.TestCase):
    def test_app_has_no_ipc_handler(self):
        for path in qmlscan.app_files():
            code = qmlscan.strip_comments(qmlscan.read(path))
            self.assertIsNone(re.search(r"\bIpcHandler\b", code), path)

    def test_independent_substring_count(self):
        # Raw bytes, comments included, every file in app/: not even a mention.
        hits = 0
        for f in os.listdir(qmlscan.APP):
            p = os.path.join(qmlscan.APP, f)
            if os.path.isfile(p):
                with open(p, "rb") as fh:
                    hits += fh.read().count(b"IpcHandler")
        self.assertEqual(hits, 0)

    def test_window_never_uses_panel(self):
        for path in qmlscan.app_files((".qml",)):
            code = qmlscan.blank_strings(qmlscan.strip_comments(qmlscan.read(path)))
            self.assertIsNone(re.search(r"(?<![\w.])(O\.)?Panel\s*\{", code), path)

    @unittest.skipUnless(os.path.isdir(UI), "Omarchy shell not installed here")
    def test_instantiated_omarchy_components_have_no_ipc_handler(self):
        used = used_ui_components()
        self.assertIn("Button", used)            # via AppButton
        self.assertIn("TextField", used)
        self.assertNotIn("Panel", used)
        for name in sorted(used):
            path = os.path.join(UI, name + ".qml")
            if os.path.exists(path):
                code = qmlscan.strip_comments(qmlscan.read(path))
                self.assertNotIn("IpcHandler", code, path)

    @unittest.skipUnless(os.path.isdir(COMMONS), "Omarchy shell not installed here")
    def test_commons_singletons_have_no_ipc_handler(self):
        # Theme.qml reads Color and Style from qs.Commons, which loads those singletons.
        for f in os.listdir(COMMONS):
            if f.endswith((".qml", ".js")):
                code = qmlscan.strip_comments(qmlscan.read(os.path.join(COMMONS, f)))
                self.assertNotIn("IpcHandler", code, f)


if __name__ == "__main__":
    unittest.main()
