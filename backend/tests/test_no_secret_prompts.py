"""No password prompt in Pear other than a polkit dialog. Ever.

1.x could put a zenity password box on screen from a background timer, fall back to
systemd-ask-password or getpass, and asked for a vault passphrase through `ask_passphrase()`.
2.0 deletes all of it: the only things that ask are the polkit dialogs, Apple's own sign-in
questions inside the Pear window, and (once, only if needed) the 1.x passphrase inside the
window during the move. This scans the backend, the window, the plugin, native code and the
system scripts with the two matchers of test_repo_guards (a regex over comment-stripped text,
and a parser), and both must count zero.

`input(` is the fourth way: a Python prompt on a terminal. It counts when it is within three
lines of a password or passphrase (matcher A), or inside a function that names one (matcher B).
"""

import ast
import os
import re
import unittest

from test_repo_guards import (GUARDS, PENDING, Guard, GuardCase, code_files, is_pending, read,
                              strip_a, _word_or_str_contains, _word_is)

PROMPT_GUARDS = {
    "zenity": Guard("zenity", r"zenity", _word_or_str_contains("zenity")),
    "systemd-ask-password": Guard("systemd-ask-password", r"systemd-ask-password",
                                  _word_or_str_contains("systemd-ask-password")),
    "getpass": Guard("getpass", r"\bgetpass\b", _word_is("getpass")),
    "ask_passphrase": Guard("ask_passphrase", r"\bask_passphrase\b", _word_is("ask_passphrase")),
}
GUARDS.update(PROMPT_GUARDS)

_SECRET_WORD = re.compile(r"(?i)pass(word|phrase)|getpass")


def input_near_secret_a(rel, text):
    if not rel.endswith(".py"):
        return 0
    lines = strip_a(rel, text).splitlines()
    n = 0
    for i, line in enumerate(lines):
        for _ in re.finditer(r"\binput\s*\(", line):
            window = "\n".join(lines[max(0, i - 3):i + 4])
            n += bool(_SECRET_WORD.search(window))
    return n


def input_near_secret_b(rel, text):
    if not rel.endswith(".py"):
        return 0
    tree = ast.parse(text)
    n = 0
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            continue
        calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
                 and isinstance(c.func, ast.Name) and c.func.id == "input"]
        if not calls:
            continue
        names = [fn.name] if not isinstance(fn, ast.Module) else []
        for node in ast.walk(fn):
            if isinstance(node, ast.Name):
                names.append(node.id)
            elif isinstance(node, ast.arg):
                names.append(node.arg)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.append(node.value)
        if any(_SECRET_WORD.search(x) for x in names):
            n += len(calls) if not isinstance(fn, ast.Module) else 0
    return n


class MatcherSelfTests(unittest.TestCase):
    SAMPLE_PY = (
        '"""We never use zenity or getpass."""\n'
        "import getpass\n"
        "def ask(password_prompt):\n"
        "    return input(password_prompt)\n"
        "subprocess.run(['zenity', '--password'])\n"
        "subprocess.run(['systemd-ask-password', 'x'])\n"
        "prompt.ask_passphrase()\n"
        "# zenity in a comment is not a use\n"
        "\n\n\n\n"
        "def name():\n"
        "    return input('Your name: ')\n"
    )
    SAMPLE_QML = ('// zenity\nProcess { command: ["zenity", "--password"] }\n'
                  'Process { command: ["systemd-ask-password"] }\n')

    def test_counts(self):
        for name, n in {"zenity": 1, "systemd-ask-password": 1, "getpass": 1,
                        "ask_passphrase": 1}.items():
            g = PROMPT_GUARDS[name]
            self.assertEqual(g.count_a("x.py", self.SAMPLE_PY), n, f"A {name}")
            self.assertEqual(g.count_b("x.py", self.SAMPLE_PY), n, f"B {name}")
        self.assertEqual(input_near_secret_a("x.py", self.SAMPLE_PY), 1)
        self.assertEqual(input_near_secret_b("x.py", self.SAMPLE_PY), 1)
        for name in ("zenity", "systemd-ask-password"):
            g = PROMPT_GUARDS[name]
            self.assertEqual((g.count_a("x.qml", self.SAMPLE_QML),
                              g.count_b("x.qml", self.SAMPLE_QML)), (1, 1), name)


class NoSecretPromptTests(GuardCase):
    def test_no_prompt_programs_or_calls(self):
        self.check(tuple(PROMPT_GUARDS), code_files())

    def test_no_input_near_a_secret(self):
        hits, pending = [], []
        for rel in code_files():
            if not rel.endswith(".py"):
                continue
            text = read(rel)
            a, b = input_near_secret_a(rel, text), input_near_secret_b(rel, text)
            if a or b:
                (pending if is_pending(rel) else hits).append(f"{rel}: input( (A={a}, B={b})")
        self.assertEqual(hits, [], "\n".join(hits))
        if pending:
            self.skipTest("left for the package that rewrites them: " + "; ".join(pending))

    def test_pending_files_are_the_known_ones(self):
        # A file can only be excused by its exact pre-2.0 content.
        for rel, digest in PENDING.items():
            self.assertRegex(digest, r"^[0-9a-f]{64}$", rel)
        self.assertTrue(all(not r.startswith(("backend/icp/daemon", "backend/icp/client",
                                              "backend/icp/vstore", "system/"))
                            for r in PENDING), "new 2.0 code cannot be excused")


if __name__ == "__main__":
    unittest.main()
