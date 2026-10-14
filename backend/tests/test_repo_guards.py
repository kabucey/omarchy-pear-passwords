"""Repo-wide negation guards: things that must not appear anywhere in Pear's code.

Each guard is checked by two independent matchers, and both must count zero:

- **A**, a regular expression over the file's text with comments and Python docstrings cut out
  by regular expressions;
- **B**, a parser: Python's own AST for .py files, and a small character lexer that knows
  quotes and comments for QML, JavaScript, C and shell. It yields the string literals and bare
  words the code actually contains.

So a guard cannot pass because one matcher's idea of "code" has a hole, and a word inside an
explanatory comment ("never wl-copy, which stages to /tmp") does not count as a use. A
self-test plants a known number of hits and both matchers must find exactly that many.

Files that 2.0 deletes or rewrites are listed in PENDING with their pre-2.0 sha256. While a
file still has exactly that content its hits are reported as a skip; once it changes it is
checked like every other file, and a deleted file has nothing to check.
"""

import ast
import hashlib
import io
import os
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Code that runs (or is installed) as part of Pear. Tests and docs are not code.
CODE_DIRS = ("backend/icp", "app", "plugin", "native", "system")
SKIP_EXT = {".png", ".svg", ".pem", ".md", ".pyc", ".lock", ".env"}

# Pre-2.0 content of files 2.0 deletes (D) or rewrites (R).
PENDING = {
    "backend/icp/auth/prompt.py": "8347f301a587760ad2bfdc18be40d6f6cb815be7020380472edb63ddc2537af8",  # D the Apple pipeline
    "backend/icp/auth/agent.py": "11d38d7c25ff230401c27f9f1c852fa6be25b4eceb9d902e9d765514083222ac",   # D the Apple pipeline
    "backend/icp/auth/session.py": "abdb56640ceecdfe4cf9d1310d8474963229de4b2b2b57b7cdfa537c22f31b53",  # R the Apple pipeline
    "backend/icp/auth/lockbox.py": "a91a4f251acc1a050f79ca1078cabe3b6b5fcf643ade1d1316c031c4f087c826",  # D the store
    "backend/icp/auth/held_key.py": "fd05329f3d3071987a4414e3cd7e645acf88df97eb212ac5ff60ed2747648afd",  # D the store
    "backend/icp/cli/app.py": "30bd142a08cdfd95b6c9fcbaaa4ed0bc0608d8da859f2cd65eb8693e253d3ea5",      # R the Apple pipeline
    "backend/icp/cli/ui.py": "d4be21be6e7eb7f14fad980f371642ce2a639d0d546b4a94d920c7e3f39a0a52",       # R the Apple pipeline
    "backend/icp/cli/appapi.py": "798ef2ade4fe76a6043df0ad9607cc6e8bf36bfa69368bbd7bf59229b53e0c2f",   # D the Apple pipeline
    "backend/icp/ui/reauth.py": "cddf3ebd826126ca35e9c744d19e1f0bc924903fa570fc5ebe341b2e32b5aa9a",    # D the Apple pipeline
    "backend/icp/ui/polkit_gate.py": "270c500187004791a250f2420e79ede614aae4037a6e38911e2febffd271e174",  # D the Apple pipeline
    "app/shell.qml": "63e18b1cf41cae607d6bfc9316d73af6e91e2cddf585f2f6b0f7ec69780cba98",               # R the clients
    "app/launch.sh": "c596d900ac0560c3aa316d51a32c671783262541083cccda217ff70ae00da961",               # D the clients
    "plugin/Service.qml": "16729c443268c6b1a7f6bd75b6e06a6b513e405422954dddf08127ff6eafead2",          # R the clients
}


# --- reading code ------------------------------------------------------------------------------
def code_files(dirs=CODE_DIRS, root=ROOT):
    for d in dirs:
        base = os.path.join(root, d)
        if os.path.isfile(base):
            yield d
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [n for n in dirnames if n != "__pycache__" and not n.endswith(".egg-info")]
            for name in sorted(filenames):
                if os.path.splitext(name)[1] in SKIP_EXT:
                    continue
                yield os.path.relpath(os.path.join(dirpath, name), root)


def read(rel, root=ROOT):
    with open(os.path.join(root, rel), "rb") as f:
        return f.read().decode("utf-8", "replace")


def kind_of(rel, text):
    ext = os.path.splitext(rel)[1]
    if ext == ".py" or text.startswith("#!/usr/bin/env python") or "python" in text[:40]:
        return "py"
    if ext in (".qml", ".js", ".c", ".h"):
        return "c"
    return "sh"


# Matcher A: regexes only.
_PY_TRIPLE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')
_PY_COMMENT = re.compile(r"(?m)(^|\s)#.*$")
_C_BLOCK = re.compile(r"/\*(?:.|\n)*?\*/")
_C_LINE = re.compile(r"(?m)(?<![:\"'])//.*$")
_SH_COMMENT = re.compile(r"(?m)(^|\s)#(?![!]).*$")


def strip_a(rel, text):
    k = kind_of(rel, text)
    if k == "py":
        return _PY_COMMENT.sub(r"\1", _PY_TRIPLE.sub("", text))
    if k == "c":
        return _C_LINE.sub("", _C_BLOCK.sub("", text))
    return _SH_COMMENT.sub(r"\1", text)


# Matcher B: parsers.
def _py_tokens(text):
    tree = ast.parse(text)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            out.append(("str", node.value))
        elif isinstance(node, ast.Name):
            out.append(("word", node.id))
        elif isinstance(node, ast.Attribute):
            out.append(("word", node.attr))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module:
                out.extend(("word", p) for p in node.module.split("."))
            for a in node.names:
                out.extend(("word", p) for p in a.name.split("."))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append(("word", node.name))
        elif isinstance(node, ast.keyword) and node.arg:
            out.append(("word", node.arg))
    return out


def _lex(text, kind):
    """Strings and bare words of C-like or shell text, skipping comments, honouring quotes."""
    out, i, n, word = [], 0, len(text), []

    def flush():
        if word:
            out.append(("word", "".join(word)))
            word.clear()

    while i < n:
        c = text[i]
        if kind == "c" and text.startswith("//", i):
            flush()
            i = text.find("\n", i)
            i = n if i < 0 else i
            continue
        if kind == "c" and text.startswith("/*", i):
            flush()
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if kind == "sh" and c == "#" and not word and not text.startswith("#!", i):
            i = text.find("\n", i)
            i = n if i < 0 else i
            continue
        if c in "\"'`":
            flush()
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and c != "'" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            out.append(("str", "".join(buf)))
            i = j + 1
            continue
        if c.isalnum() or c in "_-./$:@+":
            word.append(c)
        else:
            flush()
        i += 1
    flush()
    return out


def tokens_b(rel, text):
    k = kind_of(rel, text)
    if k == "py":
        return _py_tokens(text)
    return _lex(text, k)


class Guard:
    """One forbidden thing: a regex for matcher A and a token predicate for matcher B."""

    def __init__(self, name, a, b):
        self.name, self.a, self.b = name, re.compile(a), b

    def count_a(self, rel, text):
        return len(self.a.findall(strip_a(rel, text)))

    def count_b(self, rel, text):
        return sum(1 for kind, value in tokens_b(rel, text) if self.b(kind, value))


def _word_or_str_contains(needle):
    return lambda kind, value: needle in value


def _word_is(*names):
    return lambda kind, value: kind == "word" and value in names


def _str_word(word):
    pat = re.compile(rf"(?<![\w-]){re.escape(word)}(?![\w-])")
    return lambda kind, value: bool(pat.search(value))


def _tmp_path(kind, value):
    return kind == "str" and bool(re.search(r"(?:^|[\s=:;(])/tmp(?:/|$|[\s;)])", value)) \
        or kind == "word" and (value == "/tmp" or value.startswith("/tmp/"))


GUARDS = {
    "wl-copy": Guard("wl-copy", r"wl-copy", _word_or_str_contains("wl-copy")),
    "--clear": Guard("--clear", r"--clear\b", _str_word("--clear")),
    "pkexec": Guard("pkexec", r"\bpkexec\b", _str_word("pkexec")),
    "sudo": Guard("sudo", r"(?<![\w-])sudo(?![\w-])",
                  lambda k, v: bool(re.search(r"(?<![\w-])sudo(?![\w-])", v))),
    "/tmp": Guard("/tmp", r"""(?:^|[\s"'=:;(])/tmp(?:/|$|[\s"';)])""", _tmp_path),
    "polkit": Guard("polkit", r"(?i)polkit", lambda k, v: "polkit" in v.lower()),
    "AllowUserInteraction": Guard("AllowUserInteraction", r"AllowUserInteraction",
                                  _word_or_str_contains("AllowUserInteraction")),
}


def sha(rel):
    with open(os.path.join(ROOT, rel), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def is_pending(rel):
    return rel in PENDING and os.path.exists(os.path.join(ROOT, rel)) and sha(rel) == PENDING[rel]


class GuardCase(unittest.TestCase):
    """Run guards over a set of files, both matchers, with PENDING files reported not failed."""

    def check(self, guard_names, files):
        hits, pending = [], []
        for rel in files:
            text = read(rel)
            for g in (GUARDS[n] for n in guard_names):
                a, b = g.count_a(rel, text), g.count_b(rel, text)
                if a or b:
                    (pending if is_pending(rel) else hits).append(f"{rel}: {g.name} (A={a}, B={b})")
        self.assertEqual(hits, [], "\n".join(hits))
        if pending:
            self.skipTest("left for the package that rewrites them: " + "; ".join(pending))


class MatcherSelfTests(unittest.TestCase):
    """Both matchers find exactly the planted uses, and neither counts comments or docs."""

    SAMPLES = {
        "x.py": ('"""Never wl-copy, never pkexec."""\n'
                 "import subprocess  # wl-copy would stage to /tmp\n"
                 "subprocess.run(['wl-copy', '--clear'])\n"
                 "subprocess.run(['sudo', 'pkexec', 'true'])\n"
                 "open('/tmp/x')\n"
                 "from icp.daemon import polkit\n", {
                     "wl-copy": 1, "--clear": 1, "pkexec": 1, "sudo": 1, "/tmp": 1, "polkit": 1}),
        "x.qml": ('// wl-copy pkexec /tmp sudo\n'
                  'Process { command: ["wl-copy", "--clear"] }\n'
                  'Process { command: ["pkexec", "/usr/bin/true"] } /* sudo */\n'
                  'property string url: "https://example.com/tmp"\n', {
                      "wl-copy": 1, "--clear": 1, "pkexec": 1, "sudo": 0, "/tmp": 0}),
        "x.sh": ("#!/bin/sh\n# sudo wl-copy here is a comment\n"
                 "printf '%s' \"$v\" | wl-copy\nmktemp -p /tmp\necho done # pkexec\n", {
                     "wl-copy": 1, "/tmp": 1, "pkexec": 0, "sudo": 0}),
    }

    def test_both_matchers_count_the_planted_uses(self):
        for rel, (text, expected) in self.SAMPLES.items():
            for name, n in expected.items():
                with self.subTest(file=rel, guard=name):
                    g = GUARDS[name]
                    self.assertEqual(g.count_a(rel, text), n, "matcher A")
                    self.assertEqual(g.count_b(rel, text), n, "matcher B")

    def test_the_tmpfiles_path_is_not_tmp(self):
        g = GUARDS["/tmp"]
        text = 'TMPFILES_CONF = "/etc/tmpfiles.d/pear-passwords.conf"\n'
        self.assertEqual((g.count_a("p.py", text), g.count_b("p.py", text)), (0, 0))


class ClipboardGuardTests(GuardCase):
    """No wl-copy and no `--clear` anywhere in code: wl-clipboard stages its input in a /tmp
    file, and `--clear` from a timer clears whatever is on the clipboard by then."""

    def test_no_wl_copy_or_clear(self):
        self.check(("wl-copy", "--clear"), code_files())


class NoRootHelpersInCodeTests(GuardCase):
    """No pkexec and no sudo in anything that runs as the user or the daemon. The installers
    print sudo commands for you to run, and README prose names them; neither executes them."""

    INSTALLERS = {"system/install-root.sh", "system/uninstall-root.sh", "system/lib/files.sh",
                  "system/lib/user-files.sh", "system/paths.env"}

    def test_no_pkexec_or_sudo(self):
        files = [f for f in code_files() if f not in self.INSTALLERS]
        self.check(("pkexec", "sudo"), files)

    @staticmethod
    def _without_heredocs(text):
        """Drop here-document bodies: text they print is not a command they run."""
        out, end = [], None
        for line in text.splitlines():
            if end is not None:
                if line.strip() == end:
                    end = None
                continue
            m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
            if m:
                end = m.group(1)
            out.append(line)
        return "\n".join(out)

    def test_installers_never_run_sudo_or_pkexec(self):
        # They may tell you to run sudo; they never invoke it or pkexec themselves.
        for rel in ("install.sh", "uninstall.sh", *sorted(self.INSTALLERS)):
            text = self._without_heredocs(strip_a(rel, read(rel)))
            for line in text.splitlines():
                stripped = line.strip()
                self.assertFalse(re.match(r"(exec\s+)?(sudo|pkexec)\b", stripped),
                                 f"{rel}: {stripped}")
                self.assertNotIn("$(sudo", stripped, rel)
                self.assertNotRegex(stripped, r"[;&|]\s*(sudo|pkexec)\b", rel)


class NoTmpTests(GuardCase):
    """No /tmp paths in daemon or client code, or in the root installer."""

    def test_daemon_and_client(self):
        self.check(("/tmp",), code_files(("backend/icp/daemon", "backend/icp/client")))

    def test_root_installer(self):
        self.check(("/tmp",), code_files(("system/install-root.sh", "system/uninstall-root.sh",
                                          "system/lib")))

    def test_python_tempfiles_name_their_directory(self):
        """tempfile without dir= falls back to /tmp; daemon and client code must say where."""
        bad = []
        for rel in code_files(("backend/icp/daemon", "backend/icp/client")):
            if not rel.endswith(".py"):
                continue
            for node in ast.walk(ast.parse(read(rel))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile" \
                        and not any(k.arg == "dir" for k in node.keywords):
                    bad.append(f"{rel}:{node.lineno}")
        self.assertEqual(bad, [])


class BackgroundNeverPromptsTests(GuardCase):
    """The scheduler and the Apple pipeline run with nobody watching. They must not be able to
    raise a dialog, so they neither import nor name the polkit module, and never ask for user
    interaction."""

    FILES = ("backend/icp/daemon/scheduler.py", "backend/icp/daemon/apple.py")

    def test_no_polkit_in_background_modules(self):
        present = [f for f in self.FILES if os.path.exists(os.path.join(ROOT, f))]
        self.assertIn("backend/icp/daemon/apple.py", present)
        self.check(("polkit", "AllowUserInteraction"), present)
        self.assertEqual(sorted(set(self.FILES) - set(present)), [])

    def test_imports_by_ast(self):
        for rel in self.FILES:
            if not os.path.exists(os.path.join(ROOT, rel)):
                continue
            for node in ast.walk(ast.parse(read(rel))):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] + [a.name for a in node.names]
                for n in names:
                    self.assertNotIn("polkit", n.lower(), f"{rel} imports {n}")


class InstallerWritesNoManifestTests(GuardCase):
    """No installer writes a browser native-messaging manifest. Autofill is opt-in, per browser,
    only through `pear-passwords-autofill register`."""

    FILES = ("install.sh", "uninstall.sh", "system/install-root.sh", "system/uninstall-root.sh",
             "system/lib/files.sh", "system/lib/user-files.sh")
    WORDS = ("NativeMessagingHosts", "native-messaging-hosts", "native-messaging", ".mozilla",
             ".zen", "org.icp.native.json", "io.github.dragosol.pearpasswords.json",
             "NATIVE_HOST_MANIFEST", "NATIVE_HOST_NAME")

    def test_no_manifest_paths(self):
        for rel in self.FILES:
            text = read(rel)
            code = strip_a(rel, text)
            toks = tokens_b(rel, text)
            for w in self.WORDS:
                a = code.count(w)
                b = sum(1 for _, v in toks if w in v)
                self.assertEqual((a, b), (0, 0), f"{rel} mentions {w}")

    def test_uninstall_unregisters_first(self):
        body = strip_a("uninstall.sh", read("uninstall.sh"))
        self.assertIn('"$AUTOFILL_REGISTER_BIN" unregister --all', body)
        self.assertLess(body.index("unregister --all"), body.index("podman image rm"))


class PolicyGuardTests(unittest.TestCase):
    """Every action: auth_self for active local sessions only, never remembered, owned by the
    daemon's user. Raw-text counts and the parsed XML must both say so."""

    POLICY = os.path.join(ROOT, "polkit", "io.github.dragosol.pearpasswords.policy")

    def setUp(self):
        with open(self.POLICY, encoding="utf-8") as f:
            self.text = f.read()

    def test_no_keep_anywhere(self):
        self.assertEqual(len(re.findall(r"_keep", self.text)), 0)
        values = [e.text or "" for e in ET.fromstring(self.text).iter()]
        self.assertFalse([v for v in values if "keep" in v])

    def test_every_action_is_auth_self_active_only_and_owned(self):
        from icp.daemon import paths
        root = ET.fromstring(self.text)
        actions = root.findall("action")
        self.assertEqual({a.get("id") for a in actions}, set(paths.ACTIONS))
        for a in actions:
            d = a.find("defaults")
            self.assertEqual(d.findtext("allow_any"), "no", a.get("id"))
            self.assertEqual(d.findtext("allow_inactive"), "no", a.get("id"))
            self.assertEqual(d.findtext("allow_active"), "auth_self", a.get("id"))
            ann = {x.get("key"): x.text for x in a.findall("annotate")}
            self.assertEqual(ann.get("org.freedesktop.policykit.owner"),
                             "unix-user:" + paths.SERVICE_USER, a.get("id"))
            self.assertNotIn("org.freedesktop.policykit.exec.path", ann, a.get("id"))
        # the raw-text count agrees with the parse
        self.assertEqual(self.text.count("<allow_active>auth_self</allow_active>"), len(actions))
        self.assertEqual(self.text.count("unix-user:" + paths.SERVICE_USER), len(actions))


if __name__ == "__main__":
    unittest.main()
