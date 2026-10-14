"""The window starts only the processes on its fixed list, with fixed argument shapes.

Every child of the window inherits its effective group pear-client, so a child can reach the
daemon. The list (spec section 4.5) is: hyprctl for the window rules, focusing the window and
opening a link through Hyprland; pear-exec clip and migrate; the touchpad watcher; and
`systemctl show` for diagnosing a service that will not start. Nothing else, no shell, and no
toolkit helper that would launch a browser as our child.
"""

import os
import re
import unittest

import qmlscan
from icp.daemon import paths

ALLOWED = {
    '[root.pearExec, "clip"]',
    '[root.pearExec, "migrate"]',
    '["/usr/bin/hyprctl", "eval", root.windowRulesLua]',
    '["/usr/bin/hyprctl", "eval", root.windowModeLua]',
    '["/usr/bin/hyprctl", "dispatch", root.focusLua]',
    '["/usr/bin/hyprctl", "dispatch", opener.lua]',
    '["/usr/bin/python3", "-I", root.touchWatchPath]',
    '["/usr/bin/python3", "-I", root.qrScanPath]',
    '["/usr/bin/systemctl", "show", "-p", "LoadState,ActiveState,Result,ExecMainStatus", '
    '"pear-passwordsd.service"]',
}

SHELL_QML = os.path.join(qmlscan.APP, "shell.qml")


def property_value(code: str, name: str) -> str:
    m = re.search(r"readonly property string " + name + r":\s*(\"(?:[^\"\\]|\\.)*\")", code)
    assert m, name
    return eval(m.group(1))     # a plain JSON-style string literal from our own file


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.files = {p: qmlscan.strip_comments(qmlscan.read(p)) for p in qmlscan.app_files()}

    def test_every_command_is_on_the_list(self):
        found = []
        for path, code in self.files.items():
            for m in re.finditer(r"\bcommand\s*:\s*(\[[^\n]*\])", code):
                found.append(re.sub(r"\s+", " ", m.group(1)).strip())
        self.assertTrue(found)
        for cmd in found:
            self.assertIn(cmd, ALLOWED)

    def test_every_process_has_a_literal_command(self):
        # Independent of the matcher above: count Process elements and command bindings.
        procs = cmds = 0
        for code in self.files.values():
            scan = qmlscan.blank_strings(code)
            procs += len(re.findall(r"(?<![\w.])Process\s*\{", scan))
            cmds += len(re.findall(r"^\s*command\s*:", scan, re.M))
        self.assertEqual(procs, cmds)
        self.assertEqual(procs, len(ALLOWED))

    def test_no_other_way_to_start_a_process(self):
        for path, code in self.files.items():
            scan = qmlscan.blank_strings(code)
            for bad in (r"\bexecDetached\b", r"\bstartDetached\b", r"\bopenUrlExternally\b",
                        r"\.exec\s*\(", r"\bcommand\s*=", r"\bProcessContext\b"):
                self.assertIsNone(re.search(bad, scan), f"{path}: {bad}")
            for word in ('"sh"', '"bash"', '"-c"', '"/bin/sh"', '"xdg-open"'):
                self.assertNotIn(word, code, f"{path}: {word}")

    def test_fixed_paths(self):
        code = self.files[SHELL_QML]
        self.assertEqual(property_value(code, "pearExec"), paths.PEAR_EXEC)
        self.assertEqual(property_value(code, "socketPath"), paths.SOCKET_PATH)
        self.assertTrue(os.path.exists(os.path.join(qmlscan.APP, "touch_watch.py")))
        self.assertTrue(os.path.exists(os.path.join(qmlscan.APP, "qr_scan.py")))
        rules = re.search(r"readonly property string windowRulesLua:(.*?)\n\s*readonly", code,
                          re.S).group(1)
        self.assertIn("no_screen_share = true", rules)
        # escape-compositor-control-undisclosed: added on every start, not behind the
        # once-per-session global another program could set first.
        self.assertLess(rules.index("no_screen_share = true"), rules.index("if not _G."))
        self.assertIn(f"^{paths.WINDOW_TITLE}$", rules)
        # "Open as": the only thing that varies is a literal true/false from a boolean, and the
        # open handler acts on Pear's window alone.
        for name in ("windowRulesLua", "windowModeLua"):
            body = re.search(r"readonly property string " + name + r":(.*?)\n\s*readonly", code,
                             re.S).group(1)
            outside = re.sub(r'"(?:[^"\\]|\\.)*"', '""', body)
            self.assertEqual(set(re.findall(r"root\.\w+", outside)), {"root.windowFloating"}, name)
        self.assertIn('if w.class ~= [[org.quickshell]] or w.title ~= [[Pear Passwords]] then return end',
                      rules.replace('" + "', "").replace('"\n        + "', ""))
        self.assertIn(f'title: "{paths.WINDOW_TITLE}"', code)
        self.assertEqual(property_value(code, "focusLua"),
                         f'hl.dsp.focus({{ window = "title:^{paths.WINDOW_TITLE}$" }})')

    def test_links_go_through_the_url_pattern(self):
        code = self.files[SHELL_QML]
        assigns = re.findall(r"opener\.lua\s*=\s*([^\n;]*)", code)
        self.assertEqual(assigns, ['"hl.dsp.exec_cmd(\\"xdg-open https://" + url + "\\")"'])
        body = re.search(r"function openDomain\(d\) \{(.*?)\n    \}", code, re.S).group(1)
        self.assertLess(body.index("root.urlPattern.test(url)"), body.index("opener.lua ="))
        pattern = re.search(r"readonly property var urlPattern: /(.*)/\n", code).group(1)
        rx = re.compile(pattern)
        for ok in ("github.com", "login.example.co.uk", "example.com:8443/login",
                   "example.com/a/b-c_d.e~f", "xn--bcher-kva.example"):
            self.assertTrue(rx.match(ok), ok)
        for bad in ('evil.com")', 'a.com";os.execute("x', "a.com;rm -rf", "$(id).com",
                    "a.com`id`", "localhost", "a b.com", "a.com\\", "a.com'", "-a.com",
                    "a.com/<script>", "a.com/$x", "a.com\nb", ""):
            self.assertIsNone(rx.match(bad), bad)


# What Omarchy's own components start and read once the window instantiates them (Commons/
# Style, Color and Util through Theme.qml, Button, TextField). They run in the window with egid
# pear-client, so they are pinned here too: an Omarchy update that adds a process or a file
# read fails this test until it is reviewed and documented (README "Security", security.md).
OMARCHY_ALLOWED = {
    '["hyprctl", "-j", "getoption", "decoration:rounding"]',
    '["hyprctl", "-j", "getoption", "general:gaps_out"]',
    '["fc-match", "-f", "%{family[0]}", "monospace"]',
}
OMARCHY_HOME_READS = {
    'Quickshell.env("HOME") + "/.config/fontconfig/fonts.conf"',
    'Quickshell.env("HOME") + "/.local/state/omarchy/toggles/hypr/window-no-gaps.lua"',
    'root.currentThemePath + "/colors.toml"',
    'root.currentThemePath + "/shell.toml"',
    'root.home + "/.config/omarchy/shell.toml"',
}


def used_omarchy_files() -> list[str]:
    """Every Commons and Ui QML file the window instantiates, transitively."""
    import test_qml_no_ipc
    commons = os.path.join(qmlscan.OMARCHY_SHELL, "Commons")
    ui = os.path.join(qmlscan.OMARCHY_SHELL, "Ui")
    singletons = {}
    with open(os.path.join(commons, "qmldir")) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 4 and parts[0] == "singleton":
                singletons[parts[1]] = os.path.join(commons, parts[3])
    files = [os.path.join(ui, n + ".qml") for n in test_qml_no_ipc.used_ui_components()]
    files = [f for f in files if os.path.exists(f)]
    todo = list(qmlscan.app_files((".qml",))) + files
    used: set[str] = set()
    while todo:
        path = todo.pop()
        code = qmlscan.blank_strings(qmlscan.strip_comments(qmlscan.read(path)))
        for name, target in singletons.items():
            if target not in used and re.search(rf"(?<![\w.]){name}\.", code):
                used.add(target)
                todo.append(target)
    return sorted(used) + files


@unittest.skipUnless(os.path.isdir(os.path.join(qmlscan.OMARCHY_SHELL, "Commons")),
                     "Omarchy's shell components are not installed")
class OmarchyComponentTests(unittest.TestCase):
    """escape-omarchy-commons-home-reads-and-children, clipboard_ui-7."""

    def setUp(self):
        self.files = {p: qmlscan.strip_comments(qmlscan.read(p)) for p in used_omarchy_files()}

    def test_the_window_instantiates_style_and_color(self):
        names = {os.path.basename(p) for p in self.files}
        self.assertLessEqual({"Style.qml", "Color.qml"}, names)

    def test_their_processes_are_the_reviewed_ones(self):
        found = set()
        procs = cmds = 0
        for path, code in self.files.items():
            for m in re.finditer(r"\bcommand\s*:\s*(\[[^\n]*\])", code):
                found.add(re.sub(r"\s+", " ", m.group(1)).strip())
            scan = qmlscan.blank_strings(code)
            procs += len(re.findall(r"(?<![\w.])Process\s*\{", scan))
            cmds += len(re.findall(r"^\s*command\s*:", scan, re.M))
        self.assertEqual(found, OMARCHY_ALLOWED)
        self.assertEqual(procs, cmds)

    def test_nothing_runs_a_shell_on_the_windows_behalf(self):
        # Util.qml defines execDetached/execArgv (bash -lc); nothing the window loads may call
        # them, and nothing else may start a detached process.
        for path, code in list(self.files.items()) + [
                (p, qmlscan.strip_comments(qmlscan.read(p))) for p in qmlscan.app_files()]:
            scan = qmlscan.blank_strings(code)
            self.assertIsNone(re.search(r"\bUtil\.(execDetached|execArgv)\s*\(", scan), path)
            if os.path.basename(path) != "Util.qml":
                self.assertIsNone(re.search(r"\bexecDetached\s*\(", scan), path)

    def test_their_reads_from_home_are_the_documented_ones(self):
        found = set()
        for code in self.files.values():
            for m in re.finditer(r"^\s*path\s*:\s*(.+)$", code, re.M):
                expr = m.group(1).strip()
                if "env(" in expr or "home" in expr.lower() or "Path +" in expr:
                    found.add(expr)
        self.assertEqual(found, OMARCHY_HOME_READS)


class AppFileTests(unittest.TestCase):
    def test_desktop_entry_runs_pear_exec(self):
        with open(os.path.join(qmlscan.APP, f"{paths.APP_ID}.desktop")) as f:
            lines = f.read().splitlines()
        self.assertIn(f"Exec={paths.PEAR_EXEC} ui", lines)
        self.assertEqual([l for l in lines if l.startswith("Exec=")], [f"Exec={paths.PEAR_EXEC} ui"])

    def test_launcher_script_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(qmlscan.APP, "launch.sh")))

    def test_fonts_conf_is_system_only(self):
        with open(os.path.join(qmlscan.APP, "fonts.conf")) as f:
            raw = f.read()
        conf = re.sub(r"<!--.*?-->", "", raw, flags=re.S)
        self.assertIn("<cachedir>/var/cache/fontconfig</cachedir>", conf)
        for bad in ("50-user", "51-local", "~", 'prefix="xdg"', "prefix='xdg'", "/home",
                    "conf.d", "<include>", "/etc/fonts"):
            self.assertNotIn(bad, conf)
        for path in re.findall(r">(/[^<]+)<", conf):
            self.assertTrue(path.startswith(("/usr/share/", "/usr/local/share/", "/var/cache/")),
                            path)


if __name__ == "__main__":
    unittest.main()
