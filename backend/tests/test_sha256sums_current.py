"""SHA256SUMS is current, and the hash the README's root command pins is its hash.

The root command checks the stage against the sha256 of SHA256SUMS (published in the release
notes), then every staged file against SHA256SUMS. A stale SHA256SUMS makes every install
fail at that check, and a README hash that drifted from it tells users to trust the wrong
value, so both are checked on every run. Fix either with tools/gen-sha256sums.sh.

Two matchers for "which files are staged": git's own list (what the tool uses) and an
independent walk of the same directories that skips only what .gitignore ignores.
"""

import hashlib
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUMS = os.path.join(ROOT, "SHA256SUMS")
STAGED = ("manifest.json", "app", "backend", "native", "polkit", "system")
LINE = re.compile(r"^([0-9a-f]{64})  ([^\s\\]+)$")


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _read_sums():
    with open(SUMS, encoding="utf-8") as f:
        text = f.read()
    entries = []
    for n, line in enumerate(text.splitlines(), 1):
        m = LINE.match(line)
        if not m:
            raise AssertionError(f"SHA256SUMS:{n}: not '<sha256>  <path>': {line!r}")
        entries.append((m.group(1), m.group(2)))
    return text, entries


def _walk():
    """Every regular file under the staged paths, except tests and what .gitignore ignores."""
    out = set()
    for top in STAGED:
        p = os.path.join(ROOT, top)
        if os.path.isfile(p):
            out.add(top)
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = [d for d in dirnames
                           if d not in ("__pycache__", "build", "dist", "venv", ".venv")
                           and not d.endswith(".egg-info")]
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT)
                if name.endswith(".pyc") or rel.startswith("backend/tests/"):
                    continue
                if os.path.islink(os.path.join(ROOT, rel)):
                    continue
                out.add(rel)
    return out


def _git_list():
    try:
        proc = subprocess.run(["git", "-C", ROOT, "ls-files", "-co", "--exclude-standard", "--",
                               *STAGED], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    return {f for f in proc.stdout.splitlines()
            if not f.startswith("backend/tests/") and os.path.isfile(os.path.join(ROOT, f))}


class Sha256SumsTests(unittest.TestCase):
    def setUp(self):
        self.text, self.entries = _read_sums()
        self.listed = [p for _, p in self.entries]

    def test_format_and_order(self):
        self.assertTrue(self.text.endswith("\n"))
        self.assertEqual(self.listed, sorted(self.listed, key=lambda p: p.encode()),
                         "SHA256SUMS is not sorted by path")
        self.assertEqual(len(self.listed), len(set(self.listed)))
        for p in self.listed:
            self.assertFalse(p.startswith(("/", "./")) or ".." in p.split("/"), p)

    def test_every_listed_file_matches(self):
        stale = [p for h, p in self.entries
                 if not os.path.isfile(os.path.join(ROOT, p)) or _sha(os.path.join(ROOT, p)) != h]
        self.assertEqual(stale, [], "run tools/gen-sha256sums.sh")

    def test_lists_exactly_the_staged_files(self):
        walked = _walk()
        self.assertEqual(set(self.listed), walked, "run tools/gen-sha256sums.sh")
        git = _git_list()
        if git is not None:
            self.assertEqual(set(self.listed), git, "git's list differs from SHA256SUMS")

    def test_nothing_staged_that_root_has_no_use_for(self):
        for p in self.listed:
            self.assertFalse(p.startswith(("backend/tests/", "docs/", "anisette/", "tools/")), p)
            self.assertNotIn("__pycache__", p)
        for needed in ("system/install-root.sh", "system/lib/files.sh", "system/paths.env",
                       "system/uninstall-root.sh", "backend/requirements.lock",
                       "backend/build-requirements.lock", "backend/pyproject.toml",
                       "manifest.json"):
            self.assertIn(needed, self.listed)

    def test_stage_has_every_source_the_root_step_installs(self):
        """What system/lib/files.sh's table reads from the stage."""
        from icp.daemon import paths
        needed = ["native/pear-exec.c", "app/fonts.conf", f"app/{paths.APP_ID}.desktop",
                  f"polkit/{paths.POLKIT_ACTION_PREFIX}.policy",
                  f"system/units/{paths.SOCKET_UNIT}", f"system/units/{paths.SERVICE_UNIT}",
                  "system/sysusers.d/pear-passwords.conf", "system/tmpfiles.d/pear-passwords.conf",
                  "system/libexec/pear-passwordsd", "system/libexec/pear-autofill-host",
                  "system/bin/pear-passwords-autofill"]
        missing = [p for p in needed if p not in self.listed]
        self.assertEqual(missing, [], "the root step reads these from the stage")

    def test_readme_pins_this_hash(self):
        with open(SUMS, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        pinned = re.findall(r'echo "([0-9a-f]{64})  SHA256SUMS"', readme)
        self.assertEqual(pinned, [digest], "run tools/gen-sha256sums.sh")

    def test_readme_command_is_install_sh_command(self):
        """The README shows the command install.sh prints, byte for byte apart from the hash."""
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        cmd = re.search(r"^sudo sh -c '.*'$", readme, re.M).group(0)
        proc = subprocess.run(
            ["bash", "-c", 'sums_hash=HASH; eval "$(sed -n "/^root_command() {/,/^}/p" install.sh)";'
             ' root_command'], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(re.sub(r"[0-9a-f]{64}", "HASH", cmd), proc.stdout.strip())

    def test_the_tool_agrees(self):
        if _git_list() is None:
            self.skipTest("not a git checkout")
        proc = subprocess.run([os.path.join(ROOT, "tools", "gen-sha256sums.sh"), "--check"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
