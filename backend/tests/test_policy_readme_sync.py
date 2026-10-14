"""The README's dialog table, docs/protocol.md and the installed polkit policy agree.

What a user is told a dialog says, and when, must be what the policy file makes the dialog
say and what the daemon raises it for. All five actions, including `.autofill`, are checked.
The policy file is the daemon's; until it is on the branch, only the README and protocol.md are
compared, and the policy half is reported as skipped.
"""

import os
import re
import unittest
import xml.etree.ElementTree as ET

from icp.daemon import paths, protocol

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY = os.path.join(ROOT, "polkit", f"{paths.POLKIT_ACTION_PREFIX}.policy")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _section(text, heading):
    m = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        raise AssertionError(f"no section {heading!r}")
    return m.group(1)


def _rows(section):
    rows = []
    for line in section.splitlines():
        if line.startswith("|") and not set(line) <= set("|-: "):
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]


def readme_actions():
    rows = _rows(_section(_read("README.md"), "How unlocking works"))
    return {r[0].strip("`"): r[1] for r in rows if r[0].startswith("`io.")}


def protocol_actions():
    rows = _rows(_section(_read("docs", "protocol.md"), "5. Prompts (polkit)"))
    return {r[0].strip("`"): r[1] for r in rows if r[0].startswith("`io.")}


class PolicyReadmeSyncTests(unittest.TestCase):
    def test_readme_names_every_action_once(self):
        self.assertEqual(set(readme_actions()), set(paths.ACTIONS))
        self.assertIn(paths.ACTION_AUTOFILL, readme_actions())

    def test_readme_messages_match_protocol(self):
        self.assertEqual(readme_actions(), protocol_actions())

    def test_readme_says_when_each_dialog_appears(self):
        rows = {r[0].strip("`"): r[2] for r in
                _rows(_section(_read("README.md"), "How unlocking works")) if r[0].startswith("`io.")}
        # Every op that raises a dialog is covered by the README's "when" column, in words.
        when = {
            "unlock": (paths.ACTION_UNLOCK, "open"),
            "grant": (paths.ACTION_REVEAL, "reveal"),
            "create": (paths.ACTION_MANAGE, "adding"),
            "delete": (paths.ACTION_MANAGE, "deleting"),
            "signin": (paths.ACTION_MANAGE, "Signing in"),
            "signout": (paths.ACTION_MANAGE, "out"),
            "migrate-begin": (paths.ACTION_MANAGE, "moving from 1.x"),
            "reset": (paths.ACTION_MANAGE, "starting over"),
            "purge-old-copy": (paths.ACTION_MANAGE, "old 1.x copy"),
            "clip-history-check": (paths.ACTION_MANAGE, "clipboard history"),
            "autofill-enable": (paths.ACTION_MANAGE, "turning browser autofill on"),
            "tpm-move": (paths.ACTION_MANAGE, "moving your keys onto the security chip"),
            "features": (paths.ACTION_MANAGE, "turning a category that waits for a check "
                                              "(Passkeys, Recently Deleted) on or off"),
            "diag-items": (paths.ACTION_MANAGE, "reading the keychain diagnostic"),
            "autofill-fill": (paths.ACTION_AUTOFILL, "Every browser fill"),
            "autofill-names": (paths.ACTION_AUTOFILL_NAMES, "name a site's accounts"),
        }
        self.assertEqual(set(when), set(protocol.PROMPT_ACTION))
        for op, (action, words) in when.items():
            self.assertEqual(protocol.PROMPT_ACTION[op], action, op)
            self.assertIn(words, rows[action], f"README does not say {op} raises {action}")

    def test_policy_messages_match_readme(self):
        self.assertTrue(os.path.exists(POLICY), POLICY)
        root = ET.fromstring(_read("polkit", f"{paths.POLKIT_ACTION_PREFIX}.policy"))
        policy = {a.get("id"): (a.findtext("message") or "").strip() for a in root.findall("action")}
        self.assertEqual(policy, readme_actions())

    def test_no_legacy_action_in_the_readme(self):
        readme = _read("README.md")
        self.assertNotIn("org.icp.unlock\"", readme)
        self.assertNotIn("sudo tee", readme)


if __name__ == "__main__":
    unittest.main()
