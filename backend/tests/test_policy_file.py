"""polkit/io.github.dragosol.pearpasswords.policy declares exactly the five actions the daemon
raises, each auth_self for active sessions only, never retained, owned by pear-passwords.

Each rule is checked twice: on the parsed XML and with a plain-text matcher, so a policy that
fools one parser still fails the other.
"""

import os
import re
import unittest
import xml.etree.ElementTree as ET

from icp.daemon import paths, protocol

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY = os.path.join(ROOT, "polkit", f"{paths.POLKIT_ACTION_PREFIX}.policy")
PROTOCOL_DOC = os.path.join(ROOT, "docs", "protocol.md")
OWNER = f"unix-user:{paths.SERVICE_USER}"


class PolicyFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(POLICY, encoding="utf-8") as f:
            cls.text = f.read()
        cls.root = ET.fromstring(cls.text.encode("utf-8"))
        cls.actions = {a.get("id"): a for a in cls.root.iter("action")}

    def test_exactly_the_five_actions(self):
        self.assertEqual(set(self.actions), set(paths.ACTIONS))
        self.assertEqual(len(re.findall(r"<action\s+id=", self.text)), 5)
        self.assertEqual(set(protocol.PROMPT_ACTION.values()), set(paths.ACTIONS))

    def test_defaults(self):
        for aid, a in self.actions.items():
            d = a.find("defaults")
            self.assertEqual([(c.tag, c.text) for c in d], [
                ("allow_any", "no"), ("allow_inactive", "no"), ("allow_active", "auth_self")],
                aid)

    def test_defaults_text(self):
        self.assertEqual(len(re.findall(r"<allow_any>no</allow_any>", self.text)), 5)
        self.assertEqual(len(re.findall(r"<allow_inactive>no</allow_inactive>", self.text)), 5)
        self.assertEqual(len(re.findall(r"<allow_active>auth_self</allow_active>", self.text)), 5)
        self.assertEqual(len(re.findall(r"<allow_\w+>", self.text)), 15)

    def test_never_retained(self):
        self.assertNotIn("_keep", self.text)
        for a in self.actions.values():
            for c in a.find("defaults"):
                self.assertFalse(c.text.endswith("_keep"))
                self.assertNotIn("auth_admin", c.text)
                self.assertNotEqual(c.text, "yes")

    def test_owner_annotation(self):
        for aid, a in self.actions.items():
            ann = {x.get("key"): x.text for x in a.findall("annotate")}
            self.assertEqual(ann, {"org.freedesktop.policykit.owner": OWNER}, aid)
        self.assertEqual(self.text.count(f'"org.freedesktop.policykit.owner">{OWNER}<'), 5)

    def test_no_exec_path_and_no_implicit_auth(self):
        self.assertNotIn("exec.path", self.text)
        self.assertNotIn("imply", self.text)

    def test_messages_match_the_protocol(self):
        with open(PROTOCOL_DOC, encoding="utf-8") as f:
            doc = f.read()
        section = doc[doc.index("## 5. Prompts"):doc.index("## 6.")]
        rows = re.findall(r"^\| `([a-z.-]+)` \| ([^|]+?) \|", section, re.M)
        expected = {aid: msg.strip() for aid, msg in rows}
        self.assertEqual(set(expected), set(paths.ACTIONS))
        for aid, a in self.actions.items():
            self.assertEqual(a.findtext("message"), expected[aid], aid)
            self.assertTrue(a.findtext("description"))

    def test_details_placeholders(self):
        msgs = {aid: a.findtext("message") for aid, a in self.actions.items()}
        self.assertIn("$(account)", msgs[paths.ACTION_REVEAL])
        self.assertIn("$(account)", msgs[paths.ACTION_AUTOFILL])
        self.assertIn("$(origin)", msgs[paths.ACTION_AUTOFILL])
        self.assertNotIn("$(", msgs[paths.ACTION_UNLOCK] + msgs[paths.ACTION_MANAGE])

    def test_legacy_policy_is_gone(self):
        self.assertEqual(sorted(os.listdir(os.path.join(ROOT, "polkit"))),
                         [os.path.basename(POLICY)])
        self.assertFalse(os.path.exists(os.path.join(ROOT, "polkit", "org.icp.unlock.policy")))


if __name__ == "__main__":
    unittest.main()
