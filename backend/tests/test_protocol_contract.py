"""docs/protocol.md and icp.daemon.protocol describe the same protocol.

The document is what the UI, the clients and a third-party extension author read; the module is
what the daemon and the clients import. Each check parses the document independently of the
module, so an op, event or error code added to one side only fails here.
"""

import os
import re
import unittest

from icp.daemon import paths, protocol

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC = os.path.join(ROOT, "docs", "protocol.md")


def _section(text: str, heading: str) -> str:
    m = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        raise AssertionError(f"protocol.md has no section {heading!r}")
    return m.group(1)


def _table_rows(section: str) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]   # drop the header row


class ProtocolDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DOC, encoding="utf-8") as f:
            cls.doc = f.read()

    def test_error_codes_match(self):
        rows = _table_rows(_section(self.doc, "12. Error codes"))
        documented = {r[0].strip("`") for r in rows}
        self.assertEqual(documented, set(protocol.ERRORS))
        # And a second, looser matcher over the whole document: every "error":"x" shown in
        # an example is a known code.
        shown = set(re.findall(r'"error":"([a-z-]+)"', self.doc))
        self.assertTrue(shown, "no error examples found")
        self.assertLessEqual(shown, set(protocol.ERRORS))

    def test_op_table_matches_roles(self):
        rows = _table_rows(_section(self.doc, "13. Op table"))
        doc_roles = {}
        doc_dialogs = {}
        for op, role, dialog, *_ in rows:
            op = op.strip("`")
            doc_roles[op] = role
            doc_dialogs[op] = dialog.strip("`")
        self.assertEqual(set(doc_roles), set(protocol.ALL_OPS))
        for role, ops in protocol.ROLE_OPS.items():
            for op in ops:
                self.assertEqual(doc_roles[op], role, op)
        self.assertEqual(doc_roles["hello"], "all")
        for op, dialog in doc_dialogs.items():
            if op in protocol.PROMPT_ACTION:
                self.assertEqual(paths.POLKIT_ACTION_PREFIX + dialog,
                                 protocol.PROMPT_ACTION[op], op)
            else:
                self.assertEqual(dialog, "–", f"{op} must not raise a dialog")

    def test_every_op_has_an_example_request(self):
        shown = set(re.findall(r'\{"op":"([a-z-]+)"', self.doc))
        self.assertEqual(shown, set(protocol.ALL_OPS))

    def test_events_match(self):
        shown = set(re.findall(r'\{"event":"([a-z-]+)"', self.doc))
        declared = set().union(*protocol.EVENTS.values())
        self.assertEqual(shown, declared)

    def test_no_lease_anywhere(self):
        # Owner decision: sync only while unlocked. No setting, no field, no code path.
        self.assertNotIn("sync_lease_h", protocol.DEFAULT_SETTINGS)
        settings = _section(self.doc, "3. Shared shapes")
        self.assertNotIn('"sync_lease_h"', settings.split("There is no")[0])
        self.assertFalse(any("lease" in k for k in protocol.SETTINGS_KEYS))


class FeaturesContractTests(unittest.TestCase):
    """The category, tag and copy-text additions (features spec 4, 6) in both places."""

    @classmethod
    def setUpClass(cls):
        with open(DOC, encoding="utf-8") as f:
            cls.doc = f.read()

    def test_meta_example_has_exactly_the_wire_fields(self):
        import json
        from icp import vstore
        from icp.daemon import wire
        block = re.search(r"### 3.1 Meta.*?```json\n(.*?)```", self.doc, re.S).group(1)
        documented = set(json.loads(block))
        m = vstore.Meta(id="x", title="t", domain="d", sites=[], username="u", nickname="",
                        has_totp=False, has_notes=False, mdat=0.0, history_count=0)
        sent = set(wire.entries([m], show_all=True)[0])
        self.assertEqual(documented, sent)

    def test_tags_in_set_and_create(self):
        self.assertIn("tags", protocol.SET_FIELDS)
        self.assertIn("tags", protocol.CREATE_FIELDS)
        section = _section(self.doc, "6. UI ops (role `ui`)")
        self.assertIn("`tags` (array of at most 16", section)
        self.assertIn('"field":"notes","detail":"not-utf8"', section)

    def test_copy_text_sources_and_limits(self):
        from icp.daemon import handlers
        self.assertEqual(protocol.COPY_TEXT_SOURCES_GRANT,
                         {"notes-edit", "totp-setup-edit", "new-password"})
        self.assertEqual(protocol.COPY_TEXT_SOURCES_CREATE,
                         {"create-password", "create-notes", "create-totp-setup"})
        self.assertFalse(protocol.COPY_TEXT_SOURCES_GRANT & protocol.COPY_TEXT_SOURCES_CREATE)
        self.assertEqual(protocol.COPY_TEXT_MAX, handlers.MAX_NOTES)
        self.assertEqual(protocol.COPY_TEXT_PER_MIN, 10)
        self.assertNotIn("copy-text", protocol.PROMPT_ACTION)
        self.assertNotIn("copy-text", protocol.GRANT_OPS)
        section = _section(self.doc, "6. UI ops (role `ui`)")
        for source in protocol.COPY_TEXT_SOURCES:
            self.assertIn(f"`{source}`", section)
        self.assertIn("1 to 16384 characters after NFC", section)
        self.assertIn("At most 10 per rolling minute", section)

    def test_features_and_diag(self):
        self.assertEqual(protocol.FEATURES, ("passkeys", "apple_deleted"))
        self.assertEqual(protocol.DEFAULT_FEATURES, {"passkeys": False, "apple_deleted": False})
        self.assertNotIn("features", protocol.SETTINGS_KEYS)        # never a window setting
        self.assertEqual(protocol.PROMPT_ACTION["features"], paths.ACTION_MANAGE)
        self.assertEqual(protocol.PROMPT_ACTION["diag-items"], paths.ACTION_MANAGE)
        self.assertIn('"features":{"passkeys":false,"apple_deleted":false}', self.doc)
        self.assertIn("**Never a value**", self.doc)


class ProtocolValueTests(unittest.TestCase):
    def test_owner_decided_defaults(self):
        self.assertEqual(protocol.GRANT_S_DEFAULT, 120)
        self.assertEqual(protocol.CLIP_TIMEOUT_S_DEFAULT, 30)
        self.assertEqual(protocol.IDLE_LOCK_S_DEFAULT, 300)
        self.assertEqual(protocol.TICKET_TTL_S, 10)
        self.assertEqual(protocol.DEFAULT_SETTINGS,
                         {"grant_s": 120, "idle_lock_s": 300, "clip_timeout_s": 30,
                          "window_mode": "floating"})
        self.assertEqual(protocol.WINDOW_MODES, ("floating", "regular"))
        lo, hi = protocol.CLIP_TIMEOUT_S_RANGE
        self.assertTrue(lo <= protocol.CLIP_TIMEOUT_S_DEFAULT <= hi)
        lo, hi = protocol.GRANT_S_RANGE
        self.assertTrue(lo <= protocol.GRANT_S_DEFAULT <= hi)
        self.assertIn(protocol.IDLE_LOCK_S_DEFAULT, protocol.IDLE_LOCK_S_CHOICES)

    def test_roles_and_prompts(self):
        self.assertEqual(set(protocol.ROLE_OPS), set(paths.ROLES))
        self.assertEqual(set(protocol.PROMPT_ACTION.values()), set(paths.ACTIONS))
        # The autofill role can raise only its own two dialogs, and the UI never raises them.
        for op, action in protocol.PROMPT_ACTION.items():
            is_autofill = op in protocol.ROLE_OPS["autofill"]
            self.assertEqual(action in (paths.ACTION_AUTOFILL, paths.ACTION_AUTOFILL_NAMES),
                             is_autofill, op)
        # clip and migrate never raise a dialog: their authority is the ticket.
        for role in protocol.TICKET_ROLES:
            self.assertFalse(protocol.ROLE_OPS[role] & set(protocol.PROMPT_ACTION), role)
        self.assertLessEqual(set(protocol.PROMPT_BUCKET), set(paths.ROLES))

    def test_ops_are_unique_to_a_role(self):
        seen = {}
        for role, ops in protocol.ROLE_OPS.items():
            for op in ops:
                self.assertNotIn(op, seen, f"{op} in {role} and {seen.get(op)}")
                seen[op] = role
        self.assertNotIn("hello", seen)

    def test_field_sets(self):
        self.assertLessEqual(protocol.COPY_FIELDS_NEED_GRANT, protocol.COPY_FIELDS)
        self.assertEqual(protocol.COPY_FIELDS - protocol.COPY_FIELDS_NEED_GRANT,
                         {"username", "domain"})
        self.assertLessEqual(protocol.GRANT_OPS, protocol.ROLE_OPS["ui"])

    def test_limits(self):
        # One raw import chunk, base64-encoded inside its JSON line, stays under the cap.
        b64 = 4 * -(-protocol.IMPORT_CHUNK_MAX // 3)
        self.assertLess(b64 + 200, protocol.MAX_REQUEST_LINE)
        self.assertLess(protocol.MAX_REQUEST_LINE, protocol.MAX_REPLY_LINE)
        self.assertLessEqual(set(protocol.IMPORT_REQUIRED), set(protocol.IMPORT_FILES))

    def test_op_error(self):
        e = protocol.OpError("rate-limited", retry_after=12)
        self.assertEqual(e.reply(7), {"rid": 7, "error": "rate-limited", "retry_after": 12})
        with self.assertRaises(ValueError):
            protocol.OpError("no-such-code")


if __name__ == "__main__":
    unittest.main()
