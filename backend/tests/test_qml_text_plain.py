"""Every Text, TextArea and TextEdit in the window renders plain text.

A Text's default textFormat is AutoText, which turns anything that looks like markup into
markup. Names, usernames, notes, sign-in messages and Apple's own strings all reach these
elements, so each one states PlainText explicitly. Two matchers that share no code beyond
comment stripping: element bodies by brace matching, and a line-shaped count.
"""

import re
import unittest

import qmlscan

PLAIN = re.compile(r"\btextFormat\s*:\s*(Text|TextArea|TextEdit)\.PlainText\b")


class PlainTextTests(unittest.TestCase):
    def test_every_text_element_is_plain(self):
        missing = []
        total = 0
        for path in qmlscan.app_files((".qml",)):
            for kind, body, line in qmlscan.text_elements(qmlscan.read(path)):
                total += 1
                if not PLAIN.search(body):
                    missing.append(f"{path}:{line} {kind}")
        self.assertGreater(total, 50, "the matcher found almost nothing - is it broken?")
        self.assertEqual(missing, [])

    def test_independent_count(self):
        # Count element openings line by line (a different shape: the type name at the start
        # of a line, optionally after `name:`), and PlainText declarations; they must agree.
        opener = re.compile(r"^\s*(?:[A-Za-z_.]+\s*:\s*)?(?:Text|TextArea|TextEdit)\s*\{")
        elements = plains = 0
        for path in qmlscan.app_files((".qml",)):
            code = qmlscan.strip_comments(qmlscan.read(path))
            for line in code.splitlines():
                if opener.match(line):
                    elements += 1
                if re.search(r"textFormat:\s*\w+\.PlainText", line):
                    plains += 1
        brace_count = sum(1 for p in qmlscan.app_files((".qml",))
                          for _ in qmlscan.text_elements(qmlscan.read(p)))
        self.assertEqual(elements, brace_count)
        self.assertEqual(plains, elements)

    def test_no_rich_formats_anywhere(self):
        for path in qmlscan.app_files():
            code = qmlscan.strip_comments(qmlscan.read(path))
            for fmt in ("StyledText", "RichText", "MarkdownText", "AutoText"):
                self.assertNotIn(fmt, code, f"{path} uses {fmt}")

    def test_matcher_catches_a_missing_format(self):
        sample = "Item {\n  Text {\n    text: \"x\"\n    Rectangle { textFormat: Text.PlainText }\n  }\n}\n"
        found = list(qmlscan.text_elements(sample))
        self.assertEqual(len(found), 1)
        self.assertIsNone(PLAIN.search(found[0][1]), "a child's property must not count")
        ok = "Text {\n  textFormat: Text.PlainText\n  text: \"Text { }\"\n}\n"
        found = list(qmlscan.text_elements(ok))
        self.assertEqual(len(found), 1)
        self.assertIsNotNone(PLAIN.search(found[0][1]))


if __name__ == "__main__":
    unittest.main()
