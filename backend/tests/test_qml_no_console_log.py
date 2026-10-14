"""Nothing in the window logs. Quickshell keeps a log of every instance under
$XDG_RUNTIME_DIR/quickshell, readable by any process running as you, so a console call next to
a revealed value is a copy of it. None at all, rather than a judgement about which are safe.
"""

import re
import unittest

import qmlscan


class NoConsoleTests(unittest.TestCase):
    def test_no_console_calls(self):
        call = re.compile(r"\bconsole\s*\.\s*\w+\s*\(")
        for path in qmlscan.app_files():
            code = qmlscan.blank_strings(qmlscan.strip_comments(qmlscan.read(path)))
            self.assertIsNone(call.search(code), path)

    def test_independent_word_count(self):
        # Any mention of `console` or `print(` in code (comments removed, strings kept) counts.
        total = 0
        for path in qmlscan.app_files():
            code = qmlscan.strip_comments(qmlscan.read(path))
            total += len(re.findall(r"console", code)) + len(re.findall(r"\bprint\s*\(", code))
        self.assertEqual(total, 0)

    def test_matcher_works(self):
        sample = 'Item { function f() { console . log ("x"); } }'
        code = qmlscan.blank_strings(qmlscan.strip_comments(sample))
        self.assertIsNotNone(re.search(r"\bconsole\s*\.\s*\w+\s*\(", code))
        commented = "// console.log(secret)\nItem {}"
        self.assertNotIn("console", qmlscan.strip_comments(commented))


if __name__ == "__main__":
    unittest.main()
