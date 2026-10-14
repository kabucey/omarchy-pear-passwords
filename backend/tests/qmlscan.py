"""A small QML scanner for the window's guard tests (test_qml_*.py). Not a test module.

QML is not parsed here; it is tokenised just enough to be sure about three things: what is a
comment, what is inside a string, and which braces belong to which element. That is all the
guards need, and keeping it this small is what makes the second, independent matcher in each
test meaningful.
"""

from __future__ import annotations

import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
APP = os.path.join(REPO, "app")
OMARCHY_SHELL = "/usr/share/omarchy/shell"


def app_files(ext=(".qml", ".js")) -> list[str]:
    return sorted(os.path.join(APP, f) for f in os.listdir(APP) if f.endswith(ext))


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def strip_comments(src: str) -> str:
    """Blank out // and /* */ comments, keeping strings, regex literals and line numbers."""
    out = []
    i, n = 0, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote or c == "\n":
                quote = None
            i += 1
            continue
        if c in "\"'`":
            quote = c
            out.append(c)
            i += 1
            continue
        if src.startswith("//", i):
            # `//` right after an expression start would be a regex in JS only as /.../, and
            # no regex here starts with a slash, so this is a comment.
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def blank_strings(src: str) -> str:
    """Replace the contents of string literals with spaces (comments already stripped)."""
    out = []
    quote = None
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if quote:
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if c == quote or c == "\n":
                quote = None
                out.append(c)
            else:
                out.append(" ")
            i += 1
            continue
        if c in "\"'`":
            quote = c
        out.append(c)
        i += 1
    return "".join(out)


def element_body(code: str, open_brace: int) -> str:
    """Text from `open_brace` (a '{') to its matching '}', in comment- and string-free code."""
    depth = 0
    for j in range(open_brace, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return code[open_brace:j + 1]
    raise ValueError("unbalanced braces")


def top_level(body: str) -> str:
    """Only the element's own lines: nested child elements and blocks are blanked."""
    out = []
    depth = 0
    for c in body:
        if c == "{":
            depth += 1
            out.append(c if depth == 1 else " ")
            continue
        if c == "}":
            depth -= 1
            out.append(c if depth == 0 else " ")
            continue
        out.append(c if depth == 1 else (" " if c != "\n" else "\n"))
    return "".join(out)


ELEMENT_RE = re.compile(r"(?<![\w.])(Text|TextArea|TextEdit)\s*\{")


def text_elements(src: str):
    """(type, top-level body, line) of every Text/TextArea/TextEdit element in `src`."""
    code = strip_comments(src)
    scan = blank_strings(code)
    for m in ELEMENT_RE.finditer(scan):
        brace = scan.index("{", m.start())
        body = element_body(code, brace)
        yield m.group(1), top_level(body), code.count("\n", 0, m.start()) + 1
