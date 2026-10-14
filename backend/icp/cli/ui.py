"""Terminal output for the development CLI. Normal output goes to stdout; progress, warnings and
errors go to stderr so `icp ... > file` captures only the result.

There is no prompting here at all. In 2.0 every question Apple's sign-in asks reaches a person
through the Frontend the daemon hands the Apple pipeline (daemon/context.py) - the Pear window
over the daemon socket, or cli/jsonui.py on stdio while developing - and never a terminal
prompt, a password read from a tty, or a dialog this process opens itself.
"""

import sys


def out(msg: str = "") -> None:
    print(msg)


def step(msg: str) -> None:
    print(msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)

