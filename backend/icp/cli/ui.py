"""Terminal output and prompt helpers. Normal output goes to stdout; progress/warnings/errors
go to stderr so `icp ... > file` captures only the result."""
import getpass
import sys


# The frontend every prompt and message goes through. None means the terminal.
#
# Sign-in is not one question: Apple ID, password, a 2FA code, sometimes an escrow bottle to
# pick and a y/N to confirm an irreversible recovery. Rather than reimplement that flow for a
# GUI - and drift from it the first time Apple changes a step - the whole layer is swappable.
# A frontend implements ask/secret/confirm_yn/emit and inherits every prompt automatically,
# including ones added later.
_frontend = None


def set_frontend(frontend) -> None:
    global _frontend
    _frontend = frontend


def get_frontend():
    return _frontend


def out(msg: str = "") -> None:
    if _frontend is not None:
        _frontend.emit("out", msg)
        return
    print(msg)


def step(msg: str) -> None:
    if _frontend is not None:
        _frontend.emit("step", msg)
        return
    print(msg, file=sys.stderr)


def warn(msg: str) -> None:
    if _frontend is not None:
        _frontend.emit("warn", msg)
        return
    print(f"warning: {msg}", file=sys.stderr)


def err(msg: str) -> None:
    if _frontend is not None:
        _frontend.emit("err", msg)
        return
    print(f"error: {msg}", file=sys.stderr)


def ask(msg: str, kind: str | None = None, default: str | None = None) -> str:
    """`kind` says what is being asked (apple_id, code, ...) so a GUI can draw the right input
    instead of echoing a terminal prompt string. The terminal ignores it."""
    if _frontend is not None:
        return _frontend.ask(msg, kind=kind, default=default)
    return input(msg).strip()


def secret(msg: str, kind: str | None = None, detail: str | None = None) -> str:
    if _frontend is not None:
        return _frontend.secret(msg, kind=kind, detail=detail)
    return getpass.getpass(msg)


def confirm_yn(msg: str, kind: str | None = None, detail: str | None = None) -> bool:
    """Yes/No prompt that defaults to No (empty or anything but y/yes)."""
    if _frontend is not None:
        return _frontend.confirm_yn(msg, kind=kind, detail=detail)
    return input(msg).strip().lower() in ("y", "yes")


def stage(stage_name: str, **info) -> None:
    """Where the sign-in flow has got to. A GUI draws progress from these; the terminal already
    prints its own step lines, so here it is a no-op."""
    if _frontend is not None and hasattr(_frontend, "stage"):
        _frontend.stage(stage_name, **info)


def choose(prompt: str, options: list, kind: str | None = None, details: list | None = None):
    """Pick one of `options` (display strings, each with an optional second line in
    `details`). Returns the index, or None to abort."""
    if _frontend is not None and hasattr(_frontend, "choose"):
        return _frontend.choose(prompt, options, kind=kind, details=details)
    for i, o in enumerate(options, 1):
        extra = details[i - 1] if details and details[i - 1] else ""
        step(f"  {i})  {o}" + (f"\n      {extra}" if extra else ""))
    while True:
        raw = ask(f"{prompt} (1-{len(options)}, blank to abort): ")
        if not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        err("invalid selection")
