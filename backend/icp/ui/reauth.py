"""Presence check before opening the keychain viewer.

Opens Omarchy's polkit overlay (the fingerprint card) via org.icp.unlock.
`pkcheck` is not used: it cannot pass ALWAYS_CHECK, so a logged-in session can
come back authorized without the overlay ever appearing.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess

POLICY_PATH = "/usr/share/polkit-1/actions/org.icp.unlock.policy"
GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "polkit_gate.py")
# Do not let an inherited environment variable choose the interpreter that decides whether the
# user authenticated.  The gate needs the distro's system Python for its gi/Polkit bindings.
SYSTEM_PYTHON = "/usr/bin/python3"
PKEXEC_PATH = "/usr/bin/pkexec"
TRUE_PATH = "/usr/bin/true"

# pkexec is setuid-root on a normal installation. Keep only the desktop-session values needed by
# the authentication agent. An allowlist is intentional: a blacklist grows stale whenever a
# runtime adds another code-loading or interpreter hook.
_PKEXEC_SAFE_PATH = "/usr/bin:/bin"
_AUTH_ENV_ALLOWLIST = frozenset({
    "DBUS_SESSION_BUS_ADDRESS",
    "DESKTOP_SESSION",
    "DISPLAY",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_TIME",
    "TERM",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_CLASS",
    "XDG_SESSION_DESKTOP",
    "XDG_SESSION_ID",
    "XDG_SESSION_TYPE",
})


def _trusted_system_executable(path: str, *, require_setuid: bool = False) -> bool:
    """Whether *path* is a root-owned, non-writable executable we may invoke.

    The paths used by the authentication fallbacks are fixed below, but checking their metadata
    keeps a damaged or locally replaced installation from turning the fallback into an invocation
    of an untrusted file. ``stat`` follows a distribution's harmless symlink (if any) and checks
    the file it would actually execute.
    """
    try:
        info = os.stat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        and bool(info.st_mode & stat.S_IXUSR)
        and (not require_setuid or bool(info.st_mode & stat.S_ISUID))
        and os.access(path, os.X_OK)
    )


def policy_installed() -> bool:
    return os.path.exists(POLICY_PATH)


def available() -> bool:
    return (
        policy_installed()
        and os.path.isfile(GATE)
        and _trusted_system_executable(SYSTEM_PYTHON)
    )


# The child in flight, so a SIGTERM to the caller can take the prompt down with it. Without
# this, retrying a stuck unlock left the first dialog on screen beside the second.
_current = None


def _run(argv, timeout, *, env=None):
    """(returncode or None, stderr text). None means it never finished - spawn failure or
    timeout - which callers treat as the gate having broken."""
    global _current
    try:
        kwargs = {
            "start_new_session": True,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.PIPE,
        }
        if env is not None:
            kwargs["env"] = env
        _current = subprocess.Popen(argv, **kwargs)
    except OSError as e:
        return None, str(e)
    try:
        _, err = _current.communicate(timeout=timeout)
        return _current.returncode, (err or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        kill_current()
        return None, "timed out"
    finally:
        _current = None


def kill_current() -> None:
    p = _current
    if p is None or p.poll() is not None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except OSError:
        pass


def challenge_status(timeout: int = 120) -> str:
    """'authed', 'denied' or 'error'.

    The whole point is telling "a person said no" apart from "the gate broke": the first must
    be respected, the second is a malfunction to route around. See polkit_gate.py's exit codes.
    """
    if not available():
        return "error"
    # ``-I`` also disables user-site and PYTHON* import configuration, so a user-owned module
    # cannot turn a genuine gate failure into a fabricated successful exit status.
    rc, _ = _run([SYSTEM_PYTHON, "-I", GATE], timeout, env=_auth_environment())
    if rc == 0:
        return "authed"
    if rc == 1:
        return "denied"
    return "error"


def challenge(timeout: int = 120) -> bool:
    """True if the user authenticated. False if they cancelled, failed, or it is unavailable."""
    return challenge_status(timeout) == "authed"


def _auth_environment() -> dict[str, str]:
    """Build the small environment needed to find the desktop authentication agent."""
    env = {name: os.environ[name] for name in _AUTH_ENV_ALLOWLIST if name in os.environ}
    env["PATH"] = _PKEXEC_SAFE_PATH
    return env


def _pkexec_environment() -> dict[str, str]:
    """Preserve only desktop-session variables; never pass arbitrary inherited environment."""
    return _auth_environment()


def pkexec_challenge(timeout: int = 90) -> str:
    """Last resort for when the polkit gate itself is broken: authenticate through pkexec,
    which raises the same desktop agent via the stock exec action on the fixed system `true`.

    Weaker than the gate, and only acceptable because it runs when the gate cannot: that
    action is auth_admin_keep, so polkit may skip the prompt within a few minutes of a previous
    success, where the gate's ALWAYS_CHECK never does. pkexec exits 126 when the dialog is
    dismissed and 127 for both a refused password and "no agent", told apart by stderr.
    """
    if not (
        _trusted_system_executable(PKEXEC_PATH, require_setuid=True)
        and _trusted_system_executable(TRUE_PATH)
    ):
        return "error"
    rc, err = _run([PKEXEC_PATH, TRUE_PATH], timeout, env=_pkexec_environment())
    if rc == 0:
        return "authed"
    if rc == 126:
        return "denied"
    if rc == 127 and "agent" not in err.lower():
        return "denied"
    return "error"


def install_hint() -> str:
    return ("Optional: allow unlocking with your system password (and, once the fingerprint\n"
            "reader works, a fingerprint) instead of retyping the passphrase:\n\n"
            f"    pkexec install -m 0644 {os.path.expanduser('~/icp/polkit/org.icp.unlock.policy')} \\\n"
            f"        {POLICY_PATH}\n")
