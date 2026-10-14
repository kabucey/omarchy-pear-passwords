#!/usr/bin/python3
"""Scan a QR code off the screen for a verification-code setup, for the Pear window.

Started by the window as `/usr/bin/python3 -I $P/app/qr_scan.py` (installed root-owned with
the window, like touch_watch.py) only when "Scan QR code" is pressed. You drag over the code
(slurp); just that area is captured (grim) into an anonymous memory file - never a file on
disk - and read by zbarimg. Fixed paths, no shell.

One JSON line goes to stdout, and nothing else is printed:
  {"ok": true, "text": "<what the code holds>"}
  {"ok": false, "reason": "cancelled" | "no-code" | "failed"}
The text is the setup key itself (usually an otpauth:// link), so it goes only to the window,
which puts it in the field you would otherwise paste it into.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

SLURP = "/usr/bin/slurp"
GRIM = "/usr/bin/grim"
ZBARIMG = "/usr/bin/zbarimg"
SELECT_TIMEOUT_S = 120             # time to drag over the code
TOOL_TIMEOUT_S = 30
MAX_PNG = 64 * 1024 * 1024
MAX_TEXT = 4096
ZBAR_NO_SYMBOLS = 4                # zbarimg's exit status when it found no code
GEOMETRY = re.compile(r"-?\d{1,6},-?\d{1,6} \d{1,6}x\d{1,6}")
ENV_KEYS = ("WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PATH", "HOME", "LANG")


def pick(lines) -> str:
    """The otpauth:// link if the area held one, else the first code found."""
    found = [line.strip() for line in lines if line.strip()]
    for line in found:
        if line.lower().startswith("otpauth://"):
            return line
    return found[0] if found else ""


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def scan(run=subprocess.run) -> dict:
    env = {k: v for k, v in os.environ.items() if k in ENV_KEYS}
    # stdin is /dev/null for every tool: slurp reads a list of preset boxes from stdin when it
    # is not a terminal, and the window's pipe never closes, so it waited for ever, overlay unshown.
    try:
        sel = run([SLURP], capture_output=True, stdin=subprocess.DEVNULL,
                  timeout=SELECT_TIMEOUT_S, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "reason": "failed"}
    if sel.returncode != 0:
        return {"ok": False, "reason": "cancelled"}
    geometry = sel.stdout.decode("ascii", "replace").strip()
    if not GEOMETRY.fullmatch(geometry):
        return {"ok": False, "reason": "failed"}
    try:
        shot = run([GRIM, "-g", geometry, "-"], capture_output=True, stdin=subprocess.DEVNULL,
                   timeout=TOOL_TIMEOUT_S, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "reason": "failed"}
    if shot.returncode != 0 or not shot.stdout or len(shot.stdout) > MAX_PNG:
        return {"ok": False, "reason": "failed"}
    # The capture can show the very key being set up: it lives in memory only, and zbarimg
    # reads it through the inherited descriptor.
    fd = os.memfd_create("pear-qr", os.MFD_CLOEXEC)
    try:
        _write_all(fd, shot.stdout)
        os.lseek(fd, 0, os.SEEK_SET)
        res = run([ZBARIMG, "--raw", "-q", f"/proc/self/fd/{fd}"], capture_output=True,
                  stdin=subprocess.DEVNULL, timeout=TOOL_TIMEOUT_S, env=env, pass_fds=(fd,))
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "reason": "failed"}
    finally:
        os.close(fd)
    if res.returncode == ZBAR_NO_SYMBOLS:
        return {"ok": False, "reason": "no-code"}
    if res.returncode != 0:
        return {"ok": False, "reason": "failed"}
    text = pick(res.stdout.decode("utf-8", "replace").splitlines())
    if not text or len(text) > MAX_TEXT or any(ord(c) < 32 for c in text):
        return {"ok": False, "reason": "no-code"}
    return {"ok": True, "text": text}


def main() -> int:
    sys.stdout.write(json.dumps(scan()) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
