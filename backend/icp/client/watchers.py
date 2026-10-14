"""Who is reading the clipboard: known clipboard-history watchers, told apart from a paste.

A Wayland clipboard has no idea who asks for its contents; the compositor just hands the offer
a pipe. pear-clip finds out by looking for the other end of that pipe in /proc (spec gate G5)
and then asks this module whether every process holding it is a history watcher. Those get
nothing and do not count as the one paste; any other identified reader does. A reader that
cannot be found at all (gone, or non-dumpable like Pear's own window) also gets nothing and
does not count; that rule lives in clip.py.

Two kinds are known. wl-paste watchers, matched on the whole command line:

  wl-paste [--type T] --watch /usr/share/omarchy/shell/plugins/clipboard/capture.sh ...
      Omarchy's clipboard history (its text and image watchers), started by the shell
  wl-paste [--type T] --watch cliphist store
      the usual cliphist setup
  wl-paste [--type T] --watch clipman store [--option ...]
      clipman

and programs that read every new clipboard entry themselves (CLIPBOARD_READERS, matched on
the program name): clipboard histories (fcitx5's clipboard addon - it read a live Pear copy on
the owner's XPS within 50 ms and took the one paste - CopyQ, clipse, GPaste, Walker's
elephant, ...), wl-clip-persist (it keeps a copy after the source is gone, which would undo
the clearing), and clipboard sync (KDE Connect, Barrier/Input Leap/Synergy), which would carry
the value to another device the moment it is copied. None of them is where a person pastes.

Every process descended from one of those counts too (capture.sh runs `wl-paste --list-types`
and perl with the pipe as stdin). Pretending to be a watcher only gets the pretender nothing,
so matching generously here can cost a paste, never a password.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterable

OMARCHY_CAPTURE = "/usr/share/omarchy/shell/plugins/clipboard/capture.sh"
# Programs that read the clipboard on every change, never as the place a person pastes into.
CLIPBOARD_READERS = frozenset({
    # clipboard histories
    "fcitx5", "copyq", "clipse", "gpaste-daemon", "elephant", "klipper", "diodon",
    "parcellite", "clipit", "greenclip", "xfce4-clipman", "clipcatd", "cliphist", "clipman",
    # clipboard keepers (a copy outlives its source, undoing the clear)
    "wl-clip-persist",
    # clipboard sync to other devices
    "kdeconnectd", "barrier", "barriers", "input-leap", "input-leaps", "synergy-core",
    "synergys",
})
MAX_ANCESTRY = 4                  # wl-paste -> capture.sh -> $(...) subshell -> perl


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    ppid: int
    argv: tuple[str, ...]


def is_watcher_argv(argv: Iterable[str]) -> bool:
    """True for the command line of a known clipboard-history watcher itself."""
    argv = list(argv)
    if argv and os.path.basename(argv[0]) in CLIPBOARD_READERS:
        return True
    if not argv or os.path.basename(argv[0]) != "wl-paste":
        return False
    for flag in ("--watch", "-w"):
        if flag in argv:
            i = argv.index(flag)
            break
    else:
        return False
    # Only a --type choice may come before --watch: a watcher of the primary selection or
    # with other options is not one of ours.
    opts = argv[1:i]
    while opts:
        if opts[0] in ("--type", "-t") and len(opts) >= 2:
            opts = opts[2:]
        elif opts[0].startswith("--type="):
            opts = opts[1:]
        else:
            return False
    cmd = argv[i + 1:]
    if cmd[:1] == [OMARCHY_CAPTURE]:
        return True
    if len(cmd) == 2 and os.path.basename(cmd[0]) == "cliphist" and cmd[1] == "store":
        return True
    if (len(cmd) >= 2 and os.path.basename(cmd[0]) == "clipman" and cmd[1] == "store"
            and all(a.startswith("--") for a in cmd[2:])):
        return True
    return False


def is_watcher(pid: int, describe: Callable[[int], ProcInfo | None]) -> bool:
    """True if `pid` is a watcher or descends from one within MAX_ANCESTRY hops."""
    seen = set()
    for _ in range(MAX_ANCESTRY + 1):
        if pid <= 1 or pid in seen:
            return False
        seen.add(pid)
        info = describe(pid)
        if info is None:
            return False
        if is_watcher_argv(info.argv):
            return True
        pid = info.ppid
    return False


def describe_proc(pid: int, proc: str = "/proc") -> ProcInfo | None:
    """Command line and parent of a live process, or None if it is gone or unreadable.
    Both files are world-readable even for non-dumpable processes."""
    try:
        with open(f"{proc}/{pid}/cmdline", "rb") as f:
            raw = f.read(64 * 1024)
        with open(f"{proc}/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
            status = f.read(16 * 1024)
    except OSError:
        return None
    ppid = 0
    for line in status.splitlines():
        if line.startswith("PPid:"):
            try:
                ppid = int(line.split()[1])
            except (IndexError, ValueError):
                ppid = 0
            break
    argv = tuple(a.decode("utf-8", "replace") for a in raw.split(b"\0") if a != b"")
    return ProcInfo(pid, ppid, argv)
