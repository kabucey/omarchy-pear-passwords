"""pear-clip: put one value on the Wayland clipboard for one paste, then take it away.

Started by the Pear window as `pear-exec clip`, with a ticket on stdin (never argv or the
environment). It redeems the ticket with the daemon for `{value, sensitive, timeout}` and owns
the regular selection through wayland.py. Spec section 4.6 and docs/protocol.md sections 7 and
10.1.

The rules, in the order a request meets them:

1. `x-kde-passwordManagerHint` (offered only for a sensitive value) is always served the word
   `secret`, which asks history managers not to keep the entry.
2. Every other request hands over a pipe. The process(es) at the other end are found in /proc,
   among this user's processes whose /proc/<pid>/fd can be read. Two kinds of reader are
   identified:
   - an ordinary process of this user that holds the pipe (wl-paste, a Wayland app, a
     Flatpak app in its own pid namespace);
   - the compositor itself (the peer of our Wayland socket, the process pear-exec verified)
     when it holds the pipe's READ end, by inode and by an O_RDONLY/O_RDWR access mode in
     /proc/<pid>/fdinfo/<fd>. That is the XWayland clipboard bridge: Hyprland's XWM runs in
     the compositor and reads the value for an X11 app. Which X11 app asked cannot be seen
     from here; the bridge counts as one reader. It only works where the compositor's /proc
     entries can be read: Hyprland as Omarchy runs it can; a compositor with file
     capabilities (Arch's sway has cap_sys_nice) cannot, and X11 pastes are then refused.
     The compositor holding only the WRITE end (it passes an ordinary Wayland paste on to us)
     is not a reader.
   If no reader is identified, the request is refused: the pipe is closed unwritten, it does
   not count, and the offer stays up. That covers a pipe nobody holds any more (a history
   watcher's child that exited without reading, faster than the scan), a compositor whose fds
   cannot be read, and a reader that cannot be inspected: a non-dumpable process, Pear's own
   window first of all. The window is set-gid and non-dumpable, and Qt Quick reads the
   clipboard text itself the moment the selection changes (every editable TextField re-checks
   "can paste"); counting that read took the one paste before the user pasted anything. So a
   copied secret cannot be pasted into a non-dumpable program, Pear's window included, and an
   unidentifiable reader gets nothing.
   - If every holder is a known clipboard-history watcher (watchers.py), the request is
     refused the same way and does not count.
3. Any other identified reader (a same-uid process, or the compositor's X11 bridge) gets the
   value and is the one paste - but only once the value was actually delivered: a write that
   hit EPIPE, or took no byte, is not a paste and the offer stays up for the real one. For
   CLIP_REREQUEST_GRACE_S afterwards the same set of holder processes may ask again (some
   toolkits read twice); nobody else gets anything. The X11 bridge never gets that second
   read: it is the same holder for every X11 app, so a re-read could hand the value to a
   different X11 client than the one the user pasted into. Then the source is destroyed.
4. With no paste by `timeout` seconds the source is destroyed. Destroying a source clears the
   clipboard only if it is still the selection: a copy you made since is never touched, and
   set_selection(null) is never sent.

Gate G5 decides rule 2. If the VM shows that /proc/<pid>/fd cannot be read from this set-gid
process, the release flips READER_POLICY to "timing" (spec section 1.4, proposal 2's fallback,
explicitly weaker): nobody is identified, so rule 2's refusal of unidentified readers cannot
apply (nothing could ever be pasted). Instead the requests in the first WATCHER_WINDOW_S after
the offer goes up are taken to be the history watcher and Pear's own window (both read the
moment the selection changes) and get nothing, and the first request after that is the paste,
whoever makes it - including the window re-reading when it gets focus back. A switch in this
root-owned file, not the environment, because pear-exec passes no environment through.

The outcome goes back to the daemon (`clip-result`), which tells the window. The window also
reads this process's stdout, one JSON line per event and never the value: `{"event": "offered"}`
once the compositor has answered a sync sent after set_selection (only then does the window say
"copied"), `{"event": "error", "reason": ...}` when it ends without ever offering, and last
`{"event": "done", "outcome": ...}`. The value lives in
a bytearray that is zeroed before exit; Python may have copied it on the way in (the JSON
reply), which is why the real boundary is that this process is non-dumpable.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import select
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

from ..daemon import protocol
from . import watchers
from .channel import Channel, ChannelError, stdin_line
from .wayland import (CALLBACK_DONE, DataControl, Connection, Event, Reader, Selection,
                      SOURCE_CANCELLED, SOURCE_SEND, WaylandError)

HINT_MIME = "x-kde-passwordManagerHint"
TEXT_MIMES = ("text/plain;charset=utf-8", "text/plain", "UTF8_STRING", "TEXT", "STRING")
TICKET_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
WRITE_DEADLINE_S = 2.0
OFFER_CONFIRM_S = 5.0               # how long the compositor may take to answer the offer

# Gate G5 switch: "proc" (identify every reader's pipe in /proc) or "timing" (the fallback).
READER_POLICY = "proc"
WATCHER_WINDOW_S = 0.25


# --- who holds the pipe (gate G5) ------------------------------------------------------------

@dataclass(frozen=True)
class Readers:
    pids: frozenset
    watchers: frozenset

    @property
    def only_watchers(self) -> bool:
        return bool(self.pids) and self.pids == self.watchers


def _set_fsgid(gid: int) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.setfsgid(ctypes.c_uint(gid))
    except (OSError, AttributeError):
        pass


def pipe_holders(fd: int, exclude: set, proc: str = "/proc") -> set:
    """Pids of our own uid's processes that hold the pipe behind `fd` (either end).
    A process whose /proc/<pid>/fd cannot be read (non-dumpable: its /proc entry is owned by
    root, or the listing is EACCES) is skipped, so a pipe only it holds has no holder here.

    /proc/<pid>/fd is checked against our fs credentials, and our fsgid is pear-client, which
    no user process has. For the scan only, the fsgid drops to our real gid, so the access
    check sees an ordinary process of this user (Yama limits attaching, not this read)."""
    st = os.fstat(fd)
    target = f"pipe:[{st.st_ino}]"
    uid = os.getuid()
    holders = set()
    egid = os.getegid()
    _set_fsgid(os.getgid())
    try:
        for name in os.listdir(proc):
            if not name.isdigit():
                continue
            pid = int(name)
            if pid in exclude:
                continue
            try:
                if os.stat(f"{proc}/{name}").st_uid != uid:
                    continue
                fds = os.listdir(f"{proc}/{name}/fd")
            except OSError:
                continue
            for f in fds:
                try:
                    if os.readlink(f"{proc}/{name}/fd/{f}") == target:
                        holders.add(pid)
                        break
                except OSError:
                    continue
    finally:
        _set_fsgid(egid)
    return holders


def holds_read_end(pid: int | None, fd: int, proc: str = "/proc") -> bool:
    """True if process `pid` (one of our uid's) has the read end of the pipe behind `fd` open:
    an fd that links to the pipe's inode and whose /proc/<pid>/fdinfo `flags` give an
    O_RDONLY or O_RDWR access mode. The write end (O_WRONLY), which a compositor holds for a
    moment while it forwards an ordinary Wayland paste to us, does not count. Anything that
    cannot be read (non-dumpable, gone, another uid) answers False."""
    if not pid or pid <= 0:
        return False
    target = f"pipe:[{os.fstat(fd).st_ino}]"
    egid = os.getegid()
    _set_fsgid(os.getgid())
    try:
        try:
            if os.stat(f"{proc}/{pid}").st_uid != os.getuid():
                return False
            fds = os.listdir(f"{proc}/{pid}/fd")
        except OSError:
            return False
        for f in fds:
            try:
                if os.readlink(f"{proc}/{pid}/fd/{f}") != target:
                    continue
                flags = None
                with open(f"{proc}/{pid}/fdinfo/{f}") as info:
                    for line in info:
                        if line.startswith("flags:"):
                            flags = int(line.split()[1], 8)
                            break
            except (OSError, ValueError, IndexError):
                continue
            if flags is not None and (flags & os.O_ACCMODE) in (os.O_RDONLY, os.O_RDWR):
                return True
        return False
    finally:
        _set_fsgid(egid)


def make_identifier(exclude: set, describe=watchers.describe_proc, compositor: int | None = None,
                    proc: str = "/proc") -> Callable[[int], Readers]:
    """The "proc" policy's identifier. `compositor` is the pid at the other end of our Wayland
    socket (the process pear-exec verified); it is in `exclude`, so it is never found by the
    general scan, but when it holds the pipe's read end itself it is the XWayland clipboard
    bridge (Hyprland's XWM, wlroots' xwm in sway) reading for an X11 app, and is a reader."""
    def identify(fd: int) -> Readers:
        # A holder that is already gone again says nothing about who reads: dropped, so a
        # vanished watcher child cannot make a watcher's request look like a paste.
        pids = {p for p in pipe_holders(fd, exclude, proc) if describe(p) is not None}
        if compositor and holds_read_end(compositor, fd, proc):
            pids.add(compositor)
        pids = frozenset(pids)
        found = frozenset(p for p in pids
                          if p != compositor and watchers.is_watcher(p, describe))
        return Readers(pids, found)
    return identify


def _reader_gone(fd: int) -> bool:
    """True once no read end of the pipe is open anywhere (POLLERR on the write end)."""
    p = select.poll()
    p.register(fd, select.POLLOUT)
    return any(ev & (select.POLLERR | select.POLLHUP) for _, ev in p.poll(0))


def identify_nobody(fd: int) -> Readers:
    """The timing fallback's identifier: every reader is unknown."""
    return Readers(frozenset(), frozenset())


def policy(name: str = None) -> tuple[Callable[[set], Callable[[int], Readers]], float]:
    """(identifier factory, watcher window) for READER_POLICY."""
    name = READER_POLICY if name is None else name
    if name == "proc":
        return make_identifier, 0.0
    if name == "timing":
        return (lambda exclude, compositor=None: identify_nobody), WATCHER_WINDOW_S
    raise ValueError(f"unknown reader policy {name!r}")


# --- the offer ----------------------------------------------------------------------------------

@dataclass
class Offer:
    """What has happened to one clipboard offer. Pure bookkeeping plus the fd writes, so the
    rules above can be tested against a fake compositor."""

    value: bytearray
    sensitive: bool
    timeout: float
    identify: Callable[[int], Readers]
    now: Callable[[], float] = time.monotonic
    grace: float = protocol.CLIP_REREQUEST_GRACE_S
    watcher_window: float = 0.0             # > 0 only under the G5 timing fallback
    bridge: int | None = None               # the compositor's pid: its XWayland bridge reads once
    started: float = 0.0
    pasted_at: float | None = None
    paste_holders: frozenset | None = None
    outcome: str | None = None              # set once the offer is over
    served: int = 0                         # writes of the value
    refused_watchers: int = 0
    refused_others: int = 0
    refused_unknown: int = 0                # live readers nobody could identify
    offered: bool = False                   # the compositor answered after set_selection
    error: str = ""                         # why it failed, for the window (never the value)
    log: list = field(default_factory=list)  # (mime, verdict) - never the value

    def mimes(self) -> list[str]:
        return list(TEXT_MIMES) + ([HINT_MIME] if self.sensitive else [])

    def start(self) -> None:
        self.started = self.now()

    def on_send(self, mime: str | None, fd: int) -> None:
        try:
            if mime == HINT_MIME and self.sensitive:
                _write_all(fd, b"secret")
                self.log.append((mime, "hint"))
                return
            if mime not in TEXT_MIMES or self.outcome is not None:
                self.log.append((mime, "refused"))
                return
            readers = self.identify(fd)
            if not readers.pids and self.watcher_window == 0.0:
                # Nobody seen: maybe a reader forked after the scan listed /proc. Look again.
                # Still nobody: either the pipe has no reader left, or its reader cannot be
                # inspected (non-dumpable, such as Pear's own window re-checking "can paste").
                # Neither gets a byte, and neither is the paste: the offer stays up.
                readers = self.identify(fd)
                if not readers.pids:
                    if _reader_gone(fd):
                        self.refused_watchers += 1
                        self.log.append((mime, "gone"))
                    else:
                        self.refused_unknown += 1
                        self.log.append((mime, "unidentified"))
                    return
            if self.pasted_at is not None:
                # Only the paste that already happened may ask again, and only briefly - never
                # the X11 bridge, which stands for whichever X11 app asks.
                if (readers.pids == self.paste_holders
                        and not (self.bridge and self.bridge in readers.pids)
                        and self.now() - self.pasted_at <= self.grace):
                    if _write_all(fd, self.value) > 0:
                        self.served += 1
                        self.log.append((mime, "re-served"))
                    else:
                        self.log.append((mime, "undelivered"))
                else:
                    self.refused_others += 1
                    self.log.append((mime, "refused"))
                return
            if readers.only_watchers or self.now() - self.started < self.watcher_window:
                self.refused_watchers += 1
                self.log.append((mime, "watcher"))
                return
            written = _write_all(fd, self.value)
            if written == 0:
                # The reader went away (EPIPE) or never read: not one byte left us.
                self.log.append((mime, "undelivered"))
                return
            # Any byte that reached the pipe is the paste, whole or not: otherwise a reader
            # that shrinks its pipe and stalls could take part of a long value again and again
            # without ever using up the copy.
            self.served += 1
            self.pasted_at = self.now()
            self.paste_holders = readers.pids
            self.log.append((mime, "pasted" if written == len(self.value) else "pasted-partly"))
        finally:
            os.close(fd)

    def on_cancelled(self) -> None:
        if self.outcome is None:
            self.outcome = "pasted" if self.pasted_at is not None else "replaced"

    def on_withdraw(self) -> None:
        if self.outcome is None:
            self.outcome = "pasted" if self.pasted_at is not None else "withdrawn"

    def tick(self) -> None:
        """Advance the clocks: end the offer after the paste grace or at the timeout."""
        if self.outcome is not None:
            return
        t = self.now()
        if self.pasted_at is not None:
            if t - self.pasted_at > self.grace:
                self.outcome = "pasted"
        elif t - self.started >= self.timeout:
            self.outcome = "expired"

    def next_wakeup(self) -> float:
        t = self.now()
        if self.pasted_at is not None:
            return max(0.0, self.pasted_at + self.grace - t) + 0.01
        return max(0.0, self.started + self.timeout - t) + 0.01

    def wipe(self) -> None:
        for i in range(len(self.value)):
            self.value[i] = 0


def _write_all(fd: int, data) -> int:
    """Write without ever blocking the loop for long: a reader that never reads loses.
    Returns how many bytes went into the pipe (0 = nothing left us)."""
    os.set_blocking(fd, False)
    view = memoryview(data)
    total = 0
    deadline = time.monotonic() + WRITE_DEADLINE_S
    try:
        while view:
            try:
                n = os.write(fd, view)
                if n <= 0:
                    return total
                total += n
                view = view[n:]
            except BlockingIOError:
                left = deadline - time.monotonic()
                if left <= 0:
                    return total
                select.select([], [fd], [], left)
            except OSError as e:
                if e.errno in (errno.EPIPE, errno.EBADF):
                    return total
                raise
        return total
    finally:
        view.release()


# --- the loop ---------------------------------------------------------------------------------

def serve(dc: DataControl, offer: Offer, daemon: Channel | None,
          on_offered: Callable[[], None] | None = None) -> str:
    """Own the selection until the offer is over. Returns the outcome. Never raises for a
    compositor failure: that is the outcome "failed". `on_offered` runs once the compositor
    has answered a sync sent after set_selection, i.e. the value really is on offer."""
    conn: Connection = dc.conn
    try:
        sel: Selection = dc.offer(offer.mimes())
    except WaylandError as e:
        offer.outcome = "failed"
        offer.error = str(e)
        return "failed"
    offer.start()
    daemon_gone = False
    try:
        # The compositor handles requests in order: its answer to this sync means it has taken
        # set_selection. Answered inside the loop, so a paste right behind it is not dropped.
        confirm = conn.sync()
        confirm_by = offer.now() + OFFER_CONFIRM_S
        while offer.outcome is None:
            waits = [conn.sock]
            if daemon is not None and not daemon_gone:
                waits.append(daemon)
            buffered = daemon is not None and not daemon_gone and daemon.has_pending()
            wake = offer.next_wakeup()
            if not offer.offered:
                wake = min(wake, max(0.0, confirm_by - offer.now()) + 0.01)
            ready, _, _ = select.select(waits, [], [], 0 if buffered else wake)
            if conn.sock in ready:
                for ev in conn.read_events(0):
                    if ev.obj == confirm and ev.opcode == CALLBACK_DONE:
                        conn.objects.pop(confirm, None)
                        if offer.outcome is None and not offer.offered:
                            offer.offered = True
                            if on_offered is not None:
                                on_offered()
                        continue
                    _dispatch(dc, sel, offer, ev)
            if not offer.offered and offer.outcome is None and offer.now() >= confirm_by:
                offer.outcome = "failed"
                offer.error = "the compositor did not answer"
                break
            if daemon is not None and not daemon_gone and (buffered or daemon in ready):
                try:
                    for msg in daemon.read_messages(0):
                        if msg.get("event") == "withdraw":
                            offer.on_withdraw()
                except ChannelError:
                    # The daemon is gone (lock, crash, UI closed): nobody may paste any more.
                    daemon_gone = True
                    offer.on_withdraw()
            offer.tick()
        # Also after `cancelled`: a cancelled source is dead and destroying it changes nothing.
        dc.destroy_source(sel)
        _flush(conn)
    except WaylandError as e:
        # The compositor went away, and the selection with it.
        offer.error = offer.error or str(e)
        if offer.outcome is None:
            offer.outcome = "pasted" if offer.pasted_at is not None else "failed"
    return offer.outcome or "failed"


def _dispatch(dc: DataControl, sel: Selection, offer: Offer, ev: Event) -> None:
    if ev.obj == sel.source:
        if ev.opcode == SOURCE_SEND:
            mime = Reader(ev.args).string()
            offer.on_send(mime, dc.conn.take_fd())
        elif ev.opcode == SOURCE_CANCELLED:
            offer.on_cancelled()
        return
    if not dc.handle_device_event(sel, ev):
        offer.outcome = offer.outcome or "failed"


def _flush(conn: Connection) -> None:
    # Let the compositor see the destroy before we disconnect; a roundtrip proves it did.
    try:
        conn.roundtrip(lambda ev: None, timeout=1.0)
    except WaylandError:
        pass


# --- entry point ---------------------------------------------------------------------------------

# Why a copy never reached the clipboard, as the window's "Couldn't copy — <reason>" says it.
NOT_OFFERED = {"replaced": "something else was copied first",
               "withdrawn": "it was taken back before the clipboard had it"}


def report(out, event: str, **fields) -> None:
    """One line for the window on stdout. Fixed words and outcomes only, never the value; a
    window that has gone away (EPIPE) changes nothing here."""
    if out is None:
        return
    try:
        out.write(json.dumps({"event": event, **fields}) + "\n")
        out.flush()
    except (OSError, ValueError):
        pass


def run(stdin, socket_path: str, wayland_path: str, identify=None, out=None) -> int:
    out = sys.stdout if out is None else out
    try:
        ticket = stdin_line(stdin, 256)
    except ValueError:
        ticket = None
    if not ticket or not TICKET_RE.match(ticket):
        print("pear-clip: no ticket on stdin", file=sys.stderr)
        report(out, "error", reason="no copy request reached the clipboard helper")
        return 2
    try:
        daemon = Channel.connect(socket_path)
        daemon.hello("clip", ticket)
        reply = daemon.request("redeem", timeout=10)
    except ChannelError as e:
        print(f"pear-clip: {e}", file=sys.stderr)
        report(out, "error", reason="the Pear Passwords service couldn't be reached")
        return 3
    if "error" in reply or not isinstance(reply.get("value"), str):
        print("pear-clip: the ticket could not be redeemed", file=sys.stderr)
        report(out, "error", reason="the copy request had expired")
        daemon.close()
        return 3
    value = bytearray(reply["value"].encode("utf-8"))
    sensitive = bool(reply.get("sensitive", True))
    timeout = reply.get("timeout", protocol.CLIP_TIMEOUT_S_DEFAULT)
    lo, hi = protocol.CLIP_TIMEOUT_S_RANGE
    if not isinstance(timeout, (int, float)) or not lo <= timeout <= hi:
        timeout = protocol.CLIP_TIMEOUT_S_DEFAULT
    reply.clear()
    del reply
    daemon.wipe()

    offer = None
    outcome = "failed"
    reason = "the clipboard couldn't be reached"
    try:
        try:
            conn = Connection.connect(wayland_path)
            dc = DataControl(conn)
        except WaylandError as e:
            print(f"pear-clip: {e}", file=sys.stderr)
        else:
            factory, window = policy()
            if identify is None:
                identify = factory({os.getpid(), conn.peer_pid or -1},
                                   compositor=conn.peer_pid)
            offer = Offer(value, sensitive, float(timeout), identify, watcher_window=window,
                          bridge=conn.peer_pid)
            outcome = serve(dc, offer, daemon, on_offered=lambda: report(out, "offered"))
            reason = (NOT_OFFERED.get(outcome) or offer.error
                      or "the compositor didn't take the clipboard")
            conn.close()
    finally:
        for i in range(len(value)):
            value[i] = 0
    if offer is None or not offer.offered:
        report(out, "error", reason=reason)
    try:
        daemon.request("clip-result", timeout=5, outcome=outcome)
    except ChannelError:
        pass
    daemon.close()
    report(out, "done", outcome=outcome)
    return 0


def main() -> int:
    from ..daemon import paths
    wayland = os.environ.get("WAYLAND_DISPLAY", "")
    if not wayland.startswith("/"):
        print("pear-clip: run through pear-exec", file=sys.stderr)
        return 2
    return run(sys.stdin, paths.SOCKET_PATH, wayland)


if __name__ == "__main__":
    raise SystemExit(main())
