"""Who is on the other end of an accepted connection, checked before a single byte is read.

The socket is 0660 pear-passwords:pear-client and the group has no members, so the kernel
already refuses anyone whose effective gid is not pear-client. These checks are the second
layer (docs/protocol.md 2.1): they read the kernel's own record of the peer and refuse a
connection the filesystem should never have let through.

1. SO_PEERCRED: the peer's gid at connect() is pear-client and its uid is a normal user.
2. SO_PEERPIDFD (77): a pidfd for exactly that process, held for the life of the connection.
   It is the polkit subject, so a recycled pid can never be asked about.
3. /proc/<pid>/status: real gid is the user's own, effective gid is pear-client (the set-gid
   exec of pear-exec and nothing else produces that pair), and real = effective uid.
   /proc/<pid>/stat gives the start time for PPid binding and the polkit fallback subject.
   Last, the pidfd is polled: a pidfd turns readable when its process exits, so a pidfd that
   is not readable proves the pid read from /proc was still that process. (Not a signal 0:
   the peer is another uid's process, and signalling it from uid pear-passwords is EPERM.)

Nothing here trusts a value the client sent; a client sends nothing until all of it passed.
"""

from __future__ import annotations

import os
import pwd
import select
import socket
import struct
from dataclasses import dataclass
from typing import Callable

from . import paths

SO_PEERPIDFD = 77                      # not exported by Python's socket module
_UCRED = struct.Struct("3i")           # pid, uid, gid


class PeerError(Exception):
    """The peer failed a check. The message is for the journal only, never for the client."""


@dataclass
class PeerInfo:
    pid: int
    uid: int
    gid: int                           # effective gid at connect(): pear-client
    pidfd: int
    start_time: int                    # /proc/<pid>/stat field 22, clock ticks since boot
    ppid: int


def peercred(sock) -> tuple[int, int, int]:
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    return _UCRED.unpack(raw)


def peer_pidfd(sock) -> int:
    raw = sock.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)
    fd = struct.unpack("i", raw)[0]
    if fd < 0:
        raise PeerError("no pidfd for the peer")
    return fd


def parse_status(text: str) -> dict:
    """The three lines of /proc/<pid>/status the checks need: Uid and Gid as four ints
    (real, effective, saved, filesystem) and PPid."""
    out = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in ("Uid", "Gid"):
            out[key] = [int(v) for v in value.split()]
        elif key == "PPid":
            out[key] = int(value.strip())
    if len(out.get("Uid", ())) != 4 or len(out.get("Gid", ())) != 4 or "PPid" not in out:
        raise PeerError("unreadable /proc status")
    return out


def parse_start_time(stat: str) -> int:
    """Field 22 (starttime) of /proc/<pid>/stat. The command name in field 2 can hold spaces
    and parentheses, so fields are counted from the last ')'."""
    rest = stat[stat.rindex(")") + 2:].split()
    # rest[0] is field 3 (state), so field 22 is rest[19]
    return int(rest[19])


def check_status(status: dict, *, uid: int, user_gid: int, client_gid: int) -> None:
    """Raise PeerError unless the process is exactly what pear-exec produces: running as
    `uid` throughout, real gid the user's own, effective gid pear-client."""
    ruid, euid = status["Uid"][0], status["Uid"][1]
    rgid, egid = status["Gid"][0], status["Gid"][1]
    if ruid != uid or euid != uid:
        raise PeerError(f"uid mismatch (real {ruid}, effective {euid}, peer {uid})")
    if egid != client_gid:
        raise PeerError(f"effective gid {egid} is not {paths.CLIENT_GROUP}")
    if rgid == client_gid or rgid != user_gid:
        raise PeerError(f"real gid {rgid} is not the user's own ({user_gid})")


def read_proc(pid: int, name: str, proc: str = "/proc") -> str:
    with open(f"{proc}/{int(pid)}/{name}", encoding="utf-8", errors="replace") as f:
        return f.read()


def start_time_of(pid: int, proc: str = "/proc") -> int | None:
    """The start time of a live pid, or None if it is gone."""
    try:
        return parse_start_time(read_proc(pid, "stat", proc))
    except (OSError, ValueError, IndexError):
        return None


def _pidfd_pid(pidfd: int, self_proc: str = "/proc") -> int | None:
    """The pid a pidfd refers to, from /proc/self/fdinfo (-1 once it has exited)."""
    try:
        with open(f"{self_proc}/self/fdinfo/{pidfd}", encoding="ascii") as f:
            for line in f:
                if line.startswith("Pid:"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def verify(sock, *, client_gid: int,
           user_gid_of: Callable[[int], int] = lambda uid: pwd.getpwuid(uid).pw_gid,
           proc: str = "/proc", self_proc: str = "/proc",
           min_uid: int = paths.MIN_CLIENT_UID) -> PeerInfo:
    """Run every check on an accepted socket. Returns PeerInfo owning a pidfd the caller must
    close, or raises PeerError (and closes the pidfd itself)."""
    try:
        pid, uid, gid = peercred(sock)
    except OSError as e:
        raise PeerError(f"SO_PEERCRED: {e}") from None
    if gid != client_gid:
        raise PeerError(f"peer gid {gid} is not {paths.CLIENT_GROUP}")
    if uid < min_uid:
        raise PeerError(f"peer uid {uid} is below {min_uid}")
    if pid <= 0:
        raise PeerError("peer has no pid")
    try:
        pidfd = peer_pidfd(sock)
    except OSError as e:
        raise PeerError(f"SO_PEERPIDFD: {e}") from None
    try:
        try:
            user_gid = user_gid_of(uid)
        except KeyError:
            raise PeerError(f"uid {uid} has no passwd entry") from None
        try:
            status = parse_status(read_proc(pid, "status", proc))
            start_time = parse_start_time(read_proc(pid, "stat", proc))
        except (OSError, ValueError, IndexError) as e:
            raise PeerError(f"/proc/{pid}: {e}") from None
        check_status(status, uid=uid, user_gid=user_gid, client_gid=client_gid)
        # The pidfd still names the process SO_PEERCRED saw; if the pid now reads differently,
        # or the process is gone, what /proc said may have been about a recycled pid.
        fd_pid = _pidfd_pid(pidfd, self_proc)
        if fd_pid is not None and fd_pid != pid:
            raise PeerError("pidfd no longer refers to the peer")
        if not alive(pidfd):
            raise PeerError("peer exited during checks")
        return PeerInfo(pid=pid, uid=uid, gid=gid, pidfd=pidfd, start_time=start_time,
                        ppid=status["PPid"])
    except BaseException:
        os.close(pidfd)
        raise


def alive(pidfd: int) -> bool:
    """True while the process behind the pidfd has not exited.

    A pidfd polls readable once its process exits. Signal 0 is not used: every peer runs as
    another uid, so pidfd_send_signal() answers EPERM for a live process, and only ESRCH
    means gone."""
    try:
        p = select.poll()
        p.register(pidfd, select.POLLIN)
        events = p.poll(0)
    except (OSError, ValueError):
        return False
    for _, ev in events:
        if ev & (select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL):
            return False
    return True
