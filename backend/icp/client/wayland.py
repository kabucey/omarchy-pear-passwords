"""Just enough of the Wayland wire protocol to own the clipboard selection.

pear-clip must hold a password in memory and hand it to exactly one reader, so it cannot use
wl-copy (wl-clipboard 2.3.0 stages its input in a /tmp file) and there is no Wayland binding
in the locked dependencies. The protocol it needs is small: wl_display, wl_registry, wl_seat
and one data-control manager, ext_data_control_v1 (preferred) or the older
zwlr_data_control_unstable_v1, which have identical request and event layouts.

Wire format, little-endian on every compositor this runs on (the wire is host byte order):
a message is `object id (u32) | size << 16 | opcode (u32) | arguments`, each argument padded to
4 bytes. Strings are a u32 length including the NUL, then the bytes. File descriptors travel
out of band as SCM_RIGHTS and are matched to `fd` arguments in arrival order.

Nothing here knows about passwords; clip.py decides what to write to which fd.
"""

from __future__ import annotations

import array
import os
import select
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass, field

DISPLAY_ID = 1
MAX_FDS_PER_MSG = 28

# Request opcodes, shared by ext_data_control_* and zwlr_data_control_*.
MANAGER_CREATE_DATA_SOURCE = 0
MANAGER_GET_DATA_DEVICE = 1
MANAGER_DESTROY = 2
DEVICE_SET_SELECTION = 0
DEVICE_DESTROY = 1
SOURCE_OFFER = 0
SOURCE_DESTROY = 1
OFFER_DESTROY = 1

# Event opcodes.
DISPLAY_ERROR = 0
DISPLAY_DELETE_ID = 1
REGISTRY_GLOBAL = 0
REGISTRY_GLOBAL_REMOVE = 1
CALLBACK_DONE = 0
DEVICE_DATA_OFFER = 0
DEVICE_SELECTION = 1
DEVICE_FINISHED = 2
DEVICE_PRIMARY_SELECTION = 3
SOURCE_SEND = 0
SOURCE_CANCELLED = 1

DATA_CONTROL_MANAGERS = ("ext_data_control_manager_v1", "zwlr_data_control_manager_v1")


class WaylandError(Exception):
    """The compositor went away, sent a protocol error, or lacks what we need."""


def _pad(n: int) -> int:
    return (n + 3) & ~3


def enc_uint(v: int) -> bytes:
    return struct.pack("=I", v & 0xFFFFFFFF)


def enc_string(s: str | None) -> bytes:
    if s is None:
        return enc_uint(0)
    raw = s.encode("utf-8") + b"\0"
    return enc_uint(len(raw)) + raw + b"\0" * (_pad(len(raw)) - len(raw))


class Reader:
    """Sequential decoder over one message's argument bytes."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def uint(self) -> int:
        if self.pos + 4 > len(self.data):
            raise WaylandError("truncated message")
        (v,) = struct.unpack_from("=I", self.data, self.pos)
        self.pos += 4
        return v

    def int(self) -> int:
        if self.pos + 4 > len(self.data):
            raise WaylandError("truncated message")
        (v,) = struct.unpack_from("=i", self.data, self.pos)
        self.pos += 4
        return v

    def string(self) -> str | None:
        n = self.uint()
        if n == 0:
            return None
        end = self.pos + _pad(n)
        if end > len(self.data) or self.data[self.pos + n - 1] != 0:
            raise WaylandError("malformed string")
        s = self.data[self.pos:self.pos + n - 1].decode("utf-8", "replace")
        self.pos = end
        return s


@dataclass
class Event:
    obj: int
    opcode: int
    args: bytes
    interface: str


@dataclass
class Global:
    name: int
    interface: str
    version: int


class Connection:
    """A client connection to one compositor socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._next_id = 2
        self.objects: dict[int, str] = {DISPLAY_ID: "wl_display"}
        self._inbuf = bytearray()
        self._fds: deque[int] = deque()
        self.peer_pid: int | None = None
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
            self.peer_pid = struct.unpack("3i", creds)[0]
        except OSError:
            pass

    @classmethod
    def connect(cls, path: str) -> "Connection":
        if not path.startswith("/"):
            raise WaylandError("WAYLAND_DISPLAY must be an absolute socket path")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            s.connect(path)
        except OSError as e:
            s.close()
            raise WaylandError(f"cannot connect to the compositor ({e.strerror})") from e
        return cls(s)

    def fileno(self) -> int:
        return self.sock.fileno()

    def close(self) -> None:
        while self._fds:
            os.close(self._fds.popleft())
        try:
            self.sock.close()
        except OSError:
            pass

    # --- requests -------------------------------------------------------------------------
    def new_id(self, interface: str) -> int:
        oid = self._next_id
        self._next_id += 1
        self.objects[oid] = interface
        return oid

    def request(self, obj: int, opcode: int, payload: bytes = b"") -> None:
        size = 8 + len(payload)
        msg = struct.pack("=II", obj, (size << 16) | opcode) + payload
        try:
            self.sock.sendall(msg)
        except OSError as e:
            raise WaylandError("the compositor closed the connection") from e

    def get_registry(self) -> int:
        reg = self.new_id("wl_registry")
        self.request(DISPLAY_ID, 1, enc_uint(reg))
        return reg

    def sync(self) -> int:
        cb = self.new_id("wl_callback")
        self.request(DISPLAY_ID, 0, enc_uint(cb))
        return cb

    def bind(self, registry: int, glob: Global, version: int) -> int:
        oid = self.new_id(glob.interface)
        self.request(registry, 0, enc_uint(glob.name) + enc_string(glob.interface)
                     + enc_uint(version) + enc_uint(oid))
        return oid

    # --- events ---------------------------------------------------------------------------
    def read_events(self, timeout: float | None) -> list[Event]:
        """Read what is available (waiting up to `timeout`) and decode whole messages.
        Raises WaylandError on EOF or a wl_display.error."""
        if timeout is not None:
            ready, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
            if not ready:
                return []
        fds = array.array("i")
        try:
            data, anc, _flags, _addr = self.sock.recvmsg(
                65536, socket.CMSG_SPACE(MAX_FDS_PER_MSG * fds.itemsize))
        except BlockingIOError:
            return []
        except OSError as e:
            raise WaylandError("the compositor closed the connection") from e
        for level, kind, cdata in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                usable = len(cdata) - (len(cdata) % fds.itemsize)
                fds.frombytes(cdata[:usable])
        for fd in fds:
            os.set_inheritable(fd, False)
            self._fds.append(fd)
        if not data:
            raise WaylandError("the compositor closed the connection")
        self._inbuf += data
        out = []
        while len(self._inbuf) >= 8:
            obj, word = struct.unpack_from("=II", self._inbuf, 0)
            size, opcode = word >> 16, word & 0xFFFF
            if size < 8:
                raise WaylandError("malformed message")
            if len(self._inbuf) < size:
                break
            args = bytes(self._inbuf[8:size])
            del self._inbuf[:size]
            iface = self.objects.get(obj, "")
            if obj == DISPLAY_ID and opcode == DISPLAY_ERROR:
                r = Reader(args)
                r.uint()
                code = r.uint()
                raise WaylandError(f"protocol error {code}: {r.string() or ''}")
            if obj == DISPLAY_ID and opcode == DISPLAY_DELETE_ID:
                self.objects.pop(Reader(args).uint(), None)
                continue
            out.append(Event(obj, opcode, args, iface))
        return out

    def take_fd(self) -> int:
        """The next out-of-band fd, for an event with an `fd` argument."""
        if not self._fds:
            raise WaylandError("expected a file descriptor that never arrived")
        return self._fds.popleft()

    def roundtrip(self, on_event, timeout: float = 5.0) -> None:
        """Send wl_display.sync and feed every event to `on_event` until it is done."""
        cb = self.sync()
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise WaylandError("the compositor did not answer")
            for ev in self.read_events(left):
                if ev.obj == cb and ev.opcode == CALLBACK_DONE:
                    self.objects.pop(cb, None)
                    return
                on_event(ev)


@dataclass
class Selection:
    """Our data-control objects once a selection has been set."""
    manager: int
    device: int
    source: int
    interface_prefix: str               # "ext_data_control" or "zwlr_data_control"
    offers: set = field(default_factory=set)


class DataControl:
    """Owns one data source on the seat's regular (never primary) selection."""

    def __init__(self, conn: Connection):
        self.conn = conn
        self.globals: list[Global] = []
        self.registry = conn.get_registry()
        conn.roundtrip(self._on_registry)

    def _on_registry(self, ev: Event) -> None:
        if ev.obj == self.registry and ev.opcode == REGISTRY_GLOBAL:
            r = Reader(ev.args)
            name, iface, version = r.uint(), r.string() or "", r.uint()
            self.globals.append(Global(name, iface, version))

    def find(self, interface: str) -> Global | None:
        for g in self.globals:
            if g.interface == interface:
                return g
        return None

    def offer(self, mimes: list[str]) -> Selection:
        """Create a source offering `mimes` and make it the selection."""
        seat = self.find("wl_seat")
        if seat is None:
            raise WaylandError("the compositor has no seat")
        mgr_glob = None
        for name in DATA_CONTROL_MANAGERS:
            mgr_glob = self.find(name)
            if mgr_glob is not None:
                break
        if mgr_glob is None:
            raise WaylandError("the compositor offers no data-control protocol")
        prefix = mgr_glob.interface.rsplit("_manager_v1", 1)[0]
        c = self.conn
        seat_id = c.bind(self.registry, seat, 1)
        manager = c.bind(self.registry, mgr_glob, 1)
        source = c.new_id(prefix + "_source_v1")
        c.request(manager, MANAGER_CREATE_DATA_SOURCE, enc_uint(source))
        for mime in mimes:
            c.request(source, SOURCE_OFFER, enc_string(mime))
        device = c.new_id(prefix + "_device_v1")
        c.request(manager, MANAGER_GET_DATA_DEVICE, enc_uint(device) + enc_uint(seat_id))
        c.request(device, DEVICE_SET_SELECTION, enc_uint(source))
        return Selection(manager, device, source, prefix)

    def handle_device_event(self, sel: Selection, ev: Event) -> bool:
        """Housekeeping for device and offer events. Returns False if the device finished
        (the seat went away), True otherwise."""
        c = self.conn
        if ev.obj == sel.device:
            if ev.opcode == DEVICE_DATA_OFFER:
                oid = Reader(ev.args).uint()
                c.objects[oid] = sel.interface_prefix + "_offer_v1"
                sel.offers.add(oid)
            elif ev.opcode in (DEVICE_SELECTION, DEVICE_PRIMARY_SELECTION):
                # We never read offers; release every one the compositor introduced.
                for oid in list(sel.offers):
                    c.request(oid, OFFER_DESTROY)
                    sel.offers.discard(oid)
            elif ev.opcode == DEVICE_FINISHED:
                return False
        return True

    def destroy_source(self, sel: Selection) -> None:
        """Withdraw the offer. The compositor clears the selection only if this source is
        still it; a newer selection someone else set is left alone. We never send
        set_selection(null), which would clear whatever is there."""
        self.conn.request(sel.source, SOURCE_DESTROY)
        self.conn.request(sel.device, DEVICE_DESTROY)
        self.conn.request(sel.manager, MANAGER_DESTROY)
