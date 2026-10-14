"""pear-passwordsd: `python -I -m icp.daemon`, started by systemd through the socket.

Startup refuses to serve if the pear-client group has members (anyone in it could connect
without pear-exec) or if systemd did not hand over the listening socket. Then: the server on
fd 3, logind lock triggers, the scheduler, READY=1, a watchdog ping, and an exit after
DAEMON_IDLE_EXIT_S with no connection and no unlocked uid (the socket starts it again). SIGTERM
and any exit path lock every uid first.
"""

from __future__ import annotations

import asyncio
import ctypes
import grp
import logging
import os
import resource
import signal
import socket
import sys

from . import paths, protocol

logger = logging.getLogger("pear-passwordsd")

SD_LISTEN_FDS_START = 3
PR_SET_DUMPABLE = 4


def sd_notify(state: str) -> bool:
    """Tell systemd something (READY=1, WATCHDOG=1, STOPPING=1). No-op outside systemd."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as s:
            s.sendto(state.encode("ascii"), addr)
        return True
    except OSError:
        return False


def listen_socket(env=None) -> socket.socket | None:
    """The socket systemd passed (LISTEN_FDS for this pid), or None."""
    env = os.environ if env is None else env
    try:
        if int(env.get("LISTEN_PID", "0")) != os.getpid() or int(env.get("LISTEN_FDS", "0")) < 1:
            return None
    except ValueError:
        return None
    sock = socket.socket(fileno=SD_LISTEN_FDS_START)
    if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
        raise SystemExit("fd 3 is not a unix stream socket")
    sock.setblocking(False)
    return sock


def client_group_gid(getgrnam=grp.getgrnam) -> int:
    """pear-client's gid. Refuses to run if the group has members: membership would let a
    process connect without going through pear-exec."""
    try:
        g = getgrnam(paths.CLIENT_GROUP)
    except KeyError:
        raise SystemExit(f"group {paths.CLIENT_GROUP} does not exist; run the system step")
    if g.gr_mem:
        raise SystemExit(f"group {paths.CLIENT_GROUP} has members ({', '.join(g.gr_mem)}); "
                         "it must have none")
    return g.gr_gid


def _harden_process() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    os.umask(0o077)


def _watchdog_interval() -> float | None:
    try:
        usec = int(os.environ.get("WATCHDOG_USEC", "0"))
    except ValueError:
        return None
    if usec <= 0 or os.environ.get("WATCHDOG_PID", str(os.getpid())) != str(os.getpid()):
        return None
    return usec / 2e6


async def serve(sock: socket.socket, client_gid: int) -> None:
    from . import handlers, peer
    from .logind import LogindWatcher
    from .scheduler import Scheduler
    from .server import Server
    from .sessions import Registry

    loop = asyncio.get_running_loop()
    registry = Registry()
    server = Server(registry, verify_peer=lambda s: peer.verify(s, client_gid=client_gid))
    srv = await server.start(sock)
    stop = asyncio.Event()

    def call_in_loop(fn, timeout: float = 10.0) -> None:
        async def run():
            fn()
        asyncio.run_coroutine_threadsafe(run(), loop).result(timeout=timeout)

    watcher = LogindWatcher(on_lock=registry.lock,
                            on_sleep=lambda: registry.lock_all("sleep"),
                            call_in_loop=call_in_loop,
                            pending=registry.wipes_pending)
    await asyncio.to_thread(watcher.start)

    scheduler = Scheduler(registry, lambda uid: handlers.background_sync(registry, uid))
    tasks = [loop.create_task(scheduler.run())]

    interval = _watchdog_interval()
    if interval:
        async def watchdog():
            while True:
                sd_notify("WATCHDOG=1")
                await asyncio.sleep(interval)
        tasks.append(loop.create_task(watchdog()))

    async def idle_exit():
        idle_since = loop.time()
        while not stop.is_set():
            await asyncio.sleep(5)
            if registry.active():
                idle_since = loop.time()
            elif loop.time() - idle_since >= protocol.DAEMON_IDLE_EXIT_S:
                logger.info("idle for %ds, exiting", protocol.DAEMON_IDLE_EXIT_S)
                stop.set()
    tasks.append(loop.create_task(idle_exit()))

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    sd_notify("READY=1")
    logger.info("serving (polkit subject: %s)", os.environ.get("PEAR_POLKIT_SUBJECT",
                                                              "pidfd"))
    try:
        await stop.wait()
    finally:
        sd_notify("STOPPING=1")
        registry.lock_all("error")
        srv.close()
        for t in tasks:
            t.cancel()
        watcher.stop()
        registry.shutdown()


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")
    _harden_process()
    client_gid = client_group_gid()
    sock = listen_socket()
    if sock is None:
        logger.error("no socket from systemd; start pear-passwordsd.socket instead")
        return 1
    asyncio.run(serve(sock, client_gid))
    return 0


if __name__ == "__main__":
    sys.exit(main())
