"""Peer verification on accept (docs/protocol.md 2.1): SO_PEERCRED, SO_PEERPIDFD, /proc.

Uses a real socketpair, so SO_PEERCRED and the pidfd are the kernel's; the /proc files the
checks read are served from a scratch directory, because a test process cannot be set-gid.
"""

import os
import shutil
import socket
import tempfile
import unittest

from icp.daemon import peer

USER_GID = 31337


def _status(uid, rgid, egid, ppid=1):
    return (f"Name:\tquickshell\nPPid:\t{ppid}\n"
            f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            f"Gid:\t{rgid}\t{egid}\t{egid}\t{egid}\n")


class ParseTests(unittest.TestCase):
    def test_own_proc_files_parse(self):
        st = peer.parse_status(peer.read_proc(os.getpid(), "status"))
        self.assertEqual(st["Uid"][0], os.getuid())
        self.assertEqual(st["Gid"][1], os.getegid())
        self.assertEqual(st["PPid"], os.getppid())
        self.assertGreater(peer.parse_start_time(peer.read_proc(os.getpid(), "stat")), 0)

    def test_start_time_survives_hostile_comm(self):
        stat = "123 (a) b) (c) S " + " ".join(str(i) for i in range(4, 60))
        self.assertEqual(peer.parse_start_time(stat), 22)

    def test_truncated_status_is_refused(self):
        with self.assertRaises(peer.PeerError):
            peer.parse_status("Uid:\t1000\t1000\nGid:\t1\t2\t3\t4\nPPid:\t1\n")


class CheckStatusTests(unittest.TestCase):
    def check(self, text, uid=1000, user_gid=USER_GID, client_gid=966):
        peer.check_status(peer.parse_status(text), uid=uid, user_gid=user_gid,
                          client_gid=client_gid)

    def test_pear_exec_child_passes(self):
        self.check(_status(1000, USER_GID, 966))

    def test_effective_gid_must_be_pear_client(self):
        with self.assertRaises(peer.PeerError):
            self.check(_status(1000, USER_GID, USER_GID))

    def test_real_gid_must_be_the_users_own(self):
        with self.assertRaises(peer.PeerError):
            self.check(_status(1000, 966, 966))          # setgid() all the way, not set-gid exec
        with self.assertRaises(peer.PeerError):
            self.check(_status(1000, 5, 966))

    def test_uid_must_match_throughout(self):
        with self.assertRaises(peer.PeerError):
            self.check(_status(1001, USER_GID, 966))
        text = "PPid:\t1\nUid:\t1000\t0\t0\t0\nGid:\t31337\t966\t966\t966\n"
        with self.assertRaises(peer.PeerError):
            self.check(text)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.proc = tempfile.mkdtemp(prefix="pearproc-")
        self.pid = os.getpid()
        os.makedirs(os.path.join(self.proc, str(self.pid)))
        self.write("stat", open(f"/proc/{self.pid}/stat").read())
        self.client_gid = os.getegid()

    def tearDown(self):
        self.a.close()
        self.b.close()
        shutil.rmtree(self.proc)

    def write(self, name, text):
        with open(os.path.join(self.proc, str(self.pid), name), "w") as f:
            f.write(text)

    def verify(self, **kw):
        args = dict(client_gid=self.client_gid, user_gid_of=lambda uid: USER_GID,
                    proc=self.proc, min_uid=0)
        args.update(kw)
        return peer.verify(self.a, **args)

    def test_accepts_and_holds_a_live_pidfd(self):
        self.write("status", _status(os.getuid(), USER_GID, self.client_gid, ppid=77))
        info = self.verify()
        try:
            self.assertEqual((info.pid, info.uid, info.ppid), (self.pid, os.getuid(), 77))
            self.assertTrue(peer.alive(info.pidfd))
            self.assertEqual(info.start_time,
                             peer.parse_start_time(open(f"/proc/{self.pid}/stat").read()))
        finally:
            os.close(info.pidfd)

    def test_peercred_gid_is_checked(self):
        # /proc says pear-client, but the kernel's record of the connect() says otherwise.
        other = self.client_gid + 1
        self.write("status", _status(os.getuid(), USER_GID, other))
        with self.assertRaises(peer.PeerError):
            self.verify(client_gid=other)

    def test_proc_egid_is_checked(self):
        self.write("status", _status(os.getuid(), USER_GID, USER_GID))
        with self.assertRaises(peer.PeerError):
            self.verify()

    def test_system_uids_are_refused(self):
        self.write("status", _status(os.getuid(), USER_GID, self.client_gid))
        with self.assertRaises(peer.PeerError):
            self.verify(min_uid=os.getuid() + 1)

    def test_vanished_proc_entry_is_refused(self):
        with self.assertRaises(peer.PeerError):
            self.verify()                                 # no status file

    def test_recycled_pid_is_refused(self):
        self.write("status", _status(os.getuid(), USER_GID, self.client_gid))
        fake_self = tempfile.mkdtemp(prefix="pearself-")
        try:
            fdinfo = os.path.join(fake_self, "self", "fdinfo")
            os.makedirs(fdinfo)
            for fd in range(3, 1024):
                with open(os.path.join(fdinfo, str(fd)), "w") as f:
                    f.write("pos:\t0\nPid:\t1\n")
            with self.assertRaises(peer.PeerError):
                self.verify(self_proc=fake_self)
        finally:
            shutil.rmtree(fake_self)

    def test_pidfd_is_closed_on_refusal(self):
        self.write("status", _status(os.getuid(), USER_GID, USER_GID))
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(peer.PeerError):
            self.verify()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_unknown_uid_is_refused(self):
        self.write("status", _status(os.getuid(), USER_GID, self.client_gid))

        def missing(uid):
            raise KeyError(uid)
        with self.assertRaises(peer.PeerError):
            self.verify(user_gid_of=missing)

    def test_peer_of_another_uid_is_alive_despite_eperm(self):
        # Gate bug 1: every real client is another uid's process, and pidfd_send_signal(pidfd, 0)
        # from uid pear-passwords answers EPERM for it. That must not read as "exited".
        import signal as _signal
        from unittest import mock
        self.write("status", _status(os.getuid(), USER_GID, self.client_gid))

        def eperm(fd, sig, *a):
            raise PermissionError(1, "Operation not permitted")
        with mock.patch.object(_signal, "pidfd_send_signal", eperm):
            info = self.verify()
            try:
                self.assertTrue(peer.alive(info.pidfd))
            finally:
                os.close(info.pidfd)


class AliveTests(unittest.TestCase):
    def test_exited_process_is_not_alive(self):
        import subprocess
        child = subprocess.Popen(["/bin/sleep", "30"])
        fd = os.pidfd_open(child.pid)
        try:
            self.assertTrue(peer.alive(fd))
            child.kill()
            child.wait()
            self.assertFalse(peer.alive(fd))
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
