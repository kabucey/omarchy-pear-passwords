"""app/qr_scan.py: scan a QR code off the screen for a verification-code setup.

1.3.2 had "Scan QR code"; 2.0 dropped it with the window's process allowlist and the owner
asked for it back. The helper runs slurp, grim and zbarimg with fixed paths and no shell,
keeps the capture in memory only, and prints one JSON line.
"""

import importlib.util
import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "..", "..", "app", "qr_scan.py")
spec = importlib.util.spec_from_file_location("qr_scan", PATH)
qr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qr)

OTP = "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example"


def fake(slurp=(0, b"10,20 300x300\n"), grim=(0, b"\x89PNG fake"), zbar=(0, OTP.encode())):
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        rc, out = {qr.SLURP: slurp, qr.GRIM: grim, qr.ZBARIMG: zbar}[argv[0]]
        if argv[0] == qr.ZBARIMG:
            fd = kw["pass_fds"][0]
            # the capture reaches zbarimg through the memory file, at offset 0
            assert os.read(fd, 16) == b"\x89PNG fake", "zbarimg must read the capture"
        return subprocess.CompletedProcess(argv, rc, out, b"")
    return run, calls


class ScanTests(unittest.TestCase):
    def test_a_code_comes_back_and_nothing_touches_disk(self):
        run, calls = fake()
        self.assertEqual(qr.scan(run), {"ok": True, "text": OTP})
        argv = [c[0] for c in calls]
        self.assertEqual(argv[0], [qr.SLURP])
        self.assertEqual(argv[1], [qr.GRIM, "-g", "10,20 300x300", "-"])
        self.assertEqual(argv[2][:3], [qr.ZBARIMG, "--raw", "-q"])
        self.assertTrue(argv[2][3].startswith("/proc/self/fd/"))
        for a, _ in calls:
            self.assertTrue(all(isinstance(x, str) for x in a))
            self.assertNotIn("/tmp", " ".join(a))
        self.assertTrue(all(c[1].get("env") is not None for c in calls))
        # slurp reads preset boxes from a non-terminal stdin before it shows anything; the
        # window's pipe never closes, so without /dev/null it waited for ever (seen live).
        self.assertTrue(all(c[1].get("stdin") is subprocess.DEVNULL for c in calls))

    def test_cancelled_selection(self):
        run, calls = fake(slurp=(1, b""))
        self.assertEqual(qr.scan(run), {"ok": False, "reason": "cancelled"})
        self.assertEqual(len(calls), 1)

    def test_no_code_in_the_area(self):
        run, _ = fake(zbar=(qr.ZBAR_NO_SYMBOLS, b""))
        self.assertEqual(qr.scan(run), {"ok": False, "reason": "no-code"})

    def test_odd_geometry_is_refused_before_capture(self):
        run, calls = fake(slurp=(0, b"10,20 300x300; rm -rf ~\n"))
        self.assertEqual(qr.scan(run), {"ok": False, "reason": "failed"})
        self.assertEqual(len(calls), 1)

    def test_an_otpauth_link_wins_over_other_codes(self):
        self.assertEqual(qr.pick(["https://example.com", OTP, "other"]), OTP)
        self.assertEqual(qr.pick(["", "JBSWY3DPEHPK3PXP"]), "JBSWY3DPEHPK3PXP")
        self.assertEqual(qr.pick([]), "")

    def test_control_characters_or_huge_text_are_not_a_code(self):
        run, _ = fake(zbar=(0, b"abc\x07def"))
        self.assertEqual(qr.scan(run)["reason"], "no-code")
        run, _ = fake(zbar=(0, b"A" * (qr.MAX_TEXT + 1)))
        self.assertEqual(qr.scan(run)["reason"], "no-code")

    def test_fixed_paths(self):
        self.assertEqual((qr.SLURP, qr.GRIM, qr.ZBARIMG),
                         ("/usr/bin/slurp", "/usr/bin/grim", "/usr/bin/zbarimg"))


if __name__ == "__main__":
    unittest.main()
