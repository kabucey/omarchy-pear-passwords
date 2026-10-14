"""Development and diagnostic commands (`python -m icp ...`).

In 2.0 nothing here signs in, syncs or reads a password: the iCloud session, the keychain and
every key live in pear-passwordsd under its own uid, and the Pear window is the only way to
them. What is left are the commands that need no key at all - checking the anisette server,
trying the password generator, and previewing a verification-code setup - so a developer can
exercise those pieces without the daemon.
"""

import argparse
import json
import logging
import sys

from . import ui


def cmd_anisette(args) -> int:
    """Ask the anisette server for machine data and report which headers came back. Prints the
    header names only: the values identify this machine to Apple."""
    from ..auth.anisette import Anisette, AnisetteError
    a = Anisette(args.anisette)
    try:
        headers = a.headers()
    except AnisetteError as e:
        ui.err(str(e))
        return 1
    ui.out(f"anisette at {a.url}: ok ({', '.join(sorted(headers))})")
    return 0


def cmd_generate(args) -> int:
    """A new password in Apple's shape, with its entropy. Nothing is stored."""
    from ..vault import generate as gen
    json.dump({"password": gen.generate(), "entropy_bits": round(gen.entropy_bits(), 1)},
              sys.stdout)
    sys.stdout.write("\n")
    return 0


def cmd_totp_preview(args) -> int:
    """What a setup key or otpauth:// link (one line on stdin) would produce. Reads nothing
    from any store and saves nothing."""
    from .. import totp
    try:
        cfg = totp.parse_setup(sys.stdin.readline().rstrip("\r\n"))
    except totp.SetupError as e:
        ui.err(str(e))
        return 1
    json.dump({"code": totp.code(cfg["secret"], digits=cfg["digits"], period=cfg["period"],
                                 algorithm=cfg["algorithm"]),
               "seconds": totp.seconds_remaining(cfg["period"]),
               "issuer": cfg.get("issuer", ""), "account": cfg.get("accountName", "")},
              sys.stdout)
    sys.stdout.write("\n")
    return 0


def build_parser():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(
        prog="icp",
        description="Pear Passwords development tools. Signing in, syncing and every password "
                    "go through the Pear Passwords window and its system service.")
    p.add_argument("--anisette",
                   help="anisette server URL (default: $ICP_ANISETTE_URL or localhost:6969)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("anisette", help="check the anisette server answers"
                   ).set_defaults(func=cmd_anisette)
    sub.add_parser("generate", help="print a new password in Apple's shape"
                   ).set_defaults(func=cmd_generate)
    sub.add_parser("totp-preview", help="preview a verification-code setup read from stdin"
                   ).set_defaults(func=cmd_totp_preview)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ui.err("aborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
