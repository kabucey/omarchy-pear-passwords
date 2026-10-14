"""Every system path, name and polkit action id Pear Passwords 2 uses, in one place.

The installer (system/install-root.sh), pear-exec (native/pear-exec.c) and the daemon must agree
on all of these. The shell side reads system/paths.env; this module is the Python side, and
backend/tests/test_paths_agree.py fails if the two ever differ. pear-exec.c hard-codes its
values and is checked against paths.env by the clients' test.

Nothing here touches the filesystem. Per-user paths in $HOME (browser manifests, the v1 vault)
are deliberately not here: they belong to the code that runs as that user.
"""

from __future__ import annotations

# --- installed tree ($P) -------------------------------------------------------------------
# Root-owned, not writable by the user. Written as $P in the spec.
PREFIX = "/usr/local/lib/pear-passwords"

VENV = f"{PREFIX}/venv"
VENV_PYTHON = f"{VENV}/bin/python"
APP_DIR = f"{PREFIX}/app"
LIBEXEC = f"{PREFIX}/libexec"
PEAR_EXEC = f"{LIBEXEC}/pear-exec"                      # root:pear-client 2755
DAEMON_WRAPPER = f"{LIBEXEC}/pear-passwordsd"           # ABI check, then the daemon
AUTOFILL_HOST = f"{LIBEXEC}/pear-autofill-host"         # native-messaging entry: pear-exec autofill
UNINSTALL_ROOT = f"{LIBEXEC}/uninstall-root"
FONTS_CONF = f"{PREFIX}/etc/fonts.conf"
EMPTY_DIR = f"{PREFIX}/empty"                           # root 0555, the redirected XDG homes

# The opt-in autofill registration command. It runs as the user (not set-gid) and only writes
# that user's own browser manifest, so it lives on PATH rather than in libexec.
AUTOFILL_REGISTER_BIN = "/usr/local/bin/pear-passwords-autofill"

# Exit status of DAEMON_WRAPPER when the venv was built for another Python minor version.
ABI_MISMATCH_EXIT = 78

# --- what pear-exec runs, per role -----------------------------------------------------------
# A fixed argv per role; pear-exec takes no other argument. Every path here and every parent
# directory must be root-owned and not group/other writable, or pear-exec refuses.
ROLE_TARGETS: dict[str, tuple[str, ...]] = {
    "ui": ("/usr/bin/quickshell", "-p", APP_DIR),
    "clip": (VENV_PYTHON, "-I", "-m", "icp.client.clip"),
    "migrate": (VENV_PYTHON, "-I", "-m", "icp.client.migrate"),
    "autofill": (VENV_PYTHON, "-I", "-m", "icp.client.autofill"),
}
ROLES = tuple(ROLE_TARGETS)

# --- runtime socket --------------------------------------------------------------------------
RUNTIME_DIR = "/run/pear-passwords"                     # DirectoryMode=0755
SOCKET_PATH = f"{RUNTIME_DIR}/client.sock"              # pear-passwords:pear-client 0660

# --- state -----------------------------------------------------------------------------------
STATE_DIR = "/var/lib/pear-passwords"                   # 0700 pear-passwords
INSTALL_STATE_DIR = "/var/lib/pear-passwords-install"
INSTALL_RECEIPT = f"{INSTALL_STATE_DIR}/receipt.sha256"  # root 0600

# Systemd's host key; named so docs and diagnostics agree on what to exclude from backups.
HOST_CREDENTIAL_SECRET = "/var/lib/systemd/credential.secret"
TPM_DEVICE = "/dev/tpmrm0"
TPM_SRK_PUBLIC_KEY = "/run/systemd/tpm2-srk-public-key.pem"


def user_dir(uid: int) -> str:
    """Per-user state directory, 0700 pear-passwords. The uid is an int, never a string from
    a client, so a path can never be smuggled in."""
    return f"{STATE_DIR}/u{_uid(uid)}"


def user_tmp_dir(uid: int) -> str:
    """Where a migration is built before it is verified and renamed into user_dir()."""
    return f"{STATE_DIR}/u{_uid(uid)}.tmp"


def credential_name(tier: str, uid: int) -> str:
    """The --name= a sealed key is bound to: pear.list.u<uid> or pear.secret.u<uid>."""
    if tier not in ("list", "secret"):
        raise ValueError(f"unknown key tier {tier!r}")
    return f"pear.{tier}.u{_uid(uid)}"


def _uid(uid: int) -> int:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise ValueError(f"bad uid {uid!r}")
    return uid


# --- identities ------------------------------------------------------------------------------
SERVICE_USER = "pear-passwords"
SERVICE_GROUP = "pear-passwords"
CLIENT_GROUP = "pear-client"                            # must have no members
MIN_CLIENT_UID = 1000

# --- systemd and other system files ----------------------------------------------------------
UNIT_DIR = "/etc/systemd/system"
SOCKET_UNIT = "pear-passwordsd.socket"
SERVICE_UNIT = "pear-passwordsd.service"
# Gate G1 fallback: root's system-scope sealing for the daemon (icp.vstore.seal_service).
SEAL_SOCKET_UNIT = "pear-passwords-seal.socket"
SEAL_SERVICE_UNIT = "pear-passwords-seal@.service"
SEAL_SOCKET_PATH = "/run/pear-passwords-seal/seal.sock"     # root:pear-passwords 0660
SYSUSERS_CONF = "/etc/sysusers.d/pear-passwords.conf"
TMPFILES_CONF = "/etc/tmpfiles.d/pear-passwords.conf"

APP_ID = "io.github.dragosol.PearPasswords"
DESKTOP_FILE = f"/usr/local/share/applications/{APP_ID}.desktop"
WINDOW_TITLE = "Pear Passwords"

# --- polkit ----------------------------------------------------------------------------------
POLKIT_ACTION_PREFIX = "io.github.dragosol.pearpasswords"
ACTION_UNLOCK = f"{POLKIT_ACTION_PREFIX}.unlock"        # tier 1: the account list
ACTION_REVEAL = f"{POLKIT_ACTION_PREFIX}.reveal"        # tier 2: one account, grant_s seconds
ACTION_MANAGE = f"{POLKIT_ACTION_PREFIX}.manage"        # sign-in, create, delete, migrate, ...
ACTION_AUTOFILL = f"{POLKIT_ACTION_PREFIX}.autofill"    # one browser fill, every time
ACTION_AUTOFILL_NAMES = f"{POLKIT_ACTION_PREFIX}.autofill-names"  # one site's account names
ACTIONS = (ACTION_UNLOCK, ACTION_REVEAL, ACTION_MANAGE, ACTION_AUTOFILL, ACTION_AUTOFILL_NAMES)

POLICY_FILE = f"/usr/share/polkit-1/actions/{POLKIT_ACTION_PREFIX}.policy"
LEGACY_POLICY_FILE = "/usr/share/polkit-1/actions/org.icp.unlock.policy"

# --- browser autofill (bring your own extension) -------------------------------------------
# The native-messaging host name an extension calls. Its manifest is only ever written by the
# opt-in `pear-passwords-autofill register` command, never by an installer.
NATIVE_HOST_NAME = "io.github.dragosol.pearpasswords"
NATIVE_HOST_MANIFEST = f"{NATIVE_HOST_NAME}.json"
# The 1.x host the migration retires (content-matched manifests only; ~/icp is never touched).
LEGACY_NATIVE_HOST_MANIFEST = "org.icp.native.json"
