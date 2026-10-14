"""Sealing the two key blobs to this machine, and telling the ways an unseal fails apart.

Primary path (spec section 6, gate G1): the daemon, as uid `pear-passwords`, runs

    systemd-creds --user encrypt --name=pear.<tier>.u<uid> - -

with the secret on a pipe, never in argv or a file. `--user` binds the blob to the daemon's
uid, so even another root-less process that got hold of the file cannot decrypt it.

What the key type is, and what it must never be. In uid scope systemd-creds cannot read
/var/lib/systemd/credential.secret itself, so it hands the request to the
io.systemd.Credentials varlink service - and that request has no field for PCRs or a public
key, and systemd 261 also drops --with-key on the way (checked: an explicit withKey sent
straight over varlink even turns a user-scope request into a system-scope blob that uid
scope then refuses with "Scope mismatch"). So the service always picks `auto`: the host key
today, host+TPM2 once a TPM2 is usable, with no PCRs. The one thing auto would add on its own
is a signed PCR-11 policy, when a tpm2-pcr-public-key.pem exists (a UKI setup) - and a blob
bound to it refuses to open after a boot that cannot present a matching signature (a Limine
fallback, another kernel). So:

- with a TPM present and such a PEM installed, nothing is sealed (SealUnavailable, with the
  reason): no store is created and no re-seal happens until the PEM is gone or the root seal
  service is selected (docs/security.md, G1);
- after sealing, the credential header's key type is read back (`key_type`), and that - not
  a probe - is what keys.json records. It is an allowlist: the scoped host type, and the
  scoped host+TPM2 type of systemd 261 and of 262, each confirmed by a real encryption on the
  gate VM. Every other type (unscoped, null, TPM-only, public-key-bound, or one a later
  systemd introduces) is refused with SealRefused, which the window explains.

Fallback (if G1 fails in the hardened unit): a root oneshot does system-scope sealing for the
daemon over a socket (`SealServiceBackend`), where the flags do apply: it runs
`--with-key=host` or `--with-key=host+tpm2` explicitly, `--tpm2-pcrs=` and an empty
`--tpm2-public-key=`. It is selected with PEAR_SEAL_BACKEND=seal-service in the unit's
environment, which only root can set; everything above it is unchanged, so the UX states stay
the same.

A failed decrypt is told apart from a failed mechanism: only when the tool demonstrably
works (a throwaway value still round-trips) is a non-zero exit a refusal of this blob
(UnsealRefused, which becomes a seal state). A tool that cannot reach its service, a busy or
locked-out TPM, ENOMEM: SealUnavailable, transient, never a seal state.

Sealing is lazy: nothing here runs at daemon start, only at unlock, so a missing or replaced
TPM shows up as a state in the app instead of a service that will not start.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
from typing import Protocol

from ..daemon import paths as system_paths
from . import StoreError

SYSTEMD_CREDS = "/usr/bin/systemd-creds"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
TPM_SYSFS = "/sys/class/tpm/tpm0"
TIMEOUT_S = 60                       # a TPM2 operation through the varlink service can be slow

# The G1 fallback service. Only consulted when PEAR_SEAL_BACKEND=seal-service.
SEAL_SERVICE_SOCKET = system_paths.SEAL_SOCKET_PATH
BACKEND_ENV = "PEAR_SEAL_BACKEND"
BACKEND_USER_CREDS = "user-creds"
BACKEND_SEAL_SERVICE = "seal-service"

# A signed PCR policy systemd-creds would pick up on its own (systemd-creds(1), --tpm2-public-key).
PCR_PUBLIC_KEY_PATHS = ("/etc/systemd/tpm2-pcr-public-key.pem",
                        "/run/systemd/tpm2-pcr-public-key.pem",
                        "/usr/local/lib/systemd/tpm2-pcr-public-key.pem",
                        "/usr/lib/systemd/tpm2-pcr-public-key.pem")

# Credential key types: the sd_id128 at the start of a credential. Every value below was
# read from a real `systemd-creds encrypt` on the gate VM (Arch, OVMF, swtpm), under systemd
# 261.2 and 262, with and without a TPM and with a tpm2-pcr-public-key.pem in place
# (docs/security.md section 8). systemd 262 added *_PINNED_SRK variants of the TPM2 types,
# and its auto mode always picks those when a TPM is used (creds-util.c, v262); the older
# TPM2 ids still exist and still decrypt, and the host-only ids did not change. The "_262"
# names below are those pinned-SRK types. ONLY the types in the two ALLOWED tables are ever
# accepted: anything else - a type a future systemd introduces, an unscoped, TPM-only, null
# or public-key-bound one - is refused (SealRefused), never guessed at.
CRED_BY_HOST = bytes.fromhex("5a1c6a86df9d4096b1d5a65e0862f19a")          # system, 261 + 262
CRED_BY_HOST_SCOPED = bytes.fromhex("55b9ed1d38594d43a8319d2ebb332ac6")   # uid, 261 + 262
CRED_BY_HOST_AND_TPM2 = bytes.fromhex("93a894094874449090caf2fc93cab553")  # system, 261
CRED_BY_HOST_AND_TPM2_262 = bytes.fromhex("1414258818a240cd900bce862db5c7b9")  # system, 262
CRED_BY_HOST_SCOPED_AND_TPM2 = bytes.fromhex("ef4ac13679a9480ea7db68897f9f165d")  # uid, 261
CRED_BY_HOST_SCOPED_AND_TPM2_262 = bytes.fromhex("2a1f877a4275431ab3f9ed1f5d8f6601")  # uid, 262
CRED_BY_TPM2 = bytes.fromhex("0c7cc07b117645919c4b0bea08bc20fe")          # no host key, 261
CRED_BY_TPM2_262 = bytes.fromhex("d4062dfb71ad4c86804b40ef1180f1fc")      # no host key, 262
CRED_BY_NULL = bytes.fromhex("058469daf6f54324800549da0f8ea2fb")          # no encryption
# Bound to a signed PCR policy (a tpm2-pcr-public-key.pem): refused, and said so by name.
CRED_BY_TPM2_WITH_PK = bytes.fromhex("faf7eb9341e3412ca1a436f95a29362f")             # 261
CRED_BY_TPM2_WITH_PK_262 = bytes.fromhex("5e2d5c7603724eaf843c6fb5f64098f5")         # 262
CRED_BY_HOST_AND_TPM2_WITH_PK = bytes.fromhex("af4950a849134eb1a73846304ff30c05")    # 261
CRED_BY_HOST_AND_TPM2_WITH_PK_262 = bytes.fromhex("afbfeaaceb6a4a3795419d135c47f37b")  # 262
CRED_BY_HOST_SCOPED_AND_TPM2_WITH_PK = bytes.fromhex("adbc4ca3efb64201ba881b6f2e4095ea")  # 261
CRED_BY_HOST_SCOPED_AND_TPM2_WITH_PK_262 = bytes.fromhex(
    "16e492949f94400286758f94b7c52bc7")                                             # 262

# The allowlists. uid scope (SystemdCredsBackend), and system scope (the seal service).
USER_ALLOWED = {CRED_BY_HOST_SCOPED: "host",
                CRED_BY_HOST_SCOPED_AND_TPM2: "host+tpm2",
                CRED_BY_HOST_SCOPED_AND_TPM2_262: "host+tpm2"}
SYSTEM_ALLOWED = {CRED_BY_HOST: "host",
                  CRED_BY_HOST_AND_TPM2: "host+tpm2",
                  CRED_BY_HOST_AND_TPM2_262: "host+tpm2"}
PK_BOUND = frozenset({CRED_BY_TPM2_WITH_PK, CRED_BY_TPM2_WITH_PK_262,
                      CRED_BY_HOST_AND_TPM2_WITH_PK, CRED_BY_HOST_AND_TPM2_WITH_PK_262,
                      CRED_BY_HOST_SCOPED_AND_TPM2_WITH_PK,
                      CRED_BY_HOST_SCOPED_AND_TPM2_WITH_PK_262})

# stderr of a mechanism failure, not a refusal of the blob (lowercase).
_TRANSIENT = ("failed to connect to io.systemd.credentials", "varlink", "connection refused",
              "connection reset", "transport endpoint", "timed out", "timer expired",
              "resource temporarily unavailable", "cannot allocate memory", "try again",
              "dictionarylockout", "dictionary lockout", "rc_retry", "rc_yielded",
              "rc_testing", "device or resource busy", "too many")

# A child gets nothing of the daemon's environment: no locale tricks, no LD_*, no PATH search.
_CHILD_ENV = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "SYSTEMD_LOG_LEVEL": "warning"}


class SealUnavailable(StoreError):
    """The sealing mechanism itself could not run (binary missing, timeout, service down).
    Transient: it says nothing about the blobs, so it never becomes a seal state."""


class SealRefused(SealUnavailable):
    """systemd-creds ran and sealed, but to something Pear does not accept: `reason` is
    "pcr-policy" (bound to a signed PCR policy, because a tpm2-pcr-public-key.pem exists) or
    "key-type" (any key type not in the allowlist). Nothing is kept. Not a seal state, and not
    transient either: it repeats until the machine changes, so the window says what it is."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason


def allowed_key_type(blob: bytes, allowed: dict) -> str:
    """"host" or "host+tpm2" for a credential whose key type is in `allowed`; SealRefused
    for every other type, named when it is a public-key-bound one."""
    h = credential_header(blob)
    kind = allowed.get(h) if len(h) == 16 else None
    if kind is not None:
        return kind
    if h in PK_BOUND:
        raise SealRefused("pcr-policy", f"systemd-creds bound the credential to a signed PCR "
                                        f"policy (key type {h.hex()}); refused")
    raise SealRefused("key-type", f"credential key type {h.hex() or 'none'} is not one Pear "
                                  "accepts; refused")


class UnsealRefused(Exception):
    """The mechanism ran and refused this blob: wrong key, missing TPM, wrong name, corrupt.
    `classify()` turns it into a SealError kind."""


class SealBackend(Protocol):
    def encrypt(self, name: str, plaintext: bytes) -> bytes: ...
    def decrypt(self, name: str, blob: bytes) -> bytes: ...
    def key_type(self, blob: bytes) -> str: ...        # "host" | "host+tpm2", or SealUnavailable
    def tpm_present(self) -> bool: ...
    def srk_fingerprint(self) -> str | None: ...


# --- platform probes (shared by both backends) ----------------------------------------------

def tpm_present() -> bool:
    """A usable TPM2: `systemd-analyze has-tpm2` exits 0 (firmware, driver, subsystem and
    libraries all present) and the kernel has a TPM device.

    The device check accepts sysfs as well as /dev/tpmrm0 because the daemon runs with
    PrivateDevices=yes and never sees /dev/tpm*; it does not need to, since the TPM work is
    done by systemd's own credentials service."""
    if not (os.path.exists(system_paths.TPM_DEVICE) or os.path.isdir(TPM_SYSFS)):
        return False
    try:
        r = subprocess.run([SYSTEMD_ANALYZE, "has-tpm2", "-q"], env=_CHILD_ENV,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def pcr_public_key_present() -> str | None:
    """The tpm2-pcr-public-key.pem systemd-creds would bind a blob to on its own, if any."""
    for p in PCR_PUBLIC_KEY_PATHS:
        if os.path.exists(p):
            return p
    return None


def tpm_sealing_blocked(backend) -> str | None:
    """"pcr-policy" when sealing through this backend with the TPM would bind the keys to a
    signed PCR policy (uid scope with a tpm2-pcr-public-key.pem), else None. The seal service
    passes an empty --tpm2-public-key=, so it is never blocked."""
    if isinstance(backend, SystemdCredsBackend) and pcr_public_key_present():
        return "pcr-policy"
    return None


def credential_header(blob: bytes) -> bytes:
    """The 16-byte key type id at the start of a credential (base64 text or raw)."""
    data = bytes(blob or b"")
    try:
        raw = base64.b64decode(b"".join(data.split()), validate=True)
    except (ValueError, TypeError):
        raw = data
    return raw[:16]


def srk_fingerprint() -> str | None:
    """SHA-256 of the TPM's storage root key (systemd-tpm2-setup's PEM), hex. None without
    one. Recorded at sealing time so "the TPM was cleared" can be told apart from "the TPM
    is switched off"."""
    try:
        with open(system_paths.TPM_SRK_PUBLIC_KEY, "rb") as f:
            pem = f.read(16384)
    except OSError:
        return None
    body = b"".join(line.strip() for line in pem.splitlines()
                    if line.strip() and not line.startswith(b"-----"))
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError:
        return None
    return hashlib.sha256(der).hexdigest() if der else None


# --- primary: systemd-creds --user -----------------------------------------------------------

class SystemdCredsBackend:
    """`systemd-creds --user` as the daemon's own uid (gate G1)."""

    CANARY_NAME = "pear.canary"

    def encrypt_argv(self, name: str) -> list[str]:
        # No --with-key / --tpm2-* flags: in uid scope they never reach the service (module
        # docstring); what the blob is bound to is checked afterwards with key_type().
        return [SYSTEMD_CREDS, "--user", "encrypt", f"--name={name}", "-", "-"]

    def decrypt_argv(self, name: str) -> list[str]:
        return [SYSTEMD_CREDS, "--user", "decrypt", f"--name={name}", "-", "-"]

    def _run(self, argv: list[str], data: bytes) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(argv, input=bytes(data), env=_CHILD_ENV,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=TIMEOUT_S, check=False)
        except FileNotFoundError:
            raise SealUnavailable(f"{argv[0]} is not installed") from None
        except subprocess.TimeoutExpired:
            raise SealUnavailable("systemd-creds timed out") from None
        except OSError as e:
            raise SealUnavailable(f"systemd-creds could not run ({e.strerror})") from None

    def encrypt(self, name: str, plaintext: bytes) -> bytes:
        if self.tpm_present():
            pem = pcr_public_key_present()
            if pem:
                raise SealRefused(
                    "pcr-policy",
                    f"{pem} exists: systemd-creds would bind the keys to a signed PCR policy, "
                    "and a boot without a matching signature could never open them")
        r = self._run(self.encrypt_argv(name), plaintext)
        if r.returncode != 0 or not r.stdout:
            # Sealing failing is never a statement about existing blobs.
            raise SealUnavailable(f"systemd-creds encrypt failed ({_why(r.stderr)})")
        self.key_type(r.stdout)                  # refuses a blob bound to the wrong thing
        return r.stdout

    def key_type(self, blob: bytes) -> str:
        """What a uid-scope blob is bound to, from its header: "host" or "host+tpm2", from
        USER_ALLOWED only. Anything else raises SealRefused."""
        return allowed_key_type(blob, USER_ALLOWED)

    def decrypt(self, name: str, blob: bytes) -> bytes:
        r = self._run(self.decrypt_argv(name), blob)
        if r.returncode < 0:
            raise SealUnavailable(f"systemd-creds killed by signal {-r.returncode}")
        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", "replace").lower()
            if any(m in err for m in _TRANSIENT):
                raise SealUnavailable(f"systemd-creds decrypt could not run ({_why(r.stderr)})")
            if not self._works():
                raise SealUnavailable(f"systemd-creds is not working ({_why(r.stderr)})")
            raise UnsealRefused(_why(r.stderr))
        return r.stdout

    def _works(self) -> bool:
        """Round-trip a throwaway value. If that fails too, the mechanism is down and the
        failed decrypt says nothing about the blob."""
        canary = os.urandom(16)
        try:
            e = self._run(self.encrypt_argv(self.CANARY_NAME), canary)
            if e.returncode != 0 or not e.stdout:
                return False
            d = self._run(self.decrypt_argv(self.CANARY_NAME), e.stdout)
        except SealUnavailable:
            return False
        return d.returncode == 0 and d.stdout == canary

    def tpm_present(self) -> bool:
        return tpm_present()

    def srk_fingerprint(self) -> str | None:
        return srk_fingerprint()


# --- fallback: root seal service (G1 fails) --------------------------------------------------

class SealServiceBackend:
    """Talks to the root `pear-passwords-seal` socket service, which runs system-scope
    `systemd-creds encrypt|decrypt --with-key=auto --tpm2-pcrs= --tpm2-public-key=` for the
    daemon. One request per connection, one JSON line each way:

        {"op":"encrypt"|"decrypt","name":"pear.list.u1000","b64":"..."}
        {"b64":"..."}  |  {"error":"refused"|"bad-request"|"internal","detail":"..."}

    The service accepts only SO_PEERCRED uid `pear-passwords` and names matching
    pear.(list|secret).u<digits>; it holds nothing between requests. An encrypt carries
    "with": "host" | "host+tpm2", which the service passes as an explicit --with-key (system
    scope runs locally, so the flags apply there)."""

    def __init__(self, path: str = SEAL_SERVICE_SOCKET):
        self.path = path

    def _call(self, op: str, name: str, data: bytes, with_key: str | None = None) -> bytes:
        body = {"op": op, "name": name, "b64": base64.b64encode(bytes(data)).decode()}
        if with_key is not None:
            body["with"] = with_key
        req = json.dumps(body).encode() + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as s:
                s.settimeout(TIMEOUT_S)
                s.connect(self.path)
                s.sendall(req)
                s.shutdown(socket.SHUT_WR)
                buf = bytearray()
                while len(buf) < 1 << 20:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise SealUnavailable(f"seal service unreachable ({e.strerror or e})") from None
        try:
            reply = json.loads(bytes(buf).split(b"\n", 1)[0])
        except ValueError:
            raise SealUnavailable("seal service sent garbage") from None
        if not isinstance(reply, dict):
            raise SealUnavailable("seal service sent garbage")
        if "b64" in reply:
            try:
                return base64.b64decode(reply["b64"], validate=True)
            except (TypeError, ValueError):
                raise SealUnavailable("seal service sent garbage") from None
        if reply.get("error") == "refused" and op == "decrypt":
            raise UnsealRefused(str(reply.get("detail", ""))[:200])
        raise SealUnavailable(f"seal service error {reply.get('error')!r}")

    def encrypt(self, name: str, plaintext: bytes) -> bytes:
        want = "host+tpm2" if self.tpm_present() else "host"
        blob = self._call("encrypt", name, plaintext, want)
        if self.key_type(blob) != want:
            raise SealUnavailable("the seal service sealed with another key than asked")
        return blob

    def decrypt(self, name: str, blob: bytes) -> bytes:
        return self._call("decrypt", name, blob)

    def key_type(self, blob: bytes) -> str:
        """What a system-scope blob is bound to, from its header, from SYSTEM_ALLOWED only.
        Anything else raises SealRefused."""
        return allowed_key_type(blob, SYSTEM_ALLOWED)

    def tpm_present(self) -> bool:
        return tpm_present()

    def srk_fingerprint(self) -> str | None:
        return srk_fingerprint()


# --- selection -------------------------------------------------------------------------------

_backend: SealBackend | None = None


def get_backend() -> SealBackend:
    global _backend
    if _backend is None:
        choice = os.environ.get(BACKEND_ENV, BACKEND_USER_CREDS)
        if choice == BACKEND_SEAL_SERVICE:
            _backend = SealServiceBackend()
        elif choice == BACKEND_USER_CREDS:
            _backend = SystemdCredsBackend()
        else:
            raise StoreError(f"{BACKEND_ENV}={choice!r} is not a seal backend")
    return _backend


def set_backend(backend: SealBackend | None) -> None:
    """Replace the backend (tests use a fake; None goes back to the environment's choice)."""
    global _backend
    _backend = backend


# --- what a failed unseal means --------------------------------------------------------------

def classify(backend: SealBackend, sealed_with: str | None, recorded_srk: str | None) -> str:
    """The seal state for an unseal the backend refused (spec section 6). Only reached when
    the mechanism itself works (a transient failure is SealUnavailable, never a state):

    - blobs sealed with host+tpm2 and no TPM now: "tpm-missing" (turn PTT back on);
    - blobs sealed with host+tpm2, a TPM present, and its SRK differs from the one recorded
      at sealing time: "tpm-cleared" (the keys are gone for good);
    - the same, but no SRK to compare: systemd-tpm2-setup writes the SRK's PEM only on a
      measured (UKI) boot, so on Limine/GRUB without a UKI there never is one. A working TPM
      that refuses a host+tpm2 blob then almost always means it was cleared or replaced:
      "tpm-cleared" as well, whose screen says so with "probably";
    - anything else (host-only blob refused, same SRK and still refused): "damaged".
    """
    if sealed_with == "host+tpm2":
        if not backend.tpm_present():
            return "tpm-missing"
        now = backend.srk_fingerprint()
        if not recorded_srk or not now or now != recorded_srk:
            return "tpm-cleared"
    return "damaged"


def _why(stderr: bytes) -> str:
    """A short, printable reason for logs. systemd-creds never echoes the secret."""
    text = (stderr or b"").decode("utf-8", "replace").strip().splitlines()
    line = text[-1] if text else "no message"
    return "".join(c for c in line if c.isprintable())[:200]
