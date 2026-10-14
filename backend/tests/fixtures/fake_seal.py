"""A stand-in for `systemd-creds --user --with-key=auto` that behaves like it where it matters.

A blob is `FAKECRED` + SecretBox(host key, json{name, with, srk, data}). Decrypting checks the
name (systemd-creds binds --name= into the credential), and a "host+tpm2" blob additionally
needs the TPM present with the same SRK it was sealed under - so tests can switch the TPM off
(tpm-missing) or replace it (tpm-cleared) and get the refusals the real tool gives.
"""

from __future__ import annotations

import base64
import json
import secrets

import nacl.exceptions
import nacl.secret

from icp.vstore.seal import SealUnavailable, UnsealRefused

MAGIC = b"FAKECRED"


class FakeSealBackend:
    def __init__(self, tpm: bool = False, srk: str = "srk-one"):
        self.host_key = secrets.token_bytes(32)
        self.tpm = tpm
        self.srk = srk
        self.calls: list[tuple[str, str]] = []       # (op, name); never the data
        self.unavailable = False                     # the tool cannot run at all
        self.corrupt_next_encrypts = 0               # emit blobs that will not open
        self.srk_visible = True                      # False: no systemd-tpm2-setup PEM (no UKI)

    # --- the backend interface ---------------------------------------------------------------
    def encrypt(self, name: str, plaintext: bytes) -> bytes:
        self.calls.append(("encrypt", name))
        if self.unavailable:
            raise SealUnavailable("fake: systemd-creds is not there")
        doc = {"name": name, "with": "host+tpm2" if self.tpm else "host",
               "srk": self.srk if self.tpm else None,
               "data": base64.b64encode(bytes(plaintext)).decode()}
        blob = MAGIC + nacl.secret.SecretBox(self.host_key).encrypt(json.dumps(doc).encode())
        if self.corrupt_next_encrypts:
            self.corrupt_next_encrypts -= 1
            blob = blob[:-1] + bytes([blob[-1] ^ 1])
        return blob

    def decrypt(self, name: str, blob: bytes) -> bytes:
        self.calls.append(("decrypt", name))
        if self.unavailable:
            raise SealUnavailable("fake: systemd-creds is not there")
        if not blob.startswith(MAGIC):
            raise UnsealRefused("not a credential")
        try:
            doc = json.loads(nacl.secret.SecretBox(self.host_key).decrypt(blob[len(MAGIC):]))
        except nacl.exceptions.CryptoError:
            raise UnsealRefused("host key does not open it") from None
        if doc["name"] != name:
            raise UnsealRefused("Name in credential doesn't match expectations.")
        if doc["with"] == "host+tpm2" and (not self.tpm or doc["srk"] != self.srk):
            raise UnsealRefused("TPM2 unseal failed")
        return base64.b64decode(doc["data"])

    def key_type(self, blob: bytes) -> str:
        if not blob.startswith(MAGIC):
            raise SealUnavailable("fake: not a credential")
        doc = json.loads(nacl.secret.SecretBox(self.host_key).decrypt(blob[len(MAGIC):]))
        return doc["with"]

    def tpm_present(self) -> bool:
        return self.tpm

    def srk_fingerprint(self) -> str | None:
        return self.srk if self.tpm and self.srk_visible else None

    # --- helpers for tests -------------------------------------------------------------------
    def count(self, op: str, tier: str | None = None) -> int:
        return sum(1 for o, n in self.calls
                   if o == op and (tier is None or n.startswith(f"pear.{tier}.")))
