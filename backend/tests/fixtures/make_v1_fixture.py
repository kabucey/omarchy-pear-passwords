"""Regenerate tests/fixtures/v1_vault/: a 1.x vault (as 1.3.2 wrote it) with fake data only.

Run from the repo root:  PYTHONPATH=backend python backend/tests/fixtures/make_v1_fixture.py

The files are committed so the importer is tested against bytes this code did not just write.
Regenerating gives different ciphertext (random salt and nonces) with the same plaintext, so
the tests do not depend on any particular run. The Argon2id limits are the library minimum to
keep the tests fast; the real 1.x files use MODERATE, and nothing in the reader assumes either.

Every value is invented. Nothing here is, or was derived from, a real account.
"""

from __future__ import annotations

import json
import os
import sys

import nacl.pwhash
import nacl.secret
import nacl.utils

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from fixtures import V1_DIR, V1_PASSPHRASE  # noqa: E402

CREDENTIALS = [
    {"domain": "github.com", "username": "dev@example.test", "password": "gh-TEST-pw-1",
     "title": "GitHub", "mdat": 1780000000.0, "notes": "", "aliases": [],
     "apple_history": [{"at": 1770000000.0, "password": "gh-TEST-old-apple"}],
     "apple_title": "GitHub", "sites": ["gist.github.com"],
     "totp": {"secret": b"12345678901234567890".hex(), "secret_hex": True, "digits": 6,
              "period": 30, "algorithm": 0, "issuer": "GitHub"}},
    {"domain": "bank.example.test", "username": "alex", "password": "bank-TEST-pw",
     "title": "Bank", "mdat": 1781000000.5, "notes": "PIN hint: TEST only", "aliases": [],
     "apple_history": [], "apple_title": "", "sites": []},
    {"domain": "mail.example.test", "username": "alex@example.test",
     "password": "mail-TEST-pw", "title": "mail.example.test", "mdat": 0.0, "notes": "",
     "aliases": ["webmail.example.test"], "apple_history": [], "apple_title": "",
     "sites": [],
     "totp": {"secret": "JBSWY3DPEHPK3PXP", "digits": 8, "period": 60, "algorithm": 1,
              "issuer": ""}},
    {"domain": "AirPort", "username": "Home WiFi TEST", "password": "wifi-TEST-pw",
     "title": "Home WiFi TEST", "mdat": 1700000000.0, "notes": "", "aliases": [],
     "apple_history": [], "apple_title": "", "sites": []},
    {"domain": "shop.example.test", "username": "sam", "password": "shop-TEST-pw-a",
     "title": "Shop", "mdat": 1750000000.0, "notes": "", "aliases": [],
     "apple_history": [], "apple_title": "", "sites": []},
    {"domain": "shop.example.test", "username": "sam", "password": "shop-TEST-pw-b",
     "title": "Shop (second item)", "mdat": 1750000001.0, "notes": "", "aliases": [],
     "apple_history": [], "apple_title": "", "sites": []},
]

HISTORY = {
    "github.com\x1fdev@example.test": [
        {"at": 1779000000.0, "source": "sync", "old": "gh-TEST-old-1", "new": "gh-TEST-pw-1",
         "title": "GitHub"},
        {"at": 1778000000.0, "source": "local", "old": "gh-TEST-old-0",
         "new": "gh-TEST-old-1", "title": "GitHub"},
    ],
    "bank.example.test\x1falex": [
        {"at": 1779500000.0, "source": "sync", "old": "bank-TEST-old", "new": "bank-TEST-pw",
         "title": "Bank"},
        {"at": 1779400000.0, "source": "apple", "old": None, "new": "bank-TEST-old",
         "title": ""},
    ],
    "gone.example.test\x1fold-user": [
        {"at": 1760000000.0, "source": "sync", "old": "gone-TEST-old", "new": "gone-TEST-pw",
         "title": "Gone"},
    ],
}

NICKNAMES = {"github.com\x1fdev@example.test": "Work GitHub",
             "bank.example.test\x1falex": "TEST bank"}

ALIASES = [
    {"anonymous_id": "a-TEST-1", "address": "quiet-otter-test@icloud.example", "label": "Shop",
     "note": "", "forward_to": "alex@example.test", "is_active": True,
     "domain": "shop.example.test", "created_at": 1760000000.0},
    {"anonymous_id": "a-TEST-2", "address": "brave-heron-test@icloud.example", "label": "News",
     "note": "newsletter", "forward_to": "alex@example.test", "is_active": False,
     "domain": "", "created_at": 1761000000.0},
]

SESSION = {"username": "alex@example.test", "dsid": "0000TEST", "gsa_sk": "TEST-sk",
           "pet": "TEST-pet", "cookies": {"X-TEST": "1"}}

DEVICE = {"device_id": "00000000-TEST-0000-0000-000000000000", "serial": "C02TEST00000",
          "local_user_uuid": "00000000-TEST-0000-0000-000000000001"}


def main() -> None:
    os.makedirs(V1_DIR, exist_ok=True)
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    ops = nacl.pwhash.argon2id.OPSLIMIT_MIN
    mem = nacl.pwhash.argon2id.MEMLIMIT_MIN
    key = nacl.pwhash.argon2id.kdf(32, V1_PASSPHRASE.encode(), salt, opslimit=ops,
                                   memlimit=mem)
    box = nacl.secret.SecretBox(key)

    def put(name: str, data: bytes) -> None:
        with open(os.path.join(V1_DIR, name), "wb") as f:
            f.write(data)

    # Exactly the shapes 1.3.2 wrote (auth/lockbox.py, vault/store.py, vault/history.py,
    # vault/nicknames.py, hme/store.py, auth/session.py, auth/device.py).
    put("kdf.json", json.dumps({"salt": salt.hex(), "opslimit": ops, "memlimit": mem,
                                "alg": "argon2id"}).encode())
    put("check.enc", box.encrypt(b"icp-lockbox-v1"))
    put("vault.enc", box.encrypt(json.dumps({"credentials": CREDENTIALS}).encode()))
    put("history.enc", box.encrypt(json.dumps({"accounts": HISTORY}).encode()))
    put("nicknames.enc", box.encrypt(json.dumps({"names": NICKNAMES}).encode()))
    put("aliases.enc", box.encrypt(json.dumps({"aliases": ALIASES}).encode()))
    put("session.enc", box.encrypt(json.dumps(SESSION).encode()))
    put("device.json", json.dumps(DEVICE, indent=2).encode())


if __name__ == "__main__":
    main()
