"""GrandSlam (GSA) SRP-6a authentication.

Takes an explicit Device + Anisette instead of module globals. Produces the decrypted
server provisioning data (spd), which contains the account DSID and the PET
(password-equivalent token).
"""

import base64
import hashlib
import hmac
import logging
import plistlib as plist

import requests
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .. import const
from . import ca
from .anisette import Anisette
from .device import Device
from .headers import identity_headers
from .http import secure_session
from ..errors import AppleError

# Apple's SRP variant.
srp.rfc5054_enable()
srp.no_username_in_x()

logger = logging.getLogger(__name__)


class GSAError(AppleError):
    pass


class GSAClient:
    def __init__(self, device: Device, anisette: Anisette,
                 session: requests.Session | None = None):
        self.device = device
        self.anisette = anisette
        self.http = secure_session(verify=ca.bundle(), session=session)
        # Stashed for diagnostics (set by authenticate()).
        self.last_init_response: dict | None = None
        self.last_complete_response: dict | None = None
        self.last_session_key: bytes | None = None

    def _cpd(self) -> dict:
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(identity_headers(self.device, self.anisette))
        return cpd

    def _request_http(self, method: str, url: str, **kwargs) -> requests.Response:
        resp = self.http.request(method, url, allow_redirects=False, **kwargs)
        if 300 <= resp.status_code < 400:
            location = getattr(resp, "headers", {}).get("Location", "")
            raise GSAError(
                "GSA request returned an unexpected redirect"
                + (f" to {location!r}" if location else ""))
        return resp

    def _request(self, parameters: dict) -> dict:
        body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": self._cpd()}}
        body["Request"].update(parameters)
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": const.GSA_USER_AGENT,
            "X-MMe-Client-Info": const.GSA_CLIENT_INFO,
        }
        resp = self._request_http(
            "POST", const.GSA_ENDPOINT, headers=headers, data=plist.dumps(body), timeout=10,
        )
        return plist.loads(resp.content)["Response"]

    def authenticate(self, username: str, password: str) -> tuple[dict, dict]:
        usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, A = usr.start_authentication()

        init = self._request({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})
        self.last_init_response = init
        logger.debug("GSA init response keys: %s", list(init))
        if "sp" not in init:
            raise GSAError(f"init failed: {_status(init)}")
        if init["sp"] not in ("s2k", "s2k_fo"):
            raise GSAError(f"unsupported protocol {init['sp']}")

        # We could not derive the password without the salt, so inject it now.
        usr.p = _encrypt_password(password, init["s"], init["i"], init["sp"])
        M = usr.process_challenge(init["s"], init["B"])
        if M is None:
            raise GSAError("failed to process SRP challenge (wrong password?)")

        complete = self._request({"c": init["c"], "M1": M, "u": username, "o": "complete"})
        self.last_complete_response = complete
        logger.debug("GSA complete response keys: %s", list(complete))
        if "M2" not in complete:
            raise GSAError(f"complete failed: {_status(complete)}")
        usr.verify_session(complete["M2"])
        if not usr.authenticated():
            raise GSAError("server session verification failed (imposter?)")

        self.last_session_key = usr.get_session_key()
        spd = plist.loads(_decrypt_cbc(usr, complete["spd"]), fmt=plist.FMT_XML)
        logger.debug("GSA spd top-level keys: %s", list(spd))
        return complete, spd

    def trigger_trusted_factor(self, dsid: str, idms_token: str) -> bool:
        """Ask Apple to push a code to the trusted devices. True if it accepted the request."""
        resp = self._request_http(
            "GET", "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=self._twofa_headers(dsid, idms_token), timeout=10,
        )
        # Logged unconditionally: a 200 with no notification arriving is the interesting case,
        # and it is invisible if only failures are recorded.
        logger.debug("trusted-device trigger -> HTTP %s\nheaders=%s\nbody=%s",
                     resp.status_code, dict(resp.headers), resp.text[:800])
        if not resp.ok:
            logger.warning("trusted-device push refused: HTTP %s %s",
                           resp.status_code, resp.text[:150])
        return resp.ok

    def submit_trusted_factor(self, code: str, dsid: str, idms_token: str) -> bool:
        h = self._twofa_headers(dsid, idms_token)
        h["security-code"] = code
        resp = self._request_http(
            "GET", "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=h, timeout=10,
        )
        return resp.ok

    def list_phone_numbers(self, dsid: str, idms_token: str) -> list:
        """Trusted phone numbers as [{id, number}]. Empty if Apple won't say.

        Needed because the id is an account-specific handle, not an index - assuming 1 sends
        the code into the void on any account whose numbers have been added/removed over time.
        """
        h = self._twofa_headers(dsid, idms_token)
        h["Accept"] = "application/json"
        try:
            resp = self._request_http("GET", "https://gsa.apple.com/auth", headers=h, timeout=10)
            data = resp.json() if resp.ok else {}
        except (requests.RequestException, ValueError):
            return []
        out = []
        for p in (data.get("trustedPhoneNumbers") or []):
            if p.get("id") is not None:
                out.append({"id": p["id"],
                            "number": p.get("numberWithDialCode") or p.get("obfuscatedNumber") or "?"})
        return out

    def trigger_sms_factor(self, dsid: str, idms_token: str, phone_id: int = 1) -> None:
        # The trailing slash upstream used returns 405 Method Not Allowed; Apple's route has
        # no trailing slash. Both spellings are tried so a future change on their side is
        # visible as a real error rather than a silent non-delivery.
        body = {"phoneNumber": {"id": phone_id}, "mode": "sms"}
        h = self._twofa_headers(dsid, idms_token)
        last = None
        for url in ("https://gsa.apple.com/auth/verify/phone",
                    "https://gsa.apple.com/auth/verify/phone/"):
            resp = self._request_http("PUT", url, json=body, headers=h, timeout=10)
            if resp.ok:
                return
            last = resp
            logger.warning("SMS trigger via %s: HTTP %s", url, resp.status_code)
        # Upstream discarded this response, so a rejected request still printed "code sent"
        # and then sat waiting for a code that was never going to arrive.
        raise GSAError(
            f"Apple refused to send the SMS (HTTP {last.status_code}) for phone id "
            f"{phone_id}: {last.text[:200] or '(empty body)'}")

    def submit_sms_factor(self, code: str, dsid: str, idms_token: str, phone_id: int = 1) -> bool:
        body = {
            "phoneNumber": {"id": phone_id},
            "mode": "sms",
            "securityCode": {"code": code},
        }
        resp = self._request_http(
            "POST", "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body, headers=self._twofa_headers(dsid, idms_token), timeout=10,
        )
        return resp.ok

    def _twofa_headers(self, dsid: str, idms_token: str) -> dict:
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        h = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": const.GSA_CLIENT_INFO,
        }
        h.update(identity_headers(self.device, self.anisette))
        return h


def _encrypt_password(password: str, salt: bytes, iterations: int, protocol: str) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)


def _session_key(usr, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None:
        raise GSAError("no SRP session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def _decrypt_cbc(usr, data: bytes) -> bytes:
    key = _session_key(usr, "extra data key:")
    iv = _session_key(usr, "extra data iv:")[:16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _status(r: dict) -> str:
    s = r.get("Status", r)
    return f"ec={s.get('ec')} em={s.get('em')!r} au={s.get('au')!r}"
