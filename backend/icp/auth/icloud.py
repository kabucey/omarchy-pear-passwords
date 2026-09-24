"""Reach iCloud services with the long-lived mmeAuthToken (no password, no 2FA): loginDelegates
mints it from a fresh PET, get_account_settings returns the service-URL map. See RESEARCH.md."""

import base64
import logging
import plistlib as plist

import requests
import urllib3

from . import ca
from .anisette import Anisette
from .device import Device
from .endpoints import is_apple_service_url
from .headers import identity_headers
from .http import secure_session
from ..errors import AppleError

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

LOGIN_DELEGATES_URL = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
ACCOUNT_SETTINGS_URL = "https://setup.icloud.com/setup/get_account_settings"

# AOSKit/accountsd identity for the iCloud setup endpoints (distinct from the GSA akd UA).
#
# The hardware and OS must match what GSA claimed - loginDelegates is presented as the same
# device that just cleared 2FA, and it previously described a MacBookPro18,3 on 13.4.1 while
# GSA described something else entirely. Only the framework versions (AOSKit/accountsd) stay
# put, since Apple's rejection keyed on the OS version, not on those.
ICLOUD_USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1640.0.3 Darwin/25.6.0"
ICLOUD_CLIENT_INFO = (
    "<Mac16,7> <Mac OS X;26.6;25G72> "
    "<com.apple.AOSKit/282 (com.apple.accountsd/113)>"
)


class ICloudError(AppleError):
    pass


def _basic(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def _post_service(url: str, *, headers: dict, data, operation: str,
                  session: requests.Session | None = None):
    """POST an authenticated iCloud service request without following redirects."""
    if not is_apple_service_url(url):
        raise ICloudError(
            f"refusing an invalid {operation} URL; expected an HTTPS iCloud host")
    http = secure_session(verify=ca.bundle(), session=session)
    resp = http.post(url, headers=headers, data=data, timeout=20, allow_redirects=False)
    if 300 <= resp.status_code < 400:
        location = getattr(resp, "headers", {}).get("Location", "")
        raise ICloudError(
            f"{operation} returned an unexpected redirect"
            + (f" to {location!r}" if location else ""))
    return resp


def login_mobileme(username: str, pet: str, adsid: str, client_id: str,
                   device: Device, anisette: Anisette,
                   url: str = LOGIN_DELEGATES_URL, *,
                   session: requests.Session | None = None) -> tuple[str, str, dict, dict]:
    """Exchange the fresh PET for the persistent mmeAuthToken.
    Returns (dsid, mme_auth_token, service_data, raw_response)."""
    body = plist.dumps({
        "apple-id": username,
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": client_id,
    })
    # Same device identity as GSA, so loginDelegates sees the device that just passed 2FA.
    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": ICLOUD_USER_AGENT,
        "X-Mme-Client-Info": ICLOUD_CLIENT_INFO,
        "Accept": "*/*",
    }
    headers.update(identity_headers(device, anisette))
    headers["Authorization"] = _basic(username, pet)  # apple-id:PET (NOT dsid:PET)

    resp = _post_service(url, headers=headers, data=body, operation="loginDelegates",
                         session=session)
    logger.debug("loginDelegates -> HTTP %s (%d bytes)", resp.status_code, len(resp.content))
    data = plist.loads(resp.content)

    mm = data.get("delegates", {}).get("com.apple.mobileme", {})
    status = mm.get("status", data.get("status"))
    if status != 0:
        msg = mm.get("status-message") or data.get("status-message") or "unknown error"
        raise ICloudError(f"loginDelegates status {status}: {msg}")

    service_data = mm.get("service-data", {})
    dsid = data.get("dsid") or service_data.get("appleAccountInfo", {}).get("dsid")
    token = service_data.get("tokens", {}).get("mmeAuthToken")
    return str(dsid), token, service_data, data


def fetch_account_settings(record: dict, device: Device, anisette: Anisette,
                           url: str = ACCOUNT_SETTINGS_URL, *,
                           session: requests.Session | None = None) -> tuple[int, dict]:
    """With the stored mmeAuthToken, fetch the account/webservices settings. Auth is
    `Basic base64(dsid:mmeAuthToken)`. Returns (http_status, parsed_plist)."""
    mme = record.get("mme") or {}
    dsid = mme.get("dsid")
    token = mme.get("mmeAuthToken")
    if not token or not dsid:
        raise ICloudError("no mmeAuthToken stored; run `login` to mint one")

    headers = {
        "Authorization": _basic(str(dsid), token),
        "X-Mme-Client-Info": ICLOUD_CLIENT_INFO,
        "User-Agent": ICLOUD_USER_AGENT,
        "Accept": "*/*",
    }
    headers.update(identity_headers(device, anisette))

    resp = _post_service(url, headers=headers, data="", operation="get_account_settings",
                         session=session)
    logger.debug("get_account_settings -> HTTP %s (%d bytes)",
                 resp.status_code, len(resp.content))
    return resp.status_code, plist.loads(resp.content)


def extract_webservices(settings: dict) -> dict:
    """Flatten the service-URL map from get_account_settings, tolerating both shapes:

      - modern:  settings["webservices"][name] = {"url": ..., "status": ...}
      - classic: settings["com.apple.mobileme"]["com.apple.Dataclass.X"] = {"url": ...}

    Returns only strict HTTPS iCloud service URLs as {name: {"url": ...}} so callers can
    safely read ckdatabasews / keyvalue / escrowproxy without sending credentials to a
    server-controlled arbitrary host.
    """
    out: dict = {}
    ws = settings.get("webservices")
    if isinstance(ws, dict):
        for name, v in ws.items():
            if isinstance(v, dict) and is_apple_service_url(v.get("url")):
                out[name] = {"url": v["url"], "status": v.get("status")}

    # Some services carry their endpoint under a non-"url" key (KeychainSync -> escrowProxyUrl,
    # KeyValue -> configURL, Ubiquity -> wsUrl); capture those too.
    _alt_url_keys = ("url", "escrowProxyUrl", "configURL", "wsUrl")
    mm = settings.get("com.apple.mobileme")
    if isinstance(mm, dict):
        for name, v in mm.items():
            if not isinstance(v, dict):
                continue
            url = next((v[k] for k in _alt_url_keys if v.get(k)), None)
            if not is_apple_service_url(url):
                continue
            entry = {"url": url, "status": v.get("status")}
            escrow_url = v.get("escrowProxyUrl")
            if is_apple_service_url(escrow_url):
                entry["escrowProxyUrl"] = escrow_url
            # Normalise "com.apple.Dataclass.Foo" -> "foo" alongside the raw key.
            out.setdefault(name, entry)
            out.setdefault(name.rsplit(".", 1)[-1].lower(), entry)

    return out
