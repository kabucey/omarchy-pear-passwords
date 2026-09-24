"""Validation for service URLs returned by Apple's authenticated APIs.

The account-settings response supplies hosts for services such as Keychain escrow and
Hide My Email.  Those hosts are later used with credentials, so accepting a merely
well-formed URL is not enough: keep the request on HTTPS and inside Apple's iCloud
DNS boundary.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit


_APPLE_SERVICE_DOMAIN = "icloud.com"
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def is_apple_service_url(value: object) -> bool:
    """Return whether *value* is a strict HTTPS iCloud service base URL.

    Service URLs are appended to by callers, so query strings and fragments are
    rejected.  Hostnames are deliberately ASCII and label-checked to avoid parser
    differences between ``urlsplit`` and the HTTP client's IDNA handling.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\"
           for ch in value):
        return False
    # Treat even empty query/fragment delimiters as untrusted URL components.  Callers append
    # service-specific paths, so accepting a raw '?' or '#' would make the resulting target
    # parser-dependent (and can suppress or alter that appended path).
    if "?" in value or "#" in value:
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or not hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if port not in (None, 443) or parsed.query or parsed.fragment:
        return False
    if any(ord(ch) > 0x7F for ch in hostname):
        return False

    # A single DNS root dot is valid and was accepted by the previous web-auth validator.  Keep
    # that legitimate spelling while rejecting an empty/interior label.
    host = hostname.lower()
    if host.endswith("."):
        host = host[:-1]
        if not host or host.endswith("."):
            return False
    labels = host.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return False
    return host == _APPLE_SERVICE_DOMAIN or host.endswith("." + _APPLE_SERVICE_DOMAIN)
