"""Helpers for credential-bearing HTTP transports.

Requests otherwise imports proxy and CA-bundle settings from the process environment. The
Apple auth clients carry password-equivalent tokens, so each client gets a session whose routing
and trust settings are explicit. A supplied session is supported for offline tests and is
configured with the same safeguards.
"""

from __future__ import annotations

import requests


def secure_session(*, verify: bool | str,
                   session: requests.Session | None = None) -> requests.Session:
    """Return a session that cannot inherit proxy or CA settings from the environment."""
    http = session if session is not None else requests.Session()
    http.trust_env = False
    http.verify = verify
    return http
