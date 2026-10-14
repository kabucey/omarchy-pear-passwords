"""High-level authentication flow: SRP login + 2FA + PET extraction."""

import logging
import os

from typing import Callable

from .gsa import GSAClient, GSAError

logger = logging.getLogger(__name__)

# Called with the factor kind ("trusted" | "sms"); must return the 6-digit code.
TwoFactorCallback = Callable[[str], str]


def _pick_phone_id(gsa: GSAClient, dsid: str, idms: str) -> int:
    """Which trusted number to text. ICP_PHONE_ID overrides; otherwise the only one, or the
    first of several (listed, so a wrong guess is visible rather than silent)."""
    log = logger
    override = os.environ.get("ICP_PHONE_ID")
    if override:
        return int(override)

    numbers = gsa.list_phone_numbers(dsid, idms)
    if not numbers:
        log.warning("Apple did not list any trusted phone numbers; trying id 1. "
                    "If no code arrives, set ICP_PHONE_ID to the right one.")
        return 1
    if len(numbers) > 1:
        log.warning("Several trusted numbers on the account; using the first. "
                    "Set ICP_PHONE_ID to choose: %s",
                    ", ".join(f"{n['id']}={n['number']}" for n in numbers))
    else:
        log.warning("Texting %s (id %s)", numbers[0]["number"], numbers[0]["id"])
    return int(numbers[0]["id"])


def authenticate(gsa: GSAClient, username: str, password: str,
                 twofa: TwoFactorCallback | None) -> dict:
    """Return the decrypted server provisioning data (spd), handling 2FA transparently."""
    r, spd = gsa.authenticate(username, password)
    status = r.get("Status", {})
    au = status.get("au")
    # What Apple actually asked for, and which handles we extracted - the two things needed to
    # tell "Apple never sent it" apart from "we asked wrongly".
    logger.debug("GSA Status=%s", status)
    logger.debug("spd keys=%s adsid=%s GsIdmsToken=%s",
                 list(spd), bool(spd.get("adsid") or spd.get("DsPrsId")),
                 bool(spd.get("GsIdmsToken") or spd.get("GsIdMS")))

    if au in ("trustedDeviceSecondaryAuth", "secondaryAuth"):
        if twofa is None:
            # Nobody is there to type a code (a background sync): stand down BEFORE asking
            # Apple to push one, or the person's devices show a prompt nothing can answer.
            raise GSAError("2FA required and nobody is present to answer it")
        dsid = spd.get("adsid") or spd.get("DsPrsId")
        idms = spd.get("GsIdmsToken") or spd.get("GsIdMS")
        if not dsid or not idms:
            raise GSAError(f"2FA required but missing dsid/GsIdMS in spd: keys={list(spd)}")

        if au == "trustedDeviceSecondaryAuth":
            gsa.trigger_trusted_factor(dsid, idms)
            code = twofa("trusted")
            if not gsa.submit_trusted_factor(code, dsid, idms):
                raise GSAError("trusted-device 2FA rejected")
        elif os.environ.get("ICP_2FA_MODE", "").lower() != "sms" and \
                gsa.trigger_trusted_factor(dsid, idms):
            # Apple asked for "secondaryAuth" rather than naming trusted devices, but the
            # phone endpoints here are undocumented and unexercised (they returned 405), while
            # the trusted-device push uses the route this project actually works with. Any code
            # Apple issues validates through the same endpoint, so prefer it and keep SMS as
            # the fallback via ICP_2FA_MODE=sms.
            code = twofa("trusted")
            if not gsa.submit_trusted_factor(code, dsid, idms):
                raise GSAError(
                    "That code was rejected. If it arrived by SMS rather than on an Apple "
                    "device, retry with ICP_2FA_MODE=sms.")
        else:
            # The phone id is an account-specific handle, not an index, so ask Apple rather
            # than assuming 1 - a wrong id means the code is sent nowhere at all.
            phone_id = _pick_phone_id(gsa, dsid, idms)
            gsa.trigger_sms_factor(dsid, idms, phone_id)
            code = twofa("sms")
            if not gsa.submit_sms_factor(code, dsid, idms, phone_id):
                raise GSAError("SMS 2FA rejected")

        # Re-authenticate: the device is now trusted, so this should NOT prompt again.
        r, spd = gsa.authenticate(username, password)
        if r.get("Status", {}).get("au"):
            raise GSAError("still being asked for 2FA after submitting a code")

    return spd


def extract_pet(spd: dict) -> tuple[str, str, int | None]:
    """Return (dsid, pet, expiry_ms) from spd. The PET is a password-equivalent token."""
    dsid = spd.get("adsid") or spd.get("DsPrsId")
    tokens = spd.get("t", {})
    pet_entry = tokens.get("com.apple.gs.idms.pet", {})
    pet = pet_entry.get("token")
    if not dsid or not pet:
        raise GSAError(f"no PET in spd (keys={list(spd)}, token keys={list(tokens)})")
    return dsid, pet, pet_entry.get("expiry")
