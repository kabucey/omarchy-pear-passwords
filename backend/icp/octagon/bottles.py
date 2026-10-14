"""Describing escrow bottles, and letting the person pick one.

The device pick decides which escrow record a passcode is spent against (about 10 attempts,
then the record is destroyed), so each choice carries enough to tell two similar devices apart:
the owner's name for it, its model, when it was backed up, what kind of passcode it uses and the
end of its serial.
"""

from __future__ import annotations

from datetime import datetime


def _bottle_is_mac(b: dict) -> bool:
    cm = (b.get("meta") or {}).get("ClientMetadata") or {}
    return any("mac" in str(cm.get(k, "")).lower()
               for k in ("device_model", "model", "ProductType", "device_model_class", "device_platform"))


def _bottle_fields(b: dict) -> tuple[str | None, str | None, list[str]]:
    """(the owner's name for the device, its model, [backed-up date, passcode kind, serial])
    from escrow GETRECORDS metadata. Any of it can be missing: that lookup is best-effort."""
    meta = b.get("meta") or {}
    cm = meta.get("ClientMetadata") or {}
    own = cm.get("device_name") or cm.get("deviceName")
    model = (cm.get("device_model") or cm.get("model") or cm.get("ProductType")
             or cm.get("device_model_class"))
    facts = []
    is_mac = _bottle_is_mac(b)
    when = meta.get("com.apple.securebackup.timestamp") or cm.get("SecureBackupMetadataTimestamp")
    if isinstance(when, datetime):
        facts.append(f"backed up {when.day} {when:%b %Y}")
    elif isinstance(when, str) and when[:10].count("-") == 2:
        try:
            d = datetime.strptime(when[:10], "%Y-%m-%d")
            facts.append(f"backed up {d.day} {d:%b %Y}")
        except ValueError:
            pass
    length = cm.get("SecureBackupNumericPassphraseLength")
    if is_mac:
        facts.append("Mac login password")      # a Mac escrows with its login password
    elif cm.get("SecureBackupUsesNumericPassphrase") and isinstance(length, int) and length:
        facts.append(f"{length}-digit passcode")
    elif cm.get("SecureBackupUsesComplexPassphrase"):
        facts.append("alphanumeric passcode")
    serial = meta.get("serial")
    if serial:
        facts.append(f"serial ending {str(serial)[-4:]}")
    return own, model, facts


def is_mac(b: dict) -> bool:
    return _bottle_is_mac(b)


def name(b: dict) -> str:
    """What the device is called: the owner's own name for it, else its model."""
    own, model, _ = _bottle_fields(b)
    return own or model or "Unknown device"


def model(b: dict) -> str:
    """The model, when the name doesn't already say it ("" otherwise)."""
    own, mdl, _ = _bottle_fields(b)
    return mdl if own and mdl and mdl.lower() not in own.lower() else ""


def details(b: dict) -> str:
    _, _, facts = _bottle_fields(b)
    mdl = model(b)
    facts = ([mdl] if mdl else []) + facts
    return " · ".join(facts) if facts else "details unavailable - can't tell which device this is"


def describe(b: dict) -> str:
    """One line: name, then the facts that tell two similar devices apart."""
    return f"{name(b)} - {details(b)}"


def select(ui, bottles: list[dict]) -> dict | None:
    """Let the person pick which device's escrow bottle to recover, through `ui` (a
    daemon.context.Frontend). Auto-selects a lone bottle. Returns the chosen
    `{id, otbottle, meta}` dict, or None to abort. Any answer that is not a valid index is an
    abort, never a guess: a wrong pick spends an attempt against the wrong record."""
    if len(bottles) == 1:
        ui.emit("step", f"Using the only escrow bottle: {describe(bottles[0])}")
        return bottles[0]
    ui.emit("step", "Multiple escrow bottles found. Pick the device you want to use:\n")
    i = ui.choose("Select a device", [name(b) for b in bottles], kind="device",
                  details=[details(b) for b in bottles])
    if not isinstance(i, int) or isinstance(i, bool) or not 0 <= i < len(bottles):
        return None
    return bottles[i]
