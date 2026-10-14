"""Persistent local device identity - generated once, reused forever, so a stable
X-Mme-Device-Id lets Apple remember the 2FA approval and stop re-prompting. Anisette supplies
the volatile X-Apple-I-MD* machine data and may override these values.

The identity is not a key: in 2.0 it lives in the store's plaintext device.json (0600, under the
daemon's own uid), read and written through the store so nothing here touches a path."""

import base64
import locale
import uuid
from datetime import datetime, timezone

_FIELDS = ("device_id", "serial", "local_user_uuid")


class Device:
    def __init__(self, device_id: str, serial: str, local_user_uuid: str):
        self.device_id = device_id
        self.serial = serial
        self.local_user_uuid = local_user_uuid

    @classmethod
    def new(cls) -> "Device":
        return cls(
            device_id=str(uuid.uuid4()).upper(),
            # Mac-like 12-char serial; replaced by anisette's if it provides one.
            serial="C02" + uuid.uuid4().hex[:9].upper(),
            local_user_uuid=str(uuid.uuid4()).upper(),
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Device | None":
        """None for anything incomplete, so a damaged record is replaced rather than half-used."""
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data.get(k)
                                                 for k in _FIELDS):
            return None
        return cls(data["device_id"], data["serial"], data["local_user_uuid"])

    def to_dict(self) -> dict:
        return {"device_id": self.device_id, "serial": self.serial,
                "local_user_uuid": self.local_user_uuid}

    @classmethod
    def load_or_create(cls, store) -> "Device":
        """The store's device identity, created and saved on first use."""
        dev = cls.from_dict(store.load_device() or {})
        if dev is None:
            dev = cls.new()
            store.save_device(dev.to_dict())
        return dev

    def meta_headers(self) -> dict:
        """Fallback identity headers; anisette values override the X-Apple-I-MD* ones."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        loc = (locale.getdefaultlocale()[0] or "en_US")
        return {
            "X-Apple-I-Client-Time": now.isoformat().replace("+00:00", "Z"),
            "X-Apple-I-TimeZone": "UTC",
            "loc": loc,
            "X-Apple-Locale": loc,
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(
                self.local_user_uuid.upper().encode()
            ).decode(),
            "X-Mme-Device-Id": self.device_id.upper(),
            "X-Apple-I-SRL-NO": self.serial,
        }
