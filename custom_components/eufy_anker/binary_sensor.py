"""Binary sensor platform: detection for automations."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity

from .const import DOMAIN, MOTION_WINDOW
from .entity import EufyEntity


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(EufyMotion(coordinator, sn) for sn in coordinator.data)


class EufyMotion(EufyEntity, BinarySensorEntity):
    """On while a recent detection event exists."""

    _attr_device_class = BinarySensorDeviceClass.MOTION
    _attr_name = "Detection"

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_detection"

    @property
    def is_on(self) -> bool:
        info = self.info
        return bool(info["last_event"]) and info["now"] - _secs(info["last_event"]) <= MOTION_WINDOW


def _secs(ts: int) -> int:
    return ts // 1000 if ts > 10**11 else ts
