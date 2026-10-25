"""Switch platform: privacy mode."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity

from .const import DOMAIN
from .entity import EufyEntity


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(EufyPrivacy(coordinator, sn) for sn in coordinator.data)


class EufyPrivacy(EufyEntity, SwitchEntity):
    """Privacy mode on/off."""

    _attr_name = "Privacy mode"
    _attr_icon = "mdi:eye-off"

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_privacy"

    @property
    def is_on(self) -> bool:
        return self.info["privacy"]

    async def async_turn_on(self, **kwargs) -> None:
        await self.coordinator.api.set_privacy(self.info["device"], True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        await self.coordinator.api.set_privacy(self.info["device"], False)
        await self.coordinator.async_request_refresh()
