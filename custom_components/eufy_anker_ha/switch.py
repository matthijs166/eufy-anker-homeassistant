"""Switch platform: privacy mode."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity

from .const import DOMAIN
from .entity import EufyEntity


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [EufyPrivacy(coordinator, sn) for sn in coordinator.data]
    coordinator.vlog("switch platform: adding %d entities", len(entities))
    async_add_entities(entities)


class EufyPrivacy(EufyEntity, SwitchEntity):
    """Privacy mode on/off."""

    _attr_name = "Privacy mode"
    _attr_icon = "mdi:eye-off"

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_privacy"

    @property
    def is_on(self) -> bool:
        self.coordinator.vlog("STATE privacy %s -> %s", self.sn, self.info["privacy"])
        return self.info["privacy"]

    async def async_turn_on(self, **kwargs) -> None:
        self.coordinator.vlog("TRIGGER switch privacy turn_on %s kwargs=%s", self.sn, kwargs)
        await self.coordinator.async_set_privacy(self.sn, True)

    async def async_turn_off(self, **kwargs) -> None:
        self.coordinator.vlog("TRIGGER switch privacy turn_off %s kwargs=%s", self.sn, kwargs)
        await self.coordinator.async_set_privacy(self.sn, False)
