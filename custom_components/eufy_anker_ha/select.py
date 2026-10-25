"""Select platform for Eufy camera settings."""
from __future__ import annotations

from homeassistant.components.select import SelectEntity

from .const import DOMAIN
from .entity import EufyEntity

NIGHT_VISION_MODES = {"off": 0, "auto": 1, "on": 3}


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [EufyNightVision(coordinator, sn) for sn in coordinator.data]
    coordinator.vlog("select platform: adding %d entities", len(entities))
    async_add_entities(entities)


class EufyNightVision(EufyEntity, SelectEntity):
    """Night vision mode (off / auto / on)."""

    _attr_name = "Night vision"
    _attr_icon = "mdi:weather-night"
    _attr_options = list(NIGHT_VISION_MODES)

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_night_vision"

    @property
    def current_option(self) -> str | None:
        value = self.info["night_vision"]
        return next((mode for mode, code in NIGHT_VISION_MODES.items() if str(code) == value), None)

    async def async_select_option(self, option: str) -> None:
        await self.coordinator.async_set_night_vision(self.sn, NIGHT_VISION_MODES[option])