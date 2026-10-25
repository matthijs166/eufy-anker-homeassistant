"""Button platform for device diagnostics and PTZ movement."""
from __future__ import annotations

import json
import logging

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.helpers.entity import EntityCategory

from .api import supports_ptz
from .const import DOMAIN
from .describe import describe_device
from .entity import EufyEntity

_LOGGER = logging.getLogger(__name__)
PTZ_DIRECTIONS = ("up", "down", "left", "right")
PTZ_ICONS = {
    "up": "mdi:arrow-up",
    "down": "mdi:arrow-down",
    "left": "mdi:arrow-left",
    "right": "mdi:arrow-right",
}


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.vlog("button platform setup: %s", list(coordinator.data))
    entities = [EufyLogInfo(coordinator, sn) for sn in coordinator.data]
    entities.extend(EufyRestart(coordinator, sn, entry.entry_id) for sn in coordinator.data)
    for sn, info in coordinator.data.items():
        if supports_ptz(info["device"]):
            entities.extend(EufyPtzMove(coordinator, sn, direction) for direction in PTZ_DIRECTIONS)
    async_add_entities(entities)


class EufyLogInfo(EufyEntity, ButtonEntity):
    """Dump all device properties (decoded) to the Home Assistant log."""

    _attr_name = "Log device info"
    _attr_icon = "mdi:text-box-search-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_log_info"

    async def async_press(self) -> None:
        self.coordinator.vlog("TRIGGER button log_info %s", self.sn)
        info = self.info
        dump = describe_device(info["device"])
        dump["state"] = {key: value for key, value in info.items() if key != "device"}
        _LOGGER.warning(
            "Eufy device info for %s:\n%s", self.sn, json.dumps(dump, indent=2, default=str, sort_keys=True)
        )


class EufyRestart(EufyEntity, ButtonEntity):
    """Reload the whole integration (reconnects the cloud session and live streams)."""

    _attr_name = "Restart integration"
    _attr_device_class = ButtonDeviceClass.RESTART
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, sn, entry_id: str) -> None:
        super().__init__(coordinator, sn)
        self._entry_id = entry_id
        self._attr_unique_id = f"{sn}_restart"

    @property
    def available(self) -> bool:
        return True

    async def async_press(self) -> None:
        self.coordinator.vlog("TRIGGER button restart %s", self.sn)
        self.hass.async_create_task(self.hass.config_entries.async_reload(self._entry_id))


class EufyPtzMove(EufyEntity, ButtonEntity):
    """Move a pan/tilt camera one step in a cardinal direction."""

    def __init__(self, coordinator, sn, direction: str) -> None:
        super().__init__(coordinator, sn)
        self.direction = direction
        self._attr_name = f"Move {direction}"
        self._attr_icon = PTZ_ICONS[direction]
        self._attr_unique_id = f"{sn}_ptz_{direction}"

    async def async_press(self) -> None:
        self.coordinator.vlog("TRIGGER button ptz %s %s", self.sn, self.direction)
        await self.coordinator.async_move_ptz(self.sn, self.direction)