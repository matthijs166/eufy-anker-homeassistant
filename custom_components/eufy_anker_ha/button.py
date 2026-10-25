"""Button platform: log everything known about a device to the HA log."""
from __future__ import annotations

import json
import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN
from .describe import describe_device
from .entity import EufyEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.vlog("button platform setup: %s", list(coordinator.data))
    async_add_entities(EufyLogInfo(coordinator, sn) for sn in coordinator.data)


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
        dump["state"] = {k: v for k, v in info.items() if k != "device"}
        _LOGGER.warning(
            "Eufy device info for %s:\n%s", self.sn, json.dumps(dump, indent=2, default=str, sort_keys=True)
        )
