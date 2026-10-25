"""Data coordinator."""
from __future__ import annotations

from datetime import timedelta
import logging
import time

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import EufyApi, EufyError, privacy_enabled
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


class EufyCoordinator(DataUpdateCoordinator[dict]):
    """Poll the Eufy cloud for selected cameras."""

    def __init__(self, hass: HomeAssistant, api: EufyApi, cameras: list[str]) -> None:
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL))
        self.api = api
        self.cameras = cameras

    async def _async_update_data(self) -> dict:
        try:
            devices = await self.api.get_cameras()
            events = await self.api.get_events()
        except EufyError as err:
            raise UpdateFailed(str(err)) from err
        data: dict = {}
        for dev in devices:
            sn = dev["device_sn"]
            if sn not in self.cameras:
                continue
            mine = [e for e in events if e.get("device_sn") == sn]
            last = max(mine, key=lambda e: e.get("create_time", 0), default=None)
            data[sn] = {
                "device": dev,
                "image_url": (last or {}).get("pic_url") or dev.get("cover_path"),
                "last_event": (last or {}).get("create_time", 0),
                "privacy": privacy_enabled(dev),
                "now": int(time.time()),
            }
        return data
