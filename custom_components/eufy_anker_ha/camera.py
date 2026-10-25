"""Camera platform: live snapshot over P2P."""
from __future__ import annotations

import asyncio
import logging
import time

from homeassistant.components.camera import Camera
from homeassistant.components.ffmpeg import get_ffmpeg_manager

from .api import EufyError
from .const import DOMAIN
from .entity import EufyEntity
from .p2p import P2PError

_LOGGER = logging.getLogger(__name__)

SNAPSHOT_MAX_AGE_S = 10


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.vlog("camera platform setup: %s", list(coordinator.data))
    async_add_entities(EufyCamera(coordinator, sn) for sn in coordinator.data)


class EufyCamera(EufyEntity, Camera):
    """Live frame over P2P, falling back to the last stored event image."""

    _attr_name = None

    def __init__(self, coordinator, sn) -> None:
        EufyEntity.__init__(self, coordinator, sn)
        Camera.__init__(self)
        self._attr_unique_id = f"{sn}_camera"
        self._lock = asyncio.Lock()
        self._snapshot: tuple[float, bytes] | None = None

    async def async_camera_image(self, width=None, height=None):
        async with self._lock:
            if self._snapshot and time.monotonic() - self._snapshot[0] < SNAPSHOT_MAX_AGE_S:
                return self._snapshot[1]
            api = self.coordinator.api
            try:
                image = await api.get_snapshot(self.info["device"], get_ffmpeg_manager(self.hass).binary)
                self._snapshot = (time.monotonic(), image)
                return image
            except (P2PError, EufyError, OSError) as err:
                _LOGGER.debug("Live snapshot of %s failed, using stored image: %s", self.sn, err)
            url = self.info.get("image_url")
            image = await api.get_image(url) if url else None
            self.coordinator.vlog("camera image %s -> %s bytes", self.sn, len(image) if image else None)
            return image
