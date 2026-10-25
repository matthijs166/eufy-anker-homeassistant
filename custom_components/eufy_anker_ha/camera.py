"""Camera platform: last image."""
from __future__ import annotations

from homeassistant.components.camera import Camera

from .const import DOMAIN
from .entity import EufyEntity


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.vlog("camera platform setup: %s", list(coordinator.data))
    async_add_entities(EufyCamera(coordinator, sn) for sn in coordinator.data)


class EufyCamera(EufyEntity, Camera):
    """Shows the most recent image of a camera."""

    _attr_name = None

    def __init__(self, coordinator, sn) -> None:
        EufyEntity.__init__(self, coordinator, sn)
        Camera.__init__(self)
        self._attr_unique_id = f"{sn}_camera"

    async def async_camera_image(self, width=None, height=None):
        url = self.info.get("image_url")
        self.coordinator.vlog("ACTION camera image %s url=%s size=%sx%s", self.sn, url, width, height)
        image = await self.coordinator.api.get_image(url) if url else None
        self.coordinator.vlog("camera image %s -> %s bytes", self.sn, len(image) if image else None)
        return image
