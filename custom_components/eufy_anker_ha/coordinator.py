"""Data coordinator."""
from __future__ import annotations

from datetime import timedelta
import json
import logging
import time

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import EufyApi, redact, EufyError, camera_power_on, privacy_enabled
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

PENDING_TTL = 90  # seconds a written value is shown while the cloud still reports the old one


class EufyCoordinator(DataUpdateCoordinator[dict]):
    """Poll the Eufy cloud for selected cameras."""

    def __init__(
        self, hass: HomeAssistant, api: EufyApi, cameras: list[str], interval: int = DEFAULT_SCAN_INTERVAL
    ) -> None:
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=timedelta(seconds=interval))
        self.api = api
        self.cameras = cameras
        self.log_properties = False
        self._pending_privacy: dict[str, tuple[bool, float]] = {}
        self._pending_power: dict[str, tuple[bool, float]] = {}

    def vlog(self, msg: str, *args) -> None:
        if self.api.verbose:
            _LOGGER.info("[verbose] " + msg, *args)

    async def async_set_privacy(self, sn: str, enabled: bool) -> None:
        """Write privacy mode to the cloud, show it optimistically and verify on refresh."""
        device = self.data[sn]["device"]
        self.vlog("ACTION privacy %s -> %s (was %s)", sn, enabled, self.data[sn]["privacy"])
        try:
            await self.api.set_privacy(device, enabled)
        except EufyError as err:
            _LOGGER.error("Setting privacy mode for %s failed: %s", sn, err)
            raise
        self._pending_privacy[sn] = (enabled, time.time() + PENDING_TTL)
        self.data[sn]["privacy"] = enabled
        self.async_update_listeners()
        await self.async_request_refresh()

    async def async_set_power(self, sn: str, on: bool) -> None:
        """Write camera power to the cloud, show it optimistically and verify on refresh."""
        self.vlog("ACTION camera power %s -> %s (was %s)", sn, on, self.data[sn]["power"])
        try:
            await self.api.set_camera_power(self.data[sn]["device"], on)
        except EufyError as err:
            _LOGGER.error("Setting camera power for %s failed: %s", sn, err)
            raise
        self._pending_power[sn] = (on, time.time() + PENDING_TTL)
        self.data[sn]["power"] = on
        self.async_update_listeners()
        await self.async_request_refresh()

    async def _async_update_data(self) -> dict:
        self.vlog("SYNC start (interval=%s)", self.update_interval)
        try:
            devices = await self.api.get_cameras()
            events = await self.api.get_events()
        except EufyError as err:
            _LOGGER.warning("Eufy cloud sync failed: %s", err)
            raise UpdateFailed(str(err)) from err
        data: dict = {}
        for dev in devices:
            sn = dev["device_sn"]
            if sn not in self.cameras:
                continue
            mine = [e for e in events if e.get("device_sn") == sn]
            last = max(mine, key=lambda e: e.get("create_time", 0), default=None)
            privacy = privacy_enabled(dev)
            pending = self._pending_privacy.get(sn)
            if pending:
                wanted, expires = pending
                if privacy == wanted:
                    self.vlog("privacy %s confirmed by cloud: %s", sn, privacy)
                    del self._pending_privacy[sn]
                elif time.time() < expires:
                    self.vlog("privacy %s cloud still reports %s, keeping requested %s", sn, privacy, wanted)
                    privacy = wanted
                else:
                    _LOGGER.warning(
                        "Privacy mode of %s was written but the cloud still reports %s; "
                        "the camera did not pick it up", sn, privacy,
                    )
                    del self._pending_privacy[sn]
            power = camera_power_on(dev)
            pend = self._pending_power.get(sn)
            if pend:
                if power == pend[0] or time.time() >= pend[1]:
                    if power != pend[0]:
                        _LOGGER.warning("Camera power of %s was written but the cloud still reports %s", sn, power)
                    del self._pending_power[sn]
                else:
                    self.vlog("power %s cloud still reports %s, keeping requested %s", sn, power, pend[0])
                    power = pend[0]
            data[sn] = {
                "power": power,
                "device": dev,
                "image_url": (last or {}).get("pic_url") or dev.get("cover_path"),
                "last_event": (last or {}).get("create_time", 0),
                "privacy": privacy,
                "now": int(time.time()),
            }
            if self.log_properties:
                _LOGGER.info(
                    "Device properties %s: %s", sn,
                    json.dumps(redact(dev), default=str, sort_keys=True),
                )
            self.vlog(
                "SYNC %s power=%s privacy=%s events=%d last_event=%s image=%s params=%s",
                sn, power, privacy, len(mine), data[sn]["last_event"], data[sn]["image_url"], dev.get("params"),
            )
        self.vlog("SYNC done: %d devices on account, %d events, %d selected", len(devices), len(events), len(data))
        return data
