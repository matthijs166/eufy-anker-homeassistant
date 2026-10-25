"""Data coordinator."""
from __future__ import annotations

from datetime import timedelta
import json
import logging
import time

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import EufyApi, redact, EufyError, PARAM_NIGHT_VISION, privacy_enabled
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
        self._pending_night_vision: dict[str, tuple[str, float]] = {}

    def vlog(self, msg: str, *args) -> None:
        if self.api.verbose:
            _LOGGER.info("[verbose] " + msg, *args)

    async def async_set_privacy(self, sn: str, enabled: bool) -> None:
        """Write privacy mode to the cloud, show it optimistically and verify on refresh."""
        device = self.data[sn]["device"]
        self.vlog("ACTION privacy %s -> %s (was %s)", sn, enabled, self.data[sn]["privacy"])
        previous = self.data[sn]["privacy"]
        self.data[sn]["privacy"] = enabled
        self.async_update_listeners()
        try:
            await self.api.set_privacy(device, enabled)
        except EufyError as err:
            _LOGGER.error("Setting privacy mode for %s failed: %s", sn, err)
            self.data[sn]["privacy"] = previous
            self.async_update_listeners()
            raise
        self._pending_privacy[sn] = (enabled, time.time() + PENDING_TTL)
        self.hass.async_create_task(self.async_request_refresh())

    async def async_set_night_vision(self, sn: str, mode: int) -> None:
        """Write night vision to the cloud and show it optimistically until refreshed."""
        device = self.data[sn]["device"]
        value = str(mode)
        previous = self.data[sn]["night_vision"]
        self.data[sn]["night_vision"] = value
        self.async_update_listeners()
        try:
            await self.api.set_night_vision(device, mode)
        except EufyError:
            self.data[sn]["night_vision"] = previous
            self.async_update_listeners()
            raise
        self._pending_night_vision[sn] = (value, time.time() + PENDING_TTL)
        self.hass.async_create_task(self.async_request_refresh())

    async def async_move_ptz(self, sn: str, direction: str) -> None:
        """Move a camera one step in a cardinal direction."""
        await self.api.move_ptz(self.data[sn]["device"], direction)

    async def async_save_default_ptz_position(self, sn: str) -> None:
        """Save the camera's current position as its default PTZ preset."""
        await self.api.save_default_ptz_position(self.data[sn]["device"])

    async def async_go_to_default_ptz_position(self, sn: str) -> None:
        """Move the camera to its default PTZ preset."""
        await self.api.go_to_default_ptz_position(self.data[sn]["device"])

    async def _async_update_data(self) -> dict:
        self.vlog("SYNC start (interval=%s)", self.update_interval)
        try:
            devices = await self.api.get_cameras()
            events = await self.api.get_events()
        except EufyError as err:
            _LOGGER.warning("Eufy cloud sync failed: %s", err)
            raise UpdateFailed(str(err)) from err
        except Exception as err:  # noqa: BLE001 - never let an unexpected error kill the integration
            _LOGGER.exception("Unexpected error during Eufy cloud sync")
            raise UpdateFailed(f"{type(err).__name__}: {err}") from err
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
            night_vision = next(
                (str(param.get("param_value")) for param in dev.get("params") or []
                 if str(param.get("param_type")) == str(PARAM_NIGHT_VISION)),
                None,
            )
            pending_night_vision = self._pending_night_vision.get(sn)
            if pending_night_vision:
                wanted, expires = pending_night_vision
                if night_vision == wanted or time.time() >= expires:
                    del self._pending_night_vision[sn]
                else:
                    night_vision = wanted
            data[sn] = {
                "night_vision": night_vision,
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
                "SYNC %s privacy=%s events=%d last_event=%s image=%s params=%s",
                sn, privacy, len(mine), data[sn]["last_event"], data[sn]["image_url"], dev.get("params"),
            )
        self.vlog("SYNC done: %d devices on account, %d events, %d selected", len(devices), len(events), len(data))
        return data
