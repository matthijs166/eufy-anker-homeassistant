"""Eufy Anker cameras integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

import logging

from .api import EufyApi

from .const import (
    CONF_AUTH, CONF_CAMERAS, CONF_EMAIL, CONF_LOG_PROPERTIES, CONF_PASSWORD, CONF_SCAN_INTERVAL, CONF_VERBOSE,
    DEFAULT_SCAN_INTERVAL, DOMAIN, PACKAGE_LOGGER, PLATFORMS,
)
from .coordinator import EufyCoordinator


_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    verbose = entry.options.get(CONF_VERBOSE, entry.data.get(CONF_VERBOSE, False))
    interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    # Verbose records are INFO; lower the package logger so they reach the HA log.
    logging.getLogger(PACKAGE_LOGGER).setLevel(logging.INFO if verbose else logging.NOTSET)
    if verbose:
        _LOGGER.info(
            "[verbose] setup entry %s: cameras=%s interval=%ss options=%s",
            entry.entry_id, entry.options.get(CONF_CAMERAS, entry.data.get(CONF_CAMERAS)), interval, dict(entry.options),
        )
    api = EufyApi(
        async_get_clientsession(hass),
        entry.data[CONF_EMAIL],
        entry.data[CONF_PASSWORD],
        entry.data.get(CONF_AUTH),
        verbose=verbose,
        country=hass.config.country or "US",
    )
    cameras = entry.options.get(CONF_CAMERAS, entry.data.get(CONF_CAMERAS, []))
    entry.async_on_unload(lambda: logging.getLogger(PACKAGE_LOGGER).setLevel(logging.NOTSET))
    coordinator = EufyCoordinator(hass, api, cameras, interval)
    coordinator.log_properties = entry.options.get(CONF_LOG_PROPERTIES, False)
    await coordinator.async_config_entry_first_refresh()
    coordinator.vlog("first refresh done, forwarding platforms %s", PLATFORMS)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    entry.async_on_unload(entry.add_update_listener(_reload))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.data[DOMAIN][entry.entry_id].vlog("options changed, reloading entry: %s", dict(entry.options))
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hass.data[DOMAIN][entry.entry_id].vlog("unloading entry %s", entry.entry_id)
    if ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
    return ok
