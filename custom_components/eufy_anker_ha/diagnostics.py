"""Diagnostics download."""
from __future__ import annotations

from homeassistant.components.diagnostics import async_redact_data

from .const import DOMAIN
from .describe import describe_device

TO_REDACT = {"password", "token", "auth", "share_key", "key_ident", "email"}


async def async_get_config_entry_diagnostics(hass, entry):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    return {
        "entry": async_redact_data({**entry.data, "options": dict(entry.options)}, TO_REDACT),
        "devices": {sn: describe_device(d["device"]) for sn, d in (coordinator.data or {}).items()},
    }
