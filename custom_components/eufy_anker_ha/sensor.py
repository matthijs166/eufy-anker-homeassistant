"""Wi-Fi sensors for Eufy cameras."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import UnitOfSignalStrength

from .const import DOMAIN
from .entity import EufyEntity

PARAM_WIFI_RSSI = 1142
PARAM_WIFI_NAME = 6200


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        entity
        for sn in coordinator.data
        for entity in (EufyWifiRssi(coordinator, sn), EufyWifiName(coordinator, sn))
    ]
    coordinator.vlog("sensor platform: adding %d entities", len(entities))
    async_add_entities(entities)


def _param_value(device: dict, param_type: int):
    for param in device.get("params") or []:
        if str(param.get("param_type")) == str(param_type):
            return param.get("param_value")
    return None


class EufyWifiRssi(EufyEntity, SensorEntity):
    """Camera Wi-Fi signal strength."""

    _attr_name = "Wi-Fi signal strength"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = UnitOfSignalStrength.DECIBEL_MILLIWATT

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_wifi_rssi"

    @property
    def native_value(self) -> int | float | None:
        value = _param_value(self.info["device"], PARAM_WIFI_RSSI)
        if value is None or value == "":
            return None
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return None
        return int(numeric_value) if numeric_value.is_integer() else numeric_value


class EufyWifiName(EufyEntity, SensorEntity):
    """Connected Wi-Fi network name."""

    _attr_name = "Wi-Fi name"

    def __init__(self, coordinator, sn) -> None:
        super().__init__(coordinator, sn)
        self._attr_unique_id = f"{sn}_wifi_name"

    @property
    def native_value(self) -> str | None:
        value = _param_value(self.info["device"], PARAM_WIFI_NAME)
        return str(value) if value not in (None, "") else None