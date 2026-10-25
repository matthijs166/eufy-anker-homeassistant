"""Base entity."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import EufyCoordinator


class EufyEntity(CoordinatorEntity[EufyCoordinator]):
    """Entity bound to one camera."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: EufyCoordinator, sn: str) -> None:
        super().__init__(coordinator)
        self.sn = sn
        coordinator.vlog("entity created: %s for %s", type(self).__name__, sn)
        dev = coordinator.data[sn]["device"]
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, sn)},
            name=dev.get("device_name", sn),
            manufacturer="Eufy",
            model=dev.get("device_model"),
        )

    @property
    def available(self) -> bool:
        return super().available and self.sn in self.coordinator.data

    def _handle_coordinator_update(self) -> None:
        self.coordinator.vlog("entity update: %s %s", type(self).__name__, self.sn)
        super()._handle_coordinator_update()

    @property
    def info(self) -> dict:
        return self.coordinator.data[self.sn]
