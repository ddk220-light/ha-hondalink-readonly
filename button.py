from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DATA_COORDINATOR, DOMAIN
from .coordinator import HondaLinkDataUpdateCoordinator
from .entity import HondaLinkEntity


@dataclass(frozen=True, kw_only=True)
class HondaLinkButtonDescription(ButtonEntityDescription):
    press_fn: Callable[[HondaLinkDataUpdateCoordinator], object]


# Read-only fork: the only button asks HondaLink for fresh vehicle data.
BUTTONS: tuple[HondaLinkButtonDescription, ...] = (
    HondaLinkButtonDescription(
        key="refresh",
        translation_key="refresh",
        icon="mdi:refresh",
        press_fn=lambda coordinator: coordinator.async_force_refresh(),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    async_add_entities(HondaLinkButton(coordinator, entry, description) for description in BUTTONS)


class HondaLinkButton(HondaLinkEntity, ButtonEntity):
    entity_description: HondaLinkButtonDescription

    def __init__(
        self,
        coordinator: HondaLinkDataUpdateCoordinator,
        entry: ConfigEntry,
        description: HondaLinkButtonDescription,
    ) -> None:
        super().__init__(coordinator, entry, description.key)
        self.entity_description = description

    async def async_press(self) -> None:
        await self.entity_description.press_fn(self.coordinator)
