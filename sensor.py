from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfLength,
    UnitOfPressure,
    UnitOfSpeed,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DATA_COORDINATOR, DOMAIN
from .entity import HondaLinkEntity
from .util import (
    find_12v_battery_status,
    get_path,
    maintenance_messages,
    parse_iso_datetime,
    status_body,
    to_float,
    to_int,
)


@dataclass(frozen=True, kw_only=True)
class HondaLinkSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict[str, Any]], Any]
    attr_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None


def _tire(path: str):
    return lambda body: to_int(get_path(body, f"tireStatus.{path}.pressureData.value"))


SENSORS: tuple[HondaLinkSensorDescription, ...] = (
    HondaLinkSensorDescription(
        key="fuel_level",
        translation_key="fuel_level",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:gas-station",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda body: to_int(get_path(body, "fuelLevel.currentLevel.value")),
    ),
    HondaLinkSensorDescription(
        key="range",
        translation_key="range",
        native_unit_of_measurement=UnitOfLength.MILES,
        device_class=SensorDeviceClass.DISTANCE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda body: to_int(get_path(body, "fuelLevel.driveRange.value")),
    ),
    HondaLinkSensorDescription(
        key="odometer",
        translation_key="odometer",
        native_unit_of_measurement=UnitOfLength.MILES,
        device_class=SensorDeviceClass.DISTANCE,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda body: to_int(get_path(body, "odometer.value")),
    ),
    HondaLinkSensorDescription(
        key="oil_life",
        translation_key="oil_life",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda body: to_int(get_path(body, "oilLife.value")),
    ),
    HondaLinkSensorDescription(
        key="maintenance_items",
        translation_key="maintenance_items",
        icon="mdi:wrench-clock",
        value_fn=lambda body: (
            None if (messages := maintenance_messages(body)) is None else len(messages)
        ),
        attr_fn=lambda body: {"messages": maintenance_messages(body) or []},
    ),
    HondaLinkSensorDescription(
        key="12v_battery_status",
        translation_key="12v_battery_status",
        value_fn=find_12v_battery_status,
    ),
    HondaLinkSensorDescription(
        key="front_left_tire_pressure",
        translation_key="front_left_tire_pressure",
        native_unit_of_measurement=UnitOfPressure.KPA,
        device_class=SensorDeviceClass.PRESSURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_tire("frontLeft"),
    ),
    HondaLinkSensorDescription(
        key="front_right_tire_pressure",
        translation_key="front_right_tire_pressure",
        native_unit_of_measurement=UnitOfPressure.KPA,
        device_class=SensorDeviceClass.PRESSURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_tire("frontRight"),
    ),
    HondaLinkSensorDescription(
        key="rear_left_tire_pressure",
        translation_key="rear_left_tire_pressure",
        native_unit_of_measurement=UnitOfPressure.KPA,
        device_class=SensorDeviceClass.PRESSURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_tire("rearLeft"),
    ),
    HondaLinkSensorDescription(
        key="rear_right_tire_pressure",
        translation_key="rear_right_tire_pressure",
        native_unit_of_measurement=UnitOfPressure.KPA,
        device_class=SensorDeviceClass.PRESSURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_tire("rearRight"),
    ),
    HondaLinkSensorDescription(
        key="cabin_temperature",
        translation_key="cabin_temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda body: to_float(get_path(body, "temperature.cabin.value")),
    ),
    HondaLinkSensorDescription(
        key="vehicle_speed",
        translation_key="vehicle_speed",
        native_unit_of_measurement=UnitOfSpeed.MILES_PER_HOUR,
        device_class=SensorDeviceClass.SPEED,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda body: to_float(get_path(body, "gpsData.velocity.value")),
    ),
    HondaLinkSensorDescription(
        key="remote_engine_status",
        translation_key="remote_engine_status",
        value_fn=lambda body: get_path(body, "remoteEngineStart.vehicleStartEvent.resStatus"),
    ),
    HondaLinkSensorDescription(
        key="last_update",
        translation_key="last_update",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda body: parse_iso_datetime(get_path(body, "timestamp")),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    entities: list[SensorEntity] = [
        HondaLinkSensor(coordinator, entry, description) for description in SENSORS
    ]
    entities.append(HondaLinkLoginsTodaySensor(coordinator, entry))
    async_add_entities(entities)


class HondaLinkSensor(HondaLinkEntity, SensorEntity):
    entity_description: HondaLinkSensorDescription

    def __init__(
        self, coordinator, entry: ConfigEntry, description: HondaLinkSensorDescription
    ) -> None:
        super().__init__(coordinator, entry, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(status_body(self.coordinator.data or {}))

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attr_fn is None:
            return None
        return self.entity_description.attr_fn(status_body(self.coordinator.data or {}))


LOGINS_TODAY_DESCRIPTION = SensorEntityDescription(
    key="logins_today",
    translation_key="logins_today",
    entity_category=EntityCategory.DIAGNOSTIC,
    state_class=SensorStateClass.MEASUREMENT,
    icon="mdi:login",
)


class HondaLinkLoginsTodaySensor(HondaLinkEntity, SensorEntity):
    """Password sign-ins in the last 24 hours (read from the API client, not the dashboard)."""

    entity_description: SensorEntityDescription

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, LOGINS_TODAY_DESCRIPTION.key)
        self.entity_description = LOGINS_TODAY_DESCRIPTION

    @property
    def native_value(self) -> int:
        return self.coordinator.api.logins_last_day()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"failed": self.coordinator.api.login_failures_last_day()}
