from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .const import (
    DEFAULT_SCAN_INTERVAL,
    LEGACY_COMMAND_KEYS,
    MAX_BACKOFF_INTERVAL,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
)


def clamp_scan_interval(value: Any) -> int:
    """Polling interval in whole minutes, clamped to [MIN_SCAN_INTERVAL, MAX_SCAN_INTERVAL]."""
    if isinstance(value, bool):
        return DEFAULT_SCAN_INTERVAL
    try:
        number = float(value)
    except (TypeError, ValueError):
        return DEFAULT_SCAN_INTERVAL
    if math.isnan(number):
        return DEFAULT_SCAN_INTERVAL
    if number <= MIN_SCAN_INTERVAL:
        return MIN_SCAN_INTERVAL
    if number >= MAX_SCAN_INTERVAL:
        return MAX_SCAN_INTERVAL
    return int(number)


def backoff_minutes(base: int, failures: int) -> int:
    """Poll interval after consecutive failures: base, then x2, then x4, capped."""
    if failures <= 0:
        factor = 1
    elif failures == 1:
        factor = 2
    else:
        factor = 4
    return min(base * factor, max(base, MAX_BACKOFF_INTERVAL))


def strip_legacy_command_keys(mapping: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    """Copy of mapping without keys (remote PIN, lock codes) that other forks stored."""
    cleaned = {key: value for key, value in mapping.items() if key not in LEGACY_COMMAND_KEYS}
    return cleaned, len(cleaned) != len(mapping)


def get_path(data: dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = data
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
        if cur is None:
            return default
    return cur


def status_body(data: dict[str, Any]) -> dict[str, Any]:
    body = data.get("responseBody")
    return body if isinstance(body, dict) else {}


def to_int(value: Any) -> int | None:
    try:
        if value in (None, "", "unknown"):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def to_float(value: Any) -> float | None:
    try:
        if value in (None, "", "unknown"):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def first_path(data: dict[str, Any], paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = get_path(data, path)
        if value not in (None, "", "unknown"):
            return value
    return None


def value_from_status_node(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in (
        "status",
        "state",
        "condition",
        "value",
        "text",
        "displayValue",
        "message",
        "messageText",
        "statusText",
        "displayText",
        "description",
    ):
        item = value.get(key)
        if item not in (None, "", "unknown"):
            return value_from_status_node(item)
    return None


def find_12v_battery_status(data: dict[str, Any]) -> Any:
    warning_lamp_status = _find_12v_warning_lamp_status(data)
    if warning_lamp_status not in (None, "", "unknown"):
        return warning_lamp_status

    direct = first_path(
        data,
        (
            "12VBatteryStatus",
            "12VBattery.status",
            "12VBattery.value",
            "twelveVoltBatteryStatus",
            "twelveVoltBattery.status",
            "twelveVoltBattery.value",
            "auxBatteryStatus",
            "auxBattery.status",
            "auxBattery.value",
            "auxiliaryBatteryStatus",
            "auxiliaryBattery.status",
            "auxiliaryBattery.value",
            "battery12VStatus",
            "battery12V.status",
            "battery12V.value",
            "batteryStatus12V",
            "batteryVoltageStatus",
            "batteryStatus.batteryVoltageStatus",
            "batteryStatus.batteryChargeStatus",
            "batteryStatus.status",
            "batteryStatus.value",
        ),
    )
    if direct not in (None, "", "unknown"):
        return value_from_status_node(direct)
    text_status = _find_12v_text_status(data)
    if text_status not in (None, "", "unknown"):
        return text_status
    return _find_12v_battery_status(data)


def _find_12v_warning_lamp_status(data: dict[str, Any]) -> Any:
    for group in get_path(data, "warningLamps.data", []) or []:
        if not isinstance(group, dict):
            continue
        for message in group.get("messages", []) or []:
            if not isinstance(message, dict):
                continue
            text = " ".join(str(value) for value in message.values() if isinstance(value, str))
            text_lower = text.lower()
            has_12v = "12v" in text_lower or "12 v" in text_lower or "12 volt" in text_lower
            has_battery = "battery" in text_lower or "batt" in text_lower
            if has_12v and has_battery:
                return (
                    message.get("condition")
                    or message.get("status")
                    or message.get("state")
                    or message.get("value")
                    or message.get("message")
                    or message.get("messageText")
                    or message.get("text")
                    or "Detected"
                )
    return None


def _find_12v_text_status(value: Any) -> Any:
    if isinstance(value, dict):
        text = " ".join(str(item) for item in value.values() if isinstance(item, str))
        if _text_mentions_12v_battery(text):
            status = value_from_status_node(value)
            if status not in (None, "", "unknown") and not _text_mentions_12v_battery(str(status)):
                return status
            for key in (
                "normal",
                "ok",
                "active",
                "on",
                "off",
                "severity",
                "alertState",
                "lampState",
                "indicator",
                "available",
            ):
                item = value.get(key)
                if item not in (None, "", "unknown"):
                    return item
            return "Detected"
        for item in value.values():
            status = _find_12v_text_status(item)
            if status not in (None, "", "unknown"):
                return status
    elif isinstance(value, list):
        for item in value:
            status = _find_12v_text_status(item)
            if status not in (None, "", "unknown"):
                return status
    elif isinstance(value, str) and _text_mentions_12v_battery(value):
        return value
    return None


def _find_12v_battery_status(value: Any) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            if _looks_like_12v_battery_key(str(key)):
                status = value_from_status_node(item)
                if status not in (None, "", "unknown"):
                    return status
            status = _find_12v_battery_status(item)
            if status not in (None, "", "unknown"):
                return status
    if isinstance(value, list):
        for item in value:
            status = _find_12v_battery_status(item)
            if status not in (None, "", "unknown"):
                return status
    return None


def _looks_like_12v_battery_key(key: str) -> bool:
    key_lower = key.lower()
    has_12v = (
        "12v" in key_lower
        or "12_v" in key_lower
        or "twelvevolt" in key_lower
        or "twelve_volt" in key_lower
    )
    has_battery = "battery" in key_lower or "batt" in key_lower
    has_voltage = "volt" in key_lower
    has_status = "status" in key_lower or "state" in key_lower or "condition" in key_lower
    has_aux = "aux" in key_lower or "auxiliary" in key_lower
    has_power_supply = "powersupply" in key_lower or "power_supply" in key_lower
    return (
        has_12v
        or (has_aux and (has_battery or has_voltage or has_status))
        or (has_battery and (has_status or has_voltage))
        or (has_voltage and has_status)
        or has_power_supply
    )


def _text_mentions_12v_battery(text: str) -> bool:
    text_lower = text.lower()
    has_12v = "12v" in text_lower or "12 v" in text_lower or "12 volt" in text_lower
    has_battery = "battery" in text_lower or "batt" in text_lower
    return has_12v and has_battery


def parse_iso_datetime(value: Any) -> datetime | None:
    if not value or value == "unknown":
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def dms_to_decimal(value: Any) -> float | None:
    if not value or value == "unknown":
        return None
    try:
        parts = str(value).split(",")
        if len(parts) != 3:
            return None
        degrees = float(parts[0])
        sign = -1 if degrees < 0 else 1
        minutes = float(parts[1])
        seconds = float(parts[2])
        return sign * (abs(degrees) + minutes / 60 + seconds / 3600)
    except (TypeError, ValueError):
        return None


def all_door_locks_locked(body: dict[str, Any]) -> bool | None:
    doors = get_path(body, "doorStatus", {})
    if not isinstance(doors, dict):
        return None
    states = [
        str(get_path(doors, f"{key}.lockState") or "").lower()
        for key in ("firstRowDriver", "firstRowPassenger", "secondRowDriver", "secondRowPassenger")
    ]
    if "unlock" in states:
        return False
    if all(state == "lock" for state in states):
        return True
    return None


def engine_running(body: dict[str, Any]) -> bool | None:
    """Honda reports "OFF", "ON", or "IG RUN" (ignition running); anything but OFF means running."""
    status = (
        str(get_path(body, "remoteEngineStart.vehicleStartEvent.resStatus") or "").strip().upper()
    )
    if status in ("", "UNKNOWN"):
        return None
    return status != "OFF"


def maintenance_messages(body: dict[str, Any]) -> list[Any] | None:
    """Maintenance Minder messages; the live refresh nests them differently than the cached poll."""
    minder = get_path(body, "maintenanceMinder")
    if not isinstance(minder, dict):
        return None
    groups = [minder, *(item for item in minder.get("data") or [] if isinstance(item, dict))]
    return [message for group in groups for message in group.get("messages") or []]


def any_open_state(
    body: dict[str, Any], base: str, keys: list[str], state_key: str = "openState"
) -> bool | None:
    found = False
    for key in keys:
        value = get_path(body, f"{base}.{key}.{state_key}")
        # a cloud blip reports "unknown" for every door at once; that's no reading, not "open"
        if value is not None and str(value).strip().lower() not in ("", "unknown"):
            found = True
            if str(value).lower() != "closed":
                return True
    return False if found else None


def any_light_on(body: dict[str, Any]) -> bool | None:
    lights = get_path(body, "lightStatus", {})
    if not isinstance(lights, dict):
        return None
    found = False
    for item in lights.values():
        if isinstance(item, dict) and str(item.get("lightState") or "").strip().upper() not in (
            "",
            "UNKNOWN",
        ):
            found = True
            if str(item.get("lightState")).upper() != "OFF":
                return True
    return False if found else None
