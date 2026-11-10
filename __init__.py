from __future__ import annotations

import uuid

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import HondaLinkAPI, HondaLinkAuthError, HondaLinkError
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_CLIENT_REG_KEY,
    CONF_COUNTRY,
    CONF_DEVICE_ID,
    CONF_EMAIL,
    CONF_EXPIRES_AT,
    CONF_HIDAS_IDENT,
    CONF_LANGUAGE,
    CONF_LOGIN_FAILURES,
    CONF_LOGIN_TIMES,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_SCAN_INTERVAL,
    CONF_SESSION_ID,
    CONF_VIN,
    DATA_API,
    DATA_COORDINATOR,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .coordinator import HondaLinkDataUpdateCoordinator
from .util import strip_legacy_command_keys

# Read-only: no lock platform and no command buttons.
PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.DEVICE_TRACKER,
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    # Delete a remote PIN / lock command codes that other forks may have stored in this entry.
    data, data_stripped = strip_legacy_command_keys(entry.data)
    options, options_stripped = strip_legacy_command_keys(entry.options)
    if data_stripped or options_stripped:
        hass.config_entries.async_update_entry(entry, data=data, options=options)

    changed = False
    if not data.get(CONF_DEVICE_ID):
        data[CONF_DEVICE_ID] = str(uuid.uuid4())
        changed = True
    if not data.get(CONF_SESSION_ID):
        data[CONF_SESSION_ID] = str(uuid.uuid4())
        changed = True
    if changed:
        hass.config_entries.async_update_entry(entry, data=data)

    session = async_create_clientsession(hass, cookie_jar=aiohttp.CookieJar())
    api = HondaLinkAPI(
        session,
        email=data[CONF_EMAIL],
        password=data[CONF_PASSWORD],
        vin=data[CONF_VIN],
        client_reg_key=data.get(CONF_CLIENT_REG_KEY),
        access_token=data.get(CONF_ACCESS_TOKEN),
        refresh_token=data.get(CONF_REFRESH_TOKEN),
        expires_at=data.get(CONF_EXPIRES_AT),
        country=data.get(CONF_COUNTRY, "US"),
        language=data.get(CONF_LANGUAGE, "en"),
        hidas_ident=data.get(CONF_HIDAS_IDENT),
        device_id=data[CONF_DEVICE_ID],
        session_id=data[CONF_SESSION_ID],
        login_times=data.get(CONF_LOGIN_TIMES),
        login_failures=data.get(CONF_LOGIN_FAILURES),
    )
    try:
        await api.async_ensure_login()
    except HondaLinkAuthError as err:
        _persist_auth_data(hass, entry, api)
        await session.close()
        raise ConfigEntryAuthFailed(str(err)) from err
    except HondaLinkError as err:
        _persist_auth_data(hass, entry, api)
        await session.close()
        raise ConfigEntryNotReady(str(err)) from err

    _persist_auth_data(hass, entry, api)

    coordinator = HondaLinkDataUpdateCoordinator(hass, entry, api)
    try:
        await coordinator.async_config_entry_first_refresh()
    except BaseException:
        await session.close()
        raise

    hass.data[DOMAIN][entry.entry_id] = {
        DATA_API: api,
        DATA_COORDINATOR: coordinator,
    }

    entry.async_on_unload(entry.add_update_listener(_async_entry_updated))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


def _persist_auth_data(hass: HomeAssistant, entry: ConfigEntry, api: HondaLinkAPI) -> None:
    """Save tokens and sign-in attempt times (the latter so the budget survives restarts)."""
    auth_data = api.export_auth_data()
    if any(entry.data.get(key) != value for key, value in auth_data.items()):
        hass.config_entries.async_update_entry(entry, data={**entry.data, **auth_data})


async def _async_entry_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Apply options changes to the running coordinator.

    Applied in place (rather than reloading the entry) because setup itself
    updates entry.data with refreshed tokens, which would retrigger a
    reload-on-update listener.
    """
    bucket = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if not bucket:
        return
    bucket[DATA_COORDINATOR].set_base_interval(
        entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    )


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        bucket = hass.data[DOMAIN].pop(entry.entry_id, None)
        if bucket:
            await bucket[DATA_API].session.close()
    return unload_ok
