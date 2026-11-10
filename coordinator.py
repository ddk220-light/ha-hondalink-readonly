from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import HondaLinkAPI, HondaLinkAuthError, HondaLinkCooldownError, HondaLinkError
from .const import CONF_SCAN_INTERVAL, CONF_VIN, DEFAULT_SCAN_INTERVAL, DOMAIN
from .util import backoff_minutes, clamp_scan_interval

_LOGGER = logging.getLogger(__name__)


class HondaLinkDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Polls the cached HondaLink dashboard. Read-only: it sends no vehicle commands."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, api: HondaLinkAPI) -> None:
        self.entry = entry
        self.api = api
        self.vin = entry.data[CONF_VIN]
        self.last_refresh_response: dict[str, Any] | None = None
        self._base_minutes = clamp_scan_interval(
            entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        )
        self._failures = 0
        super().__init__(
            hass,
            logging.getLogger(__name__),
            name=DOMAIN,
            update_interval=timedelta(minutes=self._base_minutes),
        )

    def set_base_interval(self, minutes: int) -> None:
        """Apply a new polling interval (from the options flow)."""
        minutes = clamp_scan_interval(minutes)
        if minutes == self._base_minutes:
            # Entry updates also fire for token/sign-in bookkeeping; don't cancel a backoff then.
            return
        self._base_minutes = minutes
        self._failures = 0
        self.update_interval = timedelta(minutes=minutes)

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            data = await self.api.async_get_dashboard_latest(self.vin)
        except HondaLinkAuthError as err:
            # Home Assistant stops polling and asks the user to sign in again; no retry.
            raise ConfigEntryAuthFailed(str(err)) from err
        except HondaLinkError as err:
            self._failures += 1
            self.update_interval = timedelta(
                minutes=backoff_minutes(self._base_minutes, self._failures)
            )
            raise UpdateFailed(str(err)) from err
        finally:
            # Saved on failure too, so sign-in attempts count against the budget after a restart.
            self._persist_auth_data()
        self._failures = 0
        self.update_interval = timedelta(minutes=self._base_minutes)
        return data

    def _persist_auth_data(self) -> None:
        auth_data = self.api.export_auth_data()
        if any(self.entry.data.get(k) != v for k, v in auth_data.items()):
            self.hass.config_entries.async_update_entry(
                self.entry, data={**self.entry.data, **auth_data}
            )

    async def async_force_refresh(self) -> None:
        try:
            result = await self.api.async_request_dashboard_update(self.vin)
            self.last_refresh_response = result.response
        except HondaLinkCooldownError as err:
            _LOGGER.info("HondaLink refresh ignored, cooling down: %s", err)
        except HondaLinkError as err:
            _LOGGER.warning("HondaLink live dashboard refresh request failed: %s", err)
        await self.async_refresh()
