from __future__ import annotations

import logging
import uuid
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HondaLinkAPI, HondaLinkAuthError, HondaLinkError, HondaLinkLoginBudgetError
from .const import (
    CONF_EMAIL,
    CONF_LOGIN_FAILURES,
    CONF_LOGIN_TIMES,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_VEHICLE_INFO,
    CONF_VIN,
    DEFAULT_NAME,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
)
from .util import clamp_scan_interval, strip_legacy_command_keys

_LOGGER = logging.getLogger(__name__)


def _vehicle_title(vehicle: dict[str, Any] | None, vin: str, custom_name: str | None = None) -> str:
    if custom_name:
        return custom_name
    vehicle = vehicle or {}
    alias = vehicle.get("Alias Name") or vehicle.get("alias")
    if alias:
        return str(alias)
    year = vehicle.get("ModelYear")
    model = vehicle.get("ModelGroupNameFriendly") or vehicle.get("ModelCode")
    if year and model:
        return f"{year} Honda {model}"
    return f"{DEFAULT_NAME} {vin[-6:]}"


def _vehicle_label(vehicle: dict[str, Any]) -> str:
    vin = vehicle.get("VIN", "")
    title = _vehicle_title(vehicle, vin)
    return f"{title} ({vin})"


class HondaLinkConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._api: HondaLinkAPI | None = None
        self._base_data: dict[str, Any] = {}
        self._vehicles: list[dict[str, Any]] = []
        self._custom_name: str | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            password = user_input[CONF_PASSWORD]
            vin = user_input.get(CONF_VIN, "").strip().upper()
            self._custom_name = user_input.get(CONF_NAME, "").strip() or None
            device_id = str(uuid.uuid4())
            session_id = str(uuid.uuid4())

            session = async_get_clientsession(self.hass)
            api = HondaLinkAPI(
                session,
                email=email,
                password=password,
                vin=vin or None,
                device_id=device_id,
                session_id=session_id,
            )

            try:
                await api.async_login()
                vehicles = await api.async_get_vehicles()
            except HondaLinkAuthError:
                _LOGGER.warning("HondaLink authentication failed during config flow")
                errors["base"] = "invalid_auth"
            except HondaLinkLoginBudgetError:
                _LOGGER.warning("HondaLink sign-in skipped during config flow: too many attempts")
                errors["base"] = "too_many_attempts"
            except HondaLinkError as err:
                _LOGGER.warning(
                    "HondaLink connection failed during config flow (%s)", type(err).__name__
                )
                errors["base"] = "cannot_connect"
            except Exception as err:
                # No traceback or message: it could carry account details or raw responses.
                _LOGGER.error("Unexpected HondaLink config flow error (%s)", type(err).__name__)
                errors["base"] = "unknown"
            else:
                vehicle_info: dict[str, Any] | None = None
                if vin:
                    vehicle_info = next((item for item in vehicles if item.get("VIN") == vin), None)
                    if vehicle_info is None:
                        try:
                            vehicle_info = await api.async_get_vehicle_by_vin(vin)
                        except HondaLinkError as err:
                            _LOGGER.warning(
                                "HondaLink VIN lookup failed during config flow (%s)",
                                type(err).__name__,
                            )
                            vehicle_info = None
                elif len(vehicles) == 1:
                    vehicle_info = vehicles[0]
                    vin = str(vehicle_info.get("VIN", "")).upper()
                    api.vin = vin
                elif len(vehicles) > 1:
                    self._api = api
                    self._vehicles = vehicles
                    self._base_data = self._entry_data(api, email, password, "", None)
                    return await self.async_step_vehicle()
                else:
                    errors["base"] = "vin_required"

                if not errors:
                    if not vin:
                        errors["base"] = "vin_required"
                    else:
                        api.vin = vin
                        return await self._async_create_vehicle_entry(
                            api, email, password, vin, vehicle_info
                        )

        schema = vol.Schema(
            {
                vol.Required(CONF_EMAIL): str,
                vol.Required(CONF_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Optional(CONF_VIN, default=""): str,
                vol.Optional(CONF_NAME, default=""): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, entry_data: dict[str, Any]):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None):
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if entry is None:
            return self.async_abort(reason="unknown")
        errors: dict[str, str] = {}
        if user_input is not None:
            api = HondaLinkAPI(
                async_get_clientsession(self.hass),
                email=entry.data[CONF_EMAIL],
                password=user_input[CONF_PASSWORD],
                vin=entry.data[CONF_VIN],
                # Carry the stored attempts so re-entering a password can't bypass the budget.
                login_times=entry.data.get(CONF_LOGIN_TIMES),
                login_failures=entry.data.get(CONF_LOGIN_FAILURES),
            )
            try:
                await api.async_login()
                vehicles = await api.async_get_vehicles()
                if not any(
                    v.get("VIN", "").upper() == entry.data[CONF_VIN].upper() for v in vehicles
                ):
                    errors["base"] = "vehicle_not_found"
            except HondaLinkAuthError:
                errors["base"] = "invalid_auth"
            except HondaLinkLoginBudgetError:
                errors["base"] = "too_many_attempts"
            except HondaLinkError:
                errors["base"] = "cannot_connect"
            if errors:
                # Record this attempt even though it failed. Only the attempt times are saved:
                # the stored tokens and password are left as they were.
                auth_data = api.export_auth_data()
                attempts = {key: auth_data[key] for key in (CONF_LOGIN_TIMES, CONF_LOGIN_FAILURES)}
                if any(entry.data.get(key) != value for key, value in attempts.items()):
                    self.hass.config_entries.async_update_entry(
                        entry, data={**entry.data, **attempts}
                    )
            else:
                self.hass.config_entries.async_update_entry(
                    entry,
                    data={
                        **strip_legacy_command_keys(entry.data)[0],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        **api.export_auth_data(),
                    },
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_vehicle(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        vehicles_by_vin = {item["VIN"]: item for item in self._vehicles if item.get("VIN")}

        if user_input is not None:
            vin = user_input[CONF_VIN]
            vehicle_info = vehicles_by_vin.get(vin)
            if self._api is None:
                errors["base"] = "unknown"
            else:
                self._api.vin = vin
                data = {**self._base_data, CONF_VIN: vin, CONF_VEHICLE_INFO: vehicle_info or {}}
                await self.async_set_unique_id(vin)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=_vehicle_title(vehicle_info, vin, self._custom_name),
                    data=data,
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_VIN): vol.In(
                    {vin: _vehicle_label(vehicle) for vin, vehicle in vehicles_by_vin.items()}
                )
            }
        )
        return self.async_show_form(step_id="vehicle", data_schema=schema, errors=errors)

    async def _async_create_vehicle_entry(
        self,
        api: HondaLinkAPI,
        email: str,
        password: str,
        vin: str,
        vehicle_info: dict[str, Any] | None,
    ):
        await self.async_set_unique_id(vin)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=_vehicle_title(vehicle_info, vin, self._custom_name),
            data=self._entry_data(api, email, password, vin, vehicle_info),
        )

    def _entry_data(
        self,
        api: HondaLinkAPI,
        email: str,
        password: str,
        vin: str,
        vehicle_info: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            CONF_EMAIL: email,
            CONF_PASSWORD: password,
            CONF_VIN: vin,
            CONF_VEHICLE_INFO: vehicle_info or {},
            # Tokens plus the sign-in attempt history, so the first sign-in counts too.
            **api.export_auth_data(),
        }

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return HondaLinkOptionsFlowHandler()


class HondaLinkOptionsFlowHandler(config_entries.OptionsFlow):
    """Only the polling interval is configurable; there are no command settings."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=clamp_scan_interval(
                        options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
                    ),
                ): vol.All(
                    vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL)
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
