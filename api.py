"""HondaLink cloud client for a HARD read-only Home Assistant integration.

This fork is read-only by design. It cannot lock or unlock the car, start or stop the engine,
sound the horn or flash the lights, and it never asks for, stores or sends the HondaLink remote
PIN. Those capabilities were removed rather than disabled.

As a second line of defence, every HondaLink API request passes through ``_request_api``, which
checks the (method, path) pair against a small allowlist of read-only endpoints (vehicle list,
latest dashboard, dashboard refresh and its result) BEFORE signing in or touching the network,
and refuses any JSON body containing a ``pin`` key. A future edit, a merge from another fork, or
a crafted VIN therefore cannot turn this client into one that sends remote commands.

To be gentle on the Honda account, password sign-ins are rate-limited by two persisted budgets
(circuit breakers): a strict one for failed sign-ins, which are what can lock an account, and a
looser loop guard for all sign-ins. The live "Refresh" request has a cooldown.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiohttp

from .const import (
    API_BASE,
    APP_USER_AGENT,
    CLIENT_ID,
    CLIENT_SECRET,
    CONF_ACCESS_TOKEN,
    CONF_CLIENT_REG_KEY,
    CONF_COUNTRY,
    CONF_DEVICE_ID,
    CONF_EXPIRES_AT,
    CONF_HIDAS_IDENT,
    CONF_LANGUAGE,
    CONF_LOGIN_FAILURES,
    CONF_LOGIN_TIMES,
    CONF_REFRESH_TOKEN,
    CONF_SESSION_ID,
    DASHBOARD_FILTER_SETS,
    DEFAULT_COUNTRY,
    DEFAULT_LANGUAGE,
    DEVICE_DESCRIPTION,
    HONDA_HEADER_VERSION,
    HONDALINK_BUSINESS_ID,
    HONDALINK_SYSTEM_ID,
    IDENTITY_BASE,
    LOGIN_BUDGET_DAY,
    LOGIN_BUDGET_HOUR,
    LOGIN_FAILURE_BUDGET_DAY,
    LOGIN_FAILURE_BUDGET_HOUR,
    REFRESH_COOLDOWN_SECONDS,
)

_INVALID_SCOPE_ERROR_CODE = "0001-01-1150"
_COMMAND_SUCCESS = {"success", "completed", "complete", "ok"}
_COMMAND_PENDING = {"in_progress", "pending", "queued", "accepted", "processing"}
_COMMAND_FAILURE = {"failure", "failed", "error", "rejected", "denied", "expired", "cancelled"}
# Only structured vendor error codes, never free-form strings or bare PINs.
_ERROR_CODE = re.compile(r"(?:[1-5][0-9]{2}|[0-9]{4}-[0-9]{2}-[0-9]{4}|0x[0-9a-fA-F]{8})")

_HOUR_SECONDS = 3600
_DAY_SECONDS = 86400

# Read-only request allowlist, checked with fullmatch on the exact upper-case method. The
# character classes exclude "/", "?", "#" and whitespace (and "." from the VIN), so "..", query
# strings, fragments and extra path segments cannot match. Do NOT add command endpoints here.
_VIN_PATTERN = r"[A-Za-z0-9]{11,17}"
# 1-128 chars; must start alphanumeric and may not contain "..", so no dot segments.
_REQUEST_ID_PATTERN = r"(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_ALLOWED_REQUESTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GET", re.compile(rf"/REST/NGT/MyVehicle/1\.0(?:/{_VIN_PATTERN})?")),
    ("POST", re.compile(rf"/REST/NGT/CIG/dbd/latest/{_VIN_PATTERN}")),
    ("POST", re.compile(r"/REST/NGT/CIG/dbd/async")),
    ("GET", re.compile(rf"/REST/NGT/CIG/dbd/results/{_REQUEST_ID_PATTERN}")),
)


class HondaLinkError(Exception):
    pass


class HondaLinkAuthError(HondaLinkError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class HondaLinkCommandError(HondaLinkError):
    """The dashboard Refresh request failed (the only "command" this fork can send)."""


class HondaLinkLoginBudgetError(HondaLinkError):
    """The password sign-in budget is exhausted; no request was sent."""


class HondaLinkCooldownError(HondaLinkError):
    """Refresh was requested again too soon; no request was sent."""


class HondaLinkReadOnlyError(HondaLinkError):
    """A request outside the read-only allowlist was attempted; nothing was sent."""


@dataclass
class HondaLinkCommandResult:
    request_id: str | None
    response: dict[str, Any]


def utc_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _lower_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_invalid_scope_error(err: Exception) -> bool:
    text = str(err)
    return _INVALID_SCOPE_ERROR_CODE in text or "requested scope is invalid" in text.lower()


def _redact_payload(value: Any) -> str:
    """Never include remote text or vehicle/account data in exceptions.

    Only constrained vendor error codes and known status values are disclosed.
    Even an errorMessage can echo a password, VIN, PIN, or location.
    """
    codes: set[str] = set()
    statuses: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower() == "errorcode" and isinstance(child, (str, int)):
                    if _ERROR_CODE.fullmatch(str(child)):
                        codes.add(str(child))
                elif str(key).lower() in {"status", "commandstatus", "request_status"}:
                    status = _lower_status(child)
                    if status in _COMMAND_SUCCESS | _COMMAND_PENDING | _COMMAND_FAILURE:
                        statuses.add(status)
                elif isinstance(child, (dict, list)):
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    parts = []
    if codes:
        parts.append("error codes: " + ", ".join(sorted(codes)))
    if statuses:
        parts.append("status: " + ", ".join(sorted(statuses)))
    return "; ".join(parts) if parts else "response details omitted"


def _is_allowed_request(method: str, path: str) -> bool:
    if not isinstance(method, str) or not isinstance(path, str):
        return False
    return any(
        method == allowed_method and pattern.fullmatch(path)
        for allowed_method, pattern in _ALLOWED_REQUESTS
    )


def _contains_pin_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            (isinstance(key, str) and key.lower() == "pin") or _contains_pin_key(child)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_pin_key(child) for child in value)
    return False


def _sanitize_login_times(values: Any, now: float) -> list[float]:
    """Keep numeric sign-in timestamps from the last 24 h; future ones are clamped to now."""
    if not isinstance(values, (list, tuple)):
        return []
    result: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        stamp = float(value)
        if stamp != stamp or stamp in (float("inf"), float("-inf")):
            continue
        stamp = min(stamp, now)
        if stamp > now - _DAY_SECONDS:
            result.append(stamp)
    result.sort()
    return result


def _command_status(data: dict[str, Any]) -> str:
    """An HTTP/API envelope success does not mean the vehicle command finished."""
    outer = _lower_status(data.get("status"))
    body = data.get("responseBody")
    if not isinstance(body, dict) or outer in _COMMAND_FAILURE:
        return outer
    return _lower_status(body.get("commandStatus") or body.get("status")) or outer


class HondaLinkAPI:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        email: str,
        password: str,
        vin: str | None = None,
        client_reg_key: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        expires_at: float | None = None,
        country: str = DEFAULT_COUNTRY,
        language: str = DEFAULT_LANGUAGE,
        hidas_ident: str | None = None,
        device_id: str | None = None,
        session_id: str | None = None,
        login_times: list[float] | None = None,
        login_failures: list[float] | None = None,
    ) -> None:
        self._auth_lock = asyncio.Lock()
        self.session = session
        self.email = email
        self.password = password
        self.vin = vin
        self.client_reg_key = client_reg_key
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at or 0
        self.country = country or DEFAULT_COUNTRY
        self.language = language or DEFAULT_LANGUAGE
        self.hidas_ident = hidas_ident
        self.device_id = device_id or str(uuid.uuid4())
        self.session_id = session_id or str(uuid.uuid4())
        now = time.time()
        # Epoch seconds of all password sign-in attempts, and of the failed (or unfinished) ones.
        self.login_times: list[float] = _sanitize_login_times(login_times, now)
        self.login_failures: list[float] = _sanitize_login_times(login_failures, now)
        self._last_refresh_monotonic: float | None = None

    async def async_register_client(self) -> str:
        data = await self._request_identity(
            "POST",
            "/hidas/rs/client/register",
            data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        )
        try:
            self.client_reg_key = data["clientregistrationkey"]["client_reg_key"]
        except (KeyError, TypeError) as err:
            raise HondaLinkAuthError(
                f"Client registration failed: {_redact_payload(data)}"
            ) from err
        return self.client_reg_key

    def _prune_login_times(self, now: float) -> None:
        self.login_times = _sanitize_login_times(self.login_times, now)
        self.login_failures = _sanitize_login_times(self.login_failures, now)

    def logins_last_day(self) -> int:
        """Password sign-in attempts (successful or not) in the last 24 h."""
        self._prune_login_times(time.time())
        return len(self.login_times)

    def login_failures_last_day(self) -> int:
        """Failed or unfinished password sign-in attempts in the last 24 h."""
        self._prune_login_times(time.time())
        return len(self.login_failures)

    def _check_login_budget(self) -> float:
        """Circuit breaker: refuse to sign in again before sending anything.

        On success the attempt is recorded in both lists and its timestamp returned.
        """
        now = time.time()
        self._prune_login_times(now)
        hour_ago = now - _HOUR_SECONDS
        failures_hour = sum(1 for stamp in self.login_failures if stamp > hour_ago)
        if failures_hour >= LOGIN_FAILURE_BUDGET_HOUR:
            raise HondaLinkLoginBudgetError(
                f"HondaLink failed sign-in budget reached ({LOGIN_FAILURE_BUDGET_HOUR} per hour); "
                "not signing in again yet to protect the account"
            )
        if len(self.login_failures) >= LOGIN_FAILURE_BUDGET_DAY:
            raise HondaLinkLoginBudgetError(
                f"HondaLink failed sign-in budget reached ({LOGIN_FAILURE_BUDGET_DAY} per 24 hours); "
                "not signing in again yet to protect the account"
            )
        attempts_hour = sum(1 for stamp in self.login_times if stamp > hour_ago)
        if attempts_hour >= LOGIN_BUDGET_HOUR:
            raise HondaLinkLoginBudgetError(
                f"HondaLink sign-in budget reached ({LOGIN_BUDGET_HOUR} per hour); "
                "not signing in again yet to protect the account"
            )
        if len(self.login_times) >= LOGIN_BUDGET_DAY:
            raise HondaLinkLoginBudgetError(
                f"HondaLink sign-in budget reached ({LOGIN_BUDGET_DAY} per 24 hours); "
                "not signing in again yet to protect the account"
            )
        # Recorded before sending, pessimistically as a failure: an attempt whose outcome is
        # never learned (timeout, crash, restart) must count against the strict budget.
        self.login_times.append(now)
        self.login_failures.append(now)
        return now

    async def async_login(self) -> None:
        attempt = self._check_login_budget()
        if not self.client_reg_key:
            await self.async_register_client()

        data = await self._request_identity(
            "POST",
            "/hidas/rs/token/generate",
            data={
                "username": self.email,
                "password": self.password,
                "description": DEVICE_DESCRIPTION,
                "client_reg_key": self.client_reg_key,
            },
        )

        if data.get("request_status") != "success":
            raise HondaLinkAuthError(f"Login failed: {_redact_payload(data)}")

        # Malformed fields must surface as HondaLinkError (callers catch only that), not crash.
        token = data.get("token")
        token = token if isinstance(token, dict) else {}
        user = data.get("user")
        user = user if isinstance(user, dict) else {}
        access_token = token.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise HondaLinkAuthError(f"Login did not return access_token: {_redact_payload(data)}")

        self.access_token = access_token
        self.refresh_token = token.get("refresh_token")
        try:
            expires_in = int(float(token.get("expires_in") or 0))
        except (TypeError, ValueError, OverflowError):
            expires_in = 0
        self.expires_at = time.time() + max(expires_in - 300, 60)
        self.country = user.get("country_code") or self.country or DEFAULT_COUNTRY
        self.language = user.get("language_code") or self.language or DEFAULT_LANGUAGE
        self.hidas_ident = user.get("hidas_ident") or self.hidas_ident
        # Signed in: this attempt was not a failure. (If a clock jump re-clamped the stamp it
        # stays counted, which errs on the safe side.)
        try:
            self.login_failures.remove(attempt)
        except ValueError:
            pass

    async def async_ensure_login(self) -> None:
        if self.access_token and self.expires_at > time.time() and self.hidas_ident:
            return
        async with self._auth_lock:
            if self.access_token and self.expires_at > time.time() and self.hidas_ident:
                return
            await self.async_login()

    def export_auth_data(self) -> dict[str, Any]:
        return {
            CONF_CLIENT_REG_KEY: self.client_reg_key,
            CONF_ACCESS_TOKEN: self.access_token,
            CONF_REFRESH_TOKEN: self.refresh_token,
            CONF_EXPIRES_AT: self.expires_at,
            CONF_COUNTRY: self.country,
            CONF_LANGUAGE: self.language,
            CONF_HIDAS_IDENT: self.hidas_ident,
            CONF_DEVICE_ID: self.device_id,
            CONF_SESSION_ID: self.session_id,
            CONF_LOGIN_TIMES: list(self.login_times),
            CONF_LOGIN_FAILURES: list(self.login_failures),
        }

    async def async_get_vehicles(self) -> list[dict[str, Any]]:
        data = await self._request_api("GET", "/REST/NGT/MyVehicle/1.0")
        if _lower_status(data.get("status")) not in ("success", ""):
            raise HondaLinkError(f"Vehicle lookup failed: {_redact_payload(data)}")
        vehicles = data.get("vehicleInfo") or []
        return vehicles if isinstance(vehicles, list) else []

    async def async_get_vehicle_by_vin(self, vin: str) -> dict[str, Any] | None:
        data = await self._request_api("GET", f"/REST/NGT/MyVehicle/1.0/{vin}")
        vehicles = data.get("vehicleInfo") or []
        if isinstance(vehicles, list) and vehicles:
            return vehicles[0]
        return None

    async def async_get_dashboard_latest(self, vin: str | None = None) -> dict[str, Any]:
        vin = vin or self.vin
        if not vin:
            raise HondaLinkError("VIN is required")
        data = await self._request_api(
            "POST",
            f"/REST/NGT/CIG/dbd/latest/{vin}",
            json_body={"fromDate": "", "toDate": ""},
        )
        if _lower_status(data.get("status")) != "success":
            raise HondaLinkError(f"Dashboard request failed: {_redact_payload(data)}")
        return data

    def refresh_cooldown_remaining(self) -> float:
        """Seconds until Refresh is allowed again (0 if allowed now)."""
        if self._last_refresh_monotonic is None:
            return 0.0
        elapsed = time.monotonic() - self._last_refresh_monotonic
        return max(0.0, REFRESH_COOLDOWN_SECONDS - elapsed)

    async def async_request_dashboard_update(
        self, vin: str | None = None
    ) -> HondaLinkCommandResult:
        vin = vin or self.vin
        if not vin:
            raise HondaLinkError("VIN is required")
        remaining = self.refresh_cooldown_remaining()
        if remaining > 0:
            raise HondaLinkCooldownError(
                f"Refresh was requested recently; try again in {int(remaining) + 1} seconds"
            )
        # Recorded before sending so a failed attempt also starts the cooldown.
        self._last_refresh_monotonic = time.monotonic()
        last_error: HondaLinkError | None = None
        for filters in DASHBOARD_FILTER_SETS:
            body: dict[str, Any] = {"device": vin}
            if filters:
                body["filters"] = filters
            try:
                data = await self._request_api(
                    "POST",
                    "/REST/NGT/CIG/dbd/async",
                    json_body=body,
                )
                break
            except HondaLinkError as err:
                if not _is_invalid_scope_error(err):
                    raise
                last_error = err
        else:
            if last_error:
                raise last_error
            raise HondaLinkError("Dashboard refresh request failed")

        response_body = data.get("responseBody") or {}
        request_id = response_body.get("cigServiceRequestId")
        status = _lower_status(data.get("status"))

        if status not in ("success", "in_progress", ""):
            message = _redact_payload(data)
            raise HondaLinkCommandError(message)

        if not request_id:
            return HondaLinkCommandResult(None, data)

        result = await self._poll_refresh_result(request_id, timeout=60, poll_interval=3)
        return HondaLinkCommandResult(request_id, result)

    async def _poll_refresh_result(
        self,
        request_id: str,
        timeout: int,
        poll_interval: int,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last_data: dict[str, Any] = {}

        while time.monotonic() < deadline:
            data = await self._request_api(
                "GET",
                f"/REST/NGT/CIG/dbd/results/{request_id}",
            )
            last_data = data
            status = _command_status(data)

            if status in _COMMAND_SUCCESS:
                return data
            if status in _COMMAND_FAILURE:
                raise HondaLinkCommandError(f"Command result failed: {_redact_payload(data)}")

            await asyncio.sleep(poll_interval)

        raise HondaLinkCommandError(
            f"Command timed out waiting for completion: {_redact_payload(last_data)}"
        )

    async def _request_identity(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{IDENTITY_BASE}{path}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": APP_USER_AGENT,
        }
        return await self._send(method, url, headers=headers, data=data)

    async def _request_api(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        retry: bool = True,
    ) -> dict[str, Any]:
        # Read-only guards: checked before signing in or touching the network.
        if not _is_allowed_request(method, path):
            raise HondaLinkReadOnlyError("Request refused: not on the read-only allowlist")
        if _contains_pin_key(json_body):
            raise HondaLinkReadOnlyError("Request refused: a remote PIN must never be sent")
        await self.async_ensure_login()
        url = f"{API_BASE}{path}"
        for attempt in range(2 if retry else 1):
            token_used = self.access_token
            try:
                result = await self._send(
                    method, url, headers=self._api_headers(), json_body=json_body
                )
                header = result.get("Header")
                if isinstance(header, dict) and str(header.get("ErrorCode")) == "401":
                    raise HondaLinkAuthError("HondaLink authorization failed", status=401)
                return result
            except HondaLinkAuthError as err:
                if err.status != 401 or attempt or not retry:
                    raise
                async with self._auth_lock:
                    if self.access_token == token_used:
                        self.access_token = None
                        self.client_reg_key = None
                        await self.async_login()
        raise HondaLinkAuthError("HondaLink authorization failed")

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            async with self.session.request(
                method,
                url,
                headers=headers,
                data=data,
                json=json_body,
                timeout=aiohttp.ClientTimeout(total=30),
                allow_redirects=False,
            ) as response:
                if response.status in (401, 403):
                    raise HondaLinkAuthError(
                        "HondaLink authorization failed", status=response.status
                    )
                if 300 <= response.status < 400:
                    raise HondaLinkError("HondaLink redirect refused")
                text = await response.text()
                try:
                    payload = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    raise HondaLinkError(
                        f"Invalid JSON from HondaLink: HTTP {response.status}"
                    ) from None
                if not isinstance(payload, dict):
                    raise HondaLinkError("Unexpected HondaLink response structure")
                if response.status >= 400:
                    raise HondaLinkError(
                        f"HondaLink request failed: HTTP {response.status} {_redact_payload(payload)}"
                    )
                return payload
        except (aiohttp.ClientError, TimeoutError):
            raise HondaLinkError("HondaLink connection failed or timed out") from None

    def _api_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "bearerToken": self.access_token or "",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": APP_USER_AGENT,
            "hondaHeaderType.version": HONDA_HEADER_VERSION,
            "hondaHeaderType.messageId": str(uuid.uuid4()),
            "hondaHeaderType.siteId": self.client_reg_key or "",
            "hondaHeaderType.businessId": HONDALINK_BUSINESS_ID,
            "hondaHeaderType.systemId": HONDALINK_SYSTEM_ID,
            "hondaHeaderType.clientType": "Mobile",
            "hondaHeaderType.collectedTimestamp": utc_timestamp(),
            "hondaHeaderType.country_code": self.country,
            "hondaHeaderType.language_code": self.language,
        }
        if self.hidas_ident:
            headers["hondaHeaderType.userId"] = self.hidas_ident
        return headers
