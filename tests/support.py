"""Shared offline test helpers: fake HTTP session, fake clock, and the synthetic package loader.

Nothing here touches the network or Home Assistant. ``api``, ``util`` and ``const`` are loaded
through a synthetic package so the integration's ``__init__.py`` (which imports Home Assistant)
is never imported.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import re
import sys
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "hondalink_test_package"

if PACKAGE not in sys.modules:
    _pkg = types.ModuleType(PACKAGE)
    _pkg.__path__ = [str(REPO_ROOT)]
    sys.modules[PACKAGE] = _pkg

api_module = importlib.import_module(PACKAGE + ".api")
util = importlib.import_module(PACKAGE + ".util")
const = importlib.import_module(PACKAGE + ".const")

API = api_module.HondaLinkAPI
Error = api_module.HondaLinkError
AuthError = api_module.HondaLinkAuthError
CommandError = api_module.HondaLinkCommandError
BudgetError = api_module.HondaLinkLoginBudgetError
CooldownError = api_module.HondaLinkCooldownError
ReadOnlyError = api_module.HondaLinkReadOnlyError

# Fake, obviously-invalid account data. The password is a unique literal so tests can search
# every recorded request for it.
EMAIL = "someone@example.invalid"
PASSWORD = "pw-Unique-Literal-7731"
VIN = "1HGCM82633A004352"

IDENTITY_REGISTER_URL = const.IDENTITY_BASE + "/hidas/rs/client/register"
IDENTITY_TOKEN_URL = const.IDENTITY_BASE + "/hidas/rs/token/generate"
IDENTITY_URLS = {IDENTITY_REGISTER_URL, IDENTITY_TOKEN_URL}

START_TIME = 1_700_000_000.0

# Independent copy of the intended vehicle-API request paths (not taken from api.py).
API_BASE_URL_PATTERNS = (
    re.compile(r"/REST/NGT/MyVehicle/1\.0(/[A-Za-z0-9]{17})?"),
    re.compile(r"/REST/NGT/CIG/dbd/latest/[A-Za-z0-9]{17}"),
    re.compile(r"/REST/NGT/CIG/dbd/async"),
    re.compile(r"/REST/NGT/CIG/dbd/results/[A-Za-z0-9-]+"),
)


class Response:
    def __init__(self, status: int = 200, body: Any = "{}") -> None:
        self.status = status
        self.body = body if isinstance(body, str) else json.dumps(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def text(self):
        return self.body


@dataclass
class Call:
    method: str
    url: str
    kwargs: dict[str, Any] = field(default_factory=dict)

    @property
    def path(self) -> str:
        for base in (const.API_BASE, const.IDENTITY_BASE):
            if self.url.startswith(base):
                return self.url[len(base) :]
        return self.url


class Session:
    """Fake aiohttp session.

    Each item is a Response, an exception to raise, or a callable(method, url, kwargs) returning
    one of those. With ``handler`` every request is routed through that callable instead.
    """

    def __init__(self, *responses: Any, handler=None) -> None:
        self.responses = list(responses)
        self.handler = handler
        self.calls: list[Call] = []

    def request(self, method, url, **kwargs):
        self.calls.append(Call(method, url, kwargs))
        if self.handler is not None:
            item = self.handler(method, url, kwargs)
        else:
            if not self.responses:
                raise AssertionError(f"unexpected request: {method} {url}")
            item = self.responses.pop(0)
        if callable(item) and not isinstance(item, Response):
            item = item(method, url, kwargs)
        if isinstance(item, BaseException):
            raise item
        return item


def register_ok() -> Response:
    return Response(200, {"clientregistrationkey": {"client_reg_key": "reg-key"}})


def login_ok(expires_in: Any = 3600) -> Response:
    return Response(
        200,
        {
            "request_status": "success",
            "token": {
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_in": expires_in,
            },
            "user": {"hidas_ident": "user-ident", "country_code": "US", "language_code": "en"},
        },
    )


def login_failed() -> Response:
    return Response(200, {"request_status": "failure", "errorCode": "0001-01-1001"})


def client(session: Session | None = None, **kwargs: Any):
    kwargs.setdefault("email", EMAIL)
    kwargs.setdefault("password", PASSWORD)
    return API(session or Session(), **kwargs)


def logged_in_client(session: Session | None = None, clock: FakeClock | None = None, **kwargs):
    """A client that already holds a valid token, so no sign-in is needed."""
    now = clock.time() if clock else api_module.time.time()
    kwargs.setdefault("vin", VIN)
    kwargs.setdefault("client_reg_key", "reg-key")
    kwargs.setdefault("access_token", "access-token")
    kwargs.setdefault("expires_at", now + 10_000)
    kwargs.setdefault("hidas_ident", "user-ident")
    return client(session, **kwargs)


class FakeClock:
    """Replaces the ``time`` module inside api.py (wall clock and monotonic clock)."""

    def __init__(self, now: float = START_TIME) -> None:
        self.now = now
        self.mono = 10_000.0

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.mono += seconds


_real_sleep = asyncio.sleep


class ClockedTestCase(unittest.IsolatedAsyncioTestCase):
    """Patches api.py's clock and its asyncio.sleep (which advances the fake clock instead)."""

    async def asyncSetUp(self) -> None:
        self.clock = FakeClock()
        self.sleeps: list[float] = []

        async def fake_sleep(delay: float, *args: Any, **kwargs: Any) -> None:
            self.sleeps.append(delay)
            self.clock.advance(delay)
            await _real_sleep(0)

        fake_asyncio = types.SimpleNamespace(Lock=asyncio.Lock, sleep=fake_sleep)
        patches = [
            mock.patch.object(api_module, "time", self.clock),
            mock.patch.object(api_module, "asyncio", fake_asyncio),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)


def keys_recursive(value: Any) -> list[str]:
    """Every mapping key found anywhere inside value."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.append(str(key))
            found.extend(keys_recursive(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(keys_recursive(child))
    return found
