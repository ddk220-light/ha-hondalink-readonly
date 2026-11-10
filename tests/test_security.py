"""Offline security tests: transport hardening, read-only guarantees and redaction.

No vehicle requests or credentials are used: every HTTP session here is a fake.
"""

import asyncio
import json
import re
import unittest
from unittest.mock import AsyncMock

from support import (
    API,
    API_BASE_URL_PATTERNS,
    EMAIL,
    IDENTITY_REGISTER_URL,
    IDENTITY_TOKEN_URL,
    IDENTITY_URLS,
    PASSWORD,
    REPO_ROOT,
    VIN,
    AuthError,
    ClockedTestCase,
    CommandError,
    Error,
    ReadOnlyError,
    Response,
    Session,
    api_module,
    client,
    const,
    keys_recursive,
    logged_in_client,
    login_ok,
    register_ok,
)

# Path fragments of the remote-command endpoints that other forks used.
COMMAND_FRAGMENTS = ("/lk/async", "/eng/async", "/cfhl/async")
HISTORICAL_COMMAND_PATHS = (
    "/REST/NGT/CIG/lk/async/alk",
    "/REST/NGT/CIG/lk/async/dulk",
    "/REST/NGT/CIG/lk/async/lck",
    "/REST/NGT/CIG/lk/async/ulk",
    "/REST/NGT/CIG/eng/async/srt",
    "/REST/NGT/CIG/eng/async/sop",
    "/REST/NGT/CIG/cfhl/async/hrn",
    "/REST/NGT/CIG/cfhl/async/lgt",
    "/REST/NGT/CIG/cfhl/async/sop",
)
ALLOWED_REQUESTS = (
    ("GET", "/REST/NGT/MyVehicle/1.0"),
    ("GET", f"/REST/NGT/MyVehicle/1.0/{VIN}"),
    ("POST", f"/REST/NGT/CIG/dbd/latest/{VIN}"),
    ("POST", "/REST/NGT/CIG/dbd/async"),
    ("GET", "/REST/NGT/CIG/dbd/results/req-42"),
    ("GET", "/REST/NGT/CIG/dbd/results/a1b2c3d4-0000-4000-8000-1234567890ab"),
)
REJECTED_REQUESTS = (
    *(("POST", path) for path in HISTORICAL_COMMAND_PATHS),
    *(("GET", path) for path in HISTORICAL_COMMAND_PATHS),
    *(("PUT", path) for path in HISTORICAL_COMMAND_PATHS),
    # Result polling for the command engines.
    ("GET", "/REST/NGT/CIG/lk/results/x"),
    ("GET", "/REST/NGT/CIG/eng/results/x"),
    ("GET", "/REST/NGT/CIG/cfhl/results/x"),
    # Wrong methods on allowed paths.
    ("DELETE", "/REST/NGT/MyVehicle/1.0"),
    ("PUT", "/REST/NGT/CIG/dbd/async"),
    ("PATCH", "/REST/NGT/CIG/dbd/async"),
    ("post", "/REST/NGT/CIG/dbd/async"),
    ("Post", f"/REST/NGT/CIG/dbd/latest/{VIN}"),
    ("get", "/REST/NGT/MyVehicle/1.0"),
    ("POST", "/REST/NGT/MyVehicle/1.0"),
    ("GET", "/REST/NGT/CIG/dbd/async"),
    ("GET", f"/REST/NGT/CIG/dbd/latest/{VIN}"),
    ("POST", "/REST/NGT/CIG/dbd/results/x"),
    (" GET", "/REST/NGT/MyVehicle/1.0"),
    ("GET ", "/REST/NGT/MyVehicle/1.0"),
    # Profile and other read endpoints that are not needed.
    ("GET", f"/REST/NGT/myProfile/1.0/{VIN}"),
    ("GET", "/REST/NGT/myProfile/1.0/VIN"),
    # Path traversal.
    ("GET", "/REST/NGT/CIG/dbd/results/../../lk/async/dulk"),
    ("POST", "/REST/NGT/CIG/dbd/latest/../lk/async/dulk"),
    ("GET", "/REST/NGT/CIG/dbd/results/x/../../lk/async/dulk"),
    ("GET", "/REST/NGT/CIG/dbd/results/a..b"),
    ("GET", "/REST/NGT/CIG/dbd/results/.."),
    ("GET", "/REST/NGT/CIG/dbd/results/.hidden"),
    ("GET", f"/REST/NGT/MyVehicle/1.0/{VIN}/../../CIG/lk/async/dulk"),
    # Query strings and fragments.
    ("GET", "/REST/NGT/MyVehicle/1.0?x=1"),
    ("POST", "/REST/NGT/CIG/dbd/async?cmd=dulk"),
    ("GET", "/REST/NGT/CIG/dbd/results/x?y"),
    ("GET", "/REST/NGT/MyVehicle/1.0#frag"),
    ("POST", f"/REST/NGT/CIG/dbd/latest/{VIN}#x"),
    # Trailing slashes and extra segments.
    ("GET", "/REST/NGT/MyVehicle/1.0/"),
    ("POST", "/REST/NGT/CIG/dbd/async/"),
    ("POST", f"/REST/NGT/CIG/dbd/latest/{VIN}/"),
    ("GET", "/REST/NGT/CIG/dbd/results/x/"),
    ("POST", "/REST/NGT/CIG/dbd/async/lk/async/dulk"),
    # Embedded whitespace and newlines.
    ("POST", "/REST/NGT/CIG/dbd/async\n"),
    ("POST", "/REST/NGT/CIG/dbd/async\r\nX-Injected: 1"),
    ("POST", " /REST/NGT/CIG/dbd/async"),
    ("GET", "/REST/NGT/CIG/dbd/results/x y"),
    ("GET", "/REST/NGT/CIG/dbd/results/x\t"),
    ("GET", "/REST/NGT/CIG/dbd/results/x\nGET /REST/NGT/CIG/lk/async/dulk"),
    ("POST", f"/REST/NGT/CIG/dbd/latest/{VIN}\n"),
    # Percent-encoding.
    ("GET", "/REST/NGT/CIG/dbd/results/..%2F..%2Flk%2Fasync%2Fdulk"),
    ("GET", "/REST/NGT/CIG/dbd/results/x%2flk"),
    ("POST", "/REST/NGT/CIG/dbd%2Fasync"),
    ("POST", "/REST/NGT/CIG/dbd/latest/%2E%2E%2Flk%2Fasync%2Fdulk"),
    # Bad VINs.
    ("POST", "/REST/NGT/CIG/dbd/latest/1HGCM826"),  # too short (8)
    ("POST", "/REST/NGT/CIG/dbd/latest/1HGCM82633"),  # too short (10)
    ("POST", "/REST/NGT/CIG/dbd/latest/1HGCM82633A0043521"),  # too long (18)
    ("GET", "/REST/NGT/MyVehicle/1.0/1HGCM82633A0043521"),
    ("POST", "/REST/NGT/CIG/dbd/latest/"),
    ("POST", "/REST/NGT/CIG/dbd/latest/1HGCM82633A00435."),
    # Case, absolute URLs and other hosts.
    ("POST", "/rest/ngt/cig/dbd/async"),
    ("POST", "https://evil.example/REST/NGT/CIG/dbd/async"),
    ("POST", "//evil.example/REST/NGT/CIG/dbd/async"),
    ("POST", "REST/NGT/CIG/dbd/async"),
    ("POST", ""),
    ("", "/REST/NGT/CIG/dbd/async"),
    # Over-long request id.
    ("GET", "/REST/NGT/CIG/dbd/results/" + "a" * 129),
    # Non-string inputs.
    ("GET", None),
    (None, "/REST/NGT/MyVehicle/1.0"),
    ("POST", b"/REST/NGT/CIG/dbd/async"),
    (b"POST", "/REST/NGT/CIG/dbd/async"),
    ("GET", 123),
    ("GET", ["/REST/NGT/MyVehicle/1.0"]),
)
PIN_BODIES = (
    {"pin": "1234"},
    {"PIN": "1234"},
    {"Pin": "1234"},
    {"pIn": 1234},
    {"device": VIN, "extra": {"pin": "1234"}},
    {"device": VIN, "extra": {"deeper": {"PIN": "1234"}}},
    {"device": VIN, "filters": [{"pin": "1234"}]},
    {"device": VIN, "filters": ["DigitalTwin", [{"Pin": None}]]},
    {"device": VIN, "filters": ({"pin": ""},)},
)


def no_login(api):
    """Make any sign-in attempt fail the test loudly."""
    api.async_login = AsyncMock(side_effect=AssertionError("must not sign in"))
    api.async_ensure_login = AsyncMock(side_effect=AssertionError("must not sign in"))
    return api


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_sensitive_body_never_in_errors(self):
        for response in [
            Response(500, '{"errorMessage":"secret VIN GPS pin=1234"}'),
            Response(200, "<html>secret</html>"),
            Response(401, "secret"),
            Response(400, '{"status":"secret","errorCode":"secret-1234"}'),
        ]:
            with self.subTest(status=response.status):
                with self.assertRaises(Error) as caught:
                    await client(Session(response))._send(
                        "GET", "https://example.invalid", headers={}
                    )
                self.assertNotIn("secret", str(caught.exception))
                self.assertNotIn("1234", str(caught.exception))

    async def test_timeout_and_redirect_protection(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                session = Session(Response(status))
                with self.assertRaisesRegex(Error, "redirect refused"):
                    await client(session)._send(
                        "POST", "https://example.invalid", headers={}, data={"password": "secret"}
                    )
                options = session.calls[0].kwargs
                self.assertFalse(options["allow_redirects"])
                self.assertEqual(options["timeout"].total, 30)
                self.assertNotIn("ssl", options)  # aiohttp certificate verification stays on
                self.assertEqual(len(session.calls), 1)

    async def test_transport_error_is_sanitized(self):
        for error in [TimeoutError("secret"), api_module.aiohttp.ClientError("secret")]:
            with self.assertRaisesRegex(Error, "^HondaLink connection failed or timed out$"):
                await client(Session(error))._send("GET", "https://example.invalid", headers={})

    async def test_non_object_json_rejected(self):
        for body in ["[]", "null", '"secret"', "42"]:
            with self.assertRaisesRegex(Error, "response structure"):
                await client(Session(Response(body=body)))._send(
                    "GET", "https://example.invalid", headers={}
                )

    async def test_http_auth_status_preserved(self):
        for status in [401, 403]:
            with self.assertRaises(AuthError) as caught:
                await client(Session(Response(status, "not-json-secret")))._send(
                    "GET", "https://example.invalid", headers={}
                )
            self.assertEqual(caught.exception.status, status)


class AuthTests(unittest.IsolatedAsyncioTestCase):
    """401 handling in _request_api, using allowlisted paths."""

    READ = ("GET", "/REST/NGT/MyVehicle/1.0")
    REFRESH = ("POST", "/REST/NGT/CIG/dbd/async")

    def make_api(self, outcomes):
        api = client()
        api.async_ensure_login = AsyncMock()
        api.async_login = AsyncMock()
        api._send = AsyncMock(side_effect=outcomes)
        api.access_token = "old"
        api.client_reg_key = "old-registration"
        return api

    async def test_http_401_refreshes_registration_once(self):
        api = self.make_api([AuthError("rejected", status=401), {"status": "success"}])
        self.assertEqual(await api._request_api(*self.READ), {"status": "success"})
        api.async_login.assert_awaited_once()
        self.assertIsNone(api.client_reg_key)
        self.assertEqual(api._send.await_count, 2)

    async def test_mixed_401_does_not_retry_twice(self):
        api = self.make_api([AuthError("rejected", status=401), {"Header": {"ErrorCode": "401"}}])
        with self.assertRaises(AuthError):
            await api._request_api(*self.REFRESH, json_body={"device": VIN})
        self.assertEqual(api._send.await_count, 2)
        api.async_login.assert_awaited_once()

    async def test_body_401_refreshes_once(self):
        api = self.make_api([{"Header": {"ErrorCode": 401}}, {"status": "success"}])
        await api._request_api(*self.READ)
        api.async_login.assert_awaited_once()

    async def test_403_does_not_replay(self):
        api = self.make_api([AuthError("forbidden", status=403)])
        with self.assertRaises(AuthError):
            await api._request_api(*self.REFRESH, json_body={"device": VIN})
        api.async_login.assert_not_awaited()
        self.assertEqual(api._send.await_count, 1)

    async def test_retry_false(self):
        api = self.make_api([{"Header": {"ErrorCode": "401"}}])
        with self.assertRaises(AuthError):
            await api._request_api(*self.READ, retry=False)
        api.async_login.assert_not_awaited()

    async def test_ambiguous_network_failure_never_replays_refresh(self):
        api = self.make_api([Error("connection failed or timed out")])
        with self.assertRaises(Error):
            await api.async_request_dashboard_update(VIN)
        self.assertEqual(api._send.await_count, 1)
        api.async_login.assert_not_awaited()

    async def test_concurrent_login_is_serialized(self):
        api = client()

        async def login():
            await asyncio.sleep(0)
            api.access_token = "new"
            api.expires_at = api_module.time.time() + 1000
            api.hidas_ident = "user"

        api.async_login = AsyncMock(side_effect=login)
        await asyncio.gather(*(api.async_ensure_login() for _ in range(10)))
        api.async_login.assert_awaited_once()

    async def test_concurrent_401s_sign_in_once(self):
        api = logged_in_client()
        tokens_seen = []

        async def send(method, url, *, headers, data=None, json_body=None):
            tokens_seen.append(headers["bearerToken"])
            await asyncio.sleep(0)
            if headers["bearerToken"] == "access-token":
                return {"Header": {"ErrorCode": "401"}}
            return {"status": "success"}

        async def login():
            await asyncio.sleep(0)
            api.access_token = "fresh-token"

        api._send = AsyncMock(side_effect=send)
        api.async_login = AsyncMock(side_effect=login)
        await asyncio.gather(*(api._request_api(*self.READ) for _ in range(5)))
        api.async_login.assert_awaited_once()


class ErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_error_drops_remote_message(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={"status": "failed", "responseBody": {"errorMessage": "secret"}}
        )
        with self.assertRaises(CommandError) as caught:
            await api.async_request_dashboard_update(VIN)
        self.assertNotIn("secret", str(caught.exception))

    async def test_poll_error_drops_remote_message(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={"status": "failed", "responseBody": {"errorMessage": "secret"}}
        )
        with self.assertRaises(Error) as caught:
            await api._poll_refresh_result("request", 1, 0)
        self.assertNotIn("secret", str(caught.exception))

    async def test_dashboard_error_drops_remote_message(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={"status": "failed", "errorMessage": f"secret {VIN} {PASSWORD}"}
        )
        with self.assertRaises(Error) as caught:
            await api.async_get_dashboard_latest(VIN)
        for text in ("secret", VIN, PASSWORD):
            self.assertNotIn(text, str(caught.exception))

    async def test_login_error_drops_remote_message(self):
        session = Session(
            register_ok(),
            Response(200, {"request_status": "failure", "message": f"bad {PASSWORD} {EMAIL}"}),
        )
        with self.assertRaises(AuthError) as caught:
            await client(session).async_login()
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertNotIn(EMAIL, str(caught.exception))

    def test_summary_only_allows_known_error_codes(self):
        payload = {
            "Header": {"ErrorCode": "0001-01-1150", "ErrorDescription": "secret"},
            "VIN": "secret",
            "gps": {"latitude": 123},
        }
        summary = api_module._redact_payload(payload)
        self.assertIn("0001-01-1150", summary)
        self.assertNotIn("secret", summary)
        self.assertNotIn("123", summary)
        self.assertNotIn("secret", api_module._redact_payload({"errorCode": "secret"}))

    def test_untrusted_status_and_numeric_pin_are_not_logged(self):
        summary = api_module._redact_payload(
            {
                "status": "private-token",
                "errorCode": "1234",
                "responseBody": {"commandStatus": "private-email@example.invalid"},
            }
        )
        self.assertEqual(summary, "response details omitted")


class RefreshResultTests(ClockedTestCase):
    async def test_in_progress_submission_waits_for_completion_without_resending(self):
        api = client()
        api._request_api = AsyncMock(
            side_effect=[
                {"status": "in_progress", "responseBody": {"cigServiceRequestId": "test-request"}},
                {"status": "success", "responseBody": {"commandStatus": "in_progress"}},
                {"status": "success", "responseBody": {"commandStatus": "completed"}},
            ]
        )
        result = await api.async_request_dashboard_update(VIN)
        self.assertEqual(result.request_id, "test-request")
        self.assertEqual(result.response["responseBody"]["commandStatus"], "completed")
        self.assertEqual(
            [c.args[:2] for c in api._request_api.await_args_list],
            [
                ("POST", "/REST/NGT/CIG/dbd/async"),
                ("GET", "/REST/NGT/CIG/dbd/results/test-request"),
                ("GET", "/REST/NGT/CIG/dbd/results/test-request"),
            ],
        )

    async def test_success_envelope_does_not_hide_pending_result(self):
        api = client()
        api._request_api = AsyncMock(
            side_effect=[
                {"status": "success", "responseBody": {"commandStatus": "in_progress"}},
                {"status": "success", "responseBody": {"commandStatus": "completed"}},
            ]
        )
        result = await api._poll_refresh_result("test-request", 1, 0)
        self.assertEqual(result["responseBody"]["commandStatus"], "completed")
        self.assertEqual(api._request_api.await_count, 2)

    async def test_success_envelope_does_not_hide_failed_result(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={
                "status": "success",
                "responseBody": {
                    "commandStatus": "failed",
                    "errorCode": "0001-01-1151",
                    "errorMessage": "private-password",
                },
            }
        )
        with self.assertRaisesRegex(CommandError, "Command result failed") as caught:
            await api._poll_refresh_result("test-request", 1, 0)
        self.assertIn("0001-01-1151", str(caught.exception))
        self.assertNotIn("private-password", str(caught.exception))

    async def test_body_status_used_when_command_status_absent(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={"status": "success", "responseBody": {"status": "failed"}}
        )
        with self.assertRaisesRegex(CommandError, "Command result failed"):
            await api._poll_refresh_result("test-request", 1, 0)

    async def test_polling_gives_up_at_deadline(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={"status": "success", "responseBody": {"commandStatus": "in_progress"}}
        )
        with self.assertRaisesRegex(CommandError, "timed out"):
            await api._poll_refresh_result("test-request", timeout=60, poll_interval=3)
        self.assertEqual(api._request_api.await_count, 20)

    async def test_pending_without_request_id_is_not_polled_or_resent(self):
        for response in ({"status": "in_progress", "responseBody": {}}, {}):
            with self.subTest(response=response):
                api = client()
                api._request_api = AsyncMock(return_value=response)
                result = await api.async_request_dashboard_update(VIN)
                self.assertIsNone(result.request_id)
                self.assertEqual(api._request_api.await_count, 1)

    async def test_submission_failure_has_safe_diagnostics(self):
        api = client()
        api._request_api = AsyncMock(
            return_value={
                "status": "failed",
                "responseBody": {"errorCode": "0x01130010", "errorMessage": "private-pin"},
            }
        )
        with self.assertRaises(CommandError) as caught:
            await api.async_request_dashboard_update(VIN)
        self.assertIn("0x01130010", str(caught.exception))
        self.assertNotIn("private-pin", str(caught.exception))


class ReadOnlySurfaceTests(unittest.TestCase):
    REMOVED_METHODS = (
        "async_lock",
        "async_unlock",
        "async_start_engine",
        "async_stop_engine",
        "async_horn",
        "async_lights",
        "async_stop_horn_lights",
        "_async_cig_command",
        "_poll_cig_result",
        "_pin",
        "async_get_profile",
    )
    REMOVED_ATTRIBUTES = ("pin", "lock_command", "unlock_command", "_pin")

    def test_command_methods_do_not_exist(self):
        api = client()
        for name in self.REMOVED_METHODS:
            with self.subTest(name=name):
                self.assertFalse(hasattr(API, name))
                self.assertFalse(hasattr(api, name))

    def test_pin_and_command_attributes_do_not_exist(self):
        api = client(vin=VIN)
        for name in self.REMOVED_ATTRIBUTES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(api, name))
        self.assertFalse(any("pin" in name.lower() for name in vars(api)))

    def test_constructor_rejects_pin_and_command_arguments(self):
        for kwargs in ({"pin": "1234"}, {"lock_command": "x"}, {"unlock_command": "y"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                client(**kwargs)

    def test_const_defines_no_pin_or_command_settings(self):
        for name in (
            "CONF_PIN",
            "CONF_LOCK_COMMAND",
            "CONF_UNLOCK_COMMAND",
            "DEFAULT_LOCK_COMMAND",
            "DEFAULT_UNLOCK_COMMAND",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(const, name))

    def test_source_has_no_command_endpoints(self):
        sources = sorted(REPO_ROOT.glob("*.py"))
        self.assertIn("api.py", [path.name for path in sources])
        for path in sources:
            text = path.read_text(encoding="utf-8")
            for fragment in COMMAND_FRAGMENTS:
                with self.subTest(file=path.name, fragment=fragment):
                    self.assertNotIn(fragment, text)
            with self.subTest(file=path.name, check="no command method definitions"):
                self.assertIsNone(
                    re.search(
                        r"def (async_lock|async_unlock|async_start_engine|async_stop_engine|"
                        r"async_horn|async_lights|async_stop_horn_lights|_async_cig_command)\b",
                        text,
                    )
                )

    def test_no_lock_platform(self):
        self.assertFalse((REPO_ROOT / "lock.py").exists())
        init_text = (REPO_ROOT / "__init__.py").read_text(encoding="utf-8")
        self.assertNotIn("Platform.LOCK", init_text)


class AllowlistTests(unittest.IsolatedAsyncioTestCase):
    def test_allowlist_has_exactly_four_entries(self):
        self.assertEqual(
            [method for method, _ in api_module._ALLOWED_REQUESTS], ["GET", "POST", "POST", "GET"]
        )

    def test_intended_requests_are_allowed(self):
        for method, path in ALLOWED_REQUESTS:
            with self.subTest(method=method, path=path):
                self.assertTrue(api_module._is_allowed_request(method, path))

    def test_everything_else_is_refused(self):
        for method, path in REJECTED_REQUESTS:
            with self.subTest(method=method, path=path):
                self.assertFalse(api_module._is_allowed_request(method, path))

    async def test_refused_requests_send_nothing_and_do_not_sign_in(self):
        for method, path in REJECTED_REQUESTS:
            with self.subTest(method=method, path=path):
                session = Session()
                api = no_login(client(session))
                with self.assertRaises(ReadOnlyError):
                    await api._request_api(method, path, json_body={"device": VIN})
                self.assertEqual(session.calls, [])
                api.async_login.assert_not_awaited()
                api.async_ensure_login.assert_not_awaited()

    async def test_refusal_happens_before_sign_in_even_without_mocks(self):
        # No token: if the guard were after sign-in, the session would see identity requests.
        session = Session()
        api = client(session)
        with self.assertRaises(ReadOnlyError):
            await api._request_api("POST", "/REST/NGT/CIG/lk/async/dulk", json_body={})
        self.assertEqual(session.calls, [])
        self.assertEqual(api.login_times, [])

    async def test_pin_in_body_is_refused(self):
        for body in PIN_BODIES:
            with self.subTest(body=body):
                session = Session()
                api = no_login(client(session))
                with self.assertRaises(ReadOnlyError):
                    await api._request_api("POST", "/REST/NGT/CIG/dbd/async", json_body=body)
                self.assertEqual(session.calls, [])
                api.async_ensure_login.assert_not_awaited()

    async def test_crafted_vin_cannot_reach_other_endpoints(self):
        for vin in (
            "../lk/async/dulk",
            f"{VIN}/../../lk/async/dulk",
            f"{VIN}?x=1",
            f"{VIN}%2F..%2Flk",
            f"{VIN}\n",
        ):
            with self.subTest(vin=vin):
                session = Session()
                api = no_login(client(session, vin=vin))
                with self.assertRaises(ReadOnlyError):
                    await api.async_get_dashboard_latest()
                with self.assertRaises(ReadOnlyError):
                    await api.async_get_vehicle_by_vin(vin)
                self.assertEqual(session.calls, [])

    async def test_crafted_request_id_from_server_is_not_followed(self):
        session = Session(
            Response(
                200,
                {
                    "status": "in_progress",
                    "responseBody": {"cigServiceRequestId": "../../lk/async/dulk"},
                },
            )
        )
        api = logged_in_client(session)
        with self.assertRaises(ReadOnlyError):
            await api.async_request_dashboard_update()
        self.assertEqual([call.path for call in session.calls], ["/REST/NGT/CIG/dbd/async"])


class EndToEndTests(ClockedTestCase):
    """Sign in, read the dashboard and Refresh against a scripted fake Honda."""

    def handler(self, method, url, kwargs):
        path = url[len(const.API_BASE) :] if url.startswith(const.API_BASE) else url
        if url == IDENTITY_REGISTER_URL:
            return register_ok()
        if url == IDENTITY_TOKEN_URL:
            return login_ok()
        if path == f"/REST/NGT/CIG/dbd/latest/{VIN}":
            return Response(200, {"status": "success", "responseBody": {"odometer": {"value": 1}}})
        if path == "/REST/NGT/CIG/dbd/async":
            self.async_posts += 1
            if self.async_posts == 1:
                # First filter set rejected as invalid scope: the client falls back.
                return Response(400, {"Header": {"ErrorCode": "0001-01-1150"}})
            return Response(
                200, {"status": "in_progress", "responseBody": {"cigServiceRequestId": "req-42"}}
            )
        if path == "/REST/NGT/CIG/dbd/results/req-42":
            self.result_polls += 1
            status = "in_progress" if self.result_polls < 3 else "completed"
            return Response(200, {"status": "success", "responseBody": {"commandStatus": status}})
        raise AssertionError(f"unexpected request {method} {url}")

    async def test_read_and_refresh_send_only_allowlisted_pin_free_requests(self):
        self.async_posts = 0
        self.result_polls = 0
        session = Session(handler=self.handler)
        api = client(session, vin=VIN)

        dashboard = await api.async_get_dashboard_latest()
        self.assertEqual(dashboard["status"], "success")
        result = await api.async_request_dashboard_update()
        self.assertEqual(result.request_id, "req-42")
        self.assertEqual(result.response["responseBody"]["commandStatus"], "completed")

        self.assertEqual(
            [(call.method, call.path) for call in session.calls],
            [
                ("POST", "/hidas/rs/client/register"),
                ("POST", "/hidas/rs/token/generate"),
                ("POST", f"/REST/NGT/CIG/dbd/latest/{VIN}"),
                ("POST", "/REST/NGT/CIG/dbd/async"),
                ("POST", "/REST/NGT/CIG/dbd/async"),
                ("GET", "/REST/NGT/CIG/dbd/results/req-42"),
                ("GET", "/REST/NGT/CIG/dbd/results/req-42"),
                ("GET", "/REST/NGT/CIG/dbd/results/req-42"),
            ],
        )
        self.assertEqual(api.logins_last_day(), 1)
        self.assertEqual(api.login_failures_last_day(), 0)

        password_fields = 0
        for call in session.calls:
            with self.subTest(method=call.method, url=call.url):
                # Every URL is an identity URL or an allowlisted vehicle-API URL.
                if call.url in IDENTITY_URLS:
                    self.assertIsNone(call.kwargs.get("json"))
                else:
                    self.assertTrue(call.url.startswith(const.API_BASE + "/"))
                    self.assertTrue(api_module._is_allowed_request(call.method, call.path))
                    self.assertTrue(
                        any(pattern.fullmatch(call.path) for pattern in API_BASE_URL_PATTERNS)
                    )
                    self.assertIsNone(call.kwargs.get("data"))
                self.assertFalse(call.kwargs.get("allow_redirects"))

                # No "pin" key anywhere: body, form data or headers.
                for part in ("json", "data", "headers"):
                    keys = [key.lower() for key in keys_recursive(call.kwargs.get(part))]
                    self.assertNotIn("pin", keys)
                    self.assertFalse(any("pin" == key.strip() for key in keys))

                # The password appears only in the sign-in form's password field.
                data = dict(call.kwargs.get("data") or {})
                if call.url == IDENTITY_TOKEN_URL and data.get("password") == PASSWORD:
                    password_fields += 1
                    del data["password"]
                rest = json.dumps(
                    {
                        "url": call.url,
                        "json": call.kwargs.get("json"),
                        "data": data,
                        "headers": call.kwargs.get("headers"),
                    },
                    default=str,
                )
                self.assertNotIn(PASSWORD, rest)
        self.assertEqual(password_fields, 1)

    async def test_identity_requests_send_only_expected_fields(self):
        self.async_posts = 0
        self.result_polls = 0
        session = Session(handler=self.handler)
        await client(session, vin=VIN).async_get_dashboard_latest()
        register, token = session.calls[:2]
        self.assertEqual(set(register.kwargs["data"]), {"client_id", "client_secret"})
        self.assertEqual(
            token.kwargs["data"],
            {
                "username": EMAIL,
                "password": PASSWORD,
                "description": const.DEVICE_DESCRIPTION,
                "client_reg_key": "reg-key",
            },
        )


if __name__ == "__main__":
    unittest.main()
