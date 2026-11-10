"""Offline tests for the persisted sign-in budgets and the Refresh cooldown (patched clocks)."""

import asyncio
import json
import math
import unittest

from support import (
    EMAIL,
    IDENTITY_REGISTER_URL,
    IDENTITY_TOKEN_URL,
    PASSWORD,
    VIN,
    AuthError,
    BudgetError,
    ClockedTestCase,
    CooldownError,
    Error,
    Response,
    Session,
    api_module,
    client,
    const,
    logged_in_client,
    login_failed,
    login_ok,
    register_ok,
)

HOUR = 3600
DAY = 86400


def token_calls(session):
    return sum(1 for call in session.calls if call.url == IDENTITY_TOKEN_URL)


class BudgetTestCase(ClockedTestCase):
    def assert_budget_message(self, err, *, failed):
        text = str(err)
        self.assertIn("budget", text)
        if failed:
            self.assertIn("failed sign-in", text)
        else:
            self.assertNotIn("failed", text)
        for secret in (EMAIL, PASSWORD, VIN, "reg-key", "access-token"):
            self.assertNotIn(secret, text)

    async def fail_login(self, api, session):
        session.responses.append(login_failed())
        with self.assertRaises(AuthError):
            await api.async_login()

    async def succeed_login(self, api, session):
        session.responses.append(login_ok())
        await api.async_login()
        self.assertEqual(api.access_token, "access-token")


class LoginBudgetTests(BudgetTestCase):
    def test_constants(self):
        self.assertEqual(const.LOGIN_FAILURE_BUDGET_HOUR, 3)
        self.assertEqual(const.LOGIN_FAILURE_BUDGET_DAY, 8)
        self.assertEqual(const.LOGIN_BUDGET_HOUR, 6)
        self.assertEqual(const.LOGIN_BUDGET_DAY, 100)
        self.assertEqual(const.CONF_LOGIN_FAILURES, "login_failures")
        self.assertEqual(const.CONF_LOGIN_TIMES, "login_times")

    async def test_fourth_failure_in_an_hour_is_refused_without_a_request(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        for _ in range(3):
            await self.fail_login(api, session)
            self.clock.advance(60)
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(api.login_failures_last_day(), 3)

        with self.assertRaises(BudgetError) as caught:
            await api.async_login()
        self.assert_budget_message(caught.exception, failed=True)
        self.assertIn("per hour", str(caught.exception))
        self.assertEqual(len(session.calls), 3)
        # A refused attempt is not itself recorded.
        self.assertEqual(api.logins_last_day(), 3)
        self.assertEqual(api.login_failures_last_day(), 3)

    async def test_ninth_failure_in_a_day_is_refused_without_a_request(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        for failures in (3, 3, 2):
            for _ in range(failures):
                await self.fail_login(api, session)
                self.clock.advance(60)
            self.clock.advance(HOUR)
        self.assertEqual(len(session.calls), 8)
        self.assertEqual(api.login_failures_last_day(), 8)

        with self.assertRaises(BudgetError) as caught:
            await api.async_login()
        self.assert_budget_message(caught.exception, failed=True)
        self.assertIn("per 24 hours", str(caught.exception))
        self.assertEqual(len(session.calls), 8)

        # Still refused after many hours, as long as the 8 failures are within 24 h.
        self.clock.advance(20 * HOUR)
        with self.assertRaises(BudgetError):
            await api.async_login()
        self.assertEqual(len(session.calls), 8)

    async def test_successes_do_not_consume_the_failure_budget(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        for _ in range(5):
            await self.succeed_login(api, session)
            self.clock.advance(60)
        self.assertEqual(api.logins_last_day(), 5)
        self.assertEqual(api.login_failures_last_day(), 0)
        self.assertEqual(api.login_failures, [])

        await self.succeed_login(api, session)  # 6th in the hour: allowed
        with self.assertRaises(BudgetError) as caught:  # 7th: loop guard
            await api.async_login()
        self.assert_budget_message(caught.exception, failed=False)
        self.assertIn("6 per hour", str(caught.exception))
        self.assertEqual(len(session.calls), 6)

    async def test_successes_and_failures_mix(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        await self.fail_login(api, session)
        await self.succeed_login(api, session)
        await self.fail_login(api, session)
        await self.succeed_login(api, session)
        await self.fail_login(api, session)
        self.assertEqual(api.logins_last_day(), 5)
        self.assertEqual(api.login_failures_last_day(), 3)
        with self.assertRaises(BudgetError) as caught:
            await api.async_login()
        self.assert_budget_message(caught.exception, failed=True)

    async def test_daily_loop_guard(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        # 100 successful sign-ins, 14 minutes apart: at most 5 per hour, all within 24 h.
        for _ in range(100):
            await self.succeed_login(api, session)
            self.clock.advance(14 * 60)
        self.assertEqual(api.logins_last_day(), 100)
        self.assertEqual(api.login_failures_last_day(), 0)
        with self.assertRaises(BudgetError) as caught:
            await api.async_login()
        self.assert_budget_message(caught.exception, failed=False)
        self.assertIn("100 per 24 hours", str(caught.exception))
        self.assertEqual(len(session.calls), 100)

    async def test_failed_client_registration_counts_as_failure(self):
        session = Session(Response(200, {"unexpected": True}))
        api = client(session)
        with self.assertRaises(AuthError):
            await api.async_login()
        self.assertEqual(api.login_failures_last_day(), 1)
        self.assertEqual([call.url for call in session.calls], [IDENTITY_REGISTER_URL])

    async def test_missing_access_token_counts_as_failure(self):
        session = Session(Response(200, {"request_status": "success", "token": {}}))
        api = client(session, client_reg_key="reg-key")
        with self.assertRaises(AuthError):
            await api.async_login()
        self.assertEqual(api.login_failures_last_day(), 1)
        self.assertIsNone(api.access_token)

    async def test_attempt_that_raises_mid_flight_counts_as_failure(self):
        for error, expected in (
            (TimeoutError("boom"), Error),
            (api_module.aiohttp.ClientError("boom"), Error),
            (RuntimeError("crash"), RuntimeError),
            (asyncio.CancelledError(), asyncio.CancelledError),
        ):
            with self.subTest(error=type(error).__name__):
                session = Session(error)
                api = client(session, client_reg_key="reg-key")
                with self.assertRaises(expected):
                    await api.async_login()
                self.assertEqual(api.logins_last_day(), 1)
                self.assertEqual(api.login_failures_last_day(), 1)
                self.assertEqual(len(session.calls), 1)

    async def test_malformed_success_response_does_not_escape_as_non_honda_error(self):
        # Callers (e.g. the reauth flow) only catch HondaLinkError; an odd token payload must not
        # crash them before the attempt is persisted.
        for body in (
            {"request_status": "success", "token": "not-a-dict"},
            {"request_status": "success", "token": ["x"], "user": "x"},
        ):
            with self.subTest(body=body):
                api = client(Session(Response(200, body)), client_reg_key="reg-key")
                with self.assertRaises(AuthError):
                    await api.async_login()
                self.assertEqual(api.login_failures_last_day(), 1)

    async def test_malformed_expiry_or_user_still_signs_in(self):
        for expires_in, user in (("soon", {}), (None, "x"), ({"x": 1}, None), ("3600", [])):
            with self.subTest(expires_in=expires_in, user=user):
                body = json.loads(login_ok(expires_in).body)
                body["user"] = user
                api = client(Session(Response(200, body)), client_reg_key="reg-key")
                await api.async_login()
                self.assertEqual(api.access_token, "access-token")
                self.assertGreater(api.expires_at, self.clock.time())
                self.assertEqual(api.login_failures_last_day(), 0)
                self.assertEqual(api.logins_last_day(), 1)

    async def test_budgets_survive_a_restart(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        for _ in range(3):
            await self.fail_login(api, session)
        exported = api.export_auth_data()
        self.assertEqual(len(exported[const.CONF_LOGIN_TIMES]), 3)
        self.assertEqual(len(exported[const.CONF_LOGIN_FAILURES]), 3)
        # Home Assistant stores entry data as JSON.
        stored = json.loads(json.dumps(exported))

        new_session = Session()
        restarted = client(
            new_session,
            client_reg_key=stored[const.CONF_CLIENT_REG_KEY],
            login_times=stored[const.CONF_LOGIN_TIMES],
            login_failures=stored[const.CONF_LOGIN_FAILURES],
        )
        self.clock.advance(10 * 60)
        with self.assertRaises(BudgetError):
            await restarted.async_login()
        with self.assertRaises(BudgetError):
            await restarted.async_ensure_login()
        self.assertEqual(new_session.calls, [])

    async def test_loop_guard_survives_a_restart(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        for _ in range(6):
            await self.succeed_login(api, session)
        stored = json.loads(json.dumps(api.export_auth_data()))
        self.assertEqual(stored[const.CONF_LOGIN_FAILURES], [])
        new_session = Session()
        restarted = client(new_session, login_times=stored[const.CONF_LOGIN_TIMES])
        with self.assertRaises(BudgetError):
            await restarted.async_login()
        self.assertEqual(new_session.calls, [])

    async def test_old_timestamps_expire(self):
        now = self.clock.time()
        api = client(
            Session(login_ok()),
            client_reg_key="reg-key",
            login_times=[now - HOUR - 1] * 6,
            login_failures=[now - HOUR - 1] * 3,
        )
        # Outside the hourly windows, but inside the daily ones.
        self.assertEqual(api.logins_last_day(), 6)
        self.assertEqual(api.login_failures_last_day(), 3)
        await api.async_login()

        api = client(
            Session(),
            login_times=[now - DAY - 1] * 200,
            login_failures=[now - DAY - 1] * 20,
        )
        self.assertEqual(api.logins_last_day(), 0)
        self.assertEqual(api.login_failures_last_day(), 0)
        self.assertEqual(api.export_auth_data()[const.CONF_LOGIN_FAILURES], [])

    async def test_failures_expire_with_time(self):
        session = Session()
        api = client(session, client_reg_key="reg-key")
        for _ in range(3):
            await self.fail_login(api, session)
        with self.assertRaises(BudgetError):
            await api.async_login()
        self.clock.advance(HOUR + 1)
        await self.succeed_login(api, session)
        self.assertEqual(api.login_failures_last_day(), 3)
        self.clock.advance(DAY)
        self.assertEqual(api.login_failures_last_day(), 0)
        self.assertEqual(api.logins_last_day(), 0)

    async def test_garbage_in_stored_lists(self):
        now = self.clock.time()
        garbage = [
            "x",
            str(now),
            None,
            True,
            False,
            math.nan,
            math.inf,
            -math.inf,
            {},
            [now],
            now - 10,  # valid, kept
            int(now) - 20,  # valid int, kept
            now + 10_000,  # future: clamped to now (counts as recent)
        ]
        api = client(Session(), login_times=garbage, login_failures=garbage)
        self.assertEqual(api.login_times, [now - 20, now - 10, now])
        self.assertEqual(api.login_failures, [now - 20, now - 10, now])
        self.assertTrue(all(type(stamp) is float for stamp in api.login_times))
        json.dumps(api.export_auth_data(), allow_nan=False)  # stays valid JSON

        for not_a_list in ("abc", {"a": 1}, 5, None, b"xx"):
            with self.subTest(value=not_a_list):
                api = client(Session(), login_times=not_a_list, login_failures=not_a_list)
                self.assertEqual(api.login_times, [])
                self.assertEqual(api.login_failures, [])

    async def test_future_timestamps_block_and_then_age_normally(self):
        now = self.clock.time()
        session = Session()
        api = client(session, login_failures=[now + DAY * 365] * 3)
        with self.assertRaises(BudgetError):
            await api.async_login()
        self.assertEqual(session.calls, [])
        self.clock.advance(HOUR + 1)
        self.assertEqual(api.login_failures_last_day(), 3)  # aged from "now", not from the future
        self.clock.advance(DAY)
        self.assertEqual(api.login_failures_last_day(), 0)

    async def test_401_retry_cannot_exceed_the_budget(self):
        now = self.clock.time()
        session = Session(Response(401, "{}"))
        api = logged_in_client(session, self.clock, login_failures=[now - 5] * 3)
        with self.assertRaises(BudgetError):
            await api.async_get_vehicles()
        self.assertEqual([call.path for call in session.calls], ["/REST/NGT/MyVehicle/1.0"])
        self.assertEqual(token_calls(session), 0)

    async def test_repeated_401s_are_capped_by_the_loop_guard(self):
        def handler(method, url, kwargs):
            if url == IDENTITY_REGISTER_URL:
                return register_ok()
            if url == IDENTITY_TOKEN_URL:
                return login_ok()
            return Response(401, "{}")

        session = Session(handler=handler)
        api = logged_in_client(session, self.clock)
        for _ in range(20):
            with self.assertRaises(Error):
                await api.async_get_dashboard_latest()
            self.clock.advance(60)
        self.assertEqual(token_calls(session), const.LOGIN_BUDGET_HOUR)
        self.assertEqual(api.logins_last_day(), const.LOGIN_BUDGET_HOUR)

    async def test_repeated_401s_with_failing_sign_in_are_capped_by_failure_budget(self):
        def handler(method, url, kwargs):
            if url == IDENTITY_REGISTER_URL:
                return register_ok()
            if url == IDENTITY_TOKEN_URL:
                return login_failed()
            return Response(401, "{}")

        session = Session(handler=handler)
        api = logged_in_client(session, self.clock)
        for _ in range(20):
            with self.assertRaises(Error):
                await api.async_get_dashboard_latest()
        self.assertEqual(token_calls(session), const.LOGIN_FAILURE_BUDGET_HOUR)


class RefreshCooldownTests(ClockedTestCase):
    def make(self):
        def handler(method, url, kwargs):
            if url.endswith("/REST/NGT/CIG/dbd/async"):
                return Response(
                    200,
                    {"status": "in_progress", "responseBody": {"cigServiceRequestId": "req-1"}},
                )
            return Response(200, {"status": "success", "responseBody": {"commandStatus": "ok"}})

        session = Session(handler=handler)
        return session, logged_in_client(session, self.clock)

    async def test_second_refresh_within_cooldown_is_refused(self):
        session, api = self.make()
        self.assertEqual(api.refresh_cooldown_remaining(), 0)
        await api.async_request_dashboard_update()
        calls = len(session.calls)
        self.assertEqual(calls, 2)
        self.assertEqual(api.refresh_cooldown_remaining(), const.REFRESH_COOLDOWN_SECONDS)

        self.clock.advance(const.REFRESH_COOLDOWN_SECONDS - 300)
        self.assertEqual(api.refresh_cooldown_remaining(), 300)
        with self.assertRaises(CooldownError) as caught:
            await api.async_request_dashboard_update()
        self.assertIn("seconds", str(caught.exception))
        self.assertEqual(len(session.calls), calls)

        self.clock.advance(299)
        with self.assertRaises(CooldownError):
            await api.async_request_dashboard_update(VIN)
        self.assertEqual(len(session.calls), calls)

        self.clock.advance(1)
        self.assertEqual(api.refresh_cooldown_remaining(), 0)
        await api.async_request_dashboard_update()
        self.assertEqual(len(session.calls), calls + 2)

    async def test_failed_refresh_also_starts_the_cooldown(self):
        session = Session(TimeoutError("boom"))
        api = logged_in_client(session, self.clock)
        with self.assertRaises(Error):
            await api.async_request_dashboard_update()
        self.assertGreater(api.refresh_cooldown_remaining(), 0)
        with self.assertRaises(CooldownError):
            await api.async_request_dashboard_update()
        self.assertEqual(len(session.calls), 1)

    async def test_reading_the_dashboard_is_not_limited_by_the_cooldown(self):
        session = Session(*(Response(200, {"status": "success"}) for _ in range(3)))
        api = logged_in_client(session, self.clock)
        api._last_refresh_monotonic = self.clock.monotonic()
        for _ in range(3):
            await api.async_get_dashboard_latest()
        self.assertEqual(len(session.calls), 3)

    async def test_missing_vin_sends_nothing(self):
        session = Session()
        api = logged_in_client(session, self.clock, vin=None)
        with self.assertRaises(Error):
            await api.async_request_dashboard_update()
        self.assertEqual(session.calls, [])
        self.assertEqual(api.refresh_cooldown_remaining(), 0)


if __name__ == "__main__":
    unittest.main()
