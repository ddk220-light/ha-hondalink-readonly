"""Offline tests for the pure helpers in util.py."""

import math
import unittest
from types import MappingProxyType

from support import const, util


class LockTests(unittest.TestCase):
    def body(self, *states):
        return {
            "doorStatus": {
                key: {"lockState": state}
                for key, state in zip(
                    (
                        "firstRowDriver",
                        "firstRowPassenger",
                        "secondRowDriver",
                        "secondRowPassenger",
                    ),
                    states,
                    strict=False,
                )
            }
        }

    def test_all_locked(self):
        self.assertTrue(util.all_door_locks_locked(self.body("lock", "lock", "lock", "lock")))

    def test_partial_locked_is_unknown(self):
        self.assertIsNone(util.all_door_locks_locked(self.body("lock")))

    def test_unknown_state_is_unknown(self):
        self.assertIsNone(util.all_door_locks_locked(self.body("lock", "lock", "unknown", "lock")))

    def test_known_unlock_is_unlocked(self):
        self.assertFalse(util.all_door_locks_locked(self.body("unlock")))

    def test_missing_is_unknown(self):
        self.assertIsNone(util.all_door_locks_locked({}))
        self.assertIsNone(util.all_door_locks_locked({"doorStatus": "x"}))


class MaintenanceTests(unittest.TestCase):
    def test_cached_poll_shape_without_messages(self):
        body = {"maintenanceMinder": {"data": [{"languageCode": "en"}]}}
        self.assertEqual(util.maintenance_messages(body), [])

    def test_live_refresh_shape(self):
        body = {"maintenanceMinder": {"languageCode": "en", "messages": [{"code": "A1"}]}}
        self.assertEqual(util.maintenance_messages(body), [{"code": "A1"}])

    def test_nested_messages(self):
        body = {"maintenanceMinder": {"data": [{"messages": [{"code": "B"}]}]}}
        self.assertEqual(util.maintenance_messages(body), [{"code": "B"}])

    def test_missing_is_unknown(self):
        self.assertIsNone(util.maintenance_messages({}))


class OpenStateTests(unittest.TestCase):
    body = {
        "doorStatus": {
            "firstRowDriver": {"openState": "Open"},
            "firstRowPassenger": {"openState": "Closed"},
        },
        "windowStatus": {"rearWindowRL": {"closeState": "Closed"}},
    }

    def test_single_door(self):
        self.assertTrue(util.any_open_state(self.body, "doorStatus", ["firstRowDriver"]))
        self.assertFalse(util.any_open_state(self.body, "doorStatus", ["firstRowPassenger"]))

    def test_single_window(self):
        self.assertFalse(
            util.any_open_state(self.body, "windowStatus", ["rearWindowRL"], "closeState")
        )

    def test_missing_is_unknown(self):
        self.assertIsNone(
            util.any_open_state(self.body, "windowStatus", ["rearWindowRR"], "closeState")
        )

    def test_unknown_is_unknown_not_open(self):
        body = {"doorStatus": {"hood": {"openState": "unknown"}, "trunk": {"openState": "Closed"}}}
        self.assertIsNone(util.any_open_state(body, "doorStatus", ["hood"]))
        self.assertFalse(util.any_open_state(body, "doorStatus", ["hood", "trunk"]))
        self.assertIsNone(util.any_light_on({"lightStatus": {"head": {"lightState": "unknown"}}}))


class EngineRunningTests(unittest.TestCase):
    def body(self, status):
        return {"remoteEngineStart": {"vehicleStartEvent": {"resStatus": status}}}

    def test_ig_run_is_running(self):
        self.assertTrue(util.engine_running(self.body("IG RUN")))

    def test_on_is_running(self):
        self.assertTrue(util.engine_running(self.body("ON")))

    def test_off_is_not_running(self):
        self.assertFalse(util.engine_running(self.body("OFF")))
        self.assertFalse(util.engine_running(self.body(" off ")))

    def test_unknown_is_unknown(self):
        self.assertIsNone(util.engine_running(self.body("unknown")))
        self.assertIsNone(util.engine_running({}))


class ClampScanIntervalTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(const.DEFAULT_SCAN_INTERVAL, 15)
        self.assertEqual(const.MIN_SCAN_INTERVAL, 5)
        self.assertEqual(const.MAX_SCAN_INTERVAL, 1440)

    def test_below_minimum(self):
        for value in (4, 1, 0, -5, 4.99, -math.inf):
            with self.subTest(value=value):
                self.assertEqual(util.clamp_scan_interval(value), const.MIN_SCAN_INTERVAL)

    def test_above_maximum(self):
        for value in (1441, 10_000, 1440.5, math.inf):
            with self.subTest(value=value):
                self.assertEqual(util.clamp_scan_interval(value), const.MAX_SCAN_INTERVAL)

    def test_in_range(self):
        for value, expected in ((5, 5), (15, 15), (60, 60), (1440, 1440)):
            with self.subTest(value=value):
                self.assertEqual(util.clamp_scan_interval(value), expected)

    def test_fractions_are_truncated(self):
        for value, expected in ((7.9, 7), (5.5, 5), (1439.9, 1439)):
            with self.subTest(value=value):
                result = util.clamp_scan_interval(value)
                self.assertEqual(result, expected)
                self.assertIs(type(result), int)

    def test_not_a_number_gives_default(self):
        for value in (None, "", "abc", True, False, math.nan, [], {}, object()):
            with self.subTest(value=value):
                result = util.clamp_scan_interval(value)
                self.assertEqual(result, const.DEFAULT_SCAN_INTERVAL)
                self.assertIs(type(result), int)


class BackoffTests(unittest.TestCase):
    def test_sequence(self):
        self.assertEqual(util.backoff_minutes(15, 0), 15)
        self.assertEqual(util.backoff_minutes(15, 1), 30)
        self.assertEqual(util.backoff_minutes(15, 2), 60)
        self.assertEqual(util.backoff_minutes(15, 50), 60)
        self.assertEqual(util.backoff_minutes(5, 1), 10)
        self.assertEqual(util.backoff_minutes(5, 9), 20)

    def test_negative_failures_use_base(self):
        self.assertEqual(util.backoff_minutes(15, -1), 15)

    def test_capped(self):
        self.assertEqual(const.MAX_BACKOFF_INTERVAL, 60)
        self.assertEqual(util.backoff_minutes(30, 1), 60)
        self.assertEqual(util.backoff_minutes(30, 2), 60)
        self.assertEqual(util.backoff_minutes(59, 5), 60)

    def test_base_above_cap_is_never_shortened_or_lengthened(self):
        for failures in (0, 1, 2, 10):
            with self.subTest(failures=failures):
                self.assertEqual(util.backoff_minutes(120, failures), 120)
                self.assertEqual(util.backoff_minutes(1440, failures), 1440)


class StripLegacyCommandKeysTests(unittest.TestCase):
    def test_constant(self):
        self.assertEqual(set(const.LEGACY_COMMAND_KEYS), {"pin", "lock_command", "unlock_command"})

    def test_removes_command_keys(self):
        original = {
            "email": "e",
            "password": "p",
            "pin": "1234",
            "lock_command": "x",
            "unlock_command": "y",
            "scan_interval": 15,
        }
        snapshot = dict(original)
        cleaned, changed = util.strip_legacy_command_keys(original)
        self.assertTrue(changed)
        self.assertEqual(cleaned, {"email": "e", "password": "p", "scan_interval": 15})
        self.assertEqual(original, snapshot)  # input not mutated

    def test_each_key_alone_reports_changed(self):
        for key in const.LEGACY_COMMAND_KEYS:
            with self.subTest(key=key):
                cleaned, changed = util.strip_legacy_command_keys({key: "", "vin": "v"})
                self.assertTrue(changed)
                self.assertEqual(cleaned, {"vin": "v"})

    def test_unchanged_when_nothing_to_remove(self):
        original = {"email": "e", "pinned": True, "PIN_hint": 1}
        cleaned, changed = util.strip_legacy_command_keys(original)
        self.assertFalse(changed)
        self.assertEqual(cleaned, original)
        self.assertIsNot(cleaned, original)

    def test_read_only_mapping(self):
        # Home Assistant exposes entry.data as a read-only mapping proxy.
        proxy = MappingProxyType({"pin": "1234", "email": "e"})
        cleaned, changed = util.strip_legacy_command_keys(proxy)
        self.assertTrue(changed)
        self.assertEqual(cleaned, {"email": "e"})
        self.assertIsInstance(cleaned, dict)
        self.assertIn("pin", proxy)


if __name__ == "__main__":
    unittest.main()
