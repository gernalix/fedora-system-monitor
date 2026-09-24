from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest import mock

from fedora_system_monitor.capsules.notifications import NotificationResult
from fedora_system_monitor.capsules.service_health import (
    send_service_heartbeats,
    service_monitor_key,
    service_monitor_spec,
)


class _DB:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters=()):
        self.sql = sql
        self.parameters = parameters
        return list(self.rows)


class ServiceHealthTests(unittest.TestCase):
    def test_monitor_key_is_stable_and_toml_safe(self):
        key = service_monitor_key("user:chrome-codex-switcher.service")
        self.assertEqual(key, service_monitor_key("user:chrome-codex-switcher.service"))
        self.assertRegex(key, r"^service_[a-z0-9_]+_[0-9a-f]{10}$")
        self.assertNotEqual(key, service_monitor_key("chrome-codex-switcher.service"))

    def test_monitor_spec_uses_independent_push_identity(self):
        spec = service_monitor_spec("example.service")
        self.assertEqual(spec.key, service_monitor_key("example.service"))
        self.assertIn("example.service", spec.name)

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_pushes_only_provisioned_service_and_accepts_successful_oneshot(self, keys, sender):
        identity = "example.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 21, 20, 0, tzinfo=timezone.utc)
        rows = [
            {
                "device_id": identity,
                "value": 0,
                "timestamp_utc": now.isoformat(),
                "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":true}',
            },
            {
                "device_id": "unprovisioned.service",
                "value": 1,
                "timestamp_utc": now.isoformat(),
                "details_json": '{"active_state":"active","sub_state":"running","result":"success"}',
            },
        ]
        results = send_service_heartbeats({}, _DB(rows), now=now)

        self.assertEqual(len(results), 1)
        sender.assert_called_once()
        self.assertTrue(sender.call_args.kwargs["healthy"])
        self.assertEqual(sender.call_args.args[1], service_monitor_key(identity))

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_stale_scheduled_oneshot_is_down(self, keys, sender):
        identity = "user:workflowy-roadmap-sync.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 24, 1, 0, tzinfo=timezone.utc)
        rows = [{
            "device_id": identity,
            "value": 0,
            "timestamp_utc": now.isoformat(),
            "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":true,"freshness_seconds":300,"last_success_age_seconds":901,"freshness_ok":false}',
        }]

        send_service_heartbeats({}, _DB(rows), now=now)

        self.assertFalse(sender.call_args.kwargs["healthy"])
        self.assertIn("freshness stale", sender.call_args.kwargs["message"])

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_fresh_scheduled_oneshot_is_up(self, keys, sender):
        identity = "user:workflowy-roadmap-sync.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 24, 1, 0, tzinfo=timezone.utc)
        rows = [{
            "device_id": identity,
            "value": 0,
            "timestamp_utc": now.isoformat(),
            "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":true,"freshness_seconds":300,"last_success_age_seconds":75,"freshness_ok":true}',
        }]

        send_service_heartbeats({}, _DB(rows), now=now)

        self.assertTrue(sender.call_args.kwargs["healthy"])

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_inactive_long_running_service_is_down(self, keys, sender):
        identity = "example.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 21, 20, 0, tzinfo=timezone.utc)
        rows = [{
            "device_id": identity,
            "value": 0,
            "timestamp_utc": now.isoformat(),
            "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":false}',
        }]

        send_service_heartbeats({}, _DB(rows), now=now)

        self.assertFalse(sender.call_args.kwargs["healthy"])


if __name__ == "__main__":
    unittest.main()
