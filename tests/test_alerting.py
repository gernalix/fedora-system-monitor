from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fedora_system_monitor.capsules.alerting import evaluate_metric_alerts


class AlertingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state: dict[str, object] = {}
        self.config = {
            "storage": {"small_filesystem_max_gib": 5, "small_filesystem_min_free_mib": 128},
            "thresholds": {
                "disk": {"warning_free_percent": 20, "critical_free_percent": 10, "emergency_free_percent": 5, "absolute_free_gib": 10, "recovery_hysteresis_percent": 2},
                "memory": {"ram_warning_percent": 90, "ram_critical_percent": 95, "ram_warning_duration_seconds": 300, "swap_warning_percent": 20, "swap_critical_percent": 50, "recovery_hysteresis_percent": 5},
                "network": {"internet_down_duration_seconds": 180, "wifi_down_duration_seconds": 120, "recovery_samples": 2},
            },
        }

    def get(self, key: str, default: object = None) -> object:
        return self.state.get(key, default)

    def set(self, key: str, value: object) -> None:
        self.state[key] = value

    def test_disk_alert_and_hysteresis_recovery(self) -> None:
        metric = {"category": "storage", "name": "filesystem.free_percent", "value": 8, "unit": "percent", "device_id": "/", "source": "statvfs", "details": {"total_bytes": 100 * 1024**3, "free_bytes": 8 * 1024**3}}
        signals = evaluate_metric_alerts([metric], self.config, self.get, self.set)
        self.assertEqual(signals[0].severity, "critical")
        metric["value"] = 11
        metric["details"]["free_bytes"] = 11 * 1024**3
        self.assertEqual(evaluate_metric_alerts([metric], self.config, self.get, self.set), [])
        metric["value"] = 25
        metric["details"]["free_bytes"] = 25 * 1024**3
        self.assertFalse(evaluate_metric_alerts([metric], self.config, self.get, self.set)[0].active)

    def test_duration_and_network_recovery_samples(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        metric = {"category": "network", "name": "network.internet_reachable", "value": 0, "unit": "boolean", "device_id": "default", "source": "socket"}
        self.assertEqual(evaluate_metric_alerts([metric], self.config, self.get, self.set, now=start), [])
        signals = evaluate_metric_alerts([metric], self.config, self.get, self.set, now=start + timedelta(seconds=181))
        self.assertTrue(signals[0].active)
        metric["value"] = 1
        self.assertEqual(evaluate_metric_alerts([metric], self.config, self.get, self.set, now=start + timedelta(seconds=240)), [])
        self.assertFalse(evaluate_metric_alerts([metric], self.config, self.get, self.set, now=start + timedelta(seconds=300))[0].active)

    def test_tiny_filesystem_uses_proportional_floor(self) -> None:
        metric = {
            "category": "filesystem",
            "name": "filesystem.free_percent",
            "value": 13.0,
            "unit": "percent",
            "device_id": "tiny",
            "source": "statvfs",
            "details": {"total_bytes": 32 * 1024**2, "free_bytes": 4 * 1024**2},
        }
        self.assertEqual(evaluate_metric_alerts([metric], self.config, self.get, self.set), [])

    def test_inactive_essential_service_alerts(self) -> None:
        metric = {
            "category": "service",
            "name": "service.active",
            "value": 0,
            "unit": "boolean",
            "device_id": "NetworkManager.service",
            "source": "systemd",
            "details": {"importance": "essential", "active_state": "inactive"},
        }
        signals = evaluate_metric_alerts([metric], self.config, self.get, self.set)
        self.assertEqual(signals[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
