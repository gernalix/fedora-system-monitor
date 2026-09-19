from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fedora_system_monitor.capsules.alerting import evaluate_event_alerts, evaluate_metric_alerts


class AlertingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state: dict[str, object] = {}
        self.config = {
            "storage": {"small_filesystem_max_gib": 5, "small_filesystem_min_free_mib": 128},
            "thresholds": {
                "disk": {"warning_free_percent": 20, "critical_free_percent": 10, "emergency_free_percent": 5, "absolute_free_gib": 10, "recovery_hysteresis_percent": 2},
                "memory": {"ram_warning_percent": 90, "ram_critical_percent": 95, "ram_warning_duration_seconds": 300, "available_warning_percent": 10, "available_critical_percent": 5, "psi_some_warning_percent": 10, "psi_full_critical_percent": 5, "swap_out_warning_mib_per_second": 16, "reclaim_warning_pages_per_second": 4096, "recovery_hysteresis_percent": 5},
                "battery": {"health_warning_percent": 70, "health_critical_percent": 50, "recovery_hysteresis_percent": 5},
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
        refresh = evaluate_metric_alerts([metric], self.config, self.get, self.set)
        self.assertTrue(refresh[0].active)
        self.assertEqual(refresh[0].severity, "critical")
        self.assertEqual(refresh[0].message, "filesystem free space is 11.0%")
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

    def test_ten_gib_filesystem_can_be_healthy(self) -> None:
        metric = {
            "category": "filesystem",
            "name": "filesystem.free_percent",
            "value": 96.0,
            "unit": "%",
            "device_id": "small-volume",
            "source": "statvfs",
            "details": {"total_bytes": 10 * 1024**3, "free_bytes": 9.6 * 1024**3},
        }
        self.assertEqual(evaluate_metric_alerts([metric], self.config, self.get, self.set), [])

    def test_sensor_alarm_recovers(self) -> None:
        metric = {"category": "temperature", "name": "sensor.alarm", "value": 1, "unit": "boolean", "device_id": "spd", "source": "hwmon"}
        self.assertTrue(evaluate_metric_alerts([metric], self.config, self.get, self.set)[0].active)
        metric["value"] = 0
        recovery = evaluate_metric_alerts([metric], self.config, self.get, self.set)
        self.assertEqual(len(recovery), 1)
        self.assertFalse(recovery[0].active)

    def test_zram_usage_is_informational_and_composite_pressure_alerts(self) -> None:
        self.state["alert-condition:swap.used_percent:host"] = {"active_level": "warning"}
        zram = {"category": "memory", "name": "swap.used_percent", "value": 95, "unit": "%", "device_id": "host", "source": "procfs"}
        recovery = evaluate_metric_alerts([zram], self.config, self.get, self.set)
        self.assertEqual(len(recovery), 1)
        self.assertFalse(recovery[0].active)
        pressure = {
            "category": "memory",
            "name": "memory.pressure_level",
            "value": 2,
            "unit": "level",
            "device_id": "host",
            "source": "procfs",
            "details": {
                "available_bytes": 1536 * 1024**2,
                "swap_used_percent": 99.5,
                "psi_some_avg10_percent": 35.0,
                "psi_full_avg10_percent": 20.0,
                "top_memory_processes": [{"executable": "java", "memory_percent": 22.0}],
            },
        }
        active = evaluate_metric_alerts([pressure], self.config, self.get, self.set)
        self.assertEqual(active[0].severity, "critical")
        self.assertIn("OOM risk critical", active[0].message)
        self.assertIn("top RAM java 22.0%", active[0].message)
        self.assertEqual(active[0].details["swap_used_percent"], 99.5)

    def test_storage_and_battery_anomalies_alert(self) -> None:
        metrics = [
            {"category": "storage", "name": "btrfs.corruption_errors", "value": 1, "unit": "errors", "device_id": "/", "source": "btrfs"},
            {"category": "storage", "name": "nvme_media_errors", "value": 2, "unit": "errors", "device_id": "nvme", "source": "nvme-cli"},
            {"category": "power", "name": "battery_health_percent", "value": 65, "unit": "%", "device_id": "BAT0", "source": "sysfs"},
        ]
        signals = evaluate_metric_alerts(metrics, self.config, self.get, self.set)
        self.assertEqual({signal.name for signal in signals}, {"btrfs.corruption_errors", "nvme_media_errors", "battery_health_percent"})
        self.assertEqual(next(signal for signal in signals if signal.name == "battery_health_percent").severity, "warning")

    def test_read_only_alert_recovers(self) -> None:
        metric = {"category": "filesystem", "name": "filesystem.read_only", "value": 1, "unit": "boolean", "device_id": "root", "source": "mount", "details": {}}
        self.assertTrue(evaluate_metric_alerts([metric], self.config, self.get, self.set)[0].active)
        metric["value"] = 0
        recovery = evaluate_metric_alerts([metric], self.config, self.get, self.set)
        self.assertEqual(len(recovery), 1)
        self.assertFalse(recovery[0].active)

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

    def test_event_signal_preserves_original_timestamp(self) -> None:
        signals = evaluate_event_alerts(
            [{"name": "disk_io_error", "category": "storage", "severity": "critical", "timestamp_utc": "2026-07-09T10:00:00Z"}]
        )
        self.assertEqual(signals[0].occurred_at, "2026-07-09T10:00:00Z")


if __name__ == "__main__":
    unittest.main()
