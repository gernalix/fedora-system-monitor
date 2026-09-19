from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.prometheus import exposition
from fedora_system_monitor.capsules.reporting import health_report, render, service_history_report, timeline_report, trends_report


class ReportingTests(unittest.TestCase):
    def test_health_separates_storage_from_host_stability(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            db = Database(path)
            db.open_alert_transition(
                "filesystem.free_percent:external", category="filesystem", name="filesystem.free_percent",
                severity="emergency", source="statvfs", device_id="external", details={"mount_point": "/media/external"}, message="external full",
            )
            db.open_alert_transition(
                "memory.pressure_level:host", category="memory", name="memory.pressure_level",
                severity="warning", source="procfs", device_id="host", details={}, message="pressure",
            )
            db.close()
            report = health_report(path)
        self.assertEqual(report["state"], "warning")
        self.assertEqual(report["host"]["state"], "warning")
        self.assertEqual(report["storage"]["state"], "critical")
        self.assertEqual(report["storage"]["active_alert_count"], 1)

    def test_health_keeps_critical_internal_filesystem_in_host_state(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            db = Database(path)
            db.open_alert_transition(
                "filesystem.free_percent:root", category="filesystem", name="filesystem.free_percent",
                severity="emergency", source="statvfs", device_id="root", details={"mount_point": "/"}, message="root full",
            )
            db.close()
            report = health_report(path)
        self.assertEqual(report["state"], "critical")
        self.assertEqual(report["host"]["state"], "critical")
        self.assertEqual(report["storage"]["state"], "healthy")

    def test_json_redacts_secret(self) -> None:
        output = render({"token": "token=very-secret-value"}, output_format="json")
        self.assertNotIn("very-secret-value", output)

    def test_csv(self) -> None:
        output = render([{"name": "cpu", "value": 1.5}], output_format="csv")
        self.assertIn("name", output)
        self.assertIn("cpu", output)

    def test_timeline_trends_service_history_and_prometheus(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            db = Database(path)
            now = datetime.now(timezone.utc)
            db.insert_metrics(
                [
                    {"timestamp_utc": now - timedelta(minutes=2), "category": "cpu", "name": "cpu_total_used_percent", "value": 10, "unit": "%"},
                    {"timestamp_utc": now - timedelta(minutes=1), "category": "cpu", "name": "cpu_total_used_percent", "value": 90, "unit": "%"},
                    {"timestamp_utc": now - timedelta(minutes=2), "category": "service", "name": "service.active", "value": 0, "unit": "boolean", "device_id": "example.service", "details": {"restart_count": 0}},
                    {"timestamp_utc": now - timedelta(minutes=1), "category": "service", "name": "service.active", "value": 1, "unit": "boolean", "device_id": "example.service", "details": {"restart_count": 1}},
                ],
                cadence_seconds=60,
            )
            db.insert_events({"timestamp_utc": now, "category": "network", "name": "network_online", "source": "test", "dedup_key": "online"})
            db.close()
            self.assertEqual(timeline_report(path)[0]["name"], "network_online")
            self.assertEqual(trends_report(path)["24h"]["cpu"]["sample_count"], 2)
            service = service_history_report(path)[0]
            self.assertEqual(service["restart_count"], 1)
            self.assertLess(service["availability_percent"], 100)
            payload = exposition(path)
            self.assertIn("fedora_system_monitor_cpu_total_used_percent", payload)
            self.assertIn("fedora_system_monitor_active_alerts", payload)


if __name__ == "__main__":
    unittest.main()
