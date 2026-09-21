from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from fedora_system_monitor.capsules.runtime.coordinator import _discord_exporter_service_health


class _Database:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters=()):
        self.sql = sql
        self.parameters = parameters
        return list(self.rows)


def _row(*, value: int, timestamp: datetime, active: str, sub: str):
    return {
        "value": value,
        "timestamp_utc": timestamp.isoformat(),
        "details_json": json.dumps({"active_state": active, "sub_state": sub}),
    }


class DiscordExporterMonitorTests(unittest.TestCase):
    def test_fresh_active_service_is_healthy(self):
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        healthy, message = _discord_exporter_service_health(
            _Database([_row(value=1, timestamp=now, active="active", sub="running")]),
            minute_failed=False,
            now=now,
        )
        self.assertTrue(healthy)
        self.assertIn("active/running", message)

    def test_inactive_service_is_unhealthy(self):
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        healthy, _ = _discord_exporter_service_health(
            _Database([_row(value=0, timestamp=now, active="inactive", sub="dead")]),
            minute_failed=False,
            now=now,
        )
        self.assertFalse(healthy)

    def test_stale_sample_is_unhealthy(self):
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        healthy, message = _discord_exporter_service_health(
            _Database([_row(value=1, timestamp=now - timedelta(minutes=4), active="active", sub="running")]),
            minute_failed=False,
            now=now,
        )
        self.assertFalse(healthy)
        self.assertIn("stale", message)

    def test_minute_collector_failure_is_unhealthy(self):
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        healthy, message = _discord_exporter_service_health(
            _Database([_row(value=1, timestamp=now, active="active", sub="running")]),
            minute_failed=True,
            now=now,
        )
        self.assertFalse(healthy)
        self.assertIn("collector failed", message)


if __name__ == "__main__":
    unittest.main()
