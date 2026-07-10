from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from fedora_system_monitor.capsules.database import Database, SCHEMA_VERSION, StorageError


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "monitor.sqlite3"
        self.db = Database(self.database_path, hostname="test-host")

    def tearDown(self) -> None:
        self.db.close()
        self.temporary_directory.cleanup()

    def test_schema_wal_and_required_tables(self) -> None:
        self.assertEqual(self.db.schema_version, SCHEMA_VERSION)
        self.assertEqual(self.db.journal_mode, "wal")
        tables = {
            row["name"]
            for row in self.db.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        self.assertTrue(
            {
                "periodic_metrics",
                "events",
                "alerts",
                "hardware_inventory",
                "software_inventory",
                "collector_runs",
                "schema_versions",
                "config_versions",
                "dedup_state",
                "metric_aggregates",
                "summaries",
            }.issubset(tables)
        )
        self.assertTrue(self.db.check_indexes()["ok"])

    def test_schema_v1_is_migrated_in_place(self) -> None:
        legacy_path = Path(self.temporary_directory.name) / "legacy.sqlite3"
        legacy = Database(legacy_path)
        legacy.close()
        connection = sqlite3.connect(legacy_path)
        try:
            for column in ("last_notification_error", "last_notification_status", "message"):
                connection.execute(f"ALTER TABLE alerts DROP COLUMN {column}")
            connection.execute("DELETE FROM schema_versions WHERE version = 2")
            connection.commit()
        finally:
            connection.close()
        migrated = Database(legacy_path)
        try:
            self.assertEqual(migrated.schema_version, SCHEMA_VERSION)
            columns = {row["name"] for row in migrated.query("PRAGMA table_info(alerts)")}
            self.assertTrue(
                {"message", "last_notification_status", "last_notification_error"}.issubset(columns)
            )
        finally:
            migrated.close()

    def test_metric_batch_is_transactional(self) -> None:
        with self.assertRaises(StorageError):
            self.db.insert_metrics(
                [
                    {"name": "cpu.used", "value": 20.0},
                    {"name": "invalid", "value": "not numeric"},
                ]
            )
        self.assertEqual(self.db.table_counts()["periodic_metrics"], 0)
        count = self.db.insert_metrics(
            [
                {"name": "cpu.used", "value": 20.0, "unit": "percent"},
                {"name": "memory.available", "value": 1024, "unit": "bytes"},
            ],
            cadence_seconds=60,
        )
        self.assertEqual(count, 2)
        row = self.db.query("SELECT timestamp_utc, timestamp_local, hostname FROM periodic_metrics LIMIT 1")[0]
        self.assertTrue(row["timestamp_utc"].endswith("Z"))
        self.assertIn("+", row["timestamp_local"])
        self.assertEqual(row["hostname"], "test-host")

    def test_event_deduplication_window(self) -> None:
        instant = datetime(2026, 7, 10, 8, 0, tzinfo=timezone.utc)
        event = {
            "category": "hardware",
            "name": "usb_connected",
            "device_id": "usb-serial-1",
            "source": "udev",
            "details": {"vendor": "Example"},
        }
        self.assertEqual(self.db.insert_events(event, occurred_at=instant), 1)
        self.assertEqual(
            self.db.insert_events(event, occurred_at=instant + timedelta(seconds=30)),
            0,
        )
        rows = self.db.query("SELECT occurrence_count, first_seen_utc, last_seen_utc FROM events")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["occurrence_count"], 2)
        self.assertNotEqual(rows[0]["first_seen_utc"], rows[0]["last_seen_utc"])
        self.assertEqual(
            self.db.insert_events(event, occurred_at=instant + timedelta(minutes=10)),
            1,
        )
        self.assertEqual(self.db.table_counts()["events"], 2)

    def test_json_state_and_secret_redaction(self) -> None:
        self.db.set_state("network", {"online": True, "token": "do-not-store"})
        self.assertEqual(
            self.db.get_state("network"),
            {"online": True, "token": "[REDACTED]"},
        )
        self.assertEqual(self.db.get_state("missing", {"fallback": True}), {"fallback": True})

    def test_alert_hysteresis_and_historical_recovery(self) -> None:
        arguments = {
            "threshold": 90.0,
            "hysteresis": 5.0,
            "category": "thermal",
            "name": "cpu_temperature",
            "unit": "celsius",
            "message": "CPU temperature is high",
        }
        self.assertEqual(self.db.evaluate_alert("cpu-hot", 91.0, **arguments), "opened")
        self.assertTrue(
            self.db.mark_alert_notification("cpu-hot", "failed", "token=do-not-store")
        )
        notification = self.db.query(
            "SELECT message, last_notification_status, last_notification_error FROM alerts"
        )[0]
        self.assertEqual(notification["message"], "CPU temperature is high")
        self.assertEqual(notification["last_notification_status"], "failed")
        self.assertNotIn("do-not-store", notification["last_notification_error"])
        self.assertEqual(self.db.evaluate_alert("cpu-hot", 88.0, **arguments), "updated")
        self.assertEqual(self.db.evaluate_alert("cpu-hot", 84.0, **arguments), "recovered")
        self.assertEqual(self.db.active_alerts(), [])
        recovered = self.db.query("SELECT status, recovered_at_utc FROM alerts")
        self.assertEqual(recovered[0]["status"], "recovered")
        self.assertIsNotNone(recovered[0]["recovered_at_utc"])
        self.assertEqual(self.db.evaluate_alert("cpu-hot", 96.0, **arguments), "opened")
        self.assertEqual(self.db.table_counts()["alerts"], 2)
        self.assertEqual(len(self.db.active_alerts()), 1)

    def test_collector_runs_and_inventory_snapshots(self) -> None:
        run_id = self.db.start_collector_run("minute", cadence_seconds=60)
        self.db.finish_collector_run(run_id, metrics_inserted=4)
        run = self.db.query("SELECT outcome, metrics_inserted, duration_ms FROM collector_runs")[0]
        self.assertEqual(run["outcome"], "ok")
        self.assertEqual(run["metrics_inserted"], 4)
        self.assertGreaterEqual(run["duration_ms"], 0)

        hardware_snapshot = self.db.insert_hardware_snapshot(
            {"name": "Example disk", "stable_id": "disk-1", "size_bytes": 1000}
        )
        software_snapshot = self.db.insert_software_snapshot(
            {"name": "example", "version": "1.0", "architecture": "x86_64"}
        )
        self.assertTrue(hardware_snapshot.startswith("hardware-"))
        self.assertTrue(software_snapshot.startswith("software-"))
        self.assertEqual(self.db.table_counts()["hardware_inventory"], 1)
        self.assertEqual(self.db.table_counts()["software_inventory"], 1)

    def test_inventory_retention_thins_old_snapshots(self) -> None:
        now = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
        old_first = now - timedelta(days=70)
        old_second = old_first + timedelta(days=1)
        recent = now - timedelta(days=2)
        for prefix, insert in (
            ("hardware", self.db.insert_hardware_snapshot),
            ("software", self.db.insert_software_snapshot),
        ):
            insert(
                {"name": "item", "stable_id": "item"},
                snapshot_id=f"{prefix}-old-first",
                collected_at=old_first,
            )
            insert(
                {"name": "item", "stable_id": "item"},
                snapshot_id=f"{prefix}-old-second",
                collected_at=old_second,
            )
            insert(
                {"name": "item", "stable_id": "item"},
                snapshot_id=f"{prefix}-recent",
                collected_at=recent,
            )
        result = self.db.apply_retention(now=now, inventory_daily_days=35)
        self.assertEqual(result["hardware_inventory_deleted"], 1)
        self.assertEqual(result["software_inventory_deleted"], 1)
        hardware_ids = {
            row["snapshot_id"]
            for row in self.db.query("SELECT DISTINCT snapshot_id FROM hardware_inventory")
        }
        self.assertEqual(hardware_ids, {"hardware-old-second", "hardware-recent"})

    def test_retention_aggregates_before_deleting_metrics(self) -> None:
        now = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
        old = now - timedelta(days=20)
        recent = now - timedelta(days=1)
        self.db.insert_metrics(
            [
                {"name": "cpu.used", "value": 10.0, "timestamp_utc": old, "severity": "info"},
                {
                    "name": "cpu.used",
                    "value": 30.0,
                    "timestamp_utc": old + timedelta(minutes=1),
                    "severity": "warning",
                },
                {"name": "cpu.used", "value": 15.0, "timestamp_utc": recent},
            ],
            cadence_seconds=60,
        )
        result = self.db.apply_retention(now=now, metric_days_by_cadence={60: 14})
        self.assertEqual(result["metrics_deleted"], 2)
        self.assertEqual(result["aggregates_written"], 1)
        remaining = self.db.query("SELECT value FROM periodic_metrics")
        self.assertEqual([row["value"] for row in remaining], [15.0])
        aggregate = self.db.query(
            "SELECT minimum, maximum, average, percentile_95, sample_count, problematic_seconds "
            "FROM metric_aggregates"
        )[0]
        self.assertEqual(aggregate["minimum"], 10.0)
        self.assertEqual(aggregate["maximum"], 30.0)
        self.assertEqual(aggregate["average"], 20.0)
        self.assertEqual(aggregate["percentile_95"], 30.0)
        self.assertEqual(aggregate["sample_count"], 2)
        self.assertEqual(aggregate["problematic_seconds"], 60)

    def test_summary_backup_integrity_and_index_checks(self) -> None:
        start = datetime(2026, 7, 9, tzinfo=timezone.utc)
        self.db.insert_summary(
            "daily",
            {"health": "ok", "alerts": 0},
            period_start=start,
            period_end=start + timedelta(days=1),
            health="ok",
        )
        self.assertEqual(self.db.latest_summary()["summary"]["alerts"], 0)
        backup_path = Path(self.temporary_directory.name) / "backups" / "monitor.sqlite3"
        self.assertEqual(self.db.backup(backup_path), backup_path)
        backup = Database(backup_path, initialize=False)
        try:
            self.assertEqual(backup.integrity_check(), ["ok"])
            self.assertEqual(backup.table_counts()["summaries"], 1)
        finally:
            backup.close()
        check = self.db.db_check()
        self.assertTrue(check["ok"])
        self.assertEqual(check["integrity"], ["ok"])
        self.assertTrue(check["indexes"]["ok"])

    def test_query_cannot_mutate_through_pragma_or_with(self) -> None:
        self.db.insert_metrics({"name": "guard", "value": 1}, cadence_seconds=60)
        with self.assertRaises(sqlite3.OperationalError):
            self.db.query("PRAGMA user_version=7")
        with self.assertRaises(sqlite3.OperationalError):
            self.db.query("WITH target AS (SELECT id FROM periodic_metrics) DELETE FROM periodic_metrics RETURNING id")
        self.assertEqual(self.db.query("PRAGMA user_version")[0]["user_version"], 0)
        self.assertEqual(len(self.db.query("SELECT id FROM periodic_metrics")), 1)

    def test_event_control_fields_are_not_duplicated_into_details(self) -> None:
        self.db.insert_events(
            {"name": "event", "dedup_key": "event:key", "dedup_window_seconds": 10},
            dedup_window_seconds=10,
        )
        row = self.db.query("SELECT details_json FROM events")[0]
        self.assertNotIn("dedup_window_seconds", row["details_json"])

    def test_journal_cursor_identity_consolidates_legacy_duplicates(self) -> None:
        cursor = "s=journal;i=123;b=boot;m=456;t=789;x=hash"
        event = {
            "name": "disk_io_error",
            "details": {"journal_identity": {"cursor": cursor}},
            "dedup_key": "kernel:io:disk",
        }
        first = datetime(2026, 7, 10, 8, 0, tzinfo=timezone.utc)
        self.db.insert_events(event, occurred_at=first, dedup_window_seconds=300)
        self.db.insert_events(
            event,
            occurred_at=first - timedelta(hours=1),
            dedup_window_seconds=300,
        )
        self.assertEqual(self.db.table_counts()["events"], 2)

        result = self.db.consolidate_journal_events()

        self.assertEqual(result["duplicates_removed"], 1)
        self.assertEqual(result["cursors_seeded"], 1)
        self.assertTrue(self.db.journal_cursor_seen(cursor))
        rows = self.db.query("SELECT occurrence_count FROM events")
        self.assertEqual(rows, [{"occurrence_count": 2}])
        again = self.db.consolidate_journal_events()
        self.assertEqual(again, {"duplicates_removed": 0, "cursors_seeded": 0})


if __name__ == "__main__":
    unittest.main()
