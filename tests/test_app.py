from __future__ import annotations

import io
import json
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.app import main
from fedora_system_monitor.capsules.runtime.coordinator import (
    _derived_recoveries,
    _hook_command,
    _persist_signals,
    _run_isolated_scope,
)
from fedora_system_monitor.capsules.alerting import AlertSignal
from fedora_system_monitor.capsules.command import CommandResult
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.notifications import NotificationResult


class AppTests(unittest.TestCase):
    config = Path(__file__).resolve().parents[1] / "config/fedora-system-monitor.toml"

    def test_db_check_and_read_only_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--config", str(self.config), "--database", str(database), "db-check", "--json"])
            self.assertEqual(result, 0)
            self.assertTrue(json.loads(output.getvalue())["ok"])
            database.chmod(0o440)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--config", str(self.config), "--database", str(database), "status", "--json"])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["schema_version"], 2)

    def test_collect_worker_persists_real_minute_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--config",
                        str(self.config),
                        "--database",
                        str(database),
                        "collect-worker",
                        "minute",
                        "--json",
                    ]
                )
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["scope"], "minute")
            self.assertGreater(payload["metrics"], 5)
            db = Database(database)
            try:
                names = {row["name"] for row in db.query("SELECT DISTINCT name FROM periodic_metrics")}
            finally:
                db.close()
            self.assertIn("memory.used_percent", names)

    def test_isolated_scope_uses_new_persisted_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            db = Database(database)

            def fake_run_command(*_: object, **__: object) -> CommandResult:
                db.record_collector_run(
                    "daily",
                    cadence_seconds=86400,
                    outcome="partial",
                    metrics_inserted=33,
                    events_inserted=0,
                    error_message="dnf updates: command exited with status 1",
                    details={
                        "collector_duration_ms": 20094,
                        "errors": ["dnf updates: command exited with status 1"],
                        "hardware_inventory": 17,
                        "software_inventory": 0,
                        "alert_transitions": 0,
                        "maintenance": {"db_check": {"ok": True}},
                    },
                )
                return CommandResult((), 1, "", "", 41000)

            try:
                with patch("fedora_system_monitor.capsules.runtime.coordinator.run_command", fake_run_command):
                    payload = _run_isolated_scope(Namespace(config=self.config), "daily", {}, db)
                rows = db.query("SELECT outcome FROM collector_runs ORDER BY id")
            finally:
                db.close()

            self.assertEqual(payload["outcome"], "partial")
            self.assertEqual(payload["metrics"], 33)
            self.assertEqual(payload["hardware_inventory"], 17)
            self.assertEqual([row["outcome"] for row in rows], ["partial"])

    def test_isolated_scope_does_not_reuse_old_persisted_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            db = Database(database)
            try:
                db.record_collector_run(
                    "daily",
                    cadence_seconds=86400,
                    outcome="partial",
                    metrics_inserted=33,
                    error_message="old partial",
                    details={"errors": ["old partial"]},
                )

                def fake_run_command(*_: object, **__: object) -> CommandResult:
                    return CommandResult((), 1, "", "new failure", 250)

                with patch("fedora_system_monitor.capsules.runtime.coordinator.run_command", fake_run_command):
                    payload = _run_isolated_scope(Namespace(config=self.config), "daily", {}, db)
                rows = db.query("SELECT outcome,metrics_inserted FROM collector_runs ORDER BY id")
            finally:
                db.close()

            self.assertEqual(payload["outcome"], "error")
            self.assertEqual(payload["metrics"], 0)
            self.assertEqual(
                [(row["outcome"], row["metrics_inserted"]) for row in rows],
                [("partial", 33), ("error", 0)],
            )

    def test_isolated_scope_records_subprocess_diagnostics_without_new_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "monitor.sqlite3"
            db = Database(database)
            try:
                def fake_run_command(*_: object, **__: object) -> CommandResult:
                    return CommandResult((), 2, "", "token=secret failed", 125, timed_out=True)

                with patch("fedora_system_monitor.capsules.runtime.coordinator.run_command", fake_run_command):
                    payload = _run_isolated_scope(Namespace(config=self.config), "weekly", {}, db)
                row = db.query("SELECT outcome,error_message,details_json FROM collector_runs ORDER BY id DESC LIMIT 1")[0]
            finally:
                db.close()

            details = json.loads(row["details_json"])
            self.assertEqual(payload["outcome"], "error")
            self.assertEqual(row["error_message"], "collector deadline exceeded")
            self.assertEqual(details["subprocess"]["returncode"], 2)
            self.assertTrue(details["subprocess"]["timed_out"])
            self.assertIn("[REDACTED]", details["subprocess"]["stderr"])

    def test_device_units_pass_literal_systemd_instance(self) -> None:
        unit_directory = Path(__file__).resolve().parents[1] / "systemd"
        for path in unit_directory.glob("fedora-system-monitor-device-*.service"):
            with self.subTest(unit=path.name):
                content = path.read_text(encoding="utf-8")
                self.assertIn("--device %i", content)
                self.assertNotIn("--device %I", content)

    def test_slow_down_notification_cannot_arrive_after_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database_path = Path(temp) / "monitor.sqlite3"
            config = {
                "monitor": {"lock_path": str(Path(temp) / "collector.lock")},
                "notifications": {"timeout_seconds": 1},
            }
            down_started = threading.Event()
            calls: list[str] = []

            def fake_notify(
                _: object,
                category: str,
                *,
                healthy: bool,
                message: str,
                ping_ms: int | None = None,
            ) -> NotificationResult:
                del message, ping_ms
                state = "up" if healthy else "down"
                if state == "down":
                    down_started.set()
                    time.sleep(0.15)
                calls.append(state)
                return NotificationResult("uptime-kuma", category, True, True, "delivered")

            active = AlertSignal(
                key="race-alert",
                category="system",
                name="race",
                severity="critical",
                active=True,
                message="race active",
                source="test",
            )
            recovery = AlertSignal(
                key="race-alert",
                category="system",
                name="race",
                severity="critical",
                active=False,
                message="race recovered",
                source="test",
            )

            def persist(signal: AlertSignal) -> None:
                database = Database(database_path)
                try:
                    _persist_signals(database, [signal], config)
                finally:
                    database.close()

            with patch("fedora_system_monitor.capsules.runtime.coordinator.send_category_heartbeat", side_effect=fake_notify):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    first = executor.submit(persist, active)
                    self.assertTrue(down_started.wait(2))
                    second = executor.submit(persist, recovery)
                    first.result(3)
                    second.result(3)

            self.assertEqual(calls, ["down", "up"])

    def test_remove_waits_for_concurrent_add_identity_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            config = {
                "monitor": {"lock_path": str(Path(temp) / "collector.lock")},
                "notifications": {"timeout_seconds": 0.1},
            }
            add = Namespace(
                hook_action="device-add",
                device="usb-special-2-1",
                only_if_stopping=False,
                interface="",
                action="",
            )
            remove = Namespace(
                hook_action="device-remove",
                device="usb-special-2-1",
                only_if_stopping=False,
                interface="",
                action="",
            )

            def properties(_: str) -> dict[str, str]:
                time.sleep(0.12)
                return {
                    "DEVPATH": "/devices/usb-special-2-1",
                    "SUBSYSTEM": "usb",
                    "ID_SERIAL_SHORT": "stable-test-serial",
                }

            def invoke(arguments: Namespace) -> None:
                database = Database(path)
                try:
                    _hook_command(arguments, config, database)
                finally:
                    database.close()

            with (
                patch("fedora_system_monitor.capsules.runtime.coordinator._udev_properties", side_effect=properties),
                patch("fedora_system_monitor.capsules.runtime.coordinator.send_category_heartbeat"),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                add_future = executor.submit(invoke, add)
                time.sleep(0.01)
                remove_future = executor.submit(invoke, remove)
                add_future.result(3)
                remove_future.result(3)

            database = Database(path)
            try:
                row = database.query(
                    "SELECT device_id FROM events WHERE name='device_disconnected'"
                )[0]
                self.assertTrue(row["device_id"].startswith("serial-sha256:"))
            finally:
                database.close()

    def test_clean_journal_window_recovers_stale_io_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Database(Path(temp) / "monitor.sqlite3")
            try:
                database.open_alert_transition(
                    "event:kernel_io_error:disk",
                    category="storage",
                    name="kernel_io_error",
                    severity="critical",
                    source="kernel_journal",
                    device_id="disk",
                    message="I/O error",
                    occurred_at=datetime.now(timezone.utc) - timedelta(hours=1),
                )
                recoveries = _derived_recoveries(
                    database,
                    [],
                    scope="fifteen_minute",
                    collector_healthy=True,
                    config={"collection": {"journal_lookback_minutes": 20}},
                )
                self.assertEqual(len(recoveries), 1)
                self.assertFalse(recoveries[0].active)
            finally:
                database.close()

    def test_present_mount_recovers_unsafe_removal_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Database(Path(temp) / "monitor.sqlite3")
            try:
                database.open_alert_transition(
                    "event:unsafe_device_removal:host",
                    category="hardware",
                    name="unsafe_device_removal",
                    severity="warning",
                    source="udisks2",
                    device_id="host",
                    details={"mount_point": "/run/media/daniele/09FA16D309FA16D3"},
                    message="unsafe device removal",
                    occurred_at=datetime.now(timezone.utc) - timedelta(minutes=5),
                )
                with patch(
                    "fedora_system_monitor.capsules.runtime.coordinator.run_command",
                    return_value=Namespace(ok=True),
                ):
                    recoveries = _derived_recoveries(
                        database,
                        [],
                        scope="five_minute",
                        collector_healthy=True,
                    )
                self.assertEqual(len(recoveries), 1)
                self.assertEqual(recoveries[0].key, "event:unsafe_device_removal:host")
                self.assertFalse(recoveries[0].active)
                self.assertEqual(recoveries[0].details["recovery_source"], "mount_point_present")
            finally:
                database.close()

    def test_new_boot_recovers_oom_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Database(Path(temp) / "monitor.sqlite3")
            try:
                database.open_alert_transition(
                    "event:oom_kill:host",
                    category="system",
                    name="oom_kill",
                    severity="critical",
                    source="kernel",
                    device_id="host",
                    details={"journal_identity": {"boot_id": "old-boot"}},
                    message="oom kill",
                )
                with patch.object(Path, "read_text", return_value="current-boot\n"):
                    recoveries = _derived_recoveries(database, [], collector_healthy=True)
                self.assertEqual(len(recoveries), 1)
                self.assertEqual(recoveries[0].details["recovery_source"], "new_boot")
            finally:
                database.close()

    def test_absent_smartd_device_recovers_no_such_device_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Database(Path(temp) / "monitor.sqlite3")
            try:
                database.open_alert_transition(
                    "event:smartd:smart-alert:missing",
                    category="hardware",
                    name="smartd_smart_alert",
                    severity="warning",
                    source="smartd",
                    device_id="smartd:missing",
                    details={
                        "device_node": "/dev/fedora-system-monitor-missing-test",
                        "smartd_message": (
                            "Device: /dev/fedora-system-monitor-missing-test [USB NVMe ASMedia], "
                            "open() of NVMe device failed: No such device"
                        ),
                    },
                    message="SMART disk alert: open() of NVMe device failed: No such device",
                )
                with patch(
                    "fedora_system_monitor.capsules.runtime.coordinator.run_command",
                    return_value=Namespace(ok=True, stdout="/dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n"),
                ):
                    recoveries = _derived_recoveries(database, [], collector_healthy=True)
                self.assertEqual(len(recoveries), 1)
                self.assertEqual(recoveries[0].details["recovery_source"], "smartd_device_absent")
            finally:
                database.close()

    def test_complete_filesystem_scan_recovers_absent_capacity_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Database(Path(temp) / "monitor.sqlite3")
            try:
                database.open_alert_transition(
                    "filesystem.free_percent:old-filesystem",
                    category="filesystem",
                    name="filesystem.free_percent",
                    severity="critical",
                    source="statvfs",
                    device_id="old-filesystem",
                    message="filesystem free space is 3.0%",
                )
                metrics = [{"name": "filesystem.free_percent", "device_id": "current-filesystem"}]
                recoveries = _derived_recoveries(
                    database,
                    [],
                    metrics,
                    scope="five_minute",
                    collector_healthy=True,
                )
                self.assertEqual(len(recoveries), 1)
                self.assertEqual(recoveries[0].details["recovery_source"], "filesystem_not_mounted")
            finally:
                database.close()


if __name__ == "__main__":
    unittest.main()
