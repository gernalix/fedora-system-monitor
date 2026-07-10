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
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.app import _hook_command, _persist_signals, main
from fedora_system_monitor.capsules.alerting import AlertSignal
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

            with patch("fedora_system_monitor.app.send_category_heartbeat", side_effect=fake_notify):
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
                patch("fedora_system_monitor.app._udev_properties", side_effect=properties),
                patch("fedora_system_monitor.app.send_category_heartbeat"),
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


if __name__ == "__main__":
    unittest.main()
