from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.systemd_history import DEFAULT_COLLECTOR, UnitIdentity, import_history


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "systemd_history"
CATALOG = [
    UnitIdentity("backup.service", "system", "backup.timer", "backup.service"),
    UnitIdentity("backup.timer", "system", "backup.timer", "backup.service"),
]


def fixture(name: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines()]


def system_scope(payload: dict[str, object]) -> dict[str, object]:
    scopes = payload["scopes"]
    if isinstance(scopes, dict):
        return scopes["system"]
    return scopes[0]


class SystemdHistoryTests(unittest.TestCase):
    def test_source_runtime_has_canonical_discovery_collector(self) -> None:
        self.assertTrue(DEFAULT_COLLECTOR.is_file())

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "monitor.sqlite3"
        self.db = Database(self.database, hostname="fixture-host")

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def test_initial_fixture_groups_invocation_maps_timer_and_populates_views(self) -> None:
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=CATALOG), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal", return_value=(fixture("initial.jsonl"), None)
        ):
            result = import_history(self.db, initial_lookback_hours=24)

        scope = system_scope(result)
        self.assertEqual((scope["recovery_state"], scope["entries_inserted"]), ("first_run", 3))
        self.assertIn("older", scope["warning"])
        self.assertIn("not read", scope["warning"])
        runs = self.db.query("SELECT * FROM systemd_executions_summary ORDER BY started")
        self.assertEqual(len(runs), 2)
        service = next(row for row in runs if row["unit"] == "backup.service")
        self.assertEqual(service["message_count"], 2)
        self.assertEqual(service["duration_seconds"], 5.0)
        self.assertEqual(service["status"], "failed")
        self.assertEqual((service["timer"], service["service"]), ("backup.timer", "backup.service"))
        self.assertIn("[REDACTED]", service["message"])
        timer = self.db.query("SELECT unit,timer,service FROM systemd_entries WHERE message LIKE 'Triggered%'")[0]
        self.assertEqual((timer["unit"], timer["timer"], timer["service"]), ("backup.timer", "backup.timer", "backup.service"))

    def test_incremental_replay_is_idempotent(self) -> None:
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=CATALOG), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal",
            side_effect=[(fixture("initial.jsonl"), None), (fixture("initial.jsonl"), None), (fixture("incremental.jsonl"), None)],
        ):
            first = import_history(self.db)
            replay = import_history(self.db)
            incremental = import_history(self.db)
        self.assertEqual(first["entries_inserted"], 3)
        self.assertEqual(replay["entries_inserted"], 0)
        self.assertEqual(incremental["entries_inserted"], 1)
        self.assertEqual(self.db.query("SELECT COUNT(*) AS count FROM systemd_execution_entries")[0]["count"], 4)
        self.assertEqual(self.db.query("SELECT COUNT(*) AS count FROM systemd_executions")[0]["count"], 3)
        checkpoint = self.db.query("SELECT * FROM systemd_journal_checkpoints")[0]
        self.assertEqual(checkpoint["journal_cursor"], "cursor-4")

    def test_stale_cursor_uses_bounded_fallback_and_persists_warning(self) -> None:
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=CATALOG), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal",
            side_effect=[(fixture("initial.jsonl"), None), ([], "Failed to seek to cursor"), (fixture("incremental.jsonl"), None)],
        ):
            import_history(self.db)
            recovered = import_history(self.db, fallback_lookback_hours=168)
        scope = system_scope(recovered)
        self.assertEqual(scope["recovery_state"], "journal_rotation")
        self.assertIn("bounded fallback", scope["warning"])
        checkpoint = self.db.query("SELECT recovery_state,recovery_warning,fallback_since_utc FROM systemd_journal_checkpoints")[0]
        self.assertEqual(checkpoint["recovery_state"], "journal_rotation")
        self.assertEqual(checkpoint["fallback_since_utc"], "168 hours ago")

    def test_reboot_preserves_cursor_and_records_recovery_state(self) -> None:
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=CATALOG), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal",
            side_effect=[(fixture("initial.jsonl"), None), (fixture("reboot.jsonl"), None)],
        ):
            import_history(self.db)
            rebooted = import_history(self.db)
        self.assertEqual(system_scope(rebooted)["recovery_state"], "reboot")
        checkpoint = self.db.query("SELECT boot_id,journal_cursor,recovery_state FROM systemd_journal_checkpoints")[0]
        self.assertEqual((checkpoint["boot_id"], checkpoint["journal_cursor"]), ("boot-b", "cursor-boot-b"))

    def test_missing_invocation_uses_deterministic_fallback_identity(self) -> None:
        entry = fixture("reboot.jsonl")[0]
        entry.pop("_SYSTEMD_INVOCATION_ID")
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=CATALOG), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal", return_value=([entry], None)
        ):
            import_history(self.db)
            import_history(self.db)
        run = self.db.query("SELECT run_key,invocation_id FROM systemd_executions")[0]
        self.assertTrue(run["run_key"].startswith("fallback-run:"))
        self.assertIsNone(run["invocation_id"])
        self.assertEqual(self.db.query("SELECT COUNT(*) AS count FROM systemd_execution_entries")[0]["count"], 1)

    def test_user_scope_has_an_independent_checkpoint(self) -> None:
        catalog = [UnitIdentity("user-sync.service", "user", None, "user-sync.service")]
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=catalog), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal", return_value=(fixture("user.jsonl"), None)
        ) as journal:
            result = import_history(self.db)
        self.assertEqual(result["scopes"]["user"]["entries_inserted"], 1)
        self.assertEqual(journal.call_args.args[1], "user")
        checkpoint = self.db.query("SELECT journal_scope,journal_cursor FROM systemd_journal_checkpoints")[0]
        self.assertEqual((checkpoint["journal_scope"], checkpoint["journal_cursor"]), ("user", "user-cursor-1"))

    def test_failed_recovery_is_persisted_without_advancing_cursor(self) -> None:
        with patch("fedora_system_monitor.capsules.systemd_history.discover_units", return_value=CATALOG), patch(
            "fedora_system_monitor.capsules.systemd_history._read_journal", return_value=([], "journal unavailable")
        ):
            result = import_history(self.db)
        self.assertFalse(result["passed"])
        checkpoint = self.db.query(
            "SELECT journal_cursor,recovery_state,recovery_warning FROM systemd_journal_checkpoints"
        )[0]
        self.assertIsNone(checkpoint["journal_cursor"])
        self.assertEqual(checkpoint["recovery_state"], "error")
        self.assertIn("journal unavailable", checkpoint["recovery_warning"])


if __name__ == "__main__":
    unittest.main()
