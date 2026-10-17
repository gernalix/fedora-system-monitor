from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fedora_system_monitor.capsules.prompt_history_freshness import prompt_history_freshness


class _MonitorDatabase:
    def __init__(self, observed_at: datetime, success_age: float = 30):
        self.observed_at = observed_at
        self.success_age = success_age

    def query(self, _sql, _parameters=()):
        return [{
            "timestamp_utc": self.observed_at.isoformat(),
            "details_json": json.dumps({
                "freshness_ok": True,
                "successful_inactive_oneshot": True,
                "last_success_age_seconds": self.success_age,
            }),
        }]


class PromptHistoryFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.export_parent = self.root / "exports"
        self.archive = self.export_parent / "ChatGPTExport-test"
        (self.archive / "reports").mkdir(parents=True)
        self.warehouse = self.root / "prompt_history.sqlite"
        connection = sqlite3.connect(self.warehouse)
        connection.execute(
            "CREATE TABLE source_records(source TEXT,source_key TEXT,payload_hash TEXT,kind TEXT,ingested_at TEXT)"
        )
        connection.commit()
        connection.close()
        self.now = datetime(2026, 10, 17, 20, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temporary.cleanup()

    def _audit(self, *, terminal="complete", complete=2, expected=2, age_seconds=60):
        payload = {
            "terminalState": terminal,
            "completeConversationCount": complete,
            "expectedConversationCount": expected,
            "auditedAt": (self.now - timedelta(seconds=age_seconds)).isoformat(),
        }
        (self.archive / "reports/validation.json").write_text(json.dumps(payload), encoding="utf-8")

    def _import(self, count=2):
        connection = sqlite3.connect(self.warehouse)
        for index in range(count):
            connection.execute(
                "INSERT INTO source_records VALUES(?,?,?,?,?)",
                ("chatgpt-exporter-file", f"v2:{self.archive.name}/conversations/{index}/conversation.json", str(index), "file", self.now.isoformat()),
            )
        connection.commit()
        connection.close()

    def test_complete_recent_audit_and_import_are_healthy(self):
        self._audit()
        self._import()
        healthy, message = prompt_history_freshness(
            _MonitorDatabase(self.now), export_parent=self.export_parent,
            warehouse=self.warehouse, now=self.now,
        )
        self.assertTrue(healthy)
        self.assertIn("coverage=2/2", message)

    def test_incomplete_producer_is_unhealthy_even_when_consumer_succeeds(self):
        self._audit(terminal="incomplete", complete=1, expected=2)
        self._import(1)
        healthy, message = prompt_history_freshness(
            _MonitorDatabase(self.now), export_parent=self.export_parent,
            warehouse=self.warehouse, now=self.now,
        )
        self.assertFalse(healthy)
        self.assertIn("producer audit incomplete 1/2", message)

    def test_old_complete_audit_is_unknown_not_false_ok(self):
        self._audit(age_seconds=2401)
        self._import()
        healthy, message = prompt_history_freshness(
            _MonitorDatabase(self.now), export_parent=self.export_parent,
            warehouse=self.warehouse, now=self.now,
        )
        self.assertFalse(healthy)
        self.assertIn("UNKNOWN: producer proof stale", message)

    def test_consumer_must_run_after_the_producer_audit(self):
        self._audit(age_seconds=60)
        self._import()
        healthy, message = prompt_history_freshness(
            _MonitorDatabase(self.now - timedelta(minutes=5), success_age=0),
            export_parent=self.export_parent, warehouse=self.warehouse, now=self.now,
        )
        self.assertFalse(healthy)
        self.assertIn("producer is newer", message)

    def test_import_coverage_must_match_validated_archive(self):
        self._audit()
        self._import(1)
        healthy, message = prompt_history_freshness(
            _MonitorDatabase(self.now), export_parent=self.export_parent,
            warehouse=self.warehouse, now=self.now,
        )
        self.assertFalse(healthy)
        self.assertIn("coverage 1/2", message)


if __name__ == "__main__":
    unittest.main()
