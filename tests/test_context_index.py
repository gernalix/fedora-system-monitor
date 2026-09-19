from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.capsules.context_index import (
    build_context_window,
    build_incident_bundle,
    latest_incident,
    sync_context_index,
)


class ContextIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "monitor.sqlite3"
        self.aw = self.root / "activity-watch-data"
        self.out = self.root / "fedora-context-data"
        self._make_database()
        self._make_activitywatch()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _make_database(self) -> None:
        connection = sqlite3.connect(self.db)
        connection.executescript(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                value REAL,
                unit TEXT,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                device_id TEXT,
                details_json TEXT NOT NULL,
                outcome TEXT NOT NULL,
                error_message TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                value REAL,
                unit TEXT,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                device_id TEXT,
                details_json TEXT NOT NULL,
                outcome TEXT NOT NULL,
                error_message TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                first_seen_utc TEXT NOT NULL,
                last_seen_utc TEXT NOT NULL,
                recovered_at_utc TEXT
            );
            CREATE TABLE periodic_metrics (
                id INTEGER PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                value REAL,
                unit TEXT,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                device_id TEXT,
                details_json TEXT NOT NULL,
                outcome TEXT NOT NULL,
                error_message TEXT
            );
            """
        )
        connection.execute(
            """
            INSERT INTO events
            (timestamp_utc,category,name,severity,source,device_id,details_json,outcome,error_message)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                "2026-09-19T20:59:29.000000Z",
                "graphics",
                "desktop_compositor_failure",
                "critical",
                "gnome-shell",
                "desktop-compositor",
                json.dumps(
                    {
                        "incident_id": "gfx-test-1",
                        "incident_type": "desktop_compositor_failure",
                        "trigger": "gnome_shell_coredump",
                    },
                    separators=(",", ":"),
                ),
                "failed",
                "desktop compositor failure",
            ),
        )
        connection.execute(
            """
            INSERT INTO periodic_metrics
            (timestamp_utc,category,name,value,unit,severity,source,device_id,details_json,outcome)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "2026-09-19T20:59:00.000000Z",
                "memory",
                "memory.used_percent",
                87.0,
                "percent",
                "info",
                "minute",
                "host",
                "{}",
                "ok",
            ),
        )
        connection.commit()
        connection.close()

    def _make_activitywatch(self) -> None:
        metadata = {
            "buckets": {
                "aw-watcher-window_fedora": {
                    "id": "aw-watcher-window_fedora",
                    "storage_key": "aw-watcher-window_fedora",
                    "type": "currentwindow",
                    "hostname": "fedora",
                },
                "aw-watcher-afk_fedora": {
                    "id": "aw-watcher-afk_fedora",
                    "storage_key": "aw-watcher-afk_fedora",
                    "type": "afkstatus",
                    "hostname": "fedora",
                },
            }
        }
        path = self.aw / "metadata" / "buckets.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(metadata), encoding="utf-8")
        window = self.aw / "buckets" / "aw-watcher-window_fedora" / "2026" / "09" / "2026-09-19.jsonl"
        window.parent.mkdir(parents=True)
        window.write_text(
            json.dumps(
                {
                    "timestamp": "2026-09-19T20:58:54.000000Z",
                    "duration": 60,
                    "data": {
                        "app": "google-chrome",
                        "title": "ChatGPT",
                        "url": "https://example.invalid/private",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        afk = self.aw / "buckets" / "aw-watcher-afk_fedora" / "2026" / "09" / "2026-09-19.jsonl"
        afk.parent.mkdir(parents=True)
        afk.write_text(
            json.dumps(
                {
                    "timestamp": "2026-09-19T20:58:00.000000Z",
                    "duration": 180,
                    "data": {"status": "not-afk"},
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def test_window_correlates_sources_without_raw_url(self) -> None:
        result = build_context_window(
            self.db,
            self.aw,
            center="2026-09-19T20:59:29Z",
            before_minutes=2,
            after_minutes=1,
        )
        self.assertEqual("fedora-system-monitor.context-window.v1", result["schema"])
        self.assertGreaterEqual(result["counts"]["fedora_system_monitor"], 2)
        self.assertGreaterEqual(result["counts"]["activitywatch"], 2)
        chrome = next(
            row for row in result["timeline"]
            if row["source"] == "activitywatch" and row["details"].get("app") == "google-chrome"
        )
        self.assertEqual("ChatGPT", chrome["details"]["title"])
        self.assertNotIn("url", chrome["details"])

    def test_incident_bundle_and_latest(self) -> None:
        latest = latest_incident(self.db, incident_type="graphics")
        self.assertEqual("gfx-test-1", latest["incident_id"])
        bundle = build_incident_bundle(
            self.db,
            self.aw,
            "gfx-test-1",
            before_minutes=2,
            after_minutes=1,
        )
        self.assertEqual("fedora-system-monitor.incident-bundle.v1", bundle["schema"])
        self.assertEqual("gfx-test-1", bundle["incident_id"])
        self.assertTrue(any(row["source"] == "activitywatch" for row in bundle["timeline"]))

    def test_sync_writes_daily_timeline_summary_and_incident_bundle(self) -> None:
        fake_now = datetime(2026, 9, 19, 21, 1, 0, tzinfo=timezone.utc)
        with patch("fedora_system_monitor.capsules.context_index._now", return_value=fake_now):
            result = sync_context_index(
                self.db,
                self.aw,
                self.out,
                since_minutes=5,
                incident_before_minutes=2,
                incident_after_minutes=1,
                publish_git=False,
            )
        self.assertTrue(result["ok"])
        self.assertTrue((self.out / "metadata" / "last-sync.json").exists())
        self.assertTrue((self.out / "metadata" / "sources.json").exists())
        self.assertTrue((self.out / "timeline" / "2026" / "09" / "2026-09-19.jsonl").exists())
        self.assertTrue((self.out / "summaries" / "2026-09-19.json").exists())
        self.assertTrue((self.out / "incidents" / "gfx-test-1.json").exists())


if __name__ == "__main__":
    unittest.main()
