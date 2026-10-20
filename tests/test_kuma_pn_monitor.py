"""Focused contract tests for the active Kuma-to-Pn monitor."""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules import kuma_pn_monitor as monitor


def hb(number: int, status: int, *, monitor_id: int = 40, active: bool = True,
       at: str = "2026-10-16 04:00:00") -> dict:
    return {
        "heartbeat_id": number, "monitor_id": monitor_id, "monitor_name": "Fedora Storage",
        "status": status, "active": active, "time": at,
    }


class KumaPnMonitorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.state = self.dir / "state.sqlite3"
        self.registry = self.dir / "megavault.sqlite"
        with closing(sqlite3.connect(self.registry)) as db, db:
            db.executescript("""
                CREATE TABLE projects(project_id INTEGER,slug TEXT,archived INTEGER);
                CREATE TABLE monitoring_targets(project_id INTEGER,kuma_monitor_key TEXT);
                INSERT INTO projects VALUES(15,'fedora-system-monitor',0);
                INSERT INTO projects VALUES(98,'activity-watch-uploader',0);
                INSERT INTO projects VALUES(103,'prompt-history',0);
                INSERT INTO monitoring_targets VALUES(98,'INT0002:59');
            """)
        self.created = []

    def create(self, event, project_id):
        self.created.append((event["heartbeat_id"], project_id))
        return 500 + len(self.created)

    def tick(self, events, *, base_cursor=None, watermark=None, dry_run=False,
            create=None, resolve=None):
        return monitor.run_once(
            self.state,
            fetch=lambda cursor: (events, max([e["heartbeat_id"] for e in events], default=cursor or 0)
                                      if watermark is None else watermark),
            create=create or self.create,
            resolve_project=resolve or (lambda _: 15),
            dry_run=dry_run,
            update=lambda *args: None,
        )

    def test_baseline_existing_red_is_registered_only_once(self):
        actions = self.tick([hb(100, 0), hb(101, 1, monitor_id=41)], watermark=103)
        self.assertEqual([(x["action"], x["incident_id"]) for x in actions], [("incident_created", 501)])
        self.assertEqual(self.created, [(100, 15)])
        self.assertEqual(self.tick([], watermark=103), [])
        self.assertEqual(len(self.created), 1)
        with closing(sqlite3.connect(self.state)) as db:
            self.assertEqual(monitor._cursor(db), 103)

    def test_recovery_and_short_flap_reuse_pn(self):
        self.tick([hb(100, 0)], watermark=100)
        self.assertEqual(self.tick([hb(101, 1, at="2026-10-16 04:01:00")])[0]["action"], "recovered")
        act = self.tick([hb(102, 0, at="2026-10-16 04:03:00")])[0]
        self.assertEqual(act["action"], "down_deduplicated")
        self.assertEqual(act["incident_id"], 501)
        self.assertEqual(len(self.created), 1)
        self.assertEqual(self.tick([hb(103, 0, at="2026-10-16 04:03:10")]), [])

    def test_long_recovery_opens_new_incident(self):
        self.tick([hb(100, 0)], watermark=100)
        self.tick([hb(101, 1, at="2026-10-16 04:01:00")])
        actions = self.tick([hb(102, 0, at="2026-10-16 04:12:00")])
        self.assertEqual(actions[0]["incident_id"], 502)
        self.assertEqual(self.created, [(100, 15), (102, 15)])

    def test_pending_and_inactive_do_not_create_or_recover(self):
        self.tick([hb(100, 0)], watermark=100)
        self.assertEqual(self.tick([hb(101, 2)]), [])
        self.assertEqual(self.tick([hb(102, 0, active=False)]), [])
        self.assertEqual(self.tick([hb(103, 0, active=True)]), [])
        self.assertEqual(len(self.created), 1)

    def test_partial_failure_replays_from_cursor_without_duplicate(self):
        def fail(event, project):
            if event["monitor_id"] == 41:
                raise RuntimeError("temporary Pn writer failure")
            return self.create(event, project)
        with self.assertRaisesRegex(RuntimeError, "temporary"):
            self.tick([hb(100, 0), hb(101, 0, monitor_id=41)], watermark=101, create=fail)
        with closing(sqlite3.connect(self.state)) as db:
            self.assertIsNone(monitor._cursor(db))  # baseline retried, already-created row retained
        self.tick([hb(100, 0), hb(101, 0, monitor_id=41)], watermark=101)
        self.assertEqual(self.created, [(100, 15), (101, 15)])

    def test_incremental_failure_preserves_committed_cursor(self):
        self.tick([hb(100, 1)], watermark=100)
        def fail(event, project):
            if event["heartbeat_id"] == 102:
                raise RuntimeError("fail second Pn")
            return self.create(event, project)
        with self.assertRaises(RuntimeError):
            self.tick([hb(101, 0), hb(102, 0, monitor_id=41)], watermark=103, create=fail)
        with closing(sqlite3.connect(self.state)) as db:
            self.assertEqual(monitor._cursor(db), 101)
        self.tick([hb(102, 0, monitor_id=41)], watermark=103)
        self.assertEqual(self.created, [(101, 15), (102, 15)])

    def test_dry_run_creates_no_pn_and_does_not_advance_cursor(self):
        actions = self.tick([hb(100, 0)], watermark=100, dry_run=True)
        self.assertEqual(actions[0]["action"], "would_create")
        self.assertEqual(self.created, [])
        self.assertFalse(self.state.exists())
        self.tick([hb(100, 0)], watermark=100)
        self.assertEqual(len(self.created), 1)

    def test_watermark_regression_fails_closed(self):
        self.tick([hb(100, 1)], watermark=500)
        with self.assertRaisesRegex(RuntimeError, "decreased"):
            self.tick([], watermark=100)

    def test_canonical_monitor_project_mapping_and_fallback(self):
        with closing(sqlite3.connect(self.registry)) as db, db:
            db.execute("INSERT INTO monitoring_targets VALUES(103,'INT0002:59')")
            db.commit()
        self.assertEqual(monitor.project_for_monitor(40, self.registry), 15)
        self.assertEqual(monitor.project_for_monitor(59, self.registry), 15)
        with closing(sqlite3.connect(self.registry)) as db, db:
            db.execute("DELETE FROM monitoring_targets WHERE project_id=103")
            db.commit()
        self.assertEqual(monitor.project_for_monitor(59, self.registry), 98)

    def test_cli_receipt_and_no_pn_or_heartbeat_message(self):
        event = hb(100, 0)
        event['msg'] = 'secret-value'
        def call(argv, **kwargs):
            self.assertIn('kuma-event', argv)
            self.assertNotIn('prompt', argv)
            self.assertNotIn('secret-value', kwargs['input'])
            return subprocess.CompletedProcess(argv,0,json.dumps({'status':'RECORDED','incident_id':501}),'')
        with patch.object(monitor.subprocess,'run',side_effect=call):
            self.assertEqual(monitor.register_incident(event,15),501)

    def test_checkpoint_migration_preserves_old_pn(self):
        with sqlite3.connect(self.state) as db:
            db.execute('create table monitor_checkpoint(monitor_id integer primary key, monitor_name text, last_heartbeat_id integer, is_down integer, pn_id text, down_heartbeat_id integer, recovered_at text)')
            db.execute("insert into monitor_checkpoint values(40,'old',99,1,'P45',99,null)")
        self.tick([hb(100,0)])
        with sqlite3.connect(self.state) as db:
            self.assertEqual(db.execute('select pn_id,incident_id from monitor_checkpoint').fetchone(),('P45',501))

if __name__ == '__main__':
    unittest.main()
