from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.reporting import resource_boot as boot
from fedora_system_monitor.capsules.reporting import resource_followup as follow
from fedora_system_monitor.capsules.database.process_history import SCHEMA


class FollowupTests(unittest.TestCase):
    def test_transition_crossing_a_second_matches_only_within_its_scan(self):
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript("""
                CREATE TABLE collector_runs(name,started_at_utc,finished_at_utc);
                INSERT INTO collector_runs VALUES('minute','04:16:15','04:16:18');
                CREATE TABLE alerts(id,alert_key,first_seen_utc,recovered_at_utc);
                INSERT INTO alerts VALUES(1,'health','04:05:19','04:16:17');
            """)
            self.assertEqual(follow.transition_case_id(db, "health", "04:16:18", False), 1)
            self.assertIsNone(follow.transition_case_id(db, "health", "04:16:19", False))
            db.execute("INSERT INTO alerts VALUES(2,'health','04:16:16','04:16:17')")
            self.assertIsNone(follow.transition_case_id(db, "health", "04:16:18", False))

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        env = patch.dict("os.environ", {"XDG_STATE_HOME": tmp.name})
        env.start()
        self.addCleanup(env.stop)
        self.args = SimpleNamespace(db=self.folder/"source.db", config=self.folder/"config",
            worker=None, intervention="fix-a", background=False, minutes=15, timeout=30,
            cursor="0.0", limit=1, expect_change=False, probe=None)
        self.item = dict(id=1, unit="system:a.service", metric="io_ops_min", opened="a",
                         seen="b", value=9, threshold=6)

    def test_separate_receipts_and_repeat(self):
        def check():
            return {"status":"SOTTO_SOGLIA", "probe":None}, 0
        a, _ = follow.verify(self.args, self.item, check)
        again, _ = follow.verify(self.args, self.item, lambda: self.fail("restarted"))
        self.assertEqual(again["token"], a["token"])
        self.args.intervention = "fix-b"
        b, _ = follow.verify(self.args,self.item,check)
        self.assertNotEqual(a["token"], b["token"])
        self.assertEqual(follow.latest(self.args,self.item)["token"], b["token"])
        self.assertEqual(follow.latest(self.args,self.item,a["token"])["before"]["value"],9)
        self.assertIsNone(follow.latest(self.args,dict(self.item,id=2)))
        self.assertEqual(a["functional_status"],"NON_MISURATO")

    def test_interrupted_worker_and_cursor_with_relapse(self):
        self.args.background = True
        with patch.object(follow.subprocess,"run") as submit:
            pending,_ = follow.verify(self.args,self.item,lambda: self.fail("foreground"))
            self.assertIn("--worker",submit.call_args.args[0])
        with follow.ledger() as db:
            db.execute("UPDATE pending SET deadline=0")
        with closing(sqlite3.connect(self.args.db)) as db, db:
            db.executescript("""CREATE TABLE events(id INTEGER PRIMARY KEY,category,name,timestamp_utc,
                device_id,details_json); CREATE TABLE alerts(id,alert_key,first_seen_utc,recovered_at_utc);
                INSERT INTO alerts VALUES(1,'key','a','b'),(2,'key','c',NULL);""")
            detail = json.dumps({"alert_key":"key","name":"service.resource.io_ops_min"})
            db.executemany("INSERT INTO events VALUES(?,'alert',?,?,'system:a.service',?)",
                [(i,kind,t,detail) for i,kind,t in [(1,"alert_opened","a"),(2,"alert_recovered","b"),(3,"alert_opened","c")]])
        pages = []
        for _ in range(4):
            page,_ = follow.changes(self.args)
            pages.extend(page["changes"])
            self.args.cursor = page["cursor"]
        self.assertEqual(sorted(e["kind"] for e in pages), ["APERTO","RICADUTA","RIENTRATO","VERIFICA"])
        self.assertEqual(next(e["case_id"] for e in pages if e["kind"]=="RICADUTA"),2)
        self.assertEqual(follow.latest(self.args,self.item,pending["token"])["status"],"VERIFICA_INTERROTTA")

    def test_boot_coverage_handles_missing_history_and_long_gaps(self):
        with closing(sqlite3.connect(self.args.db)) as db, db:
            for statement in SCHEMA:
                db.execute(statement)
            db.executescript("""CREATE TABLE events(category,name,timestamp_utc,details_json);
                CREATE TABLE periodic_metrics(category,name,timestamp_utc,details_json);
                INSERT INTO events VALUES('system','system_boot','1970-01-01T00:00:00Z','{"boot_id":"old"}'),
                    ('system','system_boot','1970-01-01T00:16:40Z','{"boot_id":"new"}');
                INSERT INTO process_identities(id,boot_id,pid,start_ticks,name,unit)
                    VALUES(1,'new',1,1,'chrome','test.scope');""")
            for i,t in enumerate((10,70,130,300,361),1):
                db.execute("INSERT INTO process_scans VALUES(?,?,'new',1,1,0,0,0)",(i,1000+t))
                elapsed = [None,60,60,170,61][i-1]
                db.execute("""INSERT INTO process_samples(scan_id,identity_id,clock,cpu_ticks,interval_seconds,
                    cpu_percent) VALUES(?,1,?,0,?,?)""",(i,t,elapsed,200 if elapsed else None))
        self.args.minutes,self.args.compare = 6,2
        result,code = boot.compare(self.args)
        new,old = result["boots"]
        self.assertEqual((code,result["measured_boots"],old["scans"]), (0,1,0))
        self.assertEqual((new["covered_seconds"],new["scans"]), (120,4))
        self.assertEqual(new["first_desktop_observations_seconds"], {"chrome":10})
        self.assertEqual(new["unit_cpu_percent"][0]["consecutive_high"],2)
        # Exercise the normal CLI path against a second, retained DB after raw rows expire.
        saved = self.folder/"monitor-19700101T010000Z.sqlite3"
        with closing(sqlite3.connect(self.args.db)) as live, closing(sqlite3.connect(saved)) as backup:
            live.backup(backup)
            with live:
                live.execute("DELETE FROM process_samples")
                live.execute("DELETE FROM process_scans")
        self.args.backups = self.folder
        recovered,_ = boot.compare(self.args)
        first, missing = recovered["boots"]
        self.assertEqual(first["process_source"], saved.name)
        self.assertEqual(first["unit_cpu_percent"], new["unit_cpu_percent"])
        self.assertIsNone(missing["process_source"])
        self.assertEqual(missing["scans"],0)
