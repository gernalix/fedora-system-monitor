from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.reporting import resource_case as cases
from fedora_system_monitor.capsules.reporting import resource_pid_trace as trace


class ResourceCaseTests(unittest.TestCase):
    def journal(self, windows, *, state="recovered", seen=280, metric="failed_runs"):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "monitor.db")
            unit = "system:test.service"
            name = "service.resource." + metric
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE alerts(id,source,device_id,name,status,first_seen_utc,last_seen_utc,details_json)")
                db.execute("CREATE TABLE periodic_metrics(category,name,timestamp_utc,source,device_id,value,details_json)")
                def stamp(t):
                    return cases.triage.iso(t).replace("+00:00","Z")
                db.execute("INSERT INTO alerts VALUES(1,'unit_resource_scanner',?,?,?,?,?,?)",
                           (unit, name, state, stamp(0), stamp(seen), "{}"))
                for end, value, active, boot in windows:
                    detail = dict(active=active, limit=1, boot_id=boot, window_seconds=60)
                    db.execute("INSERT INTO periodic_metrics VALUES('service',?,?,'unit_resource_scanner',?,?,?)",
                               (name, stamp(end), unit, value, json.dumps(detail)))
            args = SimpleNamespace(db=path, timeout=1)
            item = dict(id=1, opened=stamp(0), unit=unit, metric=metric)
            with patch.object(cases.time, "time", return_value=100), \
                 patch.object(cases.time, "monotonic", side_effect=[0, 2]):
                return cases.journal_verification(args, item)

    def test_journal_requires_observed_recovery_of_exact_case(self):
        points = [(220,0,True,"A"),(280,0,False,"A")]
        self.assertEqual(self.journal(points)[1], 0)
        self.assertEqual(self.journal(points, seen=250)[1], 2)
        self.assertEqual(self.journal([(220,0,True,"B"),points[1]])[1], 2)
        self.assertEqual(self.journal([(160,0,True,"A"),(220,0,False,"A")])[1], 2)
        self.assertEqual(self.journal([(220,1,True,"A"),(280,1,True,"A")], state="active")[1], 1)
        self.assertEqual(self.journal([(170,0,True,"A"),points[1]])[1], 2)
        self.assertEqual(self.journal([(170,0,True,"A"),points[1]], metric="completed_cpu_seconds")[1], 0)

    def test_attribution_accounts_only_observed_lifetime_in_group(self):
        with tempfile.TemporaryDirectory() as folder:
            before = {("1", 20): ("foo",100,120)}
            after = {("1",20): ("foo",110,126), ("2",103): ("bar",30,0), ("3",10): ("old",800,80)}
            with patch.object(trace, "group_path", return_value=(Path(folder),"/test")), \
                 patch.object(trace.os, "sysconf", return_value=100), \
                 patch.object(trace.time, "clock_gettime", return_value=1), \
                 patch.object(trace.time, "sleep"), \
                 patch.object(trace, "snapshot", side_effect=[(before,0),(after,1)]):
                result = trace.attribution("system:test.service", 1)
            self.assertEqual(result["executables"], [dict(name="bar",read_bytes=30,write_bytes=0),
                                                     dict(name="foo",read_bytes=10,write_bytes=6)])
            self.assertEqual((result["baseline_gaps"], result["unreadable_observations"]), (1,1))
