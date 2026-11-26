import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from fedora_system_monitor.capsules.collectors import _COLLECTORS, unit_resources as scanner


class UnitResources(unittest.TestCase):
    unit = "user:1000:web.service"

    def scan(self, previous, minute, cpu, *, boot="test", inode=1, journal=None):
        samples = {self.unit: {"inode": inode, "cpu": cpu * 1_000_000, "memory": 100, "io": {}}}
        return scanner.assess({}, previous, samples, journal, boot=boot, now=minute*60,
                              wall=minute*60+1000, skipped=0)

    def test_fast_collector_opens_and_recovers_after_two_complete_low_windows(self):
        self.assertIn(("unit_resources", scanner.collect_unit_resources), _COLLECTORS["minute"])
        state = {}
        results = []
        for index, seconds in enumerate((0, 62, 124, 186, 187, 188)):
            result, state = self.scan(state, index, seconds)
            rows = [m for m in result.metrics if m["name"] == "service.resource.cpu_percent"]
            results.append([m["details"]["active"] for m in rows])
        self.assertEqual(results, [[], [], [], [True], [True], [False]])

    def test_restart_gap_and_missing_journal(self):
        _, state = self.scan({}, 0, 0)
        _, state = self.scan(state, 1, 65)
        result, state = self.scan(state, 2, 150, inode=2, journal={self.unit: {"restarts": 6}})
        self.assertTrue(state["findings"][self.unit]["restarts_min"]["open"])
        self.assertFalse("cpu_percent" in state["findings"][self.unit])
        for minute in (3, 4, 15):
            _, state = self.scan(state, minute, 0, boot="new")
        self.assertTrue(state["findings"][self.unit]["restarts_min"]["open"])

    def test_regression_below_absolute_cpu_limit(self):
        state = {}
        cpu = 0
        for minute in range(21):
            cpu += 1 if minute < 18 else 18
            result, state = self.scan(state, minute, cpu)
        row = next(m for m in result.metrics if m["name"] == "service.resource.cpu_percent")
        self.assertEqual(row["value"], 30)
        self.assertEqual(row["details"]["limit"], 20)

    def test_short_lived_jobs_between_samples(self):
        state = {}
        for minute in range(6):
            journal = {self.unit: {"completed_cpu_seconds": 350}} if minute in (2, 5) else {}
            result, state = scanner.assess({}, state, {}, journal, boot="b", now=minute*60,
                                           wall=minute*60+1000, skipped=0)
        self.assertTrue(any(m["name"] == "service.resource.completed_cpu_seconds" for m in result.metrics))

    def test_repeating_failed_jobs_recover_only_after_observed_starts(self):
        state = {}
        active = []
        for minute, journal in enumerate(({}, {"failed_runs": 2}, {"failed_runs": 2}, {"failed_runs": 1},
                                          {}, {"starts": 1}, {"starts": 1})):
            result, state = scanner.assess({}, state, {}, {self.unit: journal} if journal else {},
                                           boot="b", now=minute*60, wall=minute*60+1000, skipped=0)
            active.append([m["details"]["active"] for m in result.metrics
                           if m["name"] == "service.resource.failed_runs"])
        self.assertEqual(active, [[], [], [], [True], [], [True], [False]])

    def test_short_job_memory_peak_excludes_unavailable_counters_and_keeps_highest_run(self):
        base = {"_PID": "1", "MESSAGE_ID": scanner.USAGE, "UNIT": "batch.service"}
        events = [{**base, "MEMORY_PEAK": value} for value in
                  (str(2200 * 1048576), str(2500 * 1048576), str(2**64 - 1), "[not set]")]
        reply = SimpleNamespace(ok=True, stdout="\n".join(map(json.dumps, events)))
        with patch.object(scanner, "external", return_value=reply):
            unit = "system:batch.service"
            usage = scanner.journal_window({}, 1000, 1060)
            self.assertEqual(usage[unit], {"completed_memory_peak_mib": 2500})
        state = {}
        observed = []
        low = {unit: {"completed_memory_peak_mib": 800}}
        for minute, journal in enumerate(({}, usage, {}, usage, low, {}, low)):
            result, state = scanner.assess({}, state, {}, journal, boot="b", now=minute*60,
                                           wall=minute*60+1000, skipped=0)
            observed.append([row["details"]["active"] for row in result.metrics
                             if row["name"] == "service.resource.completed_memory_peak_mib"])
        self.assertEqual(observed, [[], [], [], [True], [True], [], [False]])

    def test_walk_separates_users_and_counts_leaf_disks_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cgroup"
            dev = Path(temp) / "block"
            (dev/"8:0/slaves").mkdir(parents=True)
            (dev/"252:0/slaves/sda").mkdir(parents=True)
            for path in ("system.slice/web.service", "user.slice/user-1000.slice/user@1000.service/app.slice/web.service"):
                p = root/path
                p.mkdir(parents=True)
                (p/"cpu.stat").write_text("usage_usec 1000\n")
                (p/"io.stat").write_text("8:0 rios=6 wios=2 rbytes=24576 wbytes=8192\n252:0 rios=6 wios=2 rbytes=24576 wbytes=8192\n")
            samples, skipped = scanner.read_cgroups(root, dev)
            self.assertEqual((set(samples), skipped), ({"system:web.service", self.unit}, 0))
            self.assertEqual(samples[self.unit]["io"], {"8:0": 8})
            self.assertNotIn("memory", samples[self.unit])

    def test_journal_filters_manager_identity_and_output_budget(self):
        event = {"_SYSTEMD_USER_UNIT": "init.scope", "_UID": "1000", "MESSAGE_ID": scanner.RESTART,
                 "USER_UNIT": "web.service"}
        untrusted = {**event, "_SYSTEMD_USER_UNIT": "web.service"}
        with patch.object(scanner, "external", return_value=SimpleNamespace(ok=True,
                          stdout="\n".join(map(json.dumps, (event, untrusted, {**event, "MESSAGE_ID": scanner.FAILED}))))) as call:
            counters = scanner.journal_window({}, 1000, 1060)[self.unit]
            self.assertEqual((counters["restarts"], counters["failed_runs"]), (1, 1))
            self.assertIn("--lines=4097", call.call_args.args[1])


class RepairRouting(unittest.TestCase):
    def test_one_repair_then_separate_recovery(self):
        from fedora_system_monitor.capsules.collectors import unit_repairs
        from fedora_system_monitor.capsules.collectors.model import CollectionResult
        from unittest.mock import Mock
        store = {}
        db = Mock()
        db.get_state.side_effect = lambda k, d, **kw: store.get(k, d)
        db.set_state.side_effect = lambda k, v, **kw: store.update({k: dict(v)})
        unit = "user:1000:" + unit_repairs.CLIPMD
        findings = {unit: {"restarts_min": {"open": True}}}
        result = CollectionResult("minute")
        with patch.object(unit_repairs, "operator_identity", return_value=("u", Path("/tmp"), 1000)), \
             patch.object(unit_repairs, "operator_external", return_value=SimpleNamespace(ok=True)) as start:
            for current in (findings, findings, {}):
                unit_repairs.reconcile(result, current, {}, db)
        self.assertEqual(start.call_count, 1)
        self.assertEqual([e["name"] for e in result.events],
                         ["unit_repair_owner_check", "unit_repair_resources_recovered"])
