from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.reporting import resource_triage as triage


UNIT = "system:example.service"


def snapshot(wall, io, inode=1):
    return {"wall": wall, "boot": "boot", "mono": wall, "samples": {
        UNIT: {"inode": inode, "io": {"0:999": io}, "baseline": {}}
    }}


class ResourceTriageTests(unittest.TestCase):
    def test_rank_preserves_missing_samples_and_orders_by_frequency(self):
        frames = [("c", {"x": 8}), ("b", {"x": 7}), ("a", {"y": 99})]
        rows = triage.rank(frames, "io_ops_min", {}, 7, "persistent", 5)
        self.assertEqual([(r["unit"], r["high"], r["latest"]) for r in rows],
                         [("x", 2, 8), ("y", 1, None)])
        self.assertEqual(triage.rank(frames, "io_ops_min", {}, 7, "peak", 1)[0]["unit"], "y")
        self.assertEqual(len(triage.rank(frames, "io_ops_min", {}, 7, "latest", 5)), 1)

    def test_values_require_continuity_accounting_and_same_incarnation(self):
        one = snapshot(60, 40)
        self.assertEqual(triage.observed(one, snapshot(120, 40), 60, "io_ops_min"), {UNIT: 0})
        self.assertEqual(triage.observed(one, snapshot(120, 5), 60, "io_ops_min"), {})
        self.assertEqual(triage.observed(one, snapshot(120, 50, 2), 60, "io_ops_min"), {})
        self.assertEqual(triage.observed(one, snapshot(120, 50), None, "io_ops_min"), {})
        cur = snapshot(120, 40)
        cur["samples"][UNIT].pop("io")
        self.assertEqual(triage.observed(one, cur, 60, "io_ops_min"), {})

    def test_targeted_pid_io_omits_disappeared_pid_and_sorts_by_actual_bytes(self):
        rows = [dict(pid=i, name="process") for i in (1, 2, 3, 4)]
        reads = [(0, 5), (9, 90), None, (3, 4), (8, 7), (13, 200), None]
        with patch.object(triage, "pid_io_reading", side_effect=reads), patch.object(triage.time, "sleep"):
            result = triage.process_io(rows, UNIT, 10, 10)
        self.assertEqual((result["candidates"], result["measured"]), (4, 2))
        self.assertEqual([r["pid"] for r in result["rows"]], [2, 1])
        self.assertEqual(result["rows"][0]["write_bytes"], 110)

    def test_targeted_pid_io_uses_live_members_when_history_has_no_baseline(self):
        stale = [dict(pid=1, name="exited")]
        live = {("2", 100): ("active", 12, 8), ("3", 101): ("leaving", 13, 30)}
        with patch.object(triage.resource_pid_trace, "group_path", return_value=(Path("/scope"), "/scope")), \
             patch.object(triage.resource_pid_trace, "snapshot", return_value=(live, 0)), \
             patch.object(triage, "pid_io_reading", side_effect=[None, (44, 20), None]) as read, \
             patch.object(triage.time, "sleep"):
            result = triage.process_io(stale, UNIT, 10, 10)
        self.assertEqual(result["candidate_source"], "cgroup")
        self.assertEqual(result["candidates"], 2)
        self.assertEqual(result["rows"], [dict(pid=2, name="active", read_bytes=32, write_bytes=12)])
        self.assertEqual(read.call_args_list[1].args[0]["start_ticks"], 100)

    def test_private_receipt_keeps_latest_verification_separate_by_metric(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {"XDG_STATE_HOME": temp}):
            data = dict(unit=UNIT, metric="cpu_percent", status="NON_RIENTRATO")
            file = Path(triage.save_receipt(data))
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            triage.save_receipt(dict(data, status="SOTTO_SOGLIA"))
            self.assertEqual(triage.last_verification(UNIT, "cpu_percent")["status"], "SOTTO_SOGLIA")
            self.assertIsNone(triage.last_verification(UNIT, "memory_mib"))

    def test_learned_threshold_and_unit_override(self):
        prior = {"baseline": {"io_ops_min": (15, 500)}}
        self.assertEqual(triage.threshold(UNIT, "io_ops_min", {}, None, prior), 2000)
        overrides = {"units": {UNIT: {"io_ops_min": 7000}}}
        self.assertEqual(triage.threshold(UNIT, "io_ops_min", overrides, None, prior), 7000)

    def verify(self, windows, *, receipt=None, start=0, samples=2):
        args = SimpleNamespace(unit=UNIT, metric="io_ops_min", threshold=100,
                               expect_change=receipt is not None, probe=["dummy"] if receipt else None,
                               samples=samples, minutes=15, timeout=120)
        with patch.object(triage, "pairs", return_value=windows), patch.object(triage, "_connection"), \
             patch.object(triage, "history", return_value=[]), \
             patch.object(triage.time, "time", side_effect=[start, 121]), \
             patch.object(triage, "probe", side_effect=receipt):
            return triage.verification("unused", args, {})

    def test_verification_excludes_crossing_window_and_resets_on_gap(self):
        a,b,c,d = [snapshot(t, 0) for t in (0,60,120,180)]
        result,code = self.verify([(a,b,60), (b,c,None), (c,d,60)], start=1)
        self.assertEqual((code, result["status"], len(result["samples"])), (2, "DATI_INSUFFICIENTI", 1))
        self.assertEqual(self.verify([(a,b,60),(b,c,60)])[1], 0)
        self.assertEqual(self.verify([(a,b,60),(b,snapshot(120,80),60)])[1], 1)

    def test_functional_generation_must_change_within_measured_interval(self):
        a,b,c,d = [snapshot(t, 0) for t in (0,60,120,180)]
        windows = [(a,b,60), (b,c,60), (c,d,60)]
        receipts = [(True,b"one"),(True,b"two")]
        self.assertEqual(self.verify(windows, receipt=receipts)[1], 0)
        self.assertEqual(self.verify(windows[:2], receipt=receipts, samples=1)[1], 2)
        result,code = self.verify(windows, receipt=[(True,b"same")]*3)
        self.assertEqual((result["status"],code), ("CICLO_NON_CONFERMATO",2))


if __name__ == "__main__":
    unittest.main()
