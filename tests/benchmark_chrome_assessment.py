"""Replay existing Fedora process scans into disposable A/B databases."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import statistics
import tempfile
import time

from fedora_system_monitor.capsules.alerting import evaluate_metric_alerts
from fedora_system_monitor.capsules.collectors.chrome_assessment import append_assessment
from fedora_system_monitor.capsules.collectors.model import CollectionResult, record
from fedora_system_monitor.capsules.config import DEFAULT_CONFIG
from fedora_system_monitor.capsules.database import Database


def replay(snapshots, directory, enabled):
    db = Database(directory / ("with.db" if enabled else "without.db"))
    wall = []
    cpu = []
    try:
        for snap in snapshots:
            result = CollectionResult("minute", process_snapshot=snap)
            result.metrics.append(record(60, "collector", "fixture", 1, source="benchmark"))
            wt, ct = time.perf_counter_ns(), time.process_time_ns()
            if enabled:
                append_assessment(result, DEFAULT_CONFIG, db)
            db.insert_metrics(result.metrics, cadence_seconds=60)
            db.insert_events(result.events)
            evaluate_metric_alerts(result.metrics, DEFAULT_CONFIG, db.get_state, db.set_state)
            wall.append((time.perf_counter_ns() - wt)/1e6)
            cpu.append((time.process_time_ns() - ct)/1e6)
    finally:
        db.close()
    return wall, cpu


def main():
    uri = "file:/var/lib/fedora-system-monitor/monitor.sqlite3?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as con:
        con.row_factory = sqlite3.Row
        scans = [dict(r) for r in con.execute("SELECT * FROM process_scans ORDER BY id DESC LIMIT 20")][::-1]
        if len(scans) < 3:
            raise SystemExit("insufficient retained process scans")
        for scan in scans:
            scan["rows"] = [dict(r) for r in con.execute(
                "SELECT i.name,i.uid,s.interval_seconds,s.cpu_percent,s.read_delta,s.write_delta,s.rss_bytes "
                "FROM process_samples s JOIN process_identities i ON i.id=s.identity_id WHERE s.scan_id=?",
                (scan["id"],))]
    differences = [[], []]
    for sequence in ((False,True),(True,False),(False,True),(True,False)):
        with tempfile.TemporaryDirectory() as temp:
            groups = {enabled: replay(scans,Path(temp),enabled) for enabled in sequence}
            for i in (0,1):
                differences[i].extend(on-off for on,off in zip(groups[True][i],groups[False][i]))
    print(json.dumps({"real_scans": len(scans), "paired_observations": len(differences[0]),
                      "process_rows_per_scan_median": statistics.median(len(s["rows"]) for s in scans),
                      "original_proc_scan_median_ms": round(statistics.median(s["duration_ms"] for s in scans),3),
                      "extra_wall_median_ms": round(statistics.median(differences[0]),3),
                      "extra_cpu_median_ms": round(statistics.median(differences[1]),3)}))


if __name__ == "__main__":
    main()
