"""Compress scanner evidence for one incident and recheck that exact target."""
from datetime import datetime
import json
from pathlib import Path
import time
from types import SimpleNamespace

from ..collectors import unit_repairs
from . import _connection, resource_pid_trace
from . import resource_triage as triage


def read_alert(db, case_id):
    row = db.execute("""SELECT device_id,name,status,first_seen_utc,last_seen_utc,details_json
        FROM alerts WHERE id=? AND source='unit_resource_scanner'""", (case_id,)).fetchone()
    if row is None:
        raise ValueError("ID assente dallo storico degli avvisi dello scanner FSM")
    detail = json.loads(row["details_json"])
    return dict(id=case_id, unit=row["device_id"], metric=row["name"].removeprefix("service.resource."),
                state=row["status"], opened=row["first_seen_utc"], seen=row["last_seen_utc"],
                value=detail.get("value"), threshold=detail.get("limit"))


def journal_verification(args, item):
    # Short-lived jobs leave no cgroup counters between invocations. Use actual
    # per-unit scanner measurements, which include the recovery transition.
    start = time.time()
    deadline = time.monotonic() + args.timeout
    evidence = {}
    status = "DATI_INSUFFICIENTI"
    while True:
        with _connection(args.db) as db:
            current = read_alert(db, item["id"])
            if (current["opened"], current["unit"], current["metric"]) != (item["opened"], item["unit"], item["metric"]):
                break
            rows = db.execute("""SELECT timestamp_utc,value,details_json FROM periodic_metrics
                WHERE category='service' AND name=? AND timestamp_utc>=? AND device_id=?
                AND source='unit_resource_scanner' ORDER BY timestamp_utc DESC LIMIT 8""",
                ("service.resource." + item["metric"], triage.iso(start).replace("+00:00","Z"), item["unit"]))
            for row in rows:
                stamp = row["timestamp_utc"]
                detail = json.loads(row["details_json"])
                end = datetime.fromisoformat(stamp).timestamp()
                # A tick ending after invocation may straddle the change.
                if current["state"] != "active" and end > datetime.fromisoformat(current["seen"]).timestamp():
                    continue
                if end - detail["window_seconds"] - 1 >= start:
                    evidence[stamp] = dict(end=stamp, value=row["value"], threshold=detail["limit"],
                                           active=detail["active"], boot=detail["boot_id"],
                                           window=detail["window_seconds"])
        points = sorted(evidence.values(), key=lambda p: p["end"])
        if len(points) >= 2:
            a, b = points[-2:]
            delta = datetime.fromisoformat(b["end"]).timestamp() - datetime.fromisoformat(a["end"]).timestamp()
            # Completed jobs may be separated by unobserved minutes. Trust FSM's
            # recovery transition only when both measurements belong to this case.
            same_series = a["boot"] == b["boot"] and (item["metric"] in
                ("completed_cpu_seconds", "completed_memory_peak_mib") or abs(delta - b["window"]) <= 3)
            calm = all(p["value"] < .8 * p["threshold"] for p in (a,b))
            if same_series and calm and not b["active"] and current["state"] == "recovered":
                status = "SOTTO_SOGLIA"
                break
            if same_series and current["state"] == "active" and all(p["value"] >= p["threshold"] for p in (a,b)):
                status = "NON_RIENTRATO"
                break
        left = deadline - time.monotonic()
        if current["state"] != "active" or left <= 0:
            break
        time.sleep(min(30, left))
    return dict(unit=item["unit"], metric=item["metric"], started=triage.iso(start), status=status,
                probe=None, samples=sorted(evidence.values(), key=lambda p: p["end"])[-3:]), {
                    "SOTTO_SOGLIA": 0, "NON_RIENTRATO": 1, "DATI_INSUFFICIENTI": 2}[status]


def report(args, policy, uid):
    recipes = unit_repairs.configured_recipes(policy, uid)
    with _connection(args.db) as db:
        case_id = args.id
        if case_id is None:
            result = triage.next_incident(db, recipes, args.metric, summary_only=True)
            if "incident" not in result:
                frames = triage.history(db, "io_ops_min", 3, time.time())
                if not frames or not 0 <= time.time() - datetime.fromisoformat(frames[0][0]).timestamp() <= 180:
                    return {"status": "SCANNER_NON_RECENTE"}, 2
                return result, 0
            case_id = result["incident"]["id"]
        item = read_alert(db, case_id)
        if not args.verify:
            frames = triage.history(db, item["metric"], args.minutes, time.time())
            points = [frame[item["unit"]] for _, frame in frames if item["unit"] in frame]
            age = time.time() - datetime.fromisoformat(item["seen"]).timestamp()
            item.update(recent=0 <= age <= 180, recorded_frames=len(frames), seen_in_top5=len(points),
                        peak_in_top5=max(points, default=None),
                        recipe=recipes.get(item["unit"], {}).get(item["metric"]),
                        last_check=triage.last_verification(item["unit"], item["metric"]))
            if item["state"] == "active" and item["recent"]:
                item["processes_by_cpu"] = [
                    {key: row[key] for key in ("pid", "name", "cpu_percent")}
                    for row in triage.process_rows(db, item["unit"], 3)]
    if not args.verify:
        if args.io_seconds and item["state"] == "active" and item["recent"]:
            item["pid_io"] = resource_pid_trace.attribution(item["unit"], args.io_seconds)
        return item, 0
    if item["metric"] in triage.METRICS:
        probe = None
        if item["unit"] == f"user:{uid}:prompt-history-dashboard.service":
            script = Path(__file__).resolve().parents[4] / "scripts/fsm-verify-prompt-history"
            probe = [str(script), "--receipt"]
        check = SimpleNamespace(unit=item["unit"], metric=item["metric"], minutes=args.minutes,
                                samples=3, threshold=None, timeout=args.timeout, probe=probe,
                                expect_change=bool(probe))
        result, code = triage.verification(args.db, check, policy)
    else:
        result, code = journal_verification(args, item)
    result.update(case_id=case_id, ended=triage.iso(time.time()))
    result["receipt"] = triage.save_receipt(result)
    return result, code
