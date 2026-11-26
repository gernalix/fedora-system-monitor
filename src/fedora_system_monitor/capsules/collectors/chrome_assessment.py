"""Aggregate the operator's already sampled Chrome processes once per minute."""
import json
import time

from ..config import DEFAULT_CONFIG
from .common import operator_identity
from .model import record

METRIC = "chrome.resource_assessment"
PREVIOUS = """SELECT details_json FROM periodic_metrics WHERE category='process'
              AND name='chrome.resource_assessment' ORDER BY timestamp_utc DESC LIMIT 1"""


def assess(snapshot, uid, limits, previous):
    rows = [r for r in snapshot["rows"] if r["uid"] == uid and r["name"] in ("chrome", "google-chrome")]
    timed = [r for r in rows if 20 <= (r.get("interval_seconds") or 0) <= 90]
    cpu = [r["cpu_percent"] for r in timed if r["cpu_percent"] is not None]
    io = [(r["read_delta"] + r["write_delta"]) / r["interval_seconds"] / 1048576
          for r in timed if r["read_delta"] is not None and r["write_delta"] is not None]
    rss = [r["rss_bytes"] / 1048576 for r in rows if r["rss_bytes"] is not None]
    values = {"cpu_percent": sum(cpu) if cpu else None, "io_mib_s": sum(io) if io else None,
              "largest_process_rss_mib": max(rss, default=None)}
    limits = {key: limits["memory_mib" if key == "largest_process_rss_mib" else key] for key in values}
    continuous = (snapshot["boot_id"] == previous.get("boot_id") and uid == previous.get("uid")
                  and limits == previous.get("limits")
                  and 20 <= snapshot["timestamp"] - previous.get("timestamp", 0) <= 90)
    old = previous.get("streak", {}) if continuous else {}
    streak = {}
    for key, value in values.items():
        high = snapshot["complete"] and value is not None and value >= limits[key]
        streak[key] = min(3, old.get(key, 0) + 1) if high else 0
    ready = any(n == 3 for n in streak.values())
    return {"uid": uid, "boot_id": snapshot["boot_id"], "timestamp": snapshot["timestamp"],
            "complete": snapshot["complete"], "unreadable_processes": snapshot["unreadable"],
            "observed_chrome": len(rows), "cpu_samples": len(cpu), "io_samples": len(io),
            "rss_samples": len(rss), "values": values, "limits": limits, "streak": streak,
            "review_eligible": ready}, ready and not any(n == 3 for n in old.values())


def append_assessment(result, config, db):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    uid = operator_identity(config)[2]
    previous = db.query(PREVIOUS)
    details, crossed = assess(result.process_snapshot, uid, config.get("unit_resources", DEFAULT_CONFIG["unit_resources"]),
                              json.loads(previous[0]["details_json"]) if previous else {})
    details["evaluation_cpu_us"] = (time.process_time_ns() - cpu) // 1000
    details["evaluation_wall_us"] = (time.perf_counter_ns() - wall) // 1000
    result.metrics.append(record(60, "process", METRIC, int(details["review_eligible"]), "boolean",
                                 source="process_history", details=details))
    if crossed:
        result.events.append(record(60, "process", "chrome_sustained_resources", source="process_history",
                                    details={"values": details["values"], "streak": details["streak"],
                                             "next_action": "user_selected_single_extension_trial"}))
