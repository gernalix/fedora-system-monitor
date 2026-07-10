#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import resource
import sqlite3
import tempfile
import time

from fedora_system_monitor.capsules.database import Database


SERIES = {60: 68, 300: 120, 900: 29, 3600: 20, 86400: 23}
RETENTION_DAYS = {60: 14, 300: 60, 900: 180, 3600: 365, 86400: 1825}
INVENTORY_ITEMS = 2966
HARDWARE_EVENTS_PER_DAY = 20
SOFTWARE_EVENTS_PER_DAY = 40
ALERTS_PER_DAY = 5


def table_bytes(database: Database, names: list[str]) -> int:
    placeholders = ",".join("?" for _ in names)
    row = database.query(
        f"SELECT COALESCE(SUM(pgsize),0) AS bytes FROM dbstat WHERE name IN ({placeholders})",
        names,
    )[0]
    return int(row["bytes"])


def insert_metric_day(database: Database, day: datetime) -> int:
    inserted = 0
    chunk: list[dict[str, object]] = []
    for cadence, series_count in SERIES.items():
        samples = 86400 // cadence
        for sample in range(samples):
            instant = day + timedelta(seconds=sample * cadence)
            for series in range(series_count):
                name = f"metric_{cadence}_{series}"
                unit = "%"
                value: float | None = float((sample + series) % 101)
                device_id = f"device-{series % 8}"
                if cadence == 300 and series == 0:
                    name, unit = "interface_rx_bytes", "bytes"
                    value = float(sample * 8192)
                    device_id = "eth0"
                elif cadence == 300 and series == 1:
                    name, unit = "interface_tx_bytes", "bytes"
                    value = float(sample * 4096)
                    device_id = "eth0"
                elif series == 2:
                    unit = "boolean"
                    value = float(sample % 2)
                chunk.append(
                    {
                        "category": "synthetic",
                        "name": name,
                        "value": value,
                        "unit": unit,
                        "device_id": device_id,
                        "timestamp_utc": instant,
                        "severity": "warning" if sample % 997 == 0 else "info",
                        "source": "audit",
                    }
                )
                if len(chunk) >= 20_000:
                    inserted += database.insert_metrics(chunk, cadence_seconds=cadence)
                    chunk.clear()
        if chunk:
            inserted += database.insert_metrics(chunk, cadence_seconds=cadence)
            chunk.clear()
    return inserted


def insert_inventory_day(database: Database, day: datetime) -> int:
    items = [
        {
            "category": "software",
            "name": f"package-{index}",
            "item_key": f"rpm:package-{index}:x86_64",
            "version": f"1.{index % 100}.0-1.fc44",
            "architecture": "x86_64",
            "repository": "rpmdb",
            "source": "rpm",
            "path": f"/usr/bin/package-{index}" if index % 5 == 0 else None,
        }
        for index in range(INVENTORY_ITEMS)
    ]
    snapshot = f"software-{day:%Y%m%d}"
    database.insert_software_snapshot(items, snapshot_id=snapshot, collected_at=day)
    return len(items)


def insert_event_day(database: Database, day: datetime) -> int:
    events: list[dict[str, object]] = []
    for index in range(HARDWARE_EVENTS_PER_DAY):
        events.append(
            {
                "category": "hardware",
                "name": "device_changed",
                "device_id": f"device-{index % 8}",
                "timestamp_utc": day + timedelta(minutes=index),
                "dedup_key": f"hardware:{day.date()}:{index}",
            }
        )
    for index in range(SOFTWARE_EVENTS_PER_DAY):
        events.append(
            {
                "category": "software",
                "name": "package_update",
                "device_id": f"package-{index}",
                "timestamp_utc": day + timedelta(minutes=60 + index),
                "dedup_key": f"software:{day.date()}:{index}",
            }
        )
    return database.insert_events(events, dedup_window_seconds=0)


def insert_alert_day(database: Database, day: datetime) -> int:
    for index in range(ALERTS_PER_DAY):
        key = f"audit:{day.date()}:{index}"
        database.open_alert(
            key,
            category="system",
            name="audit_alert",
            occurred_at=day + timedelta(hours=1, minutes=index),
        )
        database.recover_alert(
            key, recovered_at=day + timedelta(hours=2, minutes=index)
        )
    return ALERTS_PER_DAY


def projected_rows(days: int) -> dict[str, int]:
    metric_rows = sum(
        SERIES[cadence] * (86400 // cadence) * min(days, retention)
        for cadence, retention in RETENTION_DAYS.items()
    )
    aggregate_rows = sum(
        SERIES[cadence] * max(0, days - retention)
        for cadence, retention in RETENTION_DAYS.items()
    )
    if days <= 35:
        snapshots = days
    else:
        snapshots = 35 + (days - 35 + 6) // 7 + (days - 35 + 29) // 30
    return {
        "metrics": metric_rows,
        "aggregates": aggregate_rows,
        "software_inventory": snapshots * INVENTORY_ITEMS,
        "events": SOFTWARE_EVENTS_PER_DAY * days
        + HARDWARE_EVENTS_PER_DAY * min(days, 365),
        "alerts": ALERTS_PER_DAY * min(days, 730),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=2)
    args = parser.parse_args()
    if args.days < 1 or args.days > 7:
        raise SystemExit("--days must be between 1 and 7")

    with tempfile.TemporaryDirectory(prefix="fsm-db-growth-") as temp:
        path = Path(temp) / "synthetic.sqlite3"
        backup_path = Path(temp) / "backup.sqlite3"
        database = Database(path, hostname="audit")
        reader = sqlite3.connect(path)
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM periodic_metrics").fetchone()
        start_day = datetime(2026, 7, 7, tzinfo=timezone.utc)
        started = time.monotonic()
        totals = {"metrics": 0, "inventory": 0, "events": 0, "alerts": 0}
        for offset in range(args.days):
            day = start_day + timedelta(days=offset)
            totals["metrics"] += insert_metric_day(database, day)
            totals["inventory"] += insert_inventory_day(database, day)
            totals["events"] += insert_event_day(database, day)
            totals["alerts"] += insert_alert_day(database, day)
        insert_seconds = time.monotonic() - started
        wal_peak = path.with_name(path.name + "-wal").stat().st_size
        checkpointer = sqlite3.connect(path)
        checkpointer.execute("PRAGMA busy_timeout=10000")
        reader.rollback()
        reader.close()

        checkpoint_started = time.monotonic()
        checkpoint_values = checkpointer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        checkpoint_seconds = time.monotonic() - checkpoint_started
        checkpointer.close()
        checkpoint = {
            "busy": int(checkpoint_values[0]),
            "log": int(checkpoint_values[1]),
            "checkpointed": int(checkpoint_values[2]),
        }
        physical_before = path.stat().st_size
        page_size = int(database.query("PRAGMA page_size")[0]["page_size"])
        page_count_before = int(database.query("PRAGMA page_count")[0]["page_count"])
        freelist_before = int(database.query("PRAGMA freelist_count")[0]["freelist_count"])

        metric_bytes = table_bytes(
            database,
            [
                "periodic_metrics",
                "idx_metrics_time",
                "idx_metrics_name_time",
                "idx_metrics_cadence_time",
            ],
        )
        inventory_bytes = table_bytes(
            database,
            ["software_inventory", "idx_software_snapshot", "idx_software_item_time"],
        )
        event_bytes = table_bytes(
            database, ["events", "idx_events_time", "idx_events_name_time", "idx_events_device_time"]
        )
        alert_bytes = table_bytes(
            database, ["alerts", "idx_alerts_status_severity", "idx_alerts_key_time", "ux_alerts_active_key"]
        )
        index_bytes_before = int(
            database.query(
                "SELECT COALESCE(SUM(pgsize),0) AS bytes FROM dbstat "
                "WHERE name IN (SELECT name FROM sqlite_master WHERE type='index')"
            )[0]["bytes"]
        )
        table_bytes_before = int(
            database.query(
                "SELECT COALESCE(SUM(pgsize),0) AS bytes FROM dbstat "
                "WHERE name NOT IN (SELECT name FROM sqlite_master WHERE type='index')"
            )[0]["bytes"]
        )

        retention_started = time.monotonic()
        retention = database.apply_retention(
            now=datetime(2026, 7, 10, tzinfo=timezone.utc),
            metric_days_by_cadence={cadence: 0 for cadence in SERIES},
            event_days=0,
            hardware_event_days=0,
            alert_days=0,
            collector_run_days=0,
            dedup_state_days=0,
            inventory_daily_days=0,
            compact=False,
        )
        retention_seconds = time.monotonic() - retention_started
        second_retention_started = time.monotonic()
        second_retention = database.apply_retention(
            now=datetime(2026, 7, 10, tzinfo=timezone.utc),
            metric_days_by_cadence={cadence: 0 for cadence in SERIES},
            event_days=0,
            hardware_event_days=0,
            alert_days=0,
            collector_run_days=0,
            dedup_state_days=0,
            inventory_daily_days=0,
            compact=False,
        )
        second_retention_seconds = time.monotonic() - second_retention_started
        aggregate_rows = database.query(
            "SELECT category,name,unit,source,device_id,bucket_start_utc,bucket_end_utc,"
            "period_seconds,sample_count,problematic_seconds,details_json "
            "FROM metric_aggregates"
        )
        invalid_aggregates = 0
        for row in aggregate_rows:
            start = datetime.fromisoformat(str(row["bucket_start_utc"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(row["bucket_end_utc"]).replace("Z", "+00:00"))
            details = json.loads(str(row["details_json"]))
            if (
                end - start != timedelta(days=1)
                or int(row["period_seconds"]) != 86400
                or int(row["problematic_seconds"]) > 86400
                or details.get("aggregation") != "daily_utc"
                or not row["category"]
                or not row["name"]
                or not row["source"]
            ):
                invalid_aggregates += 1
        software_events_remaining = int(
            database.query(
                "SELECT COUNT(*) AS count FROM events WHERE category='software'"
            )[0]["count"]
        )
        aggregate_bytes = table_bytes(
            database, ["metric_aggregates", "idx_aggregates_name_bucket"]
        )
        logical_after = sum(
            int(row["bytes"])
            for row in database.query("SELECT SUM(pgsize) AS bytes FROM dbstat GROUP BY name")
        )
        physical_after_retention = path.stat().st_size
        freelist_after_retention = int(
            database.query("PRAGMA freelist_count")[0]["freelist_count"]
        )

        compact_started = time.monotonic()
        database.compact()
        compact_seconds = time.monotonic() - compact_started
        physical_after_compact = path.stat().st_size

        integrity_started = time.monotonic()
        check = database.db_check()
        integrity_seconds = time.monotonic() - integrity_started
        backup_started = time.monotonic()
        database.backup(backup_path)
        backup_seconds = time.monotonic() - backup_started

        reuse_before = path.stat().st_size
        reuse_started = time.monotonic()
        reused_rows = insert_metric_day(
            database, start_day + timedelta(days=args.days + 1)
        )
        database.compact()
        reuse_seconds = time.monotonic() - reuse_started
        reuse_after = path.stat().st_size

        bytes_per = {
            "metric": metric_bytes / max(1, totals["metrics"]),
            "inventory": inventory_bytes / max(1, totals["inventory"]),
            "event": event_bytes / max(1, totals["events"]),
            "alert": alert_bytes / max(1, totals["alerts"]),
            "aggregate": aggregate_bytes / max(1, retention["aggregates_written"]),
        }
        base_bytes = page_size * 40
        projections: dict[str, dict[str, int]] = {}
        for horizon in (14, 60, 180, 365):
            rows = projected_rows(horizon)
            database_bytes = int(
                base_bytes
                + rows["metrics"] * bytes_per["metric"]
                + rows["software_inventory"] * bytes_per["inventory"]
                + rows["events"] * bytes_per["event"]
                + rows["alerts"] * bytes_per["alert"]
                + rows["aggregates"] * bytes_per["aggregate"]
            )
            backup_copies_upper = (
                min(horizon, 14)
                + min((horizon + 6) // 7, 8)
                + min((horizon + 29) // 30, 12)
            )
            projections[str(horizon)] = {
                **rows,
                "database_bytes": database_bytes,
                "backup_copies_upper_bound": backup_copies_upper,
                "backup_bytes_upper_bound": database_bytes * backup_copies_upper,
            }

        result = {
            "synthetic_days": args.days,
            "inserted": totals,
            "insert_seconds": round(insert_seconds, 3),
            "wal_peak_bytes": wal_peak,
            "checkpoint": checkpoint,
            "checkpoint_seconds": round(checkpoint_seconds, 4),
            "physical_before_retention": physical_before,
            "page_count_before_retention": page_count_before,
            "freelist_before_retention": freelist_before,
            "index_bytes_before_retention": index_bytes_before,
            "table_bytes_before_retention": table_bytes_before,
            "retention": retention,
            "retention_seconds": round(retention_seconds, 3),
            "second_retention": second_retention,
            "second_retention_seconds": round(second_retention_seconds, 4),
            "aggregate_validation": {
                "rows": len(aggregate_rows),
                "invalid_rows": invalid_aggregates,
                "software_events_remaining": software_events_remaining,
            },
            "logical_after_retention": logical_after,
            "physical_after_retention": physical_after_retention,
            "freelist_after_retention": freelist_after_retention,
            "compact_seconds": round(compact_seconds, 4),
            "physical_after_compact": physical_after_compact,
            "integrity_ok": check["ok"],
            "integrity_seconds": round(integrity_seconds, 4),
            "backup_bytes": backup_path.stat().st_size,
            "backup_seconds": round(backup_seconds, 3),
            "freelist_reuse": {
                "rows_inserted": reused_rows,
                "physical_before": reuse_before,
                "physical_after": reuse_after,
                "growth_bytes": reuse_after - reuse_before,
                "seconds": round(reuse_seconds, 3),
            },
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "bytes_per_row": {key: round(value, 2) for key, value in bytes_per.items()},
            "projections": projections,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
