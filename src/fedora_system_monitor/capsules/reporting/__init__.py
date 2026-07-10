"""Bounded read-only queries and human/JSON/CSV rendering."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from fedora_system_monitor.capsules.config import redact_text


ALLOWED_EXPORT_TABLES = {
    "periodic_metrics",
    "events",
    "alerts",
    "hardware_inventory",
    "software_inventory",
    "collector_runs",
    "metric_aggregates",
    "summaries",
}


@contextmanager
def _connection(path: str | Path):
    # WAL databases otherwise try to create a writable -shm file even for a
    # read-only client. Writers use short transactions and checkpoint on close,
    # so immutable read snapshots give unprivileged operators bounded access
    # without granting write permission to the database directory.
    uri = f"file:{Path(path).resolve()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=3)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def _rows(connection: sqlite3.Connection, sql: str, parameters: Iterable[Any] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(sql, tuple(parameters)).fetchall()]


def _latest_metrics(connection: sqlite3.Connection, where: str = "1=1", parameters: Iterable[Any] = ()) -> list[dict[str, Any]]:
    return _rows(
        connection,
        f"""
        SELECT m.* FROM periodic_metrics m
        JOIN (
            SELECT name, device_id, MAX(id) AS latest_id
            FROM periodic_metrics WHERE {where}
            GROUP BY name, device_id
        ) latest ON latest.latest_id=m.id
        ORDER BY m.category, m.name, m.device_id
        """,
        parameters,
    )


def status_report(path: str | Path) -> dict[str, Any]:
    database_path = Path(path)
    with _connection(database_path) as connection:
        schema = connection.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0]
        run = connection.execute(
            "SELECT name,finished_at_utc,outcome,duration_ms,error_message FROM collector_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        active = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='active'").fetchone()[0]
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("periodic_metrics", "events", "alerts", "hardware_inventory", "software_inventory")
        }
    return {
        "database": str(database_path),
        "database_bytes": database_path.stat().st_size,
        "schema_version": schema,
        "active_alerts": active,
        "last_run": dict(run) if run else None,
        "row_counts": counts,
    }


def health_report(path: str | Path) -> dict[str, Any]:
    with _connection(path) as connection:
        alerts = _rows(
            connection,
            "SELECT severity,category,name,device_id,message,first_seen_utc,last_seen_utc,occurrence_count FROM alerts WHERE status='active' ORDER BY CASE severity WHEN 'emergency' THEN 0 WHEN 'critical' THEN 1 ELSE 2 END, first_seen_utc",
        )
        failures = _rows(
            connection,
            "SELECT name,finished_at_utc,outcome,error_message FROM collector_runs WHERE outcome NOT IN ('ok','partial') ORDER BY id DESC LIMIT 10",
        )
    state = "healthy"
    if any(item["severity"] in {"critical", "emergency"} for item in alerts):
        state = "critical"
    elif alerts or failures:
        state = "warning"
    return {"state": state, "active_alert_count": len(alerts), "alerts": alerts, "recent_collector_failures": failures}


def events_report(path: str | Path, *, limit: int = 100, category: str = "", since_hours: int = 24) -> list[dict[str, Any]]:
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    clause = "timestamp_utc>=?"
    parameters: list[Any] = [since]
    if category:
        clause += " AND category=?"
        parameters.append(category)
    parameters.append(max(1, min(limit, 5000)))
    with _connection(path) as connection:
        return _rows(
            connection,
            f"SELECT id,timestamp_utc,timestamp_local,category,name,severity,source,device_id,details_json,outcome,error_message,occurrence_count FROM events WHERE {clause} ORDER BY id DESC LIMIT ?",
            parameters,
        )


def alerts_report(path: str | Path, *, active_only: bool = True, limit: int = 200) -> list[dict[str, Any]]:
    clause = "WHERE status='active'" if active_only else ""
    with _connection(path) as connection:
        return _rows(
            connection,
            f"SELECT id,first_seen_utc,last_seen_utc,recovered_at_utc,category,name,severity,status,source,device_id,message,occurrence_count,last_notification_status FROM alerts {clause} ORDER BY last_seen_utc DESC LIMIT ?",
            (max(1, min(limit, 5000)),),
        )


def metrics_report(path: str | Path, *, name: str = "", limit: int = 200) -> list[dict[str, Any]]:
    with _connection(path) as connection:
        if name:
            return _rows(
                connection,
                "SELECT id,timestamp_utc,cadence_seconds,category,name,value,unit,severity,source,device_id,details_json,outcome,error_message FROM periodic_metrics WHERE name LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{name}%", max(1, min(limit, 5000))),
            )
        return _latest_metrics(connection)[: max(1, min(limit, 5000))]


def disks_report(path: str | Path) -> dict[str, Any]:
    with _connection(path) as connection:
        metrics = _latest_metrics(connection, "category IN ('storage','filesystem','disk_io','temperature')")
        inventory = _rows(
            connection,
            "SELECT timestamp_utc,device_id,category,name,vendor,model,size_bytes,filesystem_uuid,label,filesystem,mount_point,present,details_json FROM hardware_inventory WHERE snapshot_id=(SELECT snapshot_id FROM hardware_inventory ORDER BY id DESC LIMIT 1) ORDER BY category,model,name",
        )
    return {"filesystems_and_health": metrics, "inventory": inventory}


def network_report(path: str | Path) -> dict[str, Any]:
    with _connection(path) as connection:
        metrics = _latest_metrics(connection, "category='network'")
        events = _rows(
            connection,
            "SELECT timestamp_utc,name,severity,device_id,details_json FROM events WHERE category='network' ORDER BY id DESC LIMIT 30",
        )
    return {"current": metrics, "recent_events": events}


def software_report(path: str | Path) -> dict[str, Any]:
    with _connection(path) as connection:
        counts = _rows(
            connection,
            "SELECT source AS ecosystem,COUNT(*) AS count,MAX(timestamp_utc) AS observed_timestamp_utc FROM software_inventory WHERE snapshot_id=(SELECT snapshot_id FROM software_inventory ORDER BY id DESC LIMIT 1) GROUP BY source ORDER BY source",
        )
        changes = _rows(
            connection,
            "SELECT timestamp_utc,name,severity,source,details_json,outcome,error_message FROM events WHERE category='software' ORDER BY id DESC LIMIT 100",
        )
        updates = _latest_metrics(connection, "category='software'")
    return {"inventory_counts": counts, "recent_changes": changes, "update_state": updates}


def services_report(path: str | Path) -> list[dict[str, Any]]:
    with _connection(path) as connection:
        return _latest_metrics(connection, "category IN ('service','services')")


def errors_report(path: str | Path, *, limit: int = 100) -> dict[str, Any]:
    bounded = max(1, min(limit, 1000))
    with _connection(path) as connection:
        events = _rows(
            connection,
            "SELECT timestamp_utc,category,name,severity,source,device_id,error_message,details_json FROM events WHERE severity IN ('warning','critical','emergency') OR outcome IN ('error','failed','timeout') OR error_message IS NOT NULL ORDER BY id DESC LIMIT ?",
            (bounded,),
        )
        runs = _rows(
            connection,
            "SELECT started_at_utc,finished_at_utc,name,outcome,duration_ms,error_message,details_json FROM collector_runs WHERE outcome NOT IN ('ok','partial') ORDER BY id DESC LIMIT ?",
            (bounded,),
        )
    return {"events": events, "collector_runs": runs}


def build_daily_summary(
    path: str | Path,
    *,
    day: str | None = None,
    timezone_name: str = "Europe/Copenhagen",
) -> dict[str, Any]:
    zone = ZoneInfo(timezone_name)
    target = day or datetime.now(zone).date().isoformat()
    local_date = datetime.fromisoformat(target).date()
    start = datetime.combine(local_date, datetime.min.time(), tzinfo=zone).astimezone(timezone.utc)
    end = datetime.combine(local_date + timedelta(days=1), datetime.min.time(), tzinfo=zone).astimezone(timezone.utc)
    with _connection(path) as connection:
        latest = _latest_metrics(connection)
        events = _rows(
            connection,
            "SELECT category,name,severity,COUNT(*) AS count FROM events WHERE timestamp_utc>=? AND timestamp_utc<? GROUP BY category,name,severity ORDER BY category,name",
            (start.isoformat(), end.isoformat()),
        )
        opened = connection.execute("SELECT COUNT(*) FROM alerts WHERE first_seen_utc>=? AND first_seen_utc<?", (start.isoformat(), end.isoformat())).fetchone()[0]
        resolved = connection.execute("SELECT COUNT(*) FROM alerts WHERE recovered_at_utc>=? AND recovered_at_utc<?", (start.isoformat(), end.isoformat())).fetchone()[0]
        active = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='active'").fetchone()[0]
    by_name = {(item["name"], item["device_id"]): item for item in latest}
    selected_names = {
        "memory.used_percent",
        "swap.used_percent",
        "temperature.cpu_c",
        "temperature.nvme_c",
        "network.internet_reachable",
        "wifi.connected",
        "filesystem.free_percent",
        "service.active",
        "software.updates_available",
    }
    selected = [item for (name, _), item in by_name.items() if name in selected_names]
    health = "healthy" if active == 0 else "attention"
    return {
        "day": target,
        "health": health,
        "active_alerts": active,
        "new_alerts": opened,
        "resolved_alerts": resolved,
        "current": selected,
        "event_counts": events,
    }


def export_rows(
    path: str | Path,
    *,
    table: str,
    since_hours: int = 24,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    if table not in ALLOWED_EXPORT_TABLES:
        raise ValueError(f"unsupported export table: {table}")
    bounded = max(1, min(limit, 50_000))
    since = (datetime.now(timezone.utc) - timedelta(hours=max(1, since_hours))).isoformat()
    timestamp_column = "first_seen_utc" if table == "alerts" else "started_at_utc" if table == "collector_runs" else "bucket_start_utc" if table == "metric_aggregates" else "timestamp_utc"
    if table in {"schema_versions", "config_versions"}:
        timestamp_column = "applied_ts_utc"
    with _connection(path) as connection:
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if timestamp_column not in columns:
            return _rows(connection, f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (bounded,))
        return _rows(connection, f"SELECT * FROM {table} WHERE {timestamp_column}>=? ORDER BY id DESC LIMIT ?", (since, bounded))


def render(data: Any, *, output_format: str = "text") -> str:
    sanitized = _sanitize(data)
    if output_format == "json":
        return json.dumps(sanitized, indent=2, sort_keys=True, default=str)
    if output_format == "csv":
        rows = sanitized if isinstance(sanitized, list) else [sanitized]
        if not rows:
            return ""
        flattened = [_flatten(row) for row in rows]
        fields = sorted({key for row in flattened for key in row})
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        writer.writerows(flattened)
        return buffer.getvalue().rstrip()
    return _render_text(sanitized)


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {redact_text(str(key)): _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _flatten(value: dict[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, item in value.items():
        flattened[key] = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
    return flattened


def _render_text(data: Any) -> str:
    if isinstance(data, list):
        if not data:
            return "No records."
        return "\n".join(_render_text(item) for item in data)
    if isinstance(data, dict):
        return "\n".join(f"{key}: {_render_text(value) if isinstance(value, (dict, list)) else value}" for key, value in data.items())
    return str(data)


__all__ = [
    "alerts_report",
    "build_daily_summary",
    "disks_report",
    "errors_report",
    "events_report",
    "export_rows",
    "health_report",
    "metrics_report",
    "network_report",
    "render",
    "services_report",
    "software_report",
    "status_report",
]
