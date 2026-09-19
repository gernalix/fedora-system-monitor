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
            "SELECT severity,category,name,device_id,message,details_json,first_seen_utc,last_seen_utc,occurrence_count FROM alerts WHERE status='active' ORDER BY CASE severity WHEN 'emergency' THEN 0 WHEN 'critical' THEN 1 ELSE 2 END, first_seen_utc",
        )
        failures = _rows(
            connection,
            "SELECT name,finished_at_utc,outcome,error_message FROM collector_runs WHERE outcome NOT IN ('ok','partial') ORDER BY id DESC LIMIT 10",
        )
    storage_names = {"smartd_smart_alert", "expected_device_mounted"}
    host_filesystems = {"/", "/home", "/var", "/tmp", "/boot", "/boot/efi"}

    def is_storage_alert(item: dict[str, Any]) -> bool:
        if item["category"] == "storage" or item["name"] in storage_names:
            return True
        if item["name"] not in {"filesystem.free_percent", "filesystem.inode_free_percent"}:
            return False
        try:
            details = json.loads(str(item.get("details_json") or "{}"))
        except json.JSONDecodeError:
            details = {}
        return str(details.get("mount_point") or "") not in host_filesystems

    storage_alerts = [item for item in alerts if is_storage_alert(item)]
    host_alerts = [item for item in alerts if item not in storage_alerts]

    def state_for(items: list[dict[str, Any]], *, include_failures: bool = False) -> str:
        if any(item["severity"] in {"critical", "emergency"} for item in items):
            return "critical"
        if items or (include_failures and failures):
            return "warning"
        return "healthy"

    host_state = state_for(host_alerts, include_failures=True)
    storage_state = state_for(storage_alerts)
    return {
        "state": host_state,
        "host": {"state": host_state, "active_alert_count": len(host_alerts), "alerts": host_alerts},
        "storage": {"state": storage_state, "active_alert_count": len(storage_alerts), "alerts": storage_alerts},
        "active_alert_count": len(alerts),
        "alerts": alerts,
        "recent_collector_failures": failures,
    }


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


def timeline_report(path: str | Path, *, since_hours: int = 24, limit: int = 500) -> list[dict[str, Any]]:
    """Return one deduplicated chronological event stream across host domains."""
    since = (datetime.now(timezone.utc) - timedelta(hours=max(1, since_hours))).isoformat()
    categories = ("hardware", "software", "network", "backup", "system", "alert", "service", "storage", "filesystem")
    placeholders = ",".join("?" for _ in categories)
    with _connection(path) as connection:
        return _rows(
            connection,
            f"""
            SELECT timestamp_utc,timestamp_local,category,name,severity,source,
                   device_id,outcome,occurrence_count,first_seen_utc,last_seen_utc,
                   details_json,error_message
            FROM events
            WHERE timestamp_utc>=? AND category IN ({placeholders})
            ORDER BY timestamp_utc DESC,id DESC LIMIT ?
            """,
            (since, *categories, max(1, min(limit, 5000))),
        )


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def trends_report(path: str | Path) -> dict[str, Any]:
    """Compute bounded 24-hour and seven-day operational trends from raw samples."""
    definitions = {
        "cpu": ({"cpu_total_used_percent"}, "above", 90.0, True),
        "ram": ({"memory.used_percent"}, "above", 90.0, True),
        "temperature": ({"temperature.cpu_c", "temperature.nvme_c", "temperature"}, "above", 90.0, True),
        "disk_space": ({"filesystem.free_percent"}, "below", 20.0, False),
        "network": ({"interface_download_bytes_per_second", "interface_upload_bytes_per_second"}, "above", None, True),
    }
    now = datetime.now(timezone.utc)
    output: dict[str, Any] = {}
    with _connection(path) as connection:
        for window_name, hours in (("24h", 24), ("7d", 24 * 7)):
            since = (now - timedelta(hours=hours)).isoformat()
            window: dict[str, Any] = {}
            for label, (names, direction, threshold, include_p95) in definitions.items():
                placeholders = ",".join("?" for _ in names)
                rows = connection.execute(
                    f"SELECT value,cadence_seconds,unit,name FROM periodic_metrics WHERE timestamp_utc>=? AND name IN ({placeholders}) AND value IS NOT NULL ORDER BY timestamp_utc",
                    (since, *sorted(names)),
                ).fetchall()
                values = [float(row["value"]) for row in rows]
                above_seconds = 0
                if threshold is not None:
                    for row in rows:
                        breached = float(row["value"]) > threshold if direction == "above" else float(row["value"]) < threshold
                        if breached:
                            above_seconds += min(int(row["cadence_seconds"]), 3600)
                window[label] = {
                    "minimum": min(values) if values else None,
                    "maximum": max(values) if values else None,
                    "average": sum(values) / len(values) if values else None,
                    "p95": _p95(values) if include_p95 else None,
                    "sample_count": len(values),
                    "threshold": threshold,
                    "threshold_direction": direction if threshold is not None else None,
                    "time_above_or_below_threshold_seconds": above_seconds if threshold is not None else None,
                    "units": sorted({str(row["unit"]) for row in rows if row["unit"]}),
                }
            output[window_name] = window
    return output


def service_history_report(path: str | Path, *, since_days: int = 7) -> list[dict[str, Any]]:
    """Derive service availability and restart history from existing samples."""
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, min(since_days, 365)))).isoformat()
    with _connection(path) as connection:
        rows = connection.execute(
            "SELECT timestamp_utc,value,cadence_seconds,device_id,details_json FROM periodic_metrics WHERE name='service.active' AND timestamp_utc>=? ORDER BY device_id,timestamp_utc,id",
            (since,),
        ).fetchall()
    by_service: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        by_service.setdefault(str(row["device_id"] or "unknown"), []).append(row)
    output: list[dict[str, Any]] = []
    for service, samples in sorted(by_service.items()):
        downtime = sum(min(int(row["cadence_seconds"]), 3600) for row in samples if not float(row["value"] or 0))
        observed = sum(min(int(row["cadence_seconds"]), 3600) for row in samples)
        restart_count = 0
        last_restart = None
        previous_count: int | None = None
        for row in samples:
            try:
                current_count = int(json.loads(row["details_json"] or "{}").get("restart_count") or 0)
            except (ValueError, TypeError, json.JSONDecodeError):
                current_count = 0
            if previous_count is not None and current_count > previous_count:
                restart_count += current_count - previous_count
                last_restart = row["timestamp_utc"]
            previous_count = current_count
        current_up = bool(float(samples[-1]["value"] or 0))
        current_uptime = 0
        if current_up:
            for row in reversed(samples):
                if not float(row["value"] or 0):
                    break
                current_uptime += min(int(row["cadence_seconds"]), 3600)
        down_samples = [row for row in samples if not float(row["value"] or 0)]
        output.append(
            {
                "service": service,
                "current_up": current_up,
                "uptime_seconds": current_uptime,
                "last_restart_utc": last_restart,
                "restart_count": restart_count,
                "downtime_total_seconds": downtime,
                "last_downtime_utc": down_samples[-1]["timestamp_utc"] if down_samples else None,
                "availability_percent": (100.0 * (observed - downtime) / observed) if observed else None,
                "sample_count": len(samples),
                "window_days": since_days,
            }
        )
    return output


def dashboard_report(path: str | Path) -> dict[str, Any]:
    """Assemble a local, database-backed operational dashboard."""
    with _connection(path) as connection:
        latest = _latest_metrics(connection)
        recent_events = _rows(
            connection,
            "SELECT timestamp_local,category,name,severity,device_id,outcome,occurrence_count FROM events ORDER BY id DESC LIMIT 20",
        )
        last_backup = connection.execute(
            "SELECT timestamp_utc,details_json,outcome,error_message FROM events WHERE category='backup' OR name LIKE '%backup%' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    fresh_cutoff = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    latest = [
        row for row in latest
        if str(row.get("timestamp_utc") or "") >= fresh_cutoff
        and "/systemd-private-" not in str(row.get("details_json") or "")
    ]
    groups = {
        "cpu": {"cpu_total_used_percent", "load_1m", "load_5m", "load_15m"},
        "ram": {"memory.used_percent", "ram_available_bytes", "swap.used_percent"},
        "temperatures": {"temperature.cpu_c", "temperature.nvme_c", "temperature", "sensor.alarm"},
        "filesystems": {"filesystem.free_percent", "filesystem.read_only"},
        "network": {"network.internet_reachable", "network.gateway_reachable", "wifi.connected", "interface_download_bytes_per_second", "interface_upload_bytes_per_second"},
        "services": {"service.active", "failed_service_count", "service.restart_count_window"},
    }
    return {
        "health": health_report(path),
        **{key: [row for row in latest if row["name"] in names][:100] for key, names in groups.items()},
        "alerts": alerts_report(path, active_only=True, limit=50),
        "latest_events": recent_events,
        "backup": dict(last_backup) if last_backup else {"state": "no backup event recorded"},
        "kuma": {"state": "see runtime integration status and endpoint notification state"},
    }


def prometheus_snapshot(path: str | Path) -> dict[str, Any]:
    """Public capsule API for optional exporters without exposing DB internals."""
    with _connection(path) as connection:
        active = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='active'").fetchone()[0]
        latest = _latest_metrics(connection, "timestamp_utc>=?", ((datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),))
    latest = [row for row in latest if "/systemd-private-" not in str(row.get("details_json") or "")]
    return {"active_alerts": active, "metrics": latest}


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
    "dashboard_report",
    "disks_report",
    "errors_report",
    "events_report",
    "export_rows",
    "health_report",
    "metrics_report",
    "network_report",
    "prometheus_snapshot",
    "render",
    "service_history_report",
    "services_report",
    "software_report",
    "status_report",
    "timeline_report",
    "trends_report",
]
