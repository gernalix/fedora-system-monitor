"""Administrative CLI and systemd coordinator for Fedora System Monitor."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from fedora_system_monitor import __version__
from fedora_system_monitor.capsules.alerting import AlertSignal, evaluate_event_alerts, evaluate_metric_alerts
from fedora_system_monitor.capsules.collectors import CADENCE_SECONDS, collect_scope
from fedora_system_monitor.capsules.command import (
    LockUnavailable,
    configure_logging,
    exclusive_lock,
    log_record,
    run_command,
)
from fedora_system_monitor.capsules.config import ConfigError, load_config, redact_text, validate_config
from fedora_system_monitor.capsules.database import Database, StorageError
from fedora_system_monitor.capsules.eventing import (
    build_device_event,
    build_lifecycle_event,
    build_network_event,
    classify_journal,
    stream_journal,
    stream_power_profile_dbus,
)
from fedora_system_monitor.capsules.kuma_admin import configure_push_monitors
from fedora_system_monitor.capsules.notifications import (
    endpoint_key,
    integration_status,
    notify_filesystem_free_changes,
    send_category_heartbeat,
)
from fedora_system_monitor.capsules.prometheus import exposition as prometheus_exposition, serve as serve_prometheus
from fedora_system_monitor.capsules.reporting import (
    alerts_report,
    build_daily_summary,
    dashboard_report,
    disks_report,
    errors_report,
    events_report,
    export_rows,
    health_report,
    metrics_report,
    network_report,
    render,
    service_history_report,
    services_report,
    software_report,
    status_report,
    timeline_report,
    trends_report,
)


LOGGER = logging.getLogger("fedora-system-monitor")
SOURCE_ROOT = Path(__file__).resolve().parents[2]
SYSTEM_CONFIG = Path("/etc/fedora-system-monitor/config.toml")
PROJECT_CONFIG = SOURCE_ROOT / "config/fedora-system-monitor.toml"
DEFAULT_UNITS = (
    "fedora-system-monitor-events.service",
    "fedora-system-monitor-lifecycle.service",
    "fedora-system-monitor-fast.timer",
    "fedora-system-monitor-hourly.timer",
    "fedora-system-monitor-daily.timer",
    "fedora-system-monitor-weekly.timer",
    "fedora-system-monitor-software.path",
)


def _default_config_path() -> Path:
    if SYSTEM_CONFIG.exists():
        return SYSTEM_CONFIG
    return PROJECT_CONFIG


def _load_runtime(args: argparse.Namespace, *, database: bool = True) -> tuple[dict[str, Any], Database | None]:
    config = load_config(args.config)
    if args.database:
        config["monitor"]["database_path"] = str(args.database)
    configure_logging(str(config["monitor"].get("log_level", "INFO")))
    if not database:
        return config, None
    db = Database(
        config["monitor"]["database_path"],
        hostname=config["monitor"].get("hostname") or socket.gethostname(),
        timezone_name=str(config["monitor"].get("timezone", "Europe/Copenhagen")),
    )
    db.record_config_version(config, source=str(args.config))
    return config, db


def _print(data: Any, args: argparse.Namespace, *, output_format: str | None = None) -> None:
    print(render(data, output_format=output_format or ("json" if args.json else "text")))


def _systemd_states() -> list[dict[str, str]]:
    states: list[dict[str, str]] = []
    for unit in DEFAULT_UNITS:
        result = run_command(
            ["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,UnitFileState", "--value"],
            timeout=3,
        )
        values = result.stdout.splitlines() if result.ok else []
        states.append(
            {
                "unit": unit,
                "load": values[0] if len(values) > 0 else "unknown",
                "active": values[1] if len(values) > 1 else "unknown",
                "sub": values[2] if len(values) > 2 else "unknown",
                "enabled": values[3] if len(values) > 3 else "unknown",
            }
        )
    return states


def _alert_transition_events(signals: Iterable[AlertSignal]) -> list[dict[str, Any]]:
    return [
        {
            "category": "alert",
            "name": "alert_opened" if signal.active else "alert_recovered",
            "severity": signal.severity if signal.active else "info",
            "source": "alert-engine",
            "device_id": signal.device_id,
            "details": {"alert_key": signal.key, "category": signal.category, "name": signal.name},
            "outcome": "open" if signal.active else "recovered",
            "dedup_key": f"alert-transition:{'open' if signal.active else 'recovery'}:{signal.key}",
        }
        for signal in signals
    ]


def _endpoint_alert_snapshot(db: Database, endpoint: str) -> tuple[dict[str, Any], str]:
    rows = [
        row for row in db.active_alerts() if endpoint_key(str(row["category"])) == endpoint
    ]
    signature = {
        "healthy": not rows,
        "alerts": sorted(
            (str(row["alert_key"]), str(row["severity"])) for row in rows
        ),
    }
    if rows:
        messages = [str(row.get("message") or row["name"]) for row in rows[:3]]
        message = f"{endpoint}: " + "; ".join(messages)
    else:
        message = f"{endpoint}: recovered"
    return signature, message


def _flush_transition_notifications(
    db: Database,
    transitions: list[AlertSignal],
    config: dict[str, Any],
) -> None:
    endpoints = sorted({endpoint_key(signal.category) for signal in transitions})
    lock_directory = Path(str(config.get("monitor", {}).get("lock_path", db.path))).parent
    if not os.access(lock_directory, os.W_OK):
        lock_directory = db.path.parent
    try:
        with exclusive_lock(lock_directory / "notifications.lock", timeout=0.25):
            for endpoint in endpoints:
                for _ in range(3):
                    signature, message = _endpoint_alert_snapshot(db, endpoint)
                    previous = db.get_state(
                        f"endpoint:{endpoint}", {}, namespace="notification"
                    )
                    if previous == signature:
                        break
                    result = send_category_heartbeat(
                        config,
                        endpoint,
                        healthy=bool(signature["healthy"]),
                        message=message,
                    )
                    if not result.delivered:
                        break
                    db.set_state(
                        f"endpoint:{endpoint}", signature, namespace="notification"
                    )
                    for signal in transitions:
                        if endpoint_key(signal.category) == endpoint:
                            db.mark_alert_notification(signal.key, "delivered")
                    current, _ = _endpoint_alert_snapshot(db, endpoint)
                    if current == signature:
                        break
    except LockUnavailable:
        # The holder reconciles state after each send; heartbeat is the fallback.
        return


def _persist_signals(db: Database, signals: Iterable[AlertSignal], config: dict[str, Any]) -> list[AlertSignal]:
    transitions: list[AlertSignal] = []
    for signal in signals:
        if signal.active:
            _, is_transition = db.open_alert_transition(
                signal.key,
                category=signal.category,
                name=signal.name,
                severity=signal.severity,
                source=signal.source,
                device_id=signal.device_id,
                details=signal.details or {},
                message=signal.message,
                occurred_at=signal.occurred_at,
            )
            if is_transition:
                transitions.append(signal)
        elif db.recover_alert(signal.key, details=signal.details or {}, message=signal.message):
            transitions.append(signal)

    if not transitions:
        return []
    db.insert_events(_alert_transition_events(transitions), dedup_window_seconds=30)

    _flush_transition_notifications(db, transitions, config)
    return transitions


def _derived_recoveries(
    db: Database,
    events: Iterable[dict[str, Any]],
    metrics: Iterable[dict[str, Any]] = (),
    *,
    scope: str = "",
    collector_healthy: bool = True,
    config: dict[str, Any] | None = None,
) -> list[AlertSignal]:
    event_list = list(events)
    successful_dnf = any(
        event.get("source") == "dnf5_history" and event.get("outcome") == "ok"
        for event in event_list
    )
    rows = db.query(
        "SELECT alert_key,category,name,severity,source,device_id FROM alerts "
        "WHERE status='active' AND name='dnf_transaction_failed'"
    ) if successful_dnf else []
    recoveries = [
        AlertSignal(
            key=row["alert_key"],
            category=row["category"],
            name=row["name"],
            severity=row["severity"],
            active=False,
            message="a later DNF transaction completed successfully",
            source="dnf5_history",
            device_id=row["device_id"] or "host",
            details={"recovery_source": "later_successful_transaction"},
        )
        for row in rows
    ]
    # Point-in-time kernel I/O alerts must remain visible for at least one full
    # journal lookback, but they must not remain active forever.  A successful
    # fifteen-minute collector with no fresh I/O event is explicit recovery
    # evidence because collect_journal_io scanned that complete window.
    io_names = {"disk_io_error", "kernel_io_error", "io_error", "nvme_error"}
    if scope == "fifteen_minute" and collector_healthy and not any(
        event.get("name") in io_names for event in event_list
    ):
        lookback = int(((config or {}).get("collection") or {}).get("journal_lookback_minutes", 20))
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max(1, lookback))).isoformat()
        io_rows = db.query(
            "SELECT alert_key,category,name,severity,source,device_id FROM alerts "
            "WHERE status='active' AND name IN ('disk_io_error','kernel_io_error','io_error','nvme_error') AND last_seen_utc<?",
            (cutoff,),
        )
        recoveries.extend(
            AlertSignal(
                key=row["alert_key"],
                category=row["category"],
                name=row["name"],
                severity=row["severity"],
                active=False,
                message="no kernel I/O error in a complete journal lookback",
                source="kernel_journal",
                device_id=row["device_id"] or "host",
                details={"recovery_source": "clean_journal_lookback", "lookback_minutes": lookback},
            )
            for row in io_rows
        )
    if collector_healthy:
        unsafe_rows = db.query(
            "SELECT alert_key,category,name,severity,source,device_id,details_json FROM alerts "
            "WHERE status='active' AND name='unsafe_device_removal'"
        )
        for row in unsafe_rows:
            try:
                details = json.loads(str(row.get("details_json") or "{}"))
            except json.JSONDecodeError:
                details = {}
            mount_point = str(details.get("mount_point") or "")
            if not mount_point:
                continue
            mounted = run_command(
                ["findmnt", "--json", "--target", mount_point],
                timeout=4,
                max_output=64_000,
            )
            if mounted.ok:
                recoveries.append(
                    AlertSignal(
                        key=row["alert_key"],
                        category=row["category"],
                        name=row["name"],
                        severity=row["severity"],
                        active=False,
                        message="mount point is present after unsafe removal",
                        source="mount_reconciliation",
                        device_id=row["device_id"] or "host",
                        details={
                            "recovery_source": "mount_point_present",
                            "mount_point": mount_point,
                        },
                    )
                )
    for metric in metrics:
        if metric.get("name") != "service.active":
            continue
        details = metric.get("details") or {}
        healthy = bool(metric.get("value")) or bool(details.get("successful_inactive_oneshot"))
        if not healthy:
            continue
        key = f"service.active:{metric.get('device_id') or 'host'}"
        active = db.query("SELECT severity FROM alerts WHERE alert_key=? AND status='active'", (key,))
        if active:
            recoveries.append(
                AlertSignal(
                    key=key,
                    category="service",
                    name="systemd_unit_failed",
                    severity=active[0]["severity"],
                    active=False,
                    message="systemd service is healthy",
                    source="systemd",
                    device_id=str(metric.get("device_id") or "host"),
                    details={"recovery_source": "current_service_state"},
                )
            )
    return recoveries


def _maintenance_daily(config: dict[str, Any], db: Database) -> dict[str, Any]:
    timezone_name = str(config["monitor"].get("timezone", "Europe/Copenhagen"))
    zone = ZoneInfo(timezone_name)
    now_local = datetime.now(zone)
    summary = build_daily_summary(db.path, day=now_local.date().isoformat(), timezone_name=timezone_name)
    start_local = datetime.combine(now_local.date(), datetime.min.time(), tzinfo=zone)
    end_local = datetime.combine(now_local.date() + timedelta(days=1), datetime.min.time(), tzinfo=zone)
    db.insert_summary(
        "daily",
        summary,
        period_start=start_local,
        period_end=end_local,
        health=str(summary["health"]),
    )

    backup_directory = Path(config["monitor"]["backup_directory"])
    backup_path = backup_directory / f"monitor-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.sqlite3"
    db.backup(backup_path)
    retention = config["retention"]
    retention_result = db.apply_retention(
        metric_days_by_cadence={
            60: retention["minute_days"],
            300: retention["five_minute_days"],
            900: retention["fifteen_minute_days"],
            3600: retention["hourly_days"],
            86400: retention["daily_days"],
        },
        event_days=retention["general_event_days"],
        hardware_event_days=retention["hardware_event_days"],
        alert_days=retention["alert_days"],
        inventory_daily_days=retention["inventory_daily_days"],
    )
    pruned = _prune_backups(
        backup_directory,
        int(retention["backup_daily_count"]),
        int(retention["backup_weekly_count"]),
        int(retention["backup_monthly_count"]),
    )
    return {
        "summary": summary,
        "backup": backup_path.name,
        "backup_pruned": pruned,
        "retention": retention_result,
        "db_check": db.db_check(),
    }


def _prune_backups(directory: Path, daily: int, weekly: int, monthly: int) -> int:
    candidates: list[tuple[Path, datetime]] = []
    for path in directory.glob("monitor-????????T??????Z.sqlite3"):
        try:
            stamp = datetime.strptime(path.name[8:24], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        candidates.append((path, stamp))
    candidates.sort(key=lambda item: item[1], reverse=True)
    keep: set[Path] = set(path for path, _ in candidates[:daily])
    weeks: set[tuple[int, int]] = set()
    months: set[tuple[int, int]] = set()
    for path, stamp in candidates:
        week = stamp.isocalendar()[:2]
        if len(weeks) < weekly and week not in weeks:
            weeks.add(week)
            keep.add(path)
        month = (stamp.year, stamp.month)
        if len(months) < monthly and month not in months:
            months.add(month)
            keep.add(path)
    deleted = 0
    for path, _ in candidates:
        if path not in keep:
            path.unlink()
            deleted += 1
    return deleted


def _run_scope(scope: str, config: dict[str, Any], db: Database) -> dict[str, Any]:
    cadence = CADENCE_SECONDS.get(scope, 3600)
    if cadence <= 0:
        cadence = 3600
    run_id = db.start_collector_run(scope, cadence_seconds=cadence)
    metrics_inserted = events_inserted = 0
    maintenance: dict[str, Any] = {}
    try:
        result = collect_scope(scope, config, db)
        metrics_inserted = db.insert_metrics(result.metrics, cadence_seconds=cadence, collector_run_id=run_id)
        events_inserted = db.insert_events(result.events, collector_run_id=run_id)
        if result.hardware_inventory:
            db.insert_hardware_snapshot(result.hardware_inventory)
        if result.software_inventory:
            db.insert_software_snapshot(result.software_inventory)
        signals = evaluate_metric_alerts(result.metrics, config, db.get_state, db.set_state)
        signals.extend(evaluate_event_alerts(result.events))
        signals.extend(
            _derived_recoveries(
                db,
                result.events,
                result.metrics,
                scope=scope,
                collector_healthy=not result.errors,
                config=config,
            )
        )
        transitions = _persist_signals(db, signals, config)
        telegram_changes = (
            notify_filesystem_free_changes(result.metrics, config, db)
            if scope == "five_minute"
            else []
        )
        if scope == "daily":
            maintenance = _maintenance_daily(config, db)
        elif scope == "weekly":
            retention = config["retention"]
            maintenance = {
                "db_check": db.db_check(),
                "retention": db.apply_retention(
                    metric_days_by_cadence={
                        60: retention["minute_days"],
                        300: retention["five_minute_days"],
                        900: retention["fifteen_minute_days"],
                        3600: retention["hourly_days"],
                        86400: retention["daily_days"],
                    },
                    event_days=retention["general_event_days"],
                    hardware_event_days=retention["hardware_event_days"],
                    alert_days=retention["alert_days"],
                    inventory_daily_days=retention["inventory_daily_days"],
                    compact=True,
                ),
            }
        outcome = "partial" if result.errors else "ok"
        db.finish_collector_run(
            run_id,
            outcome=outcome,
            metrics_inserted=metrics_inserted,
            events_inserted=events_inserted,
            error_message="; ".join(result.errors[:10]) if result.errors else None,
            details={
                "collector_duration_ms": result.duration_ms,
                "errors": result.errors[:20],
                "hardware_inventory": len(result.hardware_inventory),
                "software_inventory": len(result.software_inventory),
                "alert_transitions": len(transitions),
                "telegram_free_space": [item.__dict__ for item in telegram_changes],
                "maintenance": maintenance,
            },
        )
        return {
            "scope": scope,
            "outcome": outcome,
            "duration_ms": result.duration_ms,
            "metrics": metrics_inserted,
            "events": events_inserted,
            "hardware_inventory": len(result.hardware_inventory),
            "software_inventory": len(result.software_inventory),
            "errors": result.errors,
            "alert_transitions": len(transitions),
            "telegram_free_space": [item.__dict__ for item in telegram_changes],
            "maintenance": maintenance,
        }
    except Exception as exc:
        message = redact_text(exc)[:500]
        db.finish_collector_run(
            run_id,
            outcome="error",
            metrics_inserted=metrics_inserted,
            events_inserted=events_inserted,
            error_message=message,
        )
        raise


def _run_isolated_scope(args: argparse.Namespace, scope: str, config: dict[str, Any], db: Database) -> dict[str, Any]:
    deadlines = {
        "minute": 45,
        "five_minute": 50,
        "fifteen_minute": 120,
        "hourly": 600,
        "daily": 1200,
        "weekly": 900,
        "software_event": 120,
    }
    command = [
        sys.executable,
        "-m",
        "fedora_system_monitor",
        "--config",
        str(args.config),
        "--database",
        str(db.path),
        "collect-worker",
        scope,
        "--json",
    ]
    result = run_command(command, timeout=deadlines[scope], max_output=2_000_000)
    if result.ok:
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and payload.get("scope") == scope:
            return payload
    reason = "collector deadline exceeded" if result.timed_out else "collector subprocess failed"
    db.record_collector_run(
        scope,
        cadence_seconds=max(1, CADENCE_SECONDS.get(scope, 3600)),
        outcome="error",
        error_message=reason,
        details={"isolated": True},
    )
    event = {
        "category": "collector",
        "name": "collector_timeout" if result.timed_out else "collector_failure",
        "severity": "warning",
        "source": "coordinator",
        "device_id": scope,
        "outcome": "timeout" if result.timed_out else "error",
        "error_message": reason,
        "dedup_key": f"collector:{scope}:{'timeout' if result.timed_out else 'failure'}",
    }
    db.insert_events(event, dedup_window_seconds=300)
    return {"scope": scope, "outcome": "error", "duration_ms": result.duration_ms, "metrics": 0, "events": 1, "hardware_inventory": 0, "software_inventory": 0, "errors": [reason], "alert_transitions": 0, "maintenance": {}}


def _collect_command(args: argparse.Namespace, config: dict[str, Any], db: Database) -> dict[str, Any]:
    scopes: list[str]
    if args.scope == "fast":
        scopes = ["minute"]
        now = time.time()
        for scope, minimum_age in (("five_minute", 270), ("fifteen_minute", 840)):
            last = db.get_state(f"last-success:{scope}", 0)
            if not isinstance(last, (int, float)) or now - float(last) >= minimum_age:
                scopes.append(scope)
    else:
        scopes = [args.scope]
    results = []
    lock_path = Path(config["monitor"]["lock_path"])
    if os.geteuid() != 0 and not os.access(lock_path.parent, os.W_OK):
        lock_path = db.path.parent / "collector.lock"
    with exclusive_lock(lock_path, timeout=55):
        for scope in scopes:
            result = _run_isolated_scope(args, scope, config, db)
            results.append(result)
            if result["outcome"] in {"ok", "partial"}:
                db.set_state(f"last-success:{scope}", time.time())
    active_alerts = db.active_alerts()
    active_by_endpoint: dict[str, int] = {}
    for alert in active_alerts:
        key = endpoint_key(alert["category"])
        active_by_endpoint[key] = active_by_endpoint.get(key, 0) + 1
    heartbeat_categories: set[str] = set()
    if "minute" in scopes:
        heartbeat_categories.update(("system", "network", "services"))
    if any(scope in scopes for scope in ("five_minute", "fifteen_minute")):
        heartbeat_categories.update(("storage", "network"))
    if any(scope in scopes for scope in ("hourly", "daily", "weekly", "software_event")):
        heartbeat_categories.add("software")
    if any(scope in scopes for scope in ("hourly", "daily", "weekly")):
        heartbeat_categories.add("storage")
    failed = any(item["outcome"] == "error" for item in results)
    duration = sum(int(item["duration_ms"]) for item in results)
    heartbeats = []
    for category in sorted(heartbeat_categories):
        active = active_by_endpoint.get(category, 0)
        heartbeat = send_category_heartbeat(
            config,
            category,
            healthy=not failed and active == 0,
            message=f"{category}: collectors complete; active alerts={active}",
            ping_ms=duration,
        )
        heartbeats.append(heartbeat.__dict__)
        if heartbeat.delivered:
            signature, _ = _endpoint_alert_snapshot(db, category)
            db.set_state(f"endpoint:{category}", signature, namespace="notification")
    output: dict[str, Any] = {"results": results, "heartbeats": heartbeats}
    log_record(LOGGER, "collection_complete", scopes=scopes, outcomes=[item["outcome"] for item in results])
    return output


def _udev_properties(device: str) -> dict[str, str]:
    candidates = []
    block = Path("/dev") / device
    if block.exists():
        candidates = ["udevadm", "info", "--query=property", f"--name={block}"]
    else:
        sysfs = Path("/sys/bus/usb/devices") / device
        if sysfs.exists():
            candidates = ["udevadm", "info", "--query=property", f"--path={sysfs}"]
    if not candidates:
        return {}
    result = run_command(candidates, timeout=4, max_output=64_000)
    properties: dict[str, str] = {}
    if result.ok:
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator and key.isupper() and len(key) <= 80 and len(value) <= 1024:
                properties[key] = value
    size_path = Path("/sys/class/block") / device / "size"
    try:
        properties["SIZE_BYTES"] = str(int(size_path.read_text().strip()) * 512)
    except (OSError, ValueError):
        pass
    return properties


def _enrich_event_device(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("device_id"):
        return event
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    device_node = str(details.get("device_node") or "")
    if device_node.startswith("/dev/"):
        properties = _udev_properties(Path(device_node).name)
        identity = build_device_event("change", device_node, properties, None).get("device_id")
        if identity:
            event["device_id"] = identity
            return event
    mount_point = str(details.get("mount_point") or "")
    if mount_point:
        result = run_command(["findmnt", "--json", "--target", mount_point, "--output", "UUID,LABEL,SOURCE"], timeout=4, max_output=64_000)
        if result.ok:
            try:
                filesystems = json.loads(result.stdout).get("filesystems", [])
                item = filesystems[0] if filesystems else {}
            except (json.JSONDecodeError, AttributeError):
                item = {}
            filesystem_uuid = str(item.get("uuid") or "").strip()
            if filesystem_uuid:
                event["device_id"] = f"fs-uuid:{filesystem_uuid.lower()}"
                details["filesystem_uuid"] = filesystem_uuid
                if item.get("label"):
                    details["label"] = str(item["label"])[:128]
    return event


def _hook_command(args: argparse.Namespace, config: dict[str, Any], db: Database) -> dict[str, Any]:
    action = args.hook_action
    if action == "shutdown" and args.only_if_stopping:
        system_state = run_command(["systemctl", "is-system-running"], timeout=3)
        if system_state.stdout.strip() != "stopping":
            return {"recorded": 0, "event": "shutdown_skipped_non_shutdown_stop", "alert_transitions": 0}
    event: dict[str, Any]
    if action.startswith("device-"):
        normalized = action.removeprefix("device-")
        cache_key = f"device-cache:{args.device}"
        properties = _udev_properties(args.device) if normalized != "remove" else {}
        cached = db.get_state(cache_key, {})
        if normalized == "remove" and not cached:
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and not cached:
                time.sleep(0.05)
                cached = db.get_state(cache_key, {})
        identity_input = f"/dev/{args.device}" if Path("/sys/class/block", args.device).exists() else f"/sys/bus/usb/devices/{args.device}"
        event = build_device_event(normalized, identity_input, properties, cached)
        if normalized != "remove":
            db.set_state(cache_key, {"DEVICE_ID": event.get("device_id", ""), "details": event.get("details", {})})
    elif action == "network":
        allowlist = {
            key: os.environ[key]
            for key in (
                "CONNECTION_ID",
                "CONNECTION_TYPE",
                "DEVICE_IP_IFACE",
                "IP4_ADDRESS_0",
                "IP6_ADDRESS_0",
                "IP4_GATEWAY",
                "IP6_GATEWAY",
                "CONNECTIVITY_STATE",
            )
            if key in os.environ
        }
        event = build_network_event(args.interface, args.action, allowlist)
    else:
        event = build_lifecycle_event(action)
        boot_id = ""
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            pass
        event.setdefault("details", {})["boot_id"] = boot_id
        if action == "boot":
            try:
                boot_seconds = next(
                    int(line.split()[1])
                    for line in Path("/proc/stat").read_text().splitlines()
                    if line.startswith("btime ")
                )
                event["timestamp_utc"] = datetime.fromtimestamp(boot_seconds, timezone.utc).isoformat()
            except (OSError, StopIteration, ValueError):
                pass
            previous = db.get_state("lifecycle", {})
            if previous and not previous.get("clean_shutdown") and previous.get("boot_id") != boot_id:
                db.insert_events(
                    {
                        "category": "system",
                        "name": "unclean_boot",
                        "severity": "warning",
                        "source": "lifecycle",
                        "details": {"previous_boot_id": previous.get("boot_id", "")},
                        "outcome": "detected",
                        "dedup_key": f"unclean-boot:{boot_id}",
                    }
                )
            db.set_state("lifecycle", {"boot_id": boot_id, "clean_shutdown": False, "suspended": False})
        elif action == "shutdown":
            state = db.get_state("lifecycle", {})
            state.update({"boot_id": boot_id, "clean_shutdown": True})
            db.set_state("lifecycle", state)
        elif action in {"suspend", "resume"}:
            state = db.get_state("lifecycle", {})
            state["suspended"] = action == "suspend"
            db.set_state("lifecycle", state)
    inserted = db.insert_events([event], dedup_window_seconds=int(event.get("dedup_window_seconds", 30)))
    event_signals = evaluate_event_alerts([event])
    if event.get("name") == "device_connected" and event.get("device_id"):
        event_signals.append(
            AlertSignal(
                key=f"event:unsafe_device_removal:{event['device_id']}",
                category="hardware",
                name="unsafe_device_removal",
                severity="warning",
                active=False,
                message="device reconnected after unsafe removal",
                source="udev",
                device_id=str(event["device_id"]),
                details={"recovery_source": "device_reconnected"},
            )
        )
    transitions = _persist_signals(db, event_signals, config)
    return {"recorded": inserted, "event": event["name"], "alert_transitions": len(transitions)}


def _daemon(config: dict[str, Any], db: Database) -> int:
    def on_event(event: dict[str, Any]) -> None:
        _enrich_event_device(event)
        _persist_signals(db, evaluate_event_alerts([event]), config)

    stop_event = threading.Event()

    def power_profile_worker() -> None:
        while not stop_event.is_set():
            try:
                matched = stream_power_profile_dbus(config, db, stop_event=stop_event, on_event=on_event)
                if not stop_event.is_set():
                    LOGGER.warning("power profile dbus follower exited after %s matched events", matched)
            except Exception as exc:  # noqa: BLE001 - daemon supervision must keep the journal follower alive.
                LOGGER.warning("power profile dbus follower failed: %s", redact_text(exc)[:300])
            stop_event.wait(3)

    thread = threading.Thread(target=power_profile_worker, name="power-profile-dbus", daemon=True)
    thread.start()
    try:
        matched = stream_journal(config, db, on_event=on_event)
    finally:
        stop_event.set()
        thread.join(timeout=3)
    raise RuntimeError(f"journal follower exited unexpectedly after {matched} matched events")


def _backfill(args: argparse.Namespace, config: dict[str, Any], db: Database) -> dict[str, Any]:
    consolidation = db.consolidate_journal_events()
    fields = "MESSAGE,MESSAGE_ID,PRIORITY,_TRANSPORT,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,UNIT,JOB_RESULT,RESULT,_PID,_COMM,_UID,COREDUMP_EXE,COREDUMP_COMM,COREDUMP_SIGNAL,COREDUMP_SIGNAL_NAME,COREDUMP_UNIT,COREDUMP_UID"
    command = [
        "journalctl",
        f"--since=-{max(1, args.since_hours)}h",
        "--output=json",
        "--no-pager",
        f"--output-fields={fields}",
        "_TRANSPORT=kernel",
        "+",
        "SYSLOG_IDENTIFIER=systemd",
        "+",
        "SYSLOG_IDENTIFIER=systemd-journald",
        "+",
        "SYSLOG_IDENTIFIER=systemd-sleep",
        "+",
        "_SYSTEMD_UNIT=udisks2.service",
        "+",
        "_SYSTEMD_UNIT=NetworkManager.service",
        "+",
        "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1",
    ]
    result = run_command(command, timeout=45, max_output=32_000_000)
    if not result.ok:
        raise RuntimeError("journal backfill command failed")
    inserted = matched = 0
    signals: list[AlertSignal] = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = classify_journal(entry)
        if event is None:
            continue
        _enrich_event_device(event)
        matched += 1
        identity = {
            "cursor": str(entry.get("__CURSOR", ""))[:1024],
            "boot_id": str(entry.get("_BOOT_ID", ""))[:64],
            "monotonic": str(entry.get("__MONOTONIC_TIMESTAMP", ""))[:32],
            "realtime": str(entry.get("__REALTIME_TIMESTAMP", ""))[:32],
        }
        if identity["cursor"] and db.journal_cursor_seen(identity["cursor"]):
            continue
        event.setdefault("details", {})["journal_identity"] = identity
        try:
            micros = int(identity["realtime"])
            event["timestamp_utc"] = datetime.fromtimestamp(micros / 1_000_000, timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            pass
        inserted += db.insert_events([event], dedup_window_seconds=int(event.get("dedup_window_seconds", 300)))
        db.mark_journal_cursor(identity["cursor"])
        signals.extend(evaluate_event_alerts([event]))
    transitions = _persist_signals(db, signals, config)
    return {
        "journal_records": len(result.stdout.splitlines()),
        "matched": matched,
        "inserted": inserted,
        "alert_transitions": len(transitions),
        **consolidation,
    }


def _self_test(config: dict[str, Any], *, system: bool) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": redact_text(detail)[:300]})

    with tempfile.TemporaryDirectory(prefix="fedora-system-monitor-test-") as temp:
        path = Path(temp) / "test.sqlite3"
        db = Database(path, hostname="self-test")
        try:
            check("database", db.db_check()["ok"])
            first = db.insert_events({"name": "dedup", "dedup_key": "self-test"})
            second = db.insert_events({"name": "dedup", "dedup_key": "self-test"})
            check("deduplication", first == 1 and second == 0)
            db.open_alert("self-test", category="system", name="self_test", message="simulation")
            recovered = db.recover_alert("self-test", message="simulation recovered")
            check("alert_recovery", recovered)
            add = build_device_event("add", "/dev/fsm-test", {"ID_FS_UUID": "1111-2222", "ID_MODEL": "Test"}, None)
            remove = build_device_event("remove", "/dev/fsm-test", {}, {"DEVICE_ID": add["device_id"]})
            check("device_add_remove", bool(add["device_id"]) and remove["device_id"] == add["device_id"])
            db.insert_events([add, remove], dedup_window_seconds=0)
            mount = build_device_event("mount", "/dev/fsm-test", {"ID_FS_UUID": "1111-2222", "MOUNT_POINT": "/mnt/fsm-test"}, None)
            unmount = build_device_event("unmount", "/dev/fsm-test", {"ID_FS_UUID": "1111-2222"}, None)
            check("mount_unmount", mount["name"] == "device_mounted" and unmount["name"] == "device_unmounted")
            timeout = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
            check("command_timeout", timeout.timed_out)
            minute = collect_scope("minute", config, db)
            check("cpu_ram_swap", any(item["name"] == "memory.used_percent" for item in minute.metrics), "; ".join(minute.errors))
            check("failure_isolation", bool(minute.metrics))
            backup = db.backup(Path(temp) / "backup.sqlite3")
            check("backup", backup.exists())
            check("integrity", db.integrity_check() == ["ok"])
        finally:
            db.close()

    if system:
        unit_paths = sorted(Path("/etc/systemd/system").glob("fedora-system-monitor-*.service"))
        if not unit_paths:
            unit_paths = sorted((SOURCE_ROOT / "systemd").glob("*.service"))
        verify = run_command(["systemd-analyze", "verify", *map(str, unit_paths)], timeout=20)
        check("systemd_verify", verify.ok, verify.stderr)
        for unit in DEFAULT_UNITS:
            state = run_command(["systemctl", "is-enabled", unit], timeout=3)
            check(f"enabled:{unit}", state.ok)
    return {"passed": all(item["passed"] for item in checks), "checks": checks}


def _report_command(args: argparse.Namespace, config: dict[str, Any], db: Database | None) -> Any:
    path = db.path if db is not None else Path(config["monitor"]["database_path"])
    if args.command == "status":
        report = status_report(path)
        report["units"] = _systemd_states()
        report["uptime_kuma"] = integration_status(config)
        return report
    if args.command == "health":
        return health_report(path)
    if args.command == "events":
        return events_report(path, limit=args.limit, category=args.category, since_hours=args.since_hours)
    if args.command == "alerts":
        if args.resolve:
            if db is None:
                raise RuntimeError("resolving alerts requires write access")
            resolved = db.recover_alert(args.resolve, message="resolved by local administrator")
            return {"resolved": resolved, "alert_key": args.resolve}
        return alerts_report(path, active_only=not args.all, limit=args.limit)
    if args.command == "metrics":
        return metrics_report(path, name=args.name, limit=args.limit)
    if args.command == "disks":
        return disks_report(path)
    if args.command == "network":
        return network_report(path)
    if args.command == "software":
        return software_report(path)
    if args.command == "services":
        return services_report(path)
    if args.command == "service-history":
        return service_history_report(path, since_days=args.since_days)
    if args.command == "dashboard":
        report = dashboard_report(path)
        report["kuma"] = integration_status(config)
        return report
    if args.command == "timeline":
        return timeline_report(path, since_hours=args.since_hours, limit=args.limit)
    if args.command == "trends":
        return trends_report(path)
    if args.command == "last-errors":
        return errors_report(path, limit=args.limit)
    if args.command == "daily-summary":
        return build_daily_summary(
            path,
            day=args.day,
            timezone_name=str(config["monitor"].get("timezone", "Europe/Copenhagen")),
        )
    raise ValueError(f"unsupported report command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fedora-system-monitor", description="Fedora host monitoring administration")
    parser.add_argument("--config", type=Path, default=_default_config_path())
    parser.add_argument("--database", type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "health", "disks", "network", "software", "services", "dashboard", "trends"):
        subparsers.add_parser(name)
    history = subparsers.add_parser("service-history")
    history.add_argument("--since-days", type=int, default=7)
    timeline = subparsers.add_parser("timeline")
    timeline.add_argument("--limit", type=int, default=500)
    timeline.add_argument("--since-hours", type=int, default=24)
    prometheus = subparsers.add_parser("prometheus")
    prometheus.add_argument("--listen", default="127.0.0.1")
    prometheus.add_argument("--port", type=int, default=9109)
    prometheus.add_argument("--once", action="store_true")
    events = subparsers.add_parser("events")
    events.add_argument("--limit", type=int, default=100)
    events.add_argument("--category", default="")
    events.add_argument("--since-hours", type=int, default=24)
    alerts = subparsers.add_parser("alerts")
    alerts.add_argument("--all", action="store_true")
    alerts.add_argument("--limit", type=int, default=200)
    alerts.add_argument("--resolve", default="")
    metrics = subparsers.add_parser("metrics")
    metrics.add_argument("--name", default="")
    metrics.add_argument("--limit", type=int, default=200)
    errors = subparsers.add_parser("last-errors")
    errors.add_argument("--limit", type=int, default=100)
    summary = subparsers.add_parser("daily-summary")
    summary.add_argument("--day")
    collect = subparsers.add_parser("collect")
    collect.add_argument("scope", choices=("fast", "minute", "five_minute", "fifteen_minute", "hourly", "daily", "weekly", "software_event"))
    worker = subparsers.add_parser("collect-worker", help=argparse.SUPPRESS)
    worker.add_argument("scope", choices=("minute", "five_minute", "fifteen_minute", "hourly", "daily", "weekly", "software_event"))
    test = subparsers.add_parser("test")
    test.add_argument("--system", action="store_true")
    subparsers.add_parser("config-check")
    subparsers.add_parser("db-check")
    kuma = subparsers.add_parser("kuma-configure")
    kuma.add_argument("--base-url", required=True)
    kuma.add_argument(
        "--chrome-profile",
        type=Path,
        default=Path("/home/daniele/.var/app/com.google.Chrome/config/google-chrome"),
    )
    kuma.add_argument("--credentials", type=Path)
    export = subparsers.add_parser("export")
    export.add_argument("--format", choices=("json", "csv", "text"), default="json")
    export.add_argument("--table", choices=tuple(sorted({"periodic_metrics", "events", "alerts", "hardware_inventory", "software_inventory", "collector_runs", "metric_aggregates", "summaries"})), default="events")
    export.add_argument("--since-hours", type=int, default=24)
    export.add_argument("--limit", type=int, default=1000)
    export.add_argument("--output", type=Path)
    subparsers.add_parser("version")
    subparsers.add_parser("daemon", help=argparse.SUPPRESS)
    backfill = subparsers.add_parser("backfill", help=argparse.SUPPRESS)
    backfill.add_argument("--since-hours", type=int, default=168)
    hook = subparsers.add_parser("hook", help=argparse.SUPPRESS)
    hook.add_argument("hook_action", choices=("device-add", "device-remove", "device-change", "network", "boot", "shutdown", "reboot", "suspend", "resume"))
    hook.add_argument("--device", default="")
    hook.add_argument("--interface", default="")
    hook.add_argument("--action", default="unknown")
    hook.add_argument("--only-if-stopping", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in arguments
    arguments = [item for item in arguments if item != "--json"]
    parser = build_parser()
    args = parser.parse_args(arguments)
    args.json = json_output
    try:
        if args.command == "version":
            _print({"version": __version__}, args)
            return 0
        read_only_commands = {
            "status",
            "health",
            "events",
            "metrics",
            "disks",
            "network",
            "software",
            "services",
            "service-history",
            "dashboard",
            "timeline",
            "trends",
            "prometheus",
            "last-errors",
            "daily-summary",
            "export",
            "test",
        }
        if args.command == "alerts" and not args.resolve:
            read_only_commands.add("alerts")
        config, db = _load_runtime(
            args,
            database=args.command not in {"config-check", "kuma-configure", *read_only_commands},
        )
        if args.command == "config-check":
            errors = validate_config(config)
            output = {"ok": not errors, "errors": errors, "uptime_kuma": integration_status(config)}
            _print(output, args)
            return 0 if not errors else 2
        if args.command == "kuma-configure":
            output = configure_push_monitors(
                base_url=args.base_url,
                chrome_profile=args.chrome_profile,
                credentials_path=args.credentials or config["notifications"]["uptime_kuma_credentials"],
            )
            _print(output, args)
            return 0
        if args.command == "test":
            output = _self_test(config, system=args.system)
            _print(output, args)
            return 0 if output["passed"] else 1
        if args.command == "export":
            path = Path(config["monitor"]["database_path"])
            rows = export_rows(path, table=args.table, since_hours=args.since_hours, limit=args.limit)
            text = render(rows, output_format=args.format)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(text + "\n", encoding="utf-8")
                _print({"rows": len(rows), "output": str(args.output), "format": args.format}, args)
            else:
                print(text)
            return 0
        if args.command == "prometheus":
            path = Path(config["monitor"]["database_path"])
            if args.once:
                print(prometheus_exposition(path), end="")
            else:
                serve_prometheus(path, listen=args.listen, port=args.port)
            return 0
        if args.command in read_only_commands:
            _print(_report_command(args, config, None), args)
            return 0
        assert db is not None
        try:
            if args.command == "db-check":
                output = db.db_check()
            elif args.command == "collect":
                output = _collect_command(args, config, db)
            elif args.command == "collect-worker":
                output = _run_scope(args.scope, config, db)
            elif args.command == "daemon":
                return _daemon(config, db)
            elif args.command == "hook":
                output = _hook_command(args, config, db)
            elif args.command == "backfill":
                output = _backfill(args, config, db)
            else:
                output = _report_command(args, config, db)
            _print(output, args)
            if isinstance(output, dict) and output.get("passed") is False:
                return 1
            return 0
        finally:
            db.close()
    except (ConfigError, StorageError, LockUnavailable, OSError, RuntimeError, ValueError) as exc:
        message = redact_text(exc)
        if json_output:
            print(json.dumps({"ok": False, "error": message}, sort_keys=True))
        else:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1


__all__ = ["build_parser", "main"]
