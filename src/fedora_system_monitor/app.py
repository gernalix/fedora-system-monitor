"""CLI composition root for Fedora System Monitor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fedora_system_monitor.capsules.command import LockUnavailable
from fedora_system_monitor.capsules.config import ConfigError, redact_text
from fedora_system_monitor.capsules.database import StorageError
from fedora_system_monitor.capsules.runtime.coordinator import (
    PROJECT_CONFIG,
    SYSTEM_CONFIG,
    execute,
)
def _default_config_path() -> Path:
    return SYSTEM_CONFIG if SYSTEM_CONFIG.exists() else PROJECT_CONFIG


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
    context = subparsers.add_parser("context", help="correlate Fedora telemetry with ActivityWatch")
    context_sub = context.add_subparsers(dest="context_command", required=True)
    context_sync = context_sub.add_parser("sync", help="refresh the derived context repository")
    context_sync.add_argument("--since-minutes", type=int)
    context_sync.add_argument("--activitywatch-data", type=Path)
    context_sync.add_argument("--output-dir", type=Path)
    context_sync.add_argument("--no-push", action="store_true")
    context_around = context_sub.add_parser("around", help="show correlated context around a timestamp")
    context_around.add_argument("timestamp")
    context_around.add_argument("--before-minutes", type=int, default=10)
    context_around.add_argument("--after-minutes", type=int, default=5)
    context_around.add_argument("--activitywatch-data", type=Path)
    context_incident = context_sub.add_parser("incident", help="show a complete incident bundle")
    context_incident.add_argument("incident_id")
    context_incident.add_argument("--before-minutes", type=int)
    context_incident.add_argument("--after-minutes", type=int)
    context_incident.add_argument("--activitywatch-data", type=Path)
    context_latest = context_sub.add_parser("latest", help="show the latest indexed incident identity")
    context_latest.add_argument("--type", default="")
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
    smart_alert = subparsers.add_parser("smart-alert", help="send or open a local actionable SMART alert")
    smart_alert.add_argument("--fixture", choices=("t7-usb-nvme-read-failed",), default="")
    smart_alert.add_argument("--message", default="")
    smart_alert.add_argument("--action", choices=("notify", "details", "disks"), default="notify")
    smart_alert.add_argument("--force", action="store_true")
    smart_alert.add_argument("--no-open", action="store_true")
    for name in ("config-check", "db-check", "kuma-runtime"):
        subparsers.add_parser(name)
    kuma = subparsers.add_parser("kuma-configure")
    kuma.add_argument("--base-url", required=True)
    kuma.add_argument("--chrome-profile", type=Path, default=Path("/home/daniele/.var/app/com.google.Chrome/config/google-chrome"))
    kuma.add_argument("--credentials", type=Path)
    kuma.add_argument("--service-unit", action="append", default=[], help="custom systemd service identity; repeatable, prefix user units with user:")
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
    args = build_parser().parse_args([item for item in arguments if item != "--json"])
    args.json = json_output
    try:
        return execute(args)
    except (ConfigError, StorageError, LockUnavailable, OSError, RuntimeError, ValueError) as exc:
        message = redact_text(exc)
        if json_output:
            print(json.dumps({"ok": False, "error": message}, sort_keys=True))
        else:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1


__all__ = ["build_parser", "main"]
