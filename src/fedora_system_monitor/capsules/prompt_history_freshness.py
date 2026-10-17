"""End-to-end ChatGPT export freshness for the Prompt History warehouse."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fedora_system_monitor.capsules.kuma_admin import KumaMonitorSpec


ENDPOINT_KEY = "prompt_history_chatgpt_freshness"
SYNC_SERVICE_ID = "user:prompt-history-sync.service"
DEFAULT_EXPORT_PARENT = Path("/home/daniele/Documents/ChatGPT")
DEFAULT_WAREHOUSE = Path("/home/daniele/.local/share/prompt-history/prompt_history.sqlite")
PROOF_MAX_AGE_SECONDS = 2400
MONITOR_SPEC = KumaMonitorSpec(
    ENDPOINT_KEY,
    "Fedora Data Freshness · ChatGPT → Prompt History",
    "End-to-end producer audit and Prompt History import coverage; independent of systemd timer liveness.",
    180,
    60,
    2,
)


def _timestamp(value: object) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _latest_audit(export_parent: Path) -> tuple[Path, dict[str, Any], datetime] | None:
    candidates: list[tuple[datetime, Path, dict[str, Any]]] = []
    for report in export_parent.glob("ChatGPTExport-*/reports/validation.json"):
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        audited_at = _timestamp(payload.get("auditedAt"))
        if audited_at is not None:
            candidates.append((audited_at, report.parents[1], payload))
    if not candidates:
        return None
    audited_at, archive, payload = max(candidates, key=lambda item: item[0])
    return archive, payload, audited_at


def _consumer_last_success(monitor_db: Any) -> datetime | None:
    rows = monitor_db.query(
        "SELECT timestamp_utc,details_json FROM periodic_metrics "
        "WHERE name='service.active' AND device_id=? ORDER BY id DESC LIMIT 1",
        (SYNC_SERVICE_ID,),
    )
    if not rows:
        return None
    row = rows[0]
    observed_at = _timestamp(row.get("timestamp_utc"))
    if observed_at is None:
        return None
    try:
        details = json.loads(str(row.get("details_json") or "{}"))
    except (AttributeError, json.JSONDecodeError):
        return None
    if not isinstance(details, dict):
        return None
    if details.get("freshness_ok") is not True or not details.get("successful_inactive_oneshot"):
        return None
    try:
        age = float(details["last_success_age_seconds"])
    except (KeyError, TypeError, ValueError):
        return None
    if age < 0:
        return None
    return observed_at - timedelta(seconds=age)


def _imported_files(warehouse: Path, archive_name: str) -> int:
    if not warehouse.is_file():
        raise FileNotFoundError(warehouse)
    connection = sqlite3.connect(f"file:{warehouse}?mode=ro&immutable=1", uri=True)
    try:
        row = connection.execute(
            "SELECT COUNT(DISTINCT source_key) FROM source_records "
            "WHERE source='chatgpt-exporter-file' AND source_key LIKE ?",
            (f"v2:{archive_name}/conversations/%",),
        ).fetchone()
        return int(row[0] or 0)
    finally:
        connection.close()


def prompt_history_freshness(
    monitor_db: Any,
    *,
    export_parent: Path = DEFAULT_EXPORT_PARENT,
    warehouse: Path = DEFAULT_WAREHOUSE,
    now: datetime | None = None,
    max_age_seconds: int = PROOF_MAX_AGE_SECONDS,
) -> tuple[bool, str]:
    """Return producer/import health without treating message age as activity."""

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    audit = _latest_audit(export_parent)
    if audit is None:
        return False, "UNKNOWN: ChatGPT exporter has no verifiable audit"
    archive, report, audited_at = audit
    try:
        complete = int(report.get("completeConversationCount") or 0)
        expected = int(report.get("expectedConversationCount") or 0)
    except (TypeError, ValueError):
        return False, "UNKNOWN: ChatGPT exporter audit counts are invalid"
    age = (current - audited_at).total_seconds()
    terminal = str(report.get("terminalState") or "unknown")
    if terminal != "complete" or expected <= 0 or complete != expected:
        return False, (
            f"UNHEALTHY: producer audit {terminal} {complete}/{expected}; "
            f"age={max(0, round(age))}s"
        )
    if age < -30 or age > max_age_seconds:
        return False, (
            f"UNKNOWN: producer proof stale age={round(age)}s "
            f"threshold={max_age_seconds}s"
        )
    consumer_success = _consumer_last_success(monitor_db)
    if consumer_success is None:
        return False, "UNKNOWN: prompt-history consumer success is not verifiable"
    if consumer_success < audited_at:
        lag = round((audited_at - consumer_success).total_seconds())
        return False, f"UNHEALTHY: producer is newer than successful import by {lag}s"
    try:
        imported = _imported_files(warehouse, archive.name)
    except (OSError, sqlite3.Error):
        return False, "UNKNOWN: Prompt History import coverage is not readable"
    if imported < complete:
        return False, f"UNHEALTHY: imported archive coverage {imported}/{complete}"
    return True, (
        f"HEALTHY: producer audit age={round(age)}s; "
        f"imported archive coverage={imported}/{complete}"
    )


__all__ = ["ENDPOINT_KEY", "MONITOR_SPEC", "prompt_history_freshness"]
