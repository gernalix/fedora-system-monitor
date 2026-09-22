"""Derived context index joining Fedora monitor data with ActivityWatch archives.

The canonical sources remain:
- /var/lib/fedora-system-monitor/monitor.sqlite3
- gernalix/activity-watch-data (local checkout)

This capsule writes only deterministic, bounded derived views optimized for
incident reconstruction and Git review.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
from contextlib import contextmanager, suppress
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from fedora_system_monitor.capsules.config import redact_text


UTC = timezone.utc
WINDOW_SCHEMA = "fedora-system-monitor.context-window.v1"
INCIDENT_SCHEMA = "fedora-system-monitor.incident-bundle.v1"
INDEX_SCHEMA = "fedora-system-monitor.context-index.v1"
MANAGED_PREFIXES = ("metadata/", "timeline/", "incidents/", "summaries/")
_ACTIVITY_TYPES = {"afkstatus", "currentwindow", "web.tab.current"}
_MAX_TEXT = 500
_MAX_CONTEXT_ROWS = 20_000
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")

# Deliberately compact: this is a derived forensic index, not a duplicate of
# the raw monitor database. Events/alerts remain complete; metrics are selected
# for incident usefulness.
_METRIC_NAMES = {
    "cpu_total_used_percent",
    "memory.used_percent",
    "memory.available_percent",
    "memory.pressure_level",
    "memory.psi_some_avg10",
    "memory.psi_full_avg10",
    "swap.device.used_bytes",
    "swap.device.size_bytes",
    "temperature.cpu_c",
    "temperature.nvme_c",
    "filesystem.free_percent",
    "filesystem.inode_free_percent",
    "interface_download_bytes_per_second",
    "interface_upload_bytes_per_second",
    "power.profile",
    "service.active",
}


class ContextIndexError(RuntimeError):
    """Raised when the derived context index cannot be updated safely."""


def _parse_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(UTC)


def _clean(value: object, limit: int = _MAX_TEXT) -> str:
    text = redact_text(str(value or "").replace("\x00", " ").strip())
    return _URL_RE.sub("[REDACTED_URL]", text)[:limit]


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {_clean(key, 120): _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value[:200]]
    if isinstance(value, str):
        return _clean(value, 1200)
    return value


def _json_details(value: object) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"raw": _clean(value)}
    return _sanitize(parsed) if isinstance(parsed, dict) else {"value": _sanitize(parsed)}


@contextmanager
def _connection(path: str | Path):
    uri = f"file:{Path(path).resolve()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=3)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def _days(start: datetime, end: datetime, *, include_previous: bool = False) -> Iterable[date]:
    current = start.astimezone(UTC).date()
    if include_previous:
        current -= timedelta(days=1)
    final = end.astimezone(UTC).date()
    while current <= final:
        yield current
        current += timedelta(days=1)


def _activity_metadata(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "metadata" / "buckets.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContextIndexError(f"cannot read ActivityWatch metadata: {type(exc).__name__}") from exc
    buckets = document.get("buckets")
    if not isinstance(buckets, dict):
        raise ContextIndexError("ActivityWatch metadata has no buckets map")
    return {str(key): dict(value) for key, value in buckets.items() if isinstance(value, dict)}


def _activity_event_id(bucket_id: str, event: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {
            "bucket": bucket_id,
            "timestamp": event.get("timestamp"),
            "duration": event.get("duration"),
            "data": event.get("data"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "aw:" + hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:24]


def _activity_record(
    bucket_id: str,
    bucket_type: str,
    event: Mapping[str, Any],
) -> dict[str, Any] | None:
    try:
        started = _parse_time(str(event.get("timestamp") or ""))
        duration = max(0.0, float(event.get("duration") or 0))
    except (TypeError, ValueError, OverflowError):
        return None
    data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
    details: dict[str, Any] = {
        "bucket_id": bucket_id,
        "bucket_type": bucket_type,
        "duration_seconds": round(duration, 3),
    }
    for key in ("app", "title", "status"):
        cleaned = _clean(data.get(key))
        if cleaned:
            details[key] = cleaned
    for key in ("incognito", "audible"):
        if key in data:
            details[key] = bool(data.get(key))
    tab_count = data.get("tabCount")
    if isinstance(tab_count, int) and not isinstance(tab_count, bool):
        details["tab_count"] = max(0, min(tab_count, 10000))
    return {
        "record_id": _activity_event_id(bucket_id, event),
        "timestamp_utc": _iso(started),
        "source": "activitywatch",
        "kind": "activity",
        "category": "activity",
        "name": bucket_type or bucket_id,
        "severity": "info",
        "device_id": bucket_id,
        "outcome": "observed",
        "details": details,
    }


def activity_records(
    root: str | Path,
    *,
    start: datetime,
    end: datetime,
    limit: int = _MAX_CONTEXT_ROWS,
) -> list[dict[str, Any]]:
    """Read bounded ActivityWatch events overlapping [start, end].

    Only activity/AFK/tab context is materialized. Raw URLs are intentionally
    excluded from this derived repository.
    """

    root_path = Path(root)
    buckets = _activity_metadata(root_path)
    records: list[dict[str, Any]] = []
    for bucket_id, meta in sorted(buckets.items()):
        bucket_type = str(meta.get("type") or "")
        if bucket_type not in _ACTIVITY_TYPES and "lock" not in bucket_id.lower():
            continue
        storage_key = str(meta.get("storage_key") or bucket_id)
        for day in _days(start, end, include_previous=True):
            path = root_path / "buckets" / storage_key / f"{day:%Y}" / f"{day:%m}" / f"{day.isoformat()}.jsonl"
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ContextIndexError(f"cannot read ActivityWatch partition {path}: {type(exc).__name__}") from exc
            for line in lines:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    started = _parse_time(str(event.get("timestamp") or ""))
                    duration = max(0.0, float(event.get("duration") or 0))
                except (json.JSONDecodeError, TypeError, ValueError, OverflowError):
                    continue
                finished = started + timedelta(seconds=duration)
                if started > end or finished < start:
                    continue
                record = _activity_record(bucket_id, bucket_type, event)
                if record is not None:
                    records.append(record)
                    if len(records) >= max(1, limit):
                        return sorted(records, key=lambda row: (row["timestamp_utc"], row["record_id"]))
    return sorted(records, key=lambda row: (row["timestamp_utc"], row["record_id"]))


def _monitor_record(kind: str, row: sqlite3.Row) -> dict[str, Any]:
    record = {
        "record_id": f"fsm:{kind}:{row['id']}",
        "timestamp_utc": _iso(_parse_time(str(row["timestamp_utc"]))),
        "source": "fedora-system-monitor",
        "kind": kind,
        "category": str(row["category"]),
        "name": str(row["name"]),
        "severity": str(row["severity"] or "info"),
        "device_id": str(row["device_id"] or ""),
        "outcome": str(row["outcome"] or ""),
        "details": _json_details(row["details_json"]),
    }
    if "value" in row.keys() and row["value"] is not None:
        record["value"] = row["value"]
    if "unit" in row.keys() and row["unit"]:
        record["unit"] = str(row["unit"])
    if "occurrence_count" in row.keys() and row["occurrence_count"] is not None:
        record["occurrence_count"] = int(row["occurrence_count"])
    if "status" in row.keys() and row["status"]:
        record["status"] = str(row["status"])
    if "error_message" in row.keys() and row["error_message"]:
        record["error_message"] = _clean(row["error_message"], 1000)
    return record


def monitor_records(
    database_path: str | Path,
    *,
    start: datetime,
    end: datetime,
    limit: int = _MAX_CONTEXT_ROWS,
) -> list[dict[str, Any]]:
    bounded = max(1, min(int(limit), _MAX_CONTEXT_ROWS))
    parameters = (_iso(start), _iso(end))
    output: list[dict[str, Any]] = []
    with _connection(database_path) as connection:
        event_rows = connection.execute(
            """
            SELECT id,timestamp_utc,category,name,value,unit,severity,source,device_id,
                   details_json,outcome,error_message,occurrence_count
            FROM events
            WHERE timestamp_utc>=? AND timestamp_utc<=?
            ORDER BY timestamp_utc,id
            """,
            parameters,
        ).fetchall()
        for row in event_rows:
            output.append(_monitor_record("event", row))

        alert_rows = connection.execute(
            """
            SELECT id,timestamp_utc,category,name,value,unit,severity,source,device_id,
                   details_json,outcome,error_message,occurrence_count,status
            FROM alerts
            WHERE first_seen_utc<=?
              AND COALESCE(recovered_at_utc,last_seen_utc)>=?
            ORDER BY timestamp_utc,id
            """,
            (_iso(end), _iso(start)),
        ).fetchall()
        for row in alert_rows:
            output.append(_monitor_record("alert", row))

        placeholders = ",".join("?" for _ in _METRIC_NAMES)
        metric_rows = connection.execute(
            f"""
            SELECT id,timestamp_utc,category,name,value,unit,severity,source,device_id,
                   details_json,outcome,error_message
            FROM periodic_metrics
            WHERE timestamp_utc>=? AND timestamp_utc<=?
              AND (name IN ({placeholders}) OR severity NOT IN ('info','ok'))
            ORDER BY timestamp_utc,id
            """,
            (_iso(start), _iso(end), *sorted(_METRIC_NAMES)),
        ).fetchall()
        for row in metric_rows:
            output.append(_monitor_record("metric", row))

    output.sort(key=lambda row: (row["timestamp_utc"], row["record_id"]))
    if len(output) > bounded:
        # Keep the most recent bounded slice. Periodic sync normally has small
        # windows; this only protects ad-hoc huge queries.
        output = output[-bounded:]
    return output


def build_context_window(
    database_path: str | Path,
    activitywatch_data_path: str | Path,
    *,
    center: str | datetime,
    before_minutes: int = 10,
    after_minutes: int = 5,
    max_records: int = _MAX_CONTEXT_ROWS,
) -> dict[str, Any]:
    center_time = _parse_time(center)
    start = center_time - timedelta(minutes=max(0, int(before_minutes)))
    end = center_time + timedelta(minutes=max(0, int(after_minutes)))
    monitor = monitor_records(database_path, start=start, end=end, limit=max_records)
    activity = activity_records(activitywatch_data_path, start=start, end=end, limit=max_records)
    timeline = sorted(monitor + activity, key=lambda row: (row["timestamp_utc"], row["record_id"]))
    if len(timeline) > max_records:
        timeline = timeline[-max_records:]
    return {
        "schema": WINDOW_SCHEMA,
        "generated_at_utc": _iso(_now()),
        "center_timestamp_utc": _iso(center_time),
        "window": {
            "start_utc": _iso(start),
            "end_utc": _iso(end),
            "before_minutes": int(before_minutes),
            "after_minutes": int(after_minutes),
        },
        "sources": {
            "fedora_system_monitor": str(Path(database_path)),
            "activitywatch_data": str(Path(activitywatch_data_path)),
        },
        "counts": {
            "records": len(timeline),
            "fedora_system_monitor": sum(1 for row in timeline if row["source"] == "fedora-system-monitor"),
            "activitywatch": sum(1 for row in timeline if row["source"] == "activitywatch"),
        },
        "timeline": timeline,
    }


def _incident_row(database_path: str | Path, incident_id: str) -> dict[str, Any] | None:
    needle = f'%"{incident_id}"%'
    with _connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id,timestamp_utc,category,name,severity,source,device_id,details_json,outcome,error_message
            FROM events
            WHERE details_json LIKE ?
            ORDER BY timestamp_utc,id
            LIMIT 200
            """,
            (needle,),
        ).fetchall()
    for row in rows:
        details = _json_details(row["details_json"])
        if str(details.get("incident_id") or "") == incident_id:
            return {**dict(row), "details": details}
    return None


def build_incident_bundle(
    database_path: str | Path,
    activitywatch_data_path: str | Path,
    incident_id: str,
    *,
    before_minutes: int = 10,
    after_minutes: int = 5,
) -> dict[str, Any]:
    incident = _incident_row(database_path, incident_id)
    if incident is None:
        raise ContextIndexError(f"incident not found: {incident_id}")
    window = build_context_window(
        database_path,
        activitywatch_data_path,
        center=str(incident["timestamp_utc"]),
        before_minutes=before_minutes,
        after_minutes=after_minutes,
    )
    details = incident["details"]
    return {
        "schema": INCIDENT_SCHEMA,
        "generated_at_utc": window["generated_at_utc"],
        "incident_id": incident_id,
        "incident_type": str(details.get("incident_type") or incident["name"]),
        "trigger": str(details.get("trigger") or ""),
        "center_timestamp_utc": window["center_timestamp_utc"],
        "window": window["window"],
        "sources": window["sources"],
        "counts": window["counts"],
        "incident_event": {
            "category": incident["category"],
            "name": incident["name"],
            "severity": incident["severity"],
            "source": incident["source"],
            "device_id": incident["device_id"],
            "outcome": incident["outcome"],
            "details": details,
        },
        "timeline": window["timeline"],
    }


def latest_incident(
    database_path: str | Path,
    *,
    incident_type: str = "",
) -> dict[str, Any] | None:
    with _connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id,timestamp_utc,category,name,severity,source,device_id,details_json,outcome
            FROM events
            WHERE details_json LIKE '%"incident_id"%'
            ORDER BY timestamp_utc DESC,id DESC
            LIMIT 500
            """
        ).fetchall()
    for row in rows:
        details = _json_details(row["details_json"])
        incident_id = str(details.get("incident_id") or "")
        kind = str(details.get("incident_type") or row["name"])
        if not incident_id:
            continue
        if incident_type and incident_type.lower() not in kind.lower() and incident_type.lower() not in str(row["category"]).lower():
            continue
        return {
            "incident_id": incident_id,
            "incident_type": kind,
            "timestamp_utc": _iso(_parse_time(str(row["timestamp_utc"]))),
            "category": str(row["category"]),
            "name": str(row["name"]),
            "severity": str(row["severity"]),
            "trigger": str(details.get("trigger") or ""),
        }
    return None


def _atomic_write(path: Path, text: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except FileNotFoundError:
        pass
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        return True
    finally:
        with suppress(FileNotFoundError):
            temp_path.unlink()


def _json_text(value: Any, *, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    output: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("record_id") and row.get("timestamp_utc"):
            output.append(row)
    return output


def _write_day(
    root: Path,
    day: date,
    records: Iterable[dict[str, Any]],
    *,
    replace_start: datetime,
    replace_end: datetime,
) -> bool:
    path = root / "timeline" / f"{day:%Y}" / f"{day:%m}" / f"{day.isoformat()}.jsonl"
    existing = _read_jsonl(path)
    kept = []
    for row in existing:
        try:
            timestamp = _parse_time(str(row["timestamp_utc"]))
        except (TypeError, ValueError):
            continue
        if replace_start <= timestamp <= replace_end:
            continue
        kept.append(_sanitize(row))
    merged = {str(row["record_id"]): row for row in kept}
    for row in records:
        merged[str(row["record_id"])] = row
    ordered = sorted(merged.values(), key=lambda row: (row["timestamp_utc"], row["record_id"]))
    return _atomic_write(path, "".join(_json_text(row, pretty=False) for row in ordered))


def _write_summary(root: Path, day: date) -> bool:
    timeline = root / "timeline" / f"{day:%Y}" / f"{day:%m}" / f"{day.isoformat()}.jsonl"
    rows = _read_jsonl(timeline)
    by_source: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_category: dict[str, int] = {}
    incidents: set[str] = set()
    for row in rows:
        by_source[str(row.get("source") or "unknown")] = by_source.get(str(row.get("source") or "unknown"), 0) + 1
        by_kind[str(row.get("kind") or "unknown")] = by_kind.get(str(row.get("kind") or "unknown"), 0) + 1
        by_category[str(row.get("category") or "unknown")] = by_category.get(str(row.get("category") or "unknown"), 0) + 1
        details = row.get("details")
        if isinstance(details, Mapping) and details.get("incident_id"):
            incidents.add(str(details["incident_id"]))
    document = {
        "schema": "fedora-system-monitor.context-day-summary.v1",
        "day_utc": day.isoformat(),
        "record_count": len(rows),
        "by_source": dict(sorted(by_source.items())),
        "by_kind": dict(sorted(by_kind.items())),
        "by_category": dict(sorted(by_category.items())),
        "incident_ids": sorted(incidents),
    }
    return _atomic_write(root / "summaries" / f"{day.isoformat()}.json", _json_text(document))


def _incident_ids_in_records(records: Iterable[dict[str, Any]]) -> list[str]:
    found: set[str] = set()
    for row in records:
        details = row.get("details")
        if isinstance(details, Mapping) and details.get("incident_id"):
            found.add(str(details["incident_id"]))
    return sorted(found)


def _read_last_sync(root: Path) -> datetime | None:
    path = root / "metadata" / "last-sync.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return _parse_time(str(value["window_end_utc"]))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


_GITHUB_RE = re.compile(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$")


def _repo_slug(remote: str) -> str | None:
    match = _GITHUB_RE.search(remote.strip())
    return match.group(1) if match else None


class ContextGitRepo:
    """Fail-closed publisher for the dedicated derived-data repository."""

    def __init__(
        self,
        root: str | Path,
        *,
        expected_repo: str,
        remote: str = "origin",
        branch: str = "main",
        timeout_seconds: int = 120,
    ):
        self.root = Path(root)
        self.expected_repo = expected_repo
        self.remote = remote
        self.branch = branch
        self.timeout_seconds = max(10, int(timeout_seconds))
        self.env = os.environ.copy()
        self.env["GIT_TERMINAL_PROMPT"] = "0"
        self.env.setdefault("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=15")

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", *args],
                cwd=self.root,
                env=self.env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=check,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContextIndexError(f"git {' '.join(args[:2])} timed out") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "git command failed").strip().splitlines()[-1]
            raise ContextIndexError(f"git {' '.join(args[:2])} failed: {_clean(detail, 300)}") from exc

    def validate(self) -> None:
        if not (self.root / ".git").exists():
            raise ContextIndexError(f"context output is not a git repository: {self.root}")
        branch = self.run("branch", "--show-current").stdout.strip()
        if branch != self.branch:
            raise ContextIndexError(f"context repository must be on {self.branch}, found {branch or 'detached'}")
        slug = _repo_slug(self.run("remote", "get-url", self.remote).stdout.strip())
        if slug != self.expected_repo:
            raise ContextIndexError(f"unexpected context repository remote: {slug or 'unknown'}")

    def dirty_paths(self) -> list[str]:
        raw = self.run("status", "--porcelain", "-z").stdout
        paths: list[str] = []
        items = raw.split("\0")
        index = 0
        while index < len(items):
            item = items[index]
            index += 1
            if not item:
                continue
            path = item[3:] if len(item) >= 4 else item
            if item[:2].strip().startswith(("R", "C")) and index < len(items) and items[index]:
                paths.append(items[index])
                index += 1
            paths.append(path)
        return paths

    def assert_managed_dirty(self) -> None:
        unexpected = [path for path in self.dirty_paths() if not path.startswith(MANAGED_PREFIXES)]
        if unexpected:
            raise ContextIndexError("unrelated context-repo changes: " + ", ".join(unexpected[:8]))

    def fetch(self) -> None:
        self.run("fetch", "--prune", self.remote, self.branch)

    def ahead_behind(self) -> tuple[int, int]:
        result = self.run("rev-list", "--left-right", "--count", f"HEAD...{self.remote}/{self.branch}")
        parts = result.stdout.strip().split()
        if len(parts) != 2:
            raise ContextIndexError("cannot determine context repository divergence")
        return int(parts[0]), int(parts[1])

    def reconcile(self) -> None:
        self.validate()
        self.assert_managed_dirty()
        if self.dirty_paths():
            self.commit("Context index recovery")
        self.fetch()
        ahead, behind = self.ahead_behind()
        if behind:
            if ahead:
                self.run("rebase", f"{self.remote}/{self.branch}")
            else:
                self.run("merge", "--ff-only", f"{self.remote}/{self.branch}")
        ahead, _ = self.ahead_behind()
        if ahead:
            self.run("push", self.remote, f"HEAD:{self.branch}")

    def commit(self, message: str) -> bool:
        self.assert_managed_dirty()
        self.run("add", "--all", "--", ".")
        if self.run("diff", "--cached", "--quiet", check=False).returncode == 0:
            return False
        self.run("commit", "-m", message)
        return True

    def commit_and_push(self, message: str) -> bool:
        changed = self.commit(message)
        self.fetch()
        ahead, behind = self.ahead_behind()
        if behind:
            self.run("rebase", f"{self.remote}/{self.branch}")
            ahead, _ = self.ahead_behind()
        if ahead:
            try:
                self.run("push", self.remote, f"HEAD:{self.branch}")
            except ContextIndexError:
                self.fetch()
                self.run("rebase", f"{self.remote}/{self.branch}")
                self.run("push", self.remote, f"HEAD:{self.branch}")
        return changed


def sync_context_index(
    database_path: str | Path,
    activitywatch_data_path: str | Path,
    output_directory: str | Path,
    *,
    since_minutes: int | None = None,
    overlap_minutes: int = 10,
    max_backfill_hours: int = 48,
    incident_before_minutes: int = 10,
    incident_after_minutes: int = 5,
    publish_git: bool = False,
    expected_repo: str = "gernalix/fedora-context-data",
    git_remote: str = "origin",
    git_branch: str = "main",
    git_timeout_seconds: int = 120,
) -> dict[str, Any]:
    root = Path(output_directory)
    root.mkdir(parents=True, exist_ok=True)

    publisher = None
    if publish_git:
        publisher = ContextGitRepo(
            root,
            expected_repo=expected_repo,
            remote=git_remote,
            branch=git_branch,
            timeout_seconds=git_timeout_seconds,
        )
        publisher.reconcile()

    end = _now()
    if since_minutes is not None:
        start = end - timedelta(minutes=max(1, int(since_minutes)))
    else:
        previous = _read_last_sync(root)
        if previous is None:
            start = end - timedelta(minutes=30)
        else:
            start = previous - timedelta(minutes=max(0, int(overlap_minutes)))
            floor = end - timedelta(hours=max(1, int(max_backfill_hours)))
            if start < floor:
                start = floor

    monitor = monitor_records(database_path, start=start, end=end)
    activity = activity_records(activitywatch_data_path, start=start, end=end)
    records = sorted(monitor + activity, key=lambda row: (row["timestamp_utc"], row["record_id"]))

    changed_files = 0
    for day in _days(start, end):
        day_start = datetime.combine(day, time.min, tzinfo=UTC)
        day_end = day_start + timedelta(days=1) - timedelta(microseconds=1)
        slice_start = max(start, day_start)
        slice_end = min(end, day_end)
        day_records = [
            row for row in records
            if slice_start <= _parse_time(str(row["timestamp_utc"])) <= slice_end
        ]
        if _write_day(root, day, day_records, replace_start=slice_start, replace_end=slice_end):
            changed_files += 1
        if _write_summary(root, day):
            changed_files += 1

    incident_ids = _incident_ids_in_records(monitor)
    bundles_written = 0
    for incident_id in incident_ids:
        try:
            bundle = build_incident_bundle(
                database_path,
                activitywatch_data_path,
                incident_id,
                before_minutes=incident_before_minutes,
                after_minutes=incident_after_minutes,
            )
        except ContextIndexError:
            continue
        if _atomic_write(root / "incidents" / f"{incident_id}.json", _json_text(bundle)):
            changed_files += 1
        bundles_written += 1

    sources = {
        "schema": INDEX_SCHEMA,
        "fedora_system_monitor": {
            "database_path": str(Path(database_path)),
            "repository": "gernalix/fedora-system-monitor",
        },
        "activitywatch": {
            "data_path": str(Path(activitywatch_data_path)),
            "repository": "gernalix/activity-watch-data",
        },
        "derived_repository": expected_repo,
        "layout": {
            "timeline": "timeline/YYYY/MM/YYYY-MM-DD.jsonl",
            "incidents": "incidents/<incident-id>.json",
            "summaries": "summaries/YYYY-MM-DD.json",
        },
    }
    if _atomic_write(root / "metadata" / "sources.json", _json_text(sources)):
        changed_files += 1

    sync_meta = {
        "schema": INDEX_SCHEMA,
        "completed_at_utc": _iso(_now()),
        "window_start_utc": _iso(start),
        "window_end_utc": _iso(end),
        "record_count": len(records),
        "fedora_record_count": len(monitor),
        "activitywatch_record_count": len(activity),
        "incident_bundle_count": bundles_written,
    }
    if _atomic_write(root / "metadata" / "last-sync.json", _json_text(sync_meta)):
        changed_files += 1

    git_changed = False
    if publisher is not None:
        git_changed = publisher.commit_and_push(f"Context index {_iso(end)}")

    return {
        "ok": True,
        "window_start_utc": _iso(start),
        "window_end_utc": _iso(end),
        "records": len(records),
        "incident_bundles": bundles_written,
        "changed_files": changed_files,
        "git_published": bool(publisher is not None),
        "git_changed": git_changed,
        "output_directory": str(root),
    }


__all__ = [
    "ContextGitRepo",
    "ContextIndexError",
    "activity_records",
    "build_context_window",
    "build_incident_bundle",
    "latest_incident",
    "monitor_records",
    "sync_context_index",
]
