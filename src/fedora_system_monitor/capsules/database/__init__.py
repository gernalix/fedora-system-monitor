"""SQLite persistence capsule for Fedora System Monitor.

``Database`` owns schema migrations, timestamps, transactional writes,
deduplication, alert lifecycle, retention aggregation, and online backups.  It
uses no third-party packages and never interpolates caller values into SQL.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..config import redact_text


SCHEMA_VERSION = 2
DEFAULT_TIMEZONE = "Europe/Copenhagen"
DEFAULT_METRIC_RETENTION_DAYS = {60: 14, 300: 60, 900: 180, 3600: 365, 86400: 3650}

_SEVERITY_RANK = {"debug": 0, "info": 1, "warning": 2, "critical": 3, "emergency": 4}
_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "token",
}

_EXPECTED_INDEXES = {
    "idx_metrics_time",
    "idx_metrics_name_time",
    "idx_metrics_cadence_time",
    "idx_events_time",
    "idx_events_name_time",
    "idx_events_device_time",
    "idx_alerts_status_severity",
    "idx_alerts_key_time",
    "ux_alerts_active_key",
    "idx_hardware_snapshot",
    "idx_hardware_item_time",
    "idx_software_snapshot",
    "idx_software_item_time",
    "idx_collector_runs_name_time",
    "idx_aggregates_name_bucket",
    "idx_summaries_period_time",
}


class StorageError(RuntimeError):
    """Raised for unsupported schemas or invalid persistence operations."""


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS periodic_metrics (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        cadence_seconds INTEGER NOT NULL,
        collector_run_id INTEGER REFERENCES collector_runs(id) ON DELETE SET NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_metrics_time ON periodic_metrics(timestamp_utc)",
    "CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON periodic_metrics(category, name, timestamp_utc)",
    "CREATE INDEX IF NOT EXISTS idx_metrics_cadence_time ON periodic_metrics(cadence_seconds, timestamp_utc)",
    """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        dedup_key TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        collector_run_id INTEGER REFERENCES collector_runs(id) ON DELETE SET NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc)",
    "CREATE INDEX IF NOT EXISTS idx_events_name_time ON events(category, name, timestamp_utc)",
    "CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, timestamp_utc)",
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL,
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'open',
        error_message TEXT,
        alert_key TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active', 'recovered')),
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        recovered_at_utc TEXT,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        threshold_value REAL,
        hysteresis REAL NOT NULL DEFAULT 0,
        direction TEXT NOT NULL DEFAULT 'above' CHECK(direction IN ('above', 'below')),
        last_notified_utc TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity, last_seen_utc)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_key_time ON alerts(alert_key, timestamp_utc)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_active_key ON alerts(alert_key) WHERE status = 'active'",
    """
    CREATE TABLE IF NOT EXISTS hardware_inventory (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'hardware',
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        snapshot_id TEXT NOT NULL,
        item_key TEXT NOT NULL,
        vendor TEXT,
        model TEXT,
        serial TEXT,
        filesystem_uuid TEXT,
        label TEXT,
        filesystem TEXT,
        size_bytes INTEGER,
        mount_point TEXT,
        present INTEGER NOT NULL DEFAULT 1 CHECK(present IN (0, 1)),
        UNIQUE(snapshot_id, item_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_hardware_snapshot ON hardware_inventory(snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_hardware_item_time ON hardware_inventory(item_key, timestamp_utc)",
    """
    CREATE TABLE IF NOT EXISTS software_inventory (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'software',
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        snapshot_id TEXT NOT NULL,
        item_key TEXT NOT NULL,
        version TEXT,
        previous_version TEXT,
        operation TEXT,
        repository TEXT,
        architecture TEXT,
        owner_user TEXT,
        path TEXT,
        size_bytes INTEGER,
        mtime_ns INTEGER,
        inode INTEGER,
        content_hash TEXT,
        UNIQUE(snapshot_id, item_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_software_snapshot ON software_inventory(snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_software_item_time ON software_inventory(item_key, timestamp_utc)",
    """
    CREATE TABLE IF NOT EXISTS collector_runs (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'collector',
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL DEFAULT 'scheduler',
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'running',
        error_message TEXT,
        started_at_utc TEXT NOT NULL,
        finished_at_utc TEXT,
        duration_ms REAL,
        cadence_seconds INTEGER,
        metrics_inserted INTEGER NOT NULL DEFAULT 0,
        events_inserted INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_collector_runs_name_time ON collector_runs(name, started_at_utc)",
    """
    CREATE TABLE IF NOT EXISTS config_versions (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'configuration',
        name TEXT NOT NULL DEFAULT 'runtime',
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        config_hash TEXT NOT NULL UNIQUE,
        config_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dedup_state (
        namespace TEXT NOT NULL,
        state_key TEXT NOT NULL,
        state_json TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL,
        expires_at_utc TEXT,
        PRIMARY KEY(namespace, state_key)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX IF NOT EXISTS idx_dedup_expiry ON dedup_state(expires_at_utc)",
    """
    CREATE TABLE IF NOT EXISTS metric_aggregates (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        aggregate_key TEXT NOT NULL UNIQUE,
        bucket_start_utc TEXT NOT NULL,
        bucket_end_utc TEXT NOT NULL,
        period_seconds INTEGER NOT NULL,
        source_cadence_seconds INTEGER NOT NULL,
        minimum REAL,
        maximum REAL,
        average REAL,
        percentile_95 REAL,
        sample_count INTEGER NOT NULL,
        problematic_seconds INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_aggregates_name_bucket ON metric_aggregates(category, name, bucket_start_utc)",
    """
    CREATE TABLE IF NOT EXISTS summaries (
        id INTEGER PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        timestamp_local TEXT NOT NULL,
        hostname TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'summary',
        name TEXT NOT NULL,
        value REAL,
        unit TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL,
        device_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        outcome TEXT NOT NULL DEFAULT 'ok',
        error_message TEXT,
        period TEXT NOT NULL,
        period_start_utc TEXT NOT NULL,
        period_end_utc TEXT NOT NULL,
        health TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        UNIQUE(period, period_start_utc, hostname)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_summaries_period_time ON summaries(period, period_start_utc)",
)

_MIGRATION_2_STATEMENTS = (
    "ALTER TABLE alerts ADD COLUMN message TEXT",
    "ALTER TABLE alerts ADD COLUMN last_notification_status TEXT",
    "ALTER TABLE alerts ADD COLUMN last_notification_error TEXT",
)


def _sanitize(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower().replace("-", "_") in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): _sanitize(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(_sanitize(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _json_loads(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _as_records(records: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(records, Mapping):
        return [records]
    return list(records)


def _percentile_95(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


class Database:
    """Own and query a versioned Fedora System Monitor SQLite database."""

    def __init__(
        self,
        path: str | Path,
        *,
        hostname: str | None = None,
        timezone_name: str = DEFAULT_TIMEZONE,
        timeout_seconds: float = 10.0,
        initialize: bool = True,
    ) -> None:
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self.hostname = hostname or socket.gethostname()
        self.timeout_seconds = timeout_seconds
        try:
            self.timezone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise StorageError(f"unknown timezone: {timezone_name}") from exc
        self._memory_connection: sqlite3.Connection | None = None
        if str(self.path) == ":memory:":
            self._memory_connection = self._new_connection()
        if initialize:
            self.initialize()

    def _new_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {max(1, int(self.timeout_seconds * 1000))}")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._memory_connection or self._new_connection()
        try:
            yield connection
        finally:
            if self._memory_connection is None:
                connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def close(self) -> None:
        """Close the persistent connection used by an in-memory database."""

        if self._memory_connection is not None:
            self._memory_connection.close()
            self._memory_connection = None

    def __enter__(self) -> Database:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def initialize(self) -> int:
        """Create or migrate the database and return its schema version."""

        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_versions (
                    version INTEGER PRIMARY KEY,
                    applied_at_utc TEXT NOT NULL,
                    description TEXT NOT NULL
                )
                """
            )
            row = connection.execute("SELECT COALESCE(MAX(version), 0) AS version FROM schema_versions").fetchone()
            current = int(row["version"])
            if current > SCHEMA_VERSION:
                raise StorageError(
                    f"database schema {current} is newer than supported schema {SCHEMA_VERSION}"
                )
            if current < 1:
                for statement in _SCHEMA_STATEMENTS:
                    connection.execute(statement)
                utc, _ = self._timestamps()
                connection.execute(
                    "INSERT INTO schema_versions(version, applied_at_utc, description) VALUES (?, ?, ?)",
                    (1, utc, "initial monitoring schema"),
                )
                current = 1
            if current < 2:
                for statement in _MIGRATION_2_STATEMENTS:
                    connection.execute(statement)
                utc, _ = self._timestamps()
                connection.execute(
                    "INSERT INTO schema_versions(version, applied_at_utc, description) VALUES (?, ?, ?)",
                    (2, utc, "alert message and notification delivery state"),
                )
        if str(self.path) != ":memory:":
            try:
                os.chmod(self.path, 0o640)
            except OSError:
                pass
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute("PRAGMA wal_autocheckpoint = 1000")
        return self.get_schema_version()

    def get_schema_version(self) -> int:
        """Return the latest applied schema migration number."""

        rows = self.query("SELECT COALESCE(MAX(version), 0) AS version FROM schema_versions")
        return int(rows[0]["version"])

    @property
    def schema_version(self) -> int:
        """Latest applied schema migration number."""

        return self.get_schema_version()

    @property
    def journal_mode(self) -> str:
        """Return SQLite's active journal mode."""

        with self._connection() as connection:
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def _coerce_datetime(self, value: datetime | str | None = None) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, str):
            candidate = value.strip()
            if candidate.endswith("Z"):
                candidate = candidate[:-1] + "+00:00"
            try:
                value = datetime.fromisoformat(candidate)
            except ValueError as exc:
                raise StorageError(f"invalid ISO timestamp: {value}") from exc
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _timestamps(self, value: datetime | str | None = None) -> tuple[str, str]:
        instant = self._coerce_datetime(value)
        utc = instant.isoformat(timespec="seconds").replace("+00:00", "Z")
        local = instant.astimezone(self.timezone).isoformat(timespec="seconds")
        return utc, local

    def _record_fields(
        self,
        record: Mapping[str, Any],
        *,
        default_category: str,
        default_source: str,
        timestamp: datetime | str | None = None,
        known_keys: set[str] | None = None,
    ) -> tuple[Any, ...]:
        utc, local = self._timestamps(record.get("timestamp_utc", timestamp))
        details = dict(record.get("details") or {})
        if known_keys is not None:
            details.update({key: value for key, value in record.items() if key not in known_keys})
        value = record.get("value")
        if isinstance(value, bool) or (value is not None and not isinstance(value, (int, float))):
            raise StorageError(f"numeric value required for {record.get('name', 'record')}")
        name = str(record.get("name") or "").strip()
        if not name:
            raise StorageError("record name is required")
        return (
            utc,
            local,
            str(record.get("hostname") or self.hostname),
            str(record.get("category") or default_category),
            name,
            value,
            record.get("unit"),
            str(record.get("severity") or "info").lower(),
            str(record.get("source") or default_source),
            record.get("device_id"),
            _json_dumps(details),
            str(record.get("outcome") or "ok"),
            redact_text(record["error_message"]) if record.get("error_message") else None,
        )

    def insert_metrics(
        self,
        metrics: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        *,
        cadence_seconds: int = 60,
        collected_at: datetime | str | None = None,
        collector_run_id: int | None = None,
    ) -> int:
        """Insert a metric batch atomically and return the inserted row count."""

        records = _as_records(metrics)
        if not records:
            return 0
        if cadence_seconds <= 0:
            raise StorageError("cadence_seconds must be greater than zero")
        known = {
            "timestamp_utc", "timestamp_local", "hostname", "category", "name", "value", "unit",
            "severity", "source", "device_id", "details", "outcome", "error_message",
            "cadence", "cadence_seconds", "collector_run_id",
        }
        rows = []
        for record in records:
            cadence = int(record.get("cadence_seconds", record.get("cadence", cadence_seconds)))
            if cadence <= 0:
                raise StorageError("metric cadence_seconds must be greater than zero")
            common = self._record_fields(
                record,
                default_category="system",
                default_source="collector",
                timestamp=collected_at,
                known_keys=known,
            )
            rows.append(common + (cadence, record.get("collector_run_id", collector_run_id)))
        with self._transaction() as connection:
            connection.executemany(
                """
                INSERT INTO periodic_metrics(
                    timestamp_utc, timestamp_local, hostname, category, name, value, unit,
                    severity, source, device_id, details_json, outcome, error_message,
                    cadence_seconds, collector_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def _event_key(self, record: Mapping[str, Any]) -> str:
        explicit = record.get("dedup_key")
        if explicit:
            return str(explicit)
        identity = {
            "category": record.get("category", "system"),
            "name": record.get("name"),
            "severity": record.get("severity", "info"),
            "source": record.get("source", "event"),
            "device_id": record.get("device_id"),
            "outcome": record.get("outcome", "ok"),
            "error_message": redact_text(record.get("error_message", "")),
        }
        digest = hashlib.sha256(_json_dumps(identity).encode("utf-8")).hexdigest()
        return f"event:{digest}"

    def insert_events(
        self,
        events: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        *,
        dedup_window_seconds: int = 300,
        occurred_at: datetime | str | None = None,
        collector_run_id: int | None = None,
    ) -> int:
        """Insert events atomically, coalescing repeats inside a time window.

        The return value is the number of new event rows.  Coalesced events
        increment ``occurrence_count`` and advance ``last_seen_utc``.
        """

        records = _as_records(events)
        if not records:
            return 0
        if dedup_window_seconds < 0:
            raise StorageError("dedup_window_seconds cannot be negative")
        known = {
            "timestamp_utc", "timestamp_local", "hostname", "category", "name", "value", "unit",
            "severity", "source", "device_id", "details", "outcome", "error_message", "dedup_key",
            "cadence", "dedup_window_seconds", "collector_run_id",
        }
        inserted = 0
        with self._transaction() as connection:
            for record in records:
                common = self._record_fields(
                    record,
                    default_category="system",
                    default_source="event",
                    timestamp=occurred_at,
                    known_keys=known,
                )
                event_utc = common[0]
                event_time = self._coerce_datetime(event_utc)
                dedup_key = self._event_key(record)
                state_row = connection.execute(
                    "SELECT state_json FROM dedup_state WHERE namespace = 'event' AND state_key = ?",
                    (dedup_key,),
                ).fetchone()
                state = _json_loads(state_row["state_json"], {}) if state_row else {}
                duplicate = False
                event_id = state.get("event_id")
                last_seen = state.get("last_seen_utc")
                if dedup_window_seconds and event_id and last_seen:
                    delta = (event_time - self._coerce_datetime(last_seen)).total_seconds()
                    duplicate = 0 <= delta <= dedup_window_seconds
                if duplicate:
                    cursor = connection.execute(
                        """
                        UPDATE events
                        SET occurrence_count = occurrence_count + 1,
                            last_seen_utc = ?, timestamp_utc = ?, timestamp_local = ?,
                            value = ?, details_json = ?, outcome = ?, error_message = ?
                        WHERE id = ?
                        """,
                        (
                            event_utc, common[0], common[1], common[5], common[10], common[11],
                            common[12], event_id,
                        ),
                    )
                    duplicate = cursor.rowcount == 1
                if not duplicate:
                    cursor = connection.execute(
                        """
                        INSERT INTO events(
                            timestamp_utc, timestamp_local, hostname, category, name, value, unit,
                            severity, source, device_id, details_json, outcome, error_message,
                            dedup_key, occurrence_count, first_seen_utc, last_seen_utc, collector_run_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                        """,
                        common + (dedup_key, event_utc, event_utc, record.get("collector_run_id", collector_run_id)),
                    )
                    event_id = cursor.lastrowid
                    inserted += 1
                state_json = _json_dumps({"event_id": event_id, "last_seen_utc": event_utc})
                expiry, _ = self._timestamps(event_time + timedelta(seconds=max(1, dedup_window_seconds)))
                connection.execute(
                    """
                    INSERT INTO dedup_state(namespace, state_key, state_json, updated_at_utc, expires_at_utc)
                    VALUES ('event', ?, ?, ?, ?)
                    ON CONFLICT(namespace, state_key) DO UPDATE SET
                        state_json = excluded.state_json,
                        updated_at_utc = excluded.updated_at_utc,
                        expires_at_utc = excluded.expires_at_utc
                    """,
                    (dedup_key, state_json, event_utc, expiry),
                )
        return inserted

    def start_collector_run(
        self,
        name: str,
        *,
        cadence_seconds: int | None = None,
        source: str = "scheduler",
        started_at: datetime | str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> int:
        """Create a running collector record and return its row id."""

        utc, local = self._timestamps(started_at)
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO collector_runs(
                    timestamp_utc, timestamp_local, hostname, name, source, details_json,
                    outcome, started_at_utc, cadence_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (utc, local, self.hostname, name, source, _json_dumps(details or {}), utc, cadence_seconds),
            )
            return int(cursor.lastrowid)

    def finish_collector_run(
        self,
        run_id: int,
        *,
        outcome: str = "ok",
        metrics_inserted: int = 0,
        events_inserted: int = 0,
        error_message: str | None = None,
        details: Mapping[str, Any] | None = None,
        finished_at: datetime | str | None = None,
    ) -> None:
        """Finish a collector record, calculating duration from its start."""

        utc, _ = self._timestamps(finished_at)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT started_at_utc, details_json FROM collector_runs WHERE id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise StorageError(f"collector run does not exist: {run_id}")
            duration_ms = max(
                0.0,
                (self._coerce_datetime(utc) - self._coerce_datetime(row["started_at_utc"])).total_seconds()
                * 1000.0,
            )
            merged_details = _json_loads(row["details_json"], {})
            merged_details.update(details or {})
            severity = "info" if outcome == "ok" else "warning"
            connection.execute(
                """
                UPDATE collector_runs
                SET finished_at_utc = ?, duration_ms = ?, value = ?, unit = 'ms',
                    severity = ?, details_json = ?, outcome = ?, error_message = ?,
                    metrics_inserted = ?, events_inserted = ?
                WHERE id = ?
                """,
                (
                    utc, duration_ms, duration_ms, severity, _json_dumps(merged_details), outcome,
                    redact_text(error_message) if error_message else None,
                    metrics_inserted, events_inserted, run_id,
                ),
            )

    def record_collector_run(self, name: str, **values: Any) -> int:
        """Create an already-completed collector record in one convenience call."""

        finish_keys = {
            "outcome", "metrics_inserted", "events_inserted", "error_message", "finished_at"
        }
        start_values = {key: value for key, value in values.items() if key not in finish_keys}
        details = start_values.pop("details", None)
        run_id = self.start_collector_run(name, details=details, **start_values)
        finish_values = {key: value for key, value in values.items() if key in finish_keys}
        self.finish_collector_run(run_id, details=details, **finish_values)
        return run_id

    @contextmanager
    def collector_run(self, name: str, **values: Any) -> Iterator[int]:
        """Context manager that records collector success or failure."""

        run_id = self.start_collector_run(name, **values)
        try:
            yield run_id
        except BaseException as exc:
            self.finish_collector_run(run_id, outcome="error", error_message=str(exc))
            raise
        else:
            self.finish_collector_run(run_id)

    def set_state(
        self,
        key: str,
        value: Any,
        *,
        namespace: str = "application",
        expires_at: datetime | str | None = None,
    ) -> None:
        """Atomically persist a JSON-compatible state value."""

        utc, _ = self._timestamps()
        expiry = self._timestamps(expires_at)[0] if expires_at is not None else None
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO dedup_state(namespace, state_key, state_json, updated_at_utc, expires_at_utc)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(namespace, state_key) DO UPDATE SET
                    state_json = excluded.state_json,
                    updated_at_utc = excluded.updated_at_utc,
                    expires_at_utc = excluded.expires_at_utc
                """,
                (namespace, key, _json_dumps(value), utc, expiry),
            )

    def get_state(self, key: str, default: Any = None, *, namespace: str = "application") -> Any:
        """Return a stored state value, or *default* if absent or expired."""

        with self._connection() as connection:
            row = connection.execute(
                "SELECT state_json, expires_at_utc FROM dedup_state WHERE namespace = ? AND state_key = ?",
                (namespace, key),
            ).fetchone()
        if row is None:
            return default
        if row["expires_at_utc"] and self._coerce_datetime(row["expires_at_utc"]) <= datetime.now(timezone.utc):
            return default
        return _json_loads(row["state_json"], default)

    def record_config_version(self, config: Mapping[str, Any], *, source: str = "config") -> int:
        """Store a redacted configuration revision once and return its row id."""

        serialized = _json_dumps(config)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        utc, local = self._timestamps()
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO config_versions(
                    timestamp_utc, timestamp_local, hostname, source, config_hash, config_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (utc, local, self.hostname, source, digest, serialized),
            )
            row = connection.execute(
                "SELECT id FROM config_versions WHERE config_hash = ?", (digest,)
            ).fetchone()
            return int(row["id"])

    def open_alert(
        self,
        alert_key: str,
        *,
        category: str,
        name: str,
        severity: str = "warning",
        source: str = "threshold",
        value: float | None = None,
        unit: str | None = None,
        device_id: str | None = None,
        threshold: float | None = None,
        hysteresis: float = 0.0,
        direction: str = "above",
        details: Mapping[str, Any] | None = None,
        message: str | None = None,
        error_message: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> int:
        """Open or update an alert and return its durable row id."""

        alert_id, _ = self.open_alert_transition(
            alert_key,
            category=category,
            name=name,
            severity=severity,
            source=source,
            value=value,
            unit=unit,
            device_id=device_id,
            threshold=threshold,
            hysteresis=hysteresis,
            direction=direction,
            details=details,
            message=message,
            error_message=error_message,
            occurred_at=occurred_at,
        )
        return alert_id

    def open_alert_transition(
        self,
        alert_key: str,
        *,
        category: str,
        name: str,
        severity: str = "warning",
        source: str = "threshold",
        value: float | None = None,
        unit: str | None = None,
        device_id: str | None = None,
        threshold: float | None = None,
        hysteresis: float = 0.0,
        direction: str = "above",
        details: Mapping[str, Any] | None = None,
        message: str | None = None,
        error_message: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> tuple[int, bool]:
        """Open/update an alert and atomically report a state/severity transition."""

        if direction not in {"above", "below"}:
            raise StorageError("alert direction must be 'above' or 'below'")
        if hysteresis < 0:
            raise StorageError("alert hysteresis cannot be negative")
        utc, local = self._timestamps(occurred_at)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT id, occurrence_count, severity FROM alerts WHERE alert_key = ? AND status = 'active'",
                (alert_key,),
            ).fetchone()
            if row:
                connection.execute(
                    """
                    UPDATE alerts SET timestamp_utc = ?, timestamp_local = ?, last_seen_utc = ?,
                        value = ?, unit = ?, severity = ?, source = ?, device_id = ?,
                        details_json = ?, error_message = ?, threshold_value = ?, hysteresis = ?,
                        direction = ?, message = COALESCE(?, message),
                        occurrence_count = occurrence_count + 1
                    WHERE id = ?
                    """,
                    (
                        utc, local, utc, value, unit, severity, source, device_id,
                        _json_dumps(details or {}), redact_text(error_message) if error_message else None,
                        threshold, hysteresis, direction, redact_text(message) if message else None, row["id"],
                    ),
                )
                return int(row["id"]), str(row["severity"]) != severity
            cursor = connection.execute(
                """
                INSERT INTO alerts(
                    timestamp_utc, timestamp_local, hostname, category, name, value, unit,
                    severity, source, device_id, details_json, outcome, error_message,
                    alert_key, status, first_seen_utc, last_seen_utc, threshold_value,
                    hysteresis, direction, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, 'active', ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc, local, self.hostname, category, name, value, unit, severity, source, device_id,
                    _json_dumps(details or {}), redact_text(error_message) if error_message else None,
                    alert_key, utc, utc, threshold, hysteresis, direction,
                    redact_text(message) if message else None,
                ),
            )
            return int(cursor.lastrowid), True

    def update_alert(
        self,
        alert_key: str,
        *,
        value: float | None = None,
        severity: str | None = None,
        details: Mapping[str, Any] | None = None,
        occurred_at: datetime | str | None = None,
    ) -> bool:
        """Update the active alert and return whether one existed."""

        utc, local = self._timestamps(occurred_at)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT id, severity, details_json FROM alerts WHERE alert_key = ? AND status = 'active'",
                (alert_key,),
            ).fetchone()
            if row is None:
                return False
            merged = _json_loads(row["details_json"], {})
            merged.update(details or {})
            connection.execute(
                """
                UPDATE alerts SET timestamp_utc = ?, timestamp_local = ?, last_seen_utc = ?,
                    value = ?, severity = ?, details_json = ?, occurrence_count = occurrence_count + 1
                WHERE id = ?
                """,
                (utc, local, utc, value, severity or row["severity"], _json_dumps(merged), row["id"]),
            )
            return True

    def recover_alert(
        self,
        alert_key: str,
        *,
        value: float | None = None,
        details: Mapping[str, Any] | None = None,
        message: str | None = None,
        recovered_at: datetime | str | None = None,
    ) -> bool:
        """Mark the active alert recovered, preserving it as history."""

        utc, local = self._timestamps(recovered_at)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT id, details_json FROM alerts WHERE alert_key = ? AND status = 'active'",
                (alert_key,),
            ).fetchone()
            if row is None:
                return False
            merged = _json_loads(row["details_json"], {})
            merged.update(details or {})
            if message:
                merged["recovery_message"] = redact_text(message)
            connection.execute(
                """
                UPDATE alerts SET timestamp_utc = ?, timestamp_local = ?, last_seen_utc = ?,
                    recovered_at_utc = ?, status = 'recovered', outcome = 'recovered', value = ?,
                    details_json = ? WHERE id = ?
                """,
                (utc, local, utc, utc, value, _json_dumps(merged), row["id"]),
            )
            return True

    def mark_alert_notification(
        self,
        alert_key: str,
        status: str,
        error: str = "",
        *,
        notified_at: datetime | str | None = None,
    ) -> bool:
        """Record notification delivery on the latest alert instance."""

        utc, _ = self._timestamps(notified_at)
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE alerts
                SET last_notified_utc = ?, last_notification_status = ?,
                    last_notification_error = ?
                WHERE id = (
                    SELECT id FROM alerts WHERE alert_key = ?
                    ORDER BY timestamp_utc DESC, id DESC LIMIT 1
                )
                """,
                (utc, status, redact_text(error) if error else None, alert_key),
            )
            return cursor.rowcount == 1

    def evaluate_alert(
        self,
        alert_key: str,
        value: float,
        threshold: float,
        *,
        direction: str = "above",
        hysteresis: float = 0.0,
        category: str = "system",
        name: str | None = None,
        severity: str = "warning",
        source: str = "threshold",
        unit: str | None = None,
        device_id: str | None = None,
        details: Mapping[str, Any] | None = None,
        message: str | None = None,
        occurred_at: datetime | str | None = None,
    ) -> str:
        """Apply threshold hysteresis and return opened/updated/recovered/normal."""

        if direction not in {"above", "below"}:
            raise StorageError("alert direction must be 'above' or 'below'")
        if hysteresis < 0:
            raise StorageError("alert hysteresis cannot be negative")
        active = bool(
            self.query(
                "SELECT 1 FROM alerts WHERE alert_key = ? AND status = 'active' LIMIT 1",
                (alert_key,),
            )
        )
        breached = value > threshold if direction == "above" else value < threshold
        cleared = value <= threshold - hysteresis if direction == "above" else value >= threshold + hysteresis
        if breached:
            self.open_alert(
                alert_key,
                category=category,
                name=name or alert_key,
                severity=severity,
                source=source,
                value=value,
                unit=unit,
                device_id=device_id,
                threshold=threshold,
                hysteresis=hysteresis,
                direction=direction,
                details=details,
                message=message,
                occurred_at=occurred_at,
            )
            return "updated" if active else "opened"
        if active and cleared:
            self.recover_alert(
                alert_key, value=value, details=details, recovered_at=occurred_at
            )
            return "recovered"
        if active:
            self.update_alert(alert_key, value=value, details=details, occurred_at=occurred_at)
            return "updated"
        return "normal"

    def active_alerts(self, *, minimum_severity: str | None = None) -> list[dict[str, Any]]:
        """Return active alerts, most severe and most recent first."""

        rows = self.query(
            "SELECT * FROM alerts WHERE status = 'active' ORDER BY last_seen_utc DESC"
        )
        if minimum_severity is None:
            return sorted(rows, key=lambda row: _SEVERITY_RANK.get(row["severity"], 1), reverse=True)
        minimum = _SEVERITY_RANK.get(minimum_severity, 0)
        return [row for row in rows if _SEVERITY_RANK.get(row["severity"], 1) >= minimum]

    def insert_hardware_snapshot(
        self,
        items: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        *,
        snapshot_id: str | None = None,
        collected_at: datetime | str | None = None,
        source: str = "hardware_inventory",
    ) -> str:
        """Insert a complete hardware snapshot atomically and return its id."""

        records = _as_records(items)
        utc, _ = self._timestamps(collected_at)
        snapshot_id = snapshot_id or f"hardware-{utc}-{uuid4().hex[:8]}"
        known = {
            "timestamp_utc", "hostname", "category", "name", "value", "unit", "severity", "source",
            "device_id", "details", "outcome", "error_message", "item_key", "stable_id", "vendor",
            "model", "serial", "filesystem_uuid", "uuid", "label", "filesystem", "fstype",
            "size_bytes", "mount_point", "present",
        }
        rows = []
        for record in records:
            common = self._record_fields(
                record,
                default_category="hardware",
                default_source=source,
                timestamp=collected_at,
                known_keys=known,
            )
            item_key = str(
                record.get("item_key") or record.get("stable_id") or record.get("device_id") or record["name"]
            )
            rows.append(
                common
                + (
                    snapshot_id, item_key, record.get("vendor"), record.get("model"), record.get("serial"),
                    record.get("filesystem_uuid", record.get("uuid")), record.get("label"),
                    record.get("filesystem", record.get("fstype")), record.get("size_bytes"),
                    record.get("mount_point"), int(bool(record.get("present", True))),
                )
            )
        with self._transaction() as connection:
            connection.executemany(
                """
                INSERT INTO hardware_inventory(
                    timestamp_utc, timestamp_local, hostname, category, name, value, unit, severity,
                    source, device_id, details_json, outcome, error_message, snapshot_id, item_key,
                    vendor, model, serial, filesystem_uuid, label, filesystem, size_bytes, mount_point, present
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return snapshot_id

    def insert_software_snapshot(
        self,
        items: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        *,
        snapshot_id: str | None = None,
        collected_at: datetime | str | None = None,
        source: str = "software_inventory",
    ) -> str:
        """Insert a complete software snapshot atomically and return its id."""

        records = _as_records(items)
        utc, _ = self._timestamps(collected_at)
        snapshot_id = snapshot_id or f"software-{utc}-{uuid4().hex[:8]}"
        known = {
            "timestamp_utc", "hostname", "category", "name", "value", "unit", "severity", "source",
            "device_id", "details", "outcome", "error_message", "item_key", "stable_id", "version",
            "previous_version", "operation", "repository", "architecture", "arch", "owner_user", "user",
            "path", "size_bytes", "mtime_ns", "inode", "content_hash", "hash",
        }
        rows = []
        for record in records:
            common = self._record_fields(
                record,
                default_category="software",
                default_source=source,
                timestamp=collected_at,
                known_keys=known,
            )
            item_key = str(record.get("item_key") or record.get("stable_id") or record["name"])
            rows.append(
                common
                + (
                    snapshot_id, item_key, record.get("version"), record.get("previous_version"),
                    record.get("operation"), record.get("repository"),
                    record.get("architecture", record.get("arch")),
                    record.get("owner_user", record.get("user")), record.get("path"),
                    record.get("size_bytes"), record.get("mtime_ns"), record.get("inode"),
                    record.get("content_hash", record.get("hash")),
                )
            )
        with self._transaction() as connection:
            connection.executemany(
                """
                INSERT INTO software_inventory(
                    timestamp_utc, timestamp_local, hostname, category, name, value, unit, severity,
                    source, device_id, details_json, outcome, error_message, snapshot_id, item_key,
                    version, previous_version, operation, repository, architecture, owner_user, path,
                    size_bytes, mtime_ns, inode, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return snapshot_id

    def insert_summary(
        self,
        period: str,
        summary: Mapping[str, Any],
        *,
        period_start: datetime | str,
        period_end: datetime | str,
        health: str,
        name: str | None = None,
        severity: str = "info",
        source: str = "summary",
    ) -> int:
        """Upsert a daily or weekly JSON summary and return its row id."""

        start_utc, _ = self._timestamps(period_start)
        end_utc, _ = self._timestamps(period_end)
        utc, local = self._timestamps()
        serialized = _json_dumps(summary)
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO summaries(
                    timestamp_utc, timestamp_local, hostname, name, severity, source, details_json,
                    period, period_start_utc, period_end_utc, health, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(period, period_start_utc, hostname) DO UPDATE SET
                    timestamp_utc = excluded.timestamp_utc,
                    timestamp_local = excluded.timestamp_local,
                    name = excluded.name,
                    severity = excluded.severity,
                    source = excluded.source,
                    details_json = excluded.details_json,
                    period_end_utc = excluded.period_end_utc,
                    health = excluded.health,
                    summary_json = excluded.summary_json
                """,
                (
                    utc, local, self.hostname, name or f"{period}_summary", severity, source, serialized,
                    period, start_utc, end_utc, health, serialized,
                ),
            )
            row = connection.execute(
                "SELECT id FROM summaries WHERE period = ? AND period_start_utc = ? AND hostname = ?",
                (period, start_utc, self.hostname),
            ).fetchone()
            return int(row["id"])

    def latest_summary(self, period: str = "daily") -> dict[str, Any] | None:
        """Return the latest summary with decoded ``summary`` content."""

        rows = self.query(
            "SELECT * FROM summaries WHERE period = ? ORDER BY period_start_utc DESC LIMIT 1",
            (period,),
        )
        if not rows:
            return None
        row = rows[0]
        row["summary"] = _json_loads(row["summary_json"], {})
        return row

    def query(
        self,
        sql: str,
        parameters: Sequence[Any] | Mapping[str, Any] = (),
    ) -> list[dict[str, Any]]:
        """Execute a read-only SELECT/WITH/PRAGMA query and return dictionaries."""

        command = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        if command not in {"SELECT", "WITH", "PRAGMA", "EXPLAIN"}:
            raise StorageError("query() accepts read-only SQL only")
        with self._connection() as connection:
            connection.execute("PRAGMA query_only = ON")
            try:
                cursor = connection.execute(sql, parameters)
                return [dict(row) for row in cursor.fetchall()]
            finally:
                if self._memory_connection is not None:
                    connection.execute("PRAGMA query_only = OFF")

    def table_counts(self) -> dict[str, int]:
        """Return row counts for all durable monitoring tables."""

        tables = (
            "periodic_metrics", "events", "alerts", "hardware_inventory", "software_inventory",
            "collector_runs", "config_versions", "dedup_state", "metric_aggregates", "summaries",
        )
        return {table: int(self.query(f"SELECT COUNT(*) AS count FROM {table}")[0]["count"]) for table in tables}

    @staticmethod
    def _journal_cursor_key(cursor: str) -> str:
        return hashlib.sha256(cursor.encode("utf-8", errors="replace")).hexdigest()

    def journal_cursor_seen(self, cursor: str) -> bool:
        """Return whether an immutable journal cursor was already imported."""

        if not cursor:
            return False
        key = self._journal_cursor_key(cursor)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM dedup_state WHERE namespace = 'journal_cursor' AND state_key = ?",
                (key,),
            ).fetchone()
        return row is not None

    def mark_journal_cursor(self, cursor: str) -> None:
        """Persist an immutable journal cursor without a retention expiry."""

        if not cursor:
            return
        self.set_state(
            self._journal_cursor_key(cursor),
            {"seen": True},
            namespace="journal_cursor",
        )

    def consolidate_journal_events(self) -> dict[str, int]:
        """Merge legacy duplicate journal rows and seed cursor identities.

        Older releases relied only on event time windows. A host clock jump can
        make a repeated historical import appear older than the dedup state.
        Journal cursors are immutable, so they are the durable import identity.
        """

        removed = seeded = 0
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT id, occurrence_count, first_seen_utc, last_seen_utc,
                       json_extract(details_json, '$.journal_identity.cursor') AS cursor
                FROM events
                WHERE json_extract(details_json, '$.journal_identity.cursor') IS NOT NULL
                  AND json_extract(details_json, '$.journal_identity.cursor') != ''
                ORDER BY id
                """
            ).fetchall()
            groups: dict[str, list[sqlite3.Row]] = defaultdict(list)
            for row in rows:
                groups[str(row["cursor"])].append(row)
            utc, _ = self._timestamps()
            for cursor, duplicates in groups.items():
                keep = duplicates[0]
                if len(duplicates) > 1:
                    occurrence_count = sum(int(row["occurrence_count"]) for row in duplicates)
                    first_seen = min(str(row["first_seen_utc"]) for row in duplicates)
                    last_seen = max(str(row["last_seen_utc"]) for row in duplicates)
                    connection.execute(
                        """
                        UPDATE events
                        SET occurrence_count = ?, first_seen_utc = ?, last_seen_utc = ?,
                            timestamp_utc = ?
                        WHERE id = ?
                        """,
                        (occurrence_count, first_seen, last_seen, last_seen, int(keep["id"])),
                    )
                    ids = [int(row["id"]) for row in duplicates[1:]]
                    connection.executemany("DELETE FROM events WHERE id = ?", ((item,) for item in ids))
                    removed += len(ids)
                key = self._journal_cursor_key(cursor)
                cursor_result = connection.execute(
                    """
                    INSERT OR IGNORE INTO dedup_state(
                        namespace, state_key, state_json, updated_at_utc, expires_at_utc
                    ) VALUES ('journal_cursor', ?, '{"seen":true}', ?, NULL)
                    """,
                    (key, utc),
                )
                seeded += cursor_result.rowcount
        return {"duplicates_removed": removed, "cursors_seeded": seeded}

    def backup(self, destination: str | Path) -> Path:
        """Create a consistent online SQLite backup and return its path."""

        target_path = Path(destination)
        if str(target_path.resolve()) == str(self.path.resolve()):
            raise StorageError("backup destination must differ from database path")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(target_path), isolation_level=None)
        try:
            with self._connection() as source:
                source.backup(target)
            result = target.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise StorageError(f"backup integrity check failed: {result}")
        finally:
            target.close()
        try:
            os.chmod(target_path, 0o640)
        except OSError:
            pass
        return target_path

    def integrity_check(self, *, quick: bool = False) -> list[str]:
        """Run SQLite integrity validation and return every diagnostic row."""

        pragma = "quick_check" if quick else "integrity_check"
        return [str(row[pragma]) for row in self.query(f"PRAGMA {pragma}")]

    def check_indexes(self) -> dict[str, Any]:
        """Report expected and installed SQLite indexes."""

        rows = self.query("SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL")
        installed = {str(row["name"]) for row in rows}
        missing = sorted(_EXPECTED_INDEXES - installed)
        return {"ok": not missing, "missing": missing, "installed": sorted(installed)}

    def db_check(self) -> dict[str, Any]:
        """Return schema, WAL, integrity, foreign-key, and index health."""

        integrity = self.integrity_check()
        foreign_keys = self.query("PRAGMA foreign_key_check")
        indexes = self.check_indexes()
        return {
            "ok": integrity == ["ok"] and not foreign_keys and indexes["ok"],
            "schema_version": self.schema_version,
            "journal_mode": self.journal_mode,
            "integrity": integrity,
            "foreign_key_errors": foreign_keys,
            "indexes": indexes,
        }

    def _aggregate_metrics(
        self,
        connection: sqlite3.Connection,
        rows: Sequence[sqlite3.Row],
    ) -> int:
        grouped: dict[tuple[Any, ...], list[sqlite3.Row]] = defaultdict(list)
        for row in rows:
            instant = self._coerce_datetime(row["timestamp_utc"])
            bucket = instant.replace(hour=0, minute=0, second=0, microsecond=0)
            key = (
                bucket, row["cadence_seconds"], row["hostname"], row["category"], row["name"],
                row["unit"], row["source"], row["device_id"],
            )
            grouped[key].append(row)

        cumulative_names = {
            "interface_rx_bytes",
            "interface_tx_bytes",
            "disk_reads_completed",
            "disk_writes_completed",
        }
        count = 0
        for key, raw_samples in grouped.items():
            bucket, cadence, hostname, category, name, unit, source, device_id = key
            bucket_end = bucket + timedelta(days=1)
            bucket_utc, bucket_local = self._timestamps(bucket)
            bucket_end_utc, _ = self._timestamps(bucket_end)
            by_timestamp: dict[str, sqlite3.Row] = {}
            for row in raw_samples:
                timestamp = str(row["timestamp_utc"])
                previous = by_timestamp.get(timestamp)
                if previous is None or int(row["id"]) > int(previous["id"]):
                    by_timestamp[timestamp] = row
            samples = sorted(
                by_timestamp.values(),
                key=lambda row: (str(row["timestamp_utc"]), int(row["id"])),
            )
            duplicates_discarded = len(raw_samples) - len(samples)
            values = [float(row["value"]) for row in samples if row["value"] is not None]
            severity = max(
                (str(row["severity"]) for row in samples),
                key=lambda item: _SEVERITY_RANK.get(item, 1),
            )
            problematic = min(86400, sum(
                int(cadence)
                for row in samples
                if _SEVERITY_RANK.get(str(row["severity"]), 1) >= _SEVERITY_RANK["warning"]
            ))
            identity = [bucket_utc, cadence, hostname, category, name, unit, source, device_id]
            aggregate_key = hashlib.sha256(_json_dumps(identity).encode("utf-8")).hexdigest()
            minimum = min(values) if values else None
            maximum = max(values) if values else None
            average = sum(values) / len(values) if values else None
            p95 = _percentile_95(values)
            sample_count = len(samples)
            expected_samples = max(1, 86400 // max(1, int(cadence)))
            metric_kind = (
                "cumulative_counter"
                if name in cumulative_names
                else "boolean"
                if unit == "boolean"
                else "gauge"
            )
            details: dict[str, Any] = {
                "aggregation": "daily_utc",
                "bucket_complete": True,
                "metric_kind": metric_kind,
                "numeric_sample_count": len(values),
                "duplicate_samples_discarded": duplicates_discarded,
                "expected_sample_count": expected_samples,
                "missing_sample_count": max(0, expected_samples - sample_count),
                "percentile_95_exact": True,
            }
            if metric_kind == "cumulative_counter" and values:
                resets = 0
                positive_delta = 0.0
                for previous, current in zip(values, values[1:]):
                    if current < previous:
                        resets += 1
                    else:
                        positive_delta += current - previous
                details.update(
                    {
                        "counter_resets": resets,
                        "positive_delta_total": positive_delta,
                        "first_value": values[0],
                        "last_value": values[-1],
                    }
                )
            existing = connection.execute(
                "SELECT * FROM metric_aggregates WHERE aggregate_key = ?",
                (aggregate_key,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO metric_aggregates(
                        timestamp_utc, timestamp_local, hostname, category, name, value, unit,
                        severity, source, device_id, details_json, aggregate_key, bucket_start_utc,
                        bucket_end_utc, period_seconds, source_cadence_seconds, minimum, maximum,
                        average, percentile_95, sample_count, problematic_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 86400, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        bucket_utc, bucket_local, hostname, category, name, average, unit, severity,
                        source, device_id, _json_dumps(details), aggregate_key, bucket_utc,
                        bucket_end_utc, cadence, minimum, maximum, average, p95, sample_count,
                        problematic,
                    ),
                )
            else:
                previous_details = _json_loads(existing["details_json"], {})
                old_numeric = int(previous_details.get("numeric_sample_count", existing["sample_count"]))
                new_numeric = len(values)
                total_numeric = old_numeric + new_numeric
                if total_numeric:
                    old_total = float(existing["average"] or 0.0) * old_numeric
                    new_total = float(average or 0.0) * new_numeric
                    merged_average = (old_total + new_total) / total_numeric
                else:
                    merged_average = None
                merged_count = int(existing["sample_count"]) + sample_count
                details["numeric_sample_count"] = total_numeric
                details["duplicate_samples_discarded"] += int(
                    previous_details.get("duplicate_samples_discarded", 0)
                )
                details["missing_sample_count"] = max(0, expected_samples - merged_count)
                details["percentile_95_exact"] = False
                details["merged_segments"] = int(previous_details.get("merged_segments", 1)) + 1
                if metric_kind == "cumulative_counter":
                    old_last = previous_details.get("last_value")
                    new_first = details.get("first_value")
                    cross_resets = 0
                    cross_delta = 0.0
                    if isinstance(old_last, (int, float)) and isinstance(new_first, (int, float)):
                        if new_first < old_last:
                            cross_resets = 1
                        else:
                            cross_delta = float(new_first) - float(old_last)
                    details["counter_resets"] = (
                        int(previous_details.get("counter_resets", 0))
                        + int(details.get("counter_resets", 0))
                        + cross_resets
                    )
                    details["positive_delta_total"] = (
                        float(previous_details.get("positive_delta_total", 0.0))
                        + float(details.get("positive_delta_total", 0.0))
                        + cross_delta
                    )
                    details["first_value"] = previous_details.get(
                        "first_value", details.get("first_value")
                    )
                old_minimum = existing["minimum"]
                old_maximum = existing["maximum"]
                merged_minimum = minimum if old_minimum is None else old_minimum if minimum is None else min(old_minimum, minimum)
                merged_maximum = maximum if old_maximum is None else old_maximum if maximum is None else max(old_maximum, maximum)
                old_severity = str(existing["severity"])
                merged_severity = max(
                    (old_severity, severity), key=lambda item: _SEVERITY_RANK.get(item, 1)
                )
                connection.execute(
                    """
                    UPDATE metric_aggregates
                    SET value = ?, severity = ?, details_json = ?, minimum = ?, maximum = ?,
                        average = ?, percentile_95 = NULL, sample_count = ?,
                        problematic_seconds = ?
                    WHERE aggregate_key = ?
                    """,
                    (
                        merged_average,
                        merged_severity,
                        _json_dumps(details),
                        merged_minimum,
                        merged_maximum,
                        merged_average,
                        merged_count,
                        min(86400, int(existing["problematic_seconds"]) + problematic),
                        aggregate_key,
                    ),
                )
            count += 1
        return count

    def _thin_inventory_snapshots(
        self,
        connection: sqlite3.Connection,
        table: str,
        *,
        current: datetime,
        daily_days: float,
    ) -> int:
        if table not in {"hardware_inventory", "software_inventory"}:
            raise StorageError(f"unsupported inventory table: {table}")
        rows = connection.execute(
            f"SELECT snapshot_id, MAX(timestamp_utc) AS timestamp_utc FROM {table} GROUP BY snapshot_id"
        ).fetchall()
        if len(rows) <= 1:
            return 0

        snapshots = [
            (str(row["snapshot_id"]), self._coerce_datetime(row["timestamp_utc"]))
            for row in rows
        ]
        cutoff = current - timedelta(days=daily_days)
        latest_id = max(snapshots, key=lambda item: (item[1], item[0]))[0]
        keep = {latest_id}
        older: list[tuple[str, datetime]] = []
        for snapshot_id, timestamp in snapshots:
            if timestamp >= cutoff:
                keep.add(snapshot_id)
            else:
                older.append((snapshot_id, timestamp))

        weekly: dict[tuple[int, int], tuple[str, datetime]] = {}
        monthly: dict[tuple[int, int], tuple[str, datetime]] = {}
        for snapshot_id, timestamp in older:
            iso = timestamp.isocalendar()
            week_key = (iso.year, iso.week)
            month_key = (timestamp.year, timestamp.month)
            if week_key not in weekly or timestamp > weekly[week_key][1]:
                weekly[week_key] = (snapshot_id, timestamp)
            if month_key not in monthly or timestamp > monthly[month_key][1]:
                monthly[month_key] = (snapshot_id, timestamp)
        keep.update(snapshot_id for snapshot_id, _ in weekly.values())
        keep.update(snapshot_id for snapshot_id, _ in monthly.values())

        delete_ids = [snapshot_id for snapshot_id, _ in snapshots if snapshot_id not in keep]
        deleted = 0
        for offset in range(0, len(delete_ids), 500):
            chunk = delete_ids[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            cursor = connection.execute(
                f"DELETE FROM {table} WHERE snapshot_id IN ({placeholders})",
                chunk,
            )
            deleted += cursor.rowcount
        return deleted

    def apply_retention(
        self,
        *,
        now: datetime | str | None = None,
        metric_days_by_cadence: Mapping[int | str, int | float] | None = None,
        unknown_metric_days: int | float = 365,
        event_days: int | float = 365,
        hardware_event_days: int | float | None = None,
        alert_days: int | float = 730,
        collector_run_days: int | float = 90,
        dedup_state_days: int | float = 30,
        inventory_daily_days: int | float = 35,
        software_events_permanent: bool = True,
        compact: bool = False,
    ) -> dict[str, int]:
        """Aggregate expired metrics, then delete data according to retention.

        Important warning/critical events and software history are preserved.
        Daily metric aggregates and summaries are never deleted here.
        """

        current = self._coerce_datetime(now)
        retention = {
            int(cadence): float(days)
            for cadence, days in (metric_days_by_cadence or DEFAULT_METRIC_RETENTION_DAYS).items()
        }
        for label, value in {
            "unknown_metric_days": unknown_metric_days,
            "event_days": event_days,
            "hardware_event_days": event_days if hardware_event_days is None else hardware_event_days,
            "alert_days": alert_days,
            "collector_run_days": collector_run_days,
            "dedup_state_days": dedup_state_days,
            "inventory_daily_days": inventory_daily_days,
            **{f"metric cadence {key}": value for key, value in retention.items()},
        }.items():
            if float(value) < 0:
                raise StorageError(f"{label} cannot be negative")

        result = {
            "metrics_deleted": 0,
            "aggregates_written": 0,
            "events_deleted": 0,
            "alerts_deleted": 0,
            "collector_runs_deleted": 0,
            "dedup_states_deleted": 0,
            "hardware_inventory_deleted": 0,
            "software_inventory_deleted": 0,
        }
        cadences = [
            int(row["cadence_seconds"])
            for row in self.query("SELECT DISTINCT cadence_seconds FROM periodic_metrics")
        ]
        for cadence in cadences:
            days = retention.get(cadence, float(unknown_metric_days))
            raw_cutoff = current - timedelta(days=days)
            complete_bucket_cutoff = raw_cutoff.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            cutoff, _ = self._timestamps(complete_bucket_cutoff)
            bucket_days = [
                str(row["bucket_day"])
                for row in self.query(
                    """
                    SELECT DISTINCT substr(timestamp_utc, 1, 10) AS bucket_day
                    FROM periodic_metrics
                    WHERE cadence_seconds = ? AND timestamp_utc < ?
                    ORDER BY bucket_day
                    """,
                    (cadence, cutoff),
                )
            ]
            for bucket_day in bucket_days:
                bucket_start = self._coerce_datetime(f"{bucket_day}T00:00:00Z")
                bucket_start_utc, _ = self._timestamps(bucket_start)
                bucket_end_utc, _ = self._timestamps(bucket_start + timedelta(days=1))
                with self._transaction() as connection:
                    expired = connection.execute(
                        """
                        SELECT * FROM periodic_metrics
                        WHERE cadence_seconds = ? AND timestamp_utc >= ? AND timestamp_utc < ?
                        """,
                        (cadence, bucket_start_utc, bucket_end_utc),
                    ).fetchall()
                    if not expired:
                        continue
                    result["aggregates_written"] += self._aggregate_metrics(connection, expired)
                    cursor = connection.execute(
                        """
                        DELETE FROM periodic_metrics
                        WHERE cadence_seconds = ? AND timestamp_utc >= ? AND timestamp_utc < ?
                        """,
                        (cadence, bucket_start_utc, bucket_end_utc),
                    )
                    result["metrics_deleted"] += cursor.rowcount

        with self._transaction() as connection:
            event_cutoff, _ = self._timestamps(current - timedelta(days=float(event_days)))
            hardware_cutoff, _ = self._timestamps(
                current - timedelta(days=float(event_days if hardware_event_days is None else hardware_event_days))
            )
            event_sql = (
                "DELETE FROM events WHERE severity IN ('debug', 'info') AND "
                "((category IN ('hardware','storage','filesystem') AND timestamp_utc < ?) "
                "OR (category NOT IN ('hardware','storage','filesystem') AND timestamp_utc < ?))"
            )
            parameters: list[Any] = [hardware_cutoff, event_cutoff]
            if software_events_permanent:
                event_sql += " AND category != 'software'"
            cursor = connection.execute(event_sql, parameters)
            result["events_deleted"] = cursor.rowcount

            alert_cutoff, _ = self._timestamps(current - timedelta(days=float(alert_days)))
            cursor = connection.execute(
                "DELETE FROM alerts WHERE status = 'recovered' AND recovered_at_utc < ?",
                (alert_cutoff,),
            )
            result["alerts_deleted"] = cursor.rowcount

            run_cutoff, _ = self._timestamps(current - timedelta(days=float(collector_run_days)))
            cursor = connection.execute(
                "DELETE FROM collector_runs WHERE finished_at_utc IS NOT NULL AND finished_at_utc < ?",
                (run_cutoff,),
            )
            result["collector_runs_deleted"] = cursor.rowcount

            state_cutoff, _ = self._timestamps(current - timedelta(days=float(dedup_state_days)))
            cursor = connection.execute(
                """
                DELETE FROM dedup_state
                WHERE (expires_at_utc IS NOT NULL AND expires_at_utc < ?)
                   OR (expires_at_utc IS NULL AND namespace = 'event' AND updated_at_utc < ?)
                """,
                (self._timestamps(current)[0], state_cutoff),
            )
            result["dedup_states_deleted"] = cursor.rowcount

            result["hardware_inventory_deleted"] = self._thin_inventory_snapshots(
                connection,
                "hardware_inventory",
                current=current,
                daily_days=float(inventory_daily_days),
            )
            result["software_inventory_deleted"] = self._thin_inventory_snapshots(
                connection,
                "software_inventory",
                current=current,
                daily_days=float(inventory_daily_days),
            )

        if compact:
            self.compact()
        return result

    def compact(self) -> None:
        """Checkpoint WAL and optimize indexes without an exclusive full VACUUM.

        Freed pages remain reusable inside the database. This avoids blocking
        event writers for the potentially long duration of a multi-gigabyte
        VACUUM while still bounding WAL growth.
        """

        with self._connection() as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("PRAGMA optimize")


__all__ = [
    "Database",
    "DEFAULT_METRIC_RETENTION_DAYS",
    "DEFAULT_TIMEZONE",
    "SCHEMA_VERSION",
    "StorageError",
]
