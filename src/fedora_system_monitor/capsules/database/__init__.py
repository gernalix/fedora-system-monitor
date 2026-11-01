"""SQLite persistence capsule for Fedora System Monitor.

``Database`` owns schema migrations, timestamps, transactional writes,
deduplication, retention aggregation, and online backups.  It
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
from .alerts import AlertStorageMixin
from .retention import RetentionStorageMixin, DEFAULT_METRIC_RETENTION_DAYS, _percentile_95
from .shared import StorageError, _json_dumps, _json_loads, _SEVERITY_RANK


SCHEMA_VERSION = 6
DEFAULT_TIMEZONE = "Europe/Copenhagen"



_EXPECTED_INDEXES = {
    "idx_process_scans_time",
    "idx_process_identity_pid",
    "idx_process_identity_name",
    "idx_process_identity_unit",
    "idx_process_samples_identity",
    "idx_metrics_collector_run",
    "idx_events_collector_run",
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
    "idx_systemd_executions_unit_time",
    "idx_systemd_entries_execution_time",
    "idx_systemd_entries_unit_time",
    "idx_systemd_imports_time",
}




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

_MIGRATION_3_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS systemd_executions (
        id INTEGER PRIMARY KEY,
        run_key TEXT NOT NULL UNIQUE,
        hostname TEXT NOT NULL,
        journal_scope TEXT NOT NULL CHECK(journal_scope IN ('system', 'user')),
        unit TEXT NOT NULL,
        timer_unit TEXT,
        service_unit TEXT,
        invocation_id TEXT,
        boot_id TEXT,
        started_at_utc TEXT NOT NULL,
        ended_at_utc TEXT,
        duration_seconds REAL,
        pid INTEGER,
        priority INTEGER,
        severity TEXT NOT NULL DEFAULT 'info',
        status TEXT NOT NULL DEFAULT 'running',
        result TEXT,
        exit_status TEXT,
        message_count INTEGER NOT NULL DEFAULT 0,
        error_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        last_message TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_systemd_executions_unit_time ON systemd_executions(hostname, journal_scope, unit, started_at_utc)",
    """
    CREATE TABLE IF NOT EXISTS systemd_execution_entries (
        id INTEGER PRIMARY KEY,
        execution_id INTEGER NOT NULL REFERENCES systemd_executions(id) ON DELETE CASCADE,
        entry_key TEXT NOT NULL UNIQUE,
        journal_cursor TEXT,
        realtime_usec INTEGER NOT NULL,
        timestamp_utc TEXT NOT NULL,
        hostname TEXT NOT NULL,
        journal_scope TEXT NOT NULL CHECK(journal_scope IN ('system', 'user')),
        unit TEXT NOT NULL,
        timer_unit TEXT,
        service_unit TEXT,
        pid INTEGER,
        priority INTEGER,
        severity TEXT NOT NULL DEFAULT 'info',
        message TEXT NOT NULL DEFAULT '',
        invocation_id TEXT,
        boot_id TEXT,
        result TEXT,
        exit_status TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_systemd_entries_execution_time ON systemd_execution_entries(execution_id, realtime_usec)",
    "CREATE INDEX IF NOT EXISTS idx_systemd_entries_unit_time ON systemd_execution_entries(hostname, journal_scope, unit, realtime_usec)",
    """
    CREATE TABLE IF NOT EXISTS systemd_journal_checkpoints (
        hostname TEXT NOT NULL,
        journal_scope TEXT NOT NULL CHECK(journal_scope IN ('system', 'user')),
        journal_cursor TEXT,
        boot_id TEXT,
        realtime_usec INTEGER,
        updated_at_utc TEXT NOT NULL,
        recovery_state TEXT NOT NULL,
        recovery_warning TEXT,
        fallback_since_utc TEXT,
        last_entries_seen INTEGER NOT NULL DEFAULT 0,
        last_entries_inserted INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(hostname, journal_scope)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS systemd_journal_imports (
        id INTEGER PRIMARY KEY,
        started_at_utc TEXT NOT NULL,
        finished_at_utc TEXT NOT NULL,
        hostname TEXT NOT NULL,
        journal_scope TEXT NOT NULL CHECK(journal_scope IN ('system', 'user')),
        mode TEXT NOT NULL,
        outcome TEXT NOT NULL,
        recovery_state TEXT NOT NULL,
        recovery_warning TEXT,
        entries_seen INTEGER NOT NULL DEFAULT 0,
        entries_inserted INTEGER NOT NULL DEFAULT 0,
        runs_touched INTEGER NOT NULL DEFAULT 0,
        cursor_before TEXT,
        cursor_after TEXT,
        boot_id_before TEXT,
        boot_id_after TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_systemd_imports_time ON systemd_journal_imports(hostname, journal_scope, finished_at_utc)",
    """
    CREATE VIEW IF NOT EXISTS systemd_executions_summary AS
    SELECT e.id, e.started_at_utc AS started, e.ended_at_utc AS ended,
        ROUND(e.duration_seconds, 3) AS duration_seconds,
        e.hostname AS host, e.journal_scope AS scope, e.unit,
        e.timer_unit AS timer, e.service_unit AS service, e.invocation_id, e.pid, e.priority, e.severity,
        e.status, e.result, e.exit_status, e.error_count, e.message_count,
        e.error_message AS error,
        e.last_message AS message
    FROM systemd_executions e
    """,
    """
    CREATE VIEW IF NOT EXISTS systemd_entries AS
    SELECT x.id, x.execution_id, x.timestamp_utc AS timestamp,
        x.hostname AS host, x.journal_scope AS scope, x.unit,
        x.timer_unit AS timer, x.service_unit AS service, x.pid, x.priority, x.severity, x.message,
        x.invocation_id, x.result, x.exit_status,
        e.started_at_utc AS execution_started, e.ended_at_utc AS execution_ended,
        ROUND(e.duration_seconds, 3) AS execution_duration_seconds
    FROM systemd_execution_entries x
    JOIN systemd_executions e ON e.id = x.execution_id
    """,
)

_MIGRATION_4_STATEMENTS = (
    """
    CREATE VIEW IF NOT EXISTS current_alerts AS
    SELECT id, alert_key, timestamp_utc, timestamp_local, hostname, category,
        name, severity, source, device_id, details_json, outcome, error_message,
        status, first_seen_utc, last_seen_utc, recovered_at_utc,
        occurrence_count, threshold_value, hysteresis, direction,
        last_notified_utc, message, last_notification_status,
        last_notification_error,
        COALESCE(message, category || ': ' || name) AS display_summary
    FROM alerts
    WHERE status = 'active'
      AND id IN (
          SELECT id FROM alerts
          WHERE status = 'active'
          ORDER BY CASE severity
              WHEN 'emergency' THEN 4 WHEN 'critical' THEN 3
              WHEN 'warning' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
              last_seen_utc DESC, id DESC
          LIMIT 100
      )
    """,
    """
    CREATE VIEW IF NOT EXISTS recent_events AS
    SELECT id, timestamp_utc, timestamp_local, hostname, category, name,
        value, unit, severity, source, device_id, details_json, outcome,
        error_message, dedup_key, occurrence_count, first_seen_utc,
        last_seen_utc, collector_run_id,
        category || ': ' || name AS display_summary
    FROM events
    WHERE id IN (
        SELECT id FROM events
        ORDER BY timestamp_utc DESC, id DESC
        LIMIT 500
      )
    """,
)




def _as_records(records: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(records, Mapping):
        return [records]
    return list(records)




_MIGRATION_5_STATEMENTS = (
    "CREATE INDEX IF NOT EXISTS idx_metrics_collector_run ON periodic_metrics(collector_run_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_collector_run ON events(collector_run_id)",
)


class Database(AlertStorageMixin, RetentionStorageMixin):
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
        # Preserve an online, integrity-checked backup before additive v6 DDL.
        if str(self.path) != ":memory:" and self.path.exists() and self.path.stat().st_size:
            with self._connection() as probe:
                exists = probe.execute("SELECT 1 FROM sqlite_master WHERE name='schema_versions'").fetchone()
                version = probe.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0] if exists else 0
            if version and version < 6:
                self.backup(self.path.parent / f"{self.path.name}.pre-v6-{uuid4().hex}.bak")
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
                current = 2
            if current < 3:
                for statement in _MIGRATION_3_STATEMENTS:
                    connection.execute(statement)
                utc, _ = self._timestamps()
                connection.execute(
                    "INSERT INTO schema_versions(version, applied_at_utc, description) VALUES (?, ?, ?)",
                    (3, utc, "persistent systemd execution journal history"),
                )
                current = 3
            if current < 4:
                for statement in _MIGRATION_4_STATEMENTS:
                    connection.execute(statement)
                utc, _ = self._timestamps()
                connection.execute(
                    "INSERT INTO schema_versions(version, applied_at_utc, description) VALUES (?, ?, ?)",
                    (4, utc, "bounded Datasette current-alert and recent-event views"),
                )
            if current < 5:
                for statement in _MIGRATION_5_STATEMENTS:
                    connection.execute(statement)
                utc, _ = self._timestamps()
                connection.execute(
                    "INSERT INTO schema_versions(version, applied_at_utc, description) VALUES (?, ?, ?)",
                    (5, utc, "indexed collector history foreign-key cleanup"),
                )
            if current < 6:
                from .process_history import SCHEMA
                for statement in SCHEMA:
                    connection.execute(statement)
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok" or connection.execute("PRAGMA foreign_key_check").fetchone():
                    raise StorageError("process history migration checks failed")
                utc, _ = self._timestamps()
                connection.execute("INSERT INTO schema_versions VALUES(?,?,?)", (6,utc,"compact per-process history"))
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

    def insert_process_snapshot(self, snapshot, options):
        from .process_history import persist, maintain
        with self._transaction() as connection:
            count = persist(connection, snapshot)
            maintenance = maintain(connection, now=snapshot['timestamp'],
                raw_hours=options['raw_hours'], aggregate_days=options['aggregate_days'])
        return {"samples": count, **maintenance}

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
            # Lifecycle hooks and journal replay can describe the same event
            # without a cursor. Merge only byte-for-byte semantic duplicates;
            # distinct recurrences retain separate rows.
            exact_groups = connection.execute(
                """
                SELECT MIN(id) AS keep_id, GROUP_CONCAT(id) AS ids,
                       SUM(occurrence_count) AS occurrences,
                       MIN(first_seen_utc) AS first_seen,
                       MAX(last_seen_utc) AS last_seen,
                       COUNT(*) AS row_count
                FROM events
                GROUP BY timestamp_utc,category,name,source,COALESCE(device_id,''),
                         details_json,dedup_key
                HAVING COUNT(*)>1
                """
            ).fetchall()
            for group in exact_groups:
                keep_id = int(group["keep_id"])
                connection.execute(
                    "UPDATE events SET occurrence_count=?,first_seen_utc=?,last_seen_utc=? WHERE id=?",
                    (int(group["occurrences"]), group["first_seen"], group["last_seen"], keep_id),
                )
                duplicate_ids = [int(item) for item in str(group["ids"]).split(",") if int(item) != keep_id]
                connection.executemany("DELETE FROM events WHERE id=?", ((item,) for item in duplicate_ids))
                removed += len(duplicate_ids)
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






__all__ = [
    "Database",
    "DEFAULT_METRIC_RETENTION_DAYS",
    "DEFAULT_TIMEZONE",
    "SCHEMA_VERSION",
    "StorageError",
]
