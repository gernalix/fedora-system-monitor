"""Bounded metric aggregation, inventory thinning and SQLite retention.

Uses the database connection and timestamp primitives supplied by Database;
keeps the existing API, WAL transactions and conservative alert retention.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
import hashlib
import math
import sqlite3
from typing import Any

from .shared import StorageError, _json_dumps, _json_loads, _SEVERITY_RANK


DEFAULT_METRIC_RETENTION_DAYS = {60: 14, 300: 60, 900: 180, 3600: 365, 86400: 3650}


def _percentile_95(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


class RetentionStorageMixin:
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
