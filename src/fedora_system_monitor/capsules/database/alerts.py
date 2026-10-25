"""Alert lifecycle storage, separate from metric and inventory persistence.

This mixin relies on the Database transaction, timestamp and query primitives;
the public Database API and its existing SQLite transaction boundaries remain intact.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from ..config import redact_text
from .shared import StorageError, _json_dumps, _json_loads, _SEVERITY_RANK


class AlertStorageMixin:
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
