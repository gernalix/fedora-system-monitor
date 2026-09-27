"""Persistent, cursor-based history for custom systemd units.

Unit discovery remains owned by ``scripts/systemd-journal-collector.sh``.  This
module consumes its catalog, reads only a small allowlist of structured journal
fields, and persists idempotent entries and logical executions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
from typing import Any, Iterable, Mapping

from .config import redact_text
from .database import Database


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PACKAGE_ROOT.parent if PACKAGE_ROOT.name == "src" else PACKAGE_ROOT
DEFAULT_COLLECTOR = SOURCE_ROOT / "scripts/systemd-journal-collector.sh"
DEFAULT_REGISTRY = Path("/home/daniele/MegaVault/megavault.sqlite")
DEFAULT_FALLBACK_SINCE = "7 days ago"
_TERMINAL_SUCCESS = ("deactivated successfully", "finished successfully", "succeeded", "stopped ")
_TERMINAL_FAILURE = ("failed", "failure", "core dumped", "killed process", "exit-code")
_SEVERITIES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


def add_cli_subcommand(subparsers: Any) -> None:
    """Register the one-shot import and read-only status CLI."""

    history = subparsers.add_parser("systemd-history", help="import or inspect persistent systemd execution history")
    commands = history.add_subparsers(dest="systemd_history_command", required=True)
    importer = commands.add_parser("import", help="import new custom-unit journal entries once")
    importer.add_argument("--journalctl", default="journalctl")
    for option in ("collector", "registry", "system-unit-dir", "user-unit-dir"):
        importer.add_argument(f"--{option}", type=Path)
    importer.add_argument("--initial-lookback-hours", type=int, default=24)
    importer.add_argument("--fallback-lookback-hours", type=int, default=168)
    commands.add_parser("status", help="read checkpoint and history status")


@dataclass(frozen=True)
class UnitIdentity:
    unit: str
    scope: str
    timer_unit: str | None
    service_unit: str | None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(realtime_usec: int) -> str:
    return datetime.fromtimestamp(realtime_usec / 1_000_000, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _scalar(value: Any) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    return str(value)


def _integer(value: Any) -> int | None:
    try:
        return int(_scalar(value) or "")
    except ValueError:
        return None


def discover_units(
    collector: Path = DEFAULT_COLLECTOR,
    *,
    environment: Mapping[str, str] | None = None,
) -> list[UnitIdentity]:
    """Return the Bash collector's canonical custom-unit catalog."""

    result = subprocess.run(
        [str(collector), "--discover"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
        env=None if environment is None else dict(environment),
    )
    if result.returncode != 0:
        raise RuntimeError(f"custom unit discovery failed: {redact_text(result.stderr).strip()}")
    discovered: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if line.strip():
            discovered.append(json.loads(line))

    timer_to_service = {
        str(row["unit"]): str(row["timer_target"])
        for row in discovered
        if row.get("timer_target")
    }
    service_to_timer: dict[str, str] = {}
    for timer, service in sorted(timer_to_service.items()):
        service_to_timer.setdefault(service, timer)
    identities = []
    for row in discovered:
        unit = str(row["unit"])
        identities.append(
            UnitIdentity(
                unit=unit,
                scope=str(row["scope"]),
                timer_unit=unit if unit.endswith(".timer") else service_to_timer.get(unit),
                service_unit=timer_to_service.get(unit) if unit.endswith(".timer") else unit,
            )
        )
    return identities


def _journal_command(
    journalctl: str,
    scope: str,
    units: Iterable[str],
    *,
    cursor: str | None,
    fallback_since: str,
) -> list[str]:
    command = [journalctl]
    if scope == "user":
        command.append("--user")
    command.extend(("--no-pager", "--output=json", "--all", "--show-cursor"))
    for unit in units:
        command.extend(("--unit", unit))
    if cursor:
        command.extend(("--after-cursor", cursor))
    else:
        command.extend(("--since", fallback_since))
    command.extend(("--until", "now"))
    return command


def _journal(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)


def _read_journal(
    journalctl: str,
    scope: str,
    units: list[str],
    *,
    cursor: str | None,
    fallback_since: str,
) -> tuple[list[dict[str, Any]], str | None]:
    command = _journal_command(journalctl, scope, units, cursor=cursor, fallback_since=fallback_since)
    result = _journal(command)
    if result.returncode != 0:
        return [], redact_text(result.stderr).strip() or f"journalctl exited with status {result.returncode}"
    entries: list[dict[str, Any]] = []
    shown_cursor: str | None = None
    for line in result.stdout.splitlines():
        if line.startswith("-- cursor:"):
            shown_cursor = line.partition(":")[2].strip() or None
            continue
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            return [], f"journalctl returned invalid JSON: {exc.msg}"
        if isinstance(value, dict):
            entries.append(value)
    if shown_cursor:
        if entries:
            entries[-1]["__FSM_SHOWN_CURSOR"] = shown_cursor
        else:
            entries.append({"__FSM_SHOWN_CURSOR": shown_cursor})
    return entries, None


def _entry_identity(
    raw: Mapping[str, Any],
    *,
    scope: str,
    default_host: str,
    catalog: Mapping[str, UnitIdentity],
) -> dict[str, Any] | None:
    realtime_usec = _integer(raw.get("__REALTIME_TIMESTAMP"))
    if realtime_usec is None:
        return None
    source_unit = _scalar(raw.get("_SYSTEMD_UNIT") or raw.get("_SYSTEMD_USER_UNIT") or raw.get("UNIT"))
    if not source_unit or source_unit not in catalog:
        return None
    known = catalog[source_unit]
    unit = source_unit
    hostname = _scalar(raw.get("_HOSTNAME")) or default_host
    cursor = _scalar(raw.get("__CURSOR"))
    boot_id = _scalar(raw.get("_BOOT_ID"))
    invocation_id = _scalar(raw.get("_SYSTEMD_INVOCATION_ID"))
    pid = _integer(raw.get("_PID"))
    priority = _integer(raw.get("PRIORITY"))
    result = _scalar(raw.get("RESULT") or raw.get("JOB_RESULT"))
    exit_status = _scalar(raw.get("EXIT_STATUS") or raw.get("EXIT_CODE"))
    message = redact_text(_scalar(raw.get("MESSAGE")) or "")[:65536]
    stable = {
        "scope": scope,
        "hostname": hostname,
        "boot_id": boot_id,
        "realtime_usec": realtime_usec,
        "monotonic_usec": _scalar(raw.get("__MONOTONIC_TIMESTAMP")),
        "unit": unit,
        "source_unit": source_unit,
        "pid": pid,
        "priority": priority,
        "message": message,
    }
    entry_key = f"cursor:{scope}:{hostname}:{cursor}" if cursor else "fallback-entry:" + hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if invocation_id:
        run_key = f"invocation:{scope}:{hostname}:{invocation_id}"
    else:
        run_key = "fallback-run:" + hashlib.sha256(
            f"{scope}\0{hostname}\0{boot_id or ''}\0{unit}\0{entry_key}".encode()
        ).hexdigest()
    return {
        "entry_key": entry_key,
        "run_key": run_key,
        "cursor": cursor,
        "realtime_usec": realtime_usec,
        "timestamp_utc": _timestamp(realtime_usec),
        "hostname": hostname,
        "scope": scope,
        "unit": unit,
        "timer_unit": known.timer_unit,
        "service_unit": known.service_unit,
        "pid": pid,
        "priority": priority,
        "severity": _SEVERITIES.get(priority, "unknown"),
        "message": message,
        "invocation_id": invocation_id,
        "boot_id": boot_id,
        "result": result,
        "exit_status": exit_status,
    }


def _entry_status(entry: Mapping[str, Any]) -> str | None:
    result = str(entry["result"] or "").lower()
    exit_status = str(entry["exit_status"] or "")
    message = str(entry["message"] or "").lower()
    if result and result not in {"success", "done"}:
        return "failed"
    if exit_status and exit_status not in {"0", "success"}:
        return "failed"
    if any(marker in message for marker in _TERMINAL_FAILURE):
        return "failed"
    if result in {"success", "done"} or exit_status in {"0", "success"}:
        return "success"
    if any(marker in message for marker in _TERMINAL_SUCCESS):
        return "success"
    return None


def _refresh_execution(connection: sqlite3.Connection, execution_id: int) -> None:
    rows = connection.execute(
        "SELECT * FROM systemd_execution_entries WHERE execution_id=? ORDER BY realtime_usec,id",
        (execution_id,),
    ).fetchall()
    if not rows:
        return
    terminal = [(row, _entry_status(row)) for row in rows]
    terminal = [(row, status) for row, status in terminal if status]
    last = rows[-1]
    end = terminal[-1][0] if terminal else None
    status = terminal[-1][1] if terminal else "running"
    errors = [row for row in rows if (_entry_status(row) == "failed" or (row["priority"] is not None and row["priority"] <= 3))]
    priorities = [row["priority"] for row in rows if row["priority"] is not None]
    connection.execute(
        """
        UPDATE systemd_executions SET
            started_at_utc=?, ended_at_utc=?, duration_seconds=?, pid=?, priority=?,
            severity=?, status=?, result=?, exit_status=?, message_count=?, error_count=?,
            error_message=?, last_message=?
        WHERE id=?
        """,
        (
            rows[0]["timestamp_utc"],
            end["timestamp_utc"] if end else None,
            (end["realtime_usec"] - rows[0]["realtime_usec"]) / 1_000_000 if end else None,
            last["pid"],
            min(priorities) if priorities else None,
            _SEVERITIES.get(min(priorities), "unknown") if priorities else "unknown",
            status,
            last["result"],
            last["exit_status"],
            len(rows),
            len(errors),
            errors[-1]["message"] if errors else None,
            last["message"],
            execution_id,
        ),
    )


def _persist_scope(
    db: Database,
    entries: list[dict[str, Any]],
    *,
    hostname: str,
    scope: str,
    catalog: Mapping[str, UnitIdentity],
    checkpoint: Mapping[str, Any] | None,
    mode: str,
    recovery_state: str,
    warning: str | None,
    started_at: str,
    fallback_since: str,
) -> dict[str, Any]:
    shown_cursor = next(
        (_scalar(raw.get("__FSM_SHOWN_CURSOR")) for raw in reversed(entries) if raw.get("__FSM_SHOWN_CURSOR")),
        None,
    )
    normalized = [
        entry
        for raw in entries
        if (entry := _entry_identity(raw, scope=scope, default_host=hostname, catalog=catalog)) is not None
    ]
    normalized.sort(key=lambda item: (item["realtime_usec"], item["entry_key"]))
    inserted = 0
    touched: set[int] = set()
    with db._transaction() as connection:  # same capsule boundary and transaction policy as Database
        for entry in normalized:
            connection.execute(
                """
                INSERT INTO systemd_executions(
                    run_key,hostname,journal_scope,unit,timer_unit,service_unit,invocation_id,boot_id,
                    started_at_utc,pid,priority,severity,status,result,exit_status
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(run_key) DO NOTHING
                """,
                (
                    entry["run_key"], entry["hostname"], scope, entry["unit"], entry["timer_unit"],
                    entry["service_unit"], entry["invocation_id"], entry["boot_id"], entry["timestamp_utc"],
                    entry["pid"], entry["priority"], entry["severity"], "running", entry["result"], entry["exit_status"],
                ),
            )
            execution_id = int(connection.execute(
                "SELECT id FROM systemd_executions WHERE run_key=?", (entry["run_key"],)
            ).fetchone()[0])
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO systemd_execution_entries(
                    execution_id,entry_key,journal_cursor,realtime_usec,timestamp_utc,hostname,journal_scope,
                    unit,timer_unit,service_unit,pid,priority,severity,message,invocation_id,boot_id,result,exit_status
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    execution_id, entry["entry_key"], entry["cursor"], entry["realtime_usec"],
                    entry["timestamp_utc"], entry["hostname"], scope, entry["unit"], entry["timer_unit"],
                    entry["service_unit"], entry["pid"], entry["priority"], entry["severity"], entry["message"],
                    entry["invocation_id"], entry["boot_id"], entry["result"], entry["exit_status"],
                ),
            )
            if cursor.rowcount:
                inserted += 1
                touched.add(execution_id)
        for execution_id in touched:
            _refresh_execution(connection, execution_id)

        last = normalized[-1] if normalized else None
        cursor_after = (last and last["cursor"]) or shown_cursor or (checkpoint and checkpoint.get("journal_cursor"))
        boot_after = (last and last["boot_id"]) or (checkpoint and checkpoint.get("boot_id"))
        realtime_after = (last and last["realtime_usec"]) or (checkpoint and checkpoint.get("realtime_usec"))
        finished_at = _utc_now()
        connection.execute(
            """
            INSERT INTO systemd_journal_checkpoints(
                hostname,journal_scope,journal_cursor,boot_id,realtime_usec,updated_at_utc,recovery_state,
                recovery_warning,fallback_since_utc,last_entries_seen,last_entries_inserted
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(hostname,journal_scope) DO UPDATE SET
                journal_cursor=excluded.journal_cursor,boot_id=excluded.boot_id,realtime_usec=excluded.realtime_usec,
                updated_at_utc=excluded.updated_at_utc,recovery_state=excluded.recovery_state,
                recovery_warning=excluded.recovery_warning,fallback_since_utc=excluded.fallback_since_utc,
                last_entries_seen=excluded.last_entries_seen,last_entries_inserted=excluded.last_entries_inserted
            """,
            (
                hostname, scope, cursor_after, boot_after, realtime_after, finished_at, recovery_state,
                warning, fallback_since if mode == "fallback" else None, len(normalized), inserted,
            ),
        )
        connection.execute(
            """
            INSERT INTO systemd_journal_imports(
                started_at_utc,finished_at_utc,hostname,journal_scope,mode,outcome,recovery_state,
                recovery_warning,entries_seen,entries_inserted,runs_touched,cursor_before,cursor_after,
                boot_id_before,boot_id_after
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                started_at, finished_at, hostname, scope, mode, "ok", recovery_state, warning,
                len(normalized), inserted, len(touched), checkpoint and checkpoint.get("journal_cursor"),
                cursor_after, checkpoint and checkpoint.get("boot_id"), boot_after,
            ),
        )
    return {
        "scope": scope,
        "mode": mode,
        "recovery_state": recovery_state,
        "warning": warning,
        "entries_seen": len(normalized),
        "entries_inserted": inserted,
        "runs_touched": len(touched),
        "cursor_advanced": bool((normalized and normalized[-1]["cursor"]) or shown_cursor),
    }


def ingest_entries(
    database: str | Path,
    entries: list[dict[str, Any]],
    *,
    hostname: str,
    scope: str,
    mappings: Mapping[str, tuple[str | None, str | None]],
) -> dict[str, int]:
    """Persist an already captured journal slice with normal deduplication."""

    catalog = {
        source_unit: UnitIdentity(source_unit, scope, timer_unit, service_unit)
        for source_unit, (service_unit, timer_unit) in mappings.items()
    }
    with Database(database, hostname=hostname) as db:
        result = _persist_scope(
            db, entries, hostname=hostname, scope=scope, catalog=catalog, checkpoint=None,
            mode="fixture", recovery_state="fixture", warning=None, started_at=_utc_now(),
            fallback_since=DEFAULT_FALLBACK_SINCE,
        )
    return {"seen": int(result["entries_seen"]), "inserted": int(result["entries_inserted"])}


def _import_history_db(
    db: Database,
    *,
    collector: Path = DEFAULT_COLLECTOR,
    journalctl: str = "journalctl",
    fallback_since: str = DEFAULT_FALLBACK_SINCE,
    initial_since: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Import system and user journal scopes, recovering invalid cursors safely."""

    hostname = db.hostname or socket.gethostname()
    identities = discover_units(collector, environment=environment)
    results: list[dict[str, Any]] = []
    for scope in ("system", "user"):
        scoped = {identity.unit: identity for identity in identities if identity.scope == scope}
        if not scoped:
            continue
        rows = db.query(
            "SELECT * FROM systemd_journal_checkpoints WHERE hostname=? AND journal_scope=?",
            (hostname, scope),
        )
        checkpoint = rows[0] if rows else None
        cursor = checkpoint and checkpoint.get("journal_cursor")
        started_at = _utc_now()
        bounded_since = fallback_since if cursor else (initial_since or fallback_since)
        entries, error = _read_journal(
            journalctl, scope, sorted(scoped), cursor=cursor, fallback_since=bounded_since
        )
        mode = "cursor" if cursor else "fallback"
        warning: str | None = None if cursor else f"first run used bounded fallback {bounded_since}; data older than that bound was not read"
        recovery_state = "incremental" if cursor else "first_run"
        if error and cursor:
            warning = f"stored cursor unavailable (journal rotation or stale cursor): {error}; used bounded fallback {fallback_since}"
            entries, fallback_error = _read_journal(
                journalctl, scope, sorted(scoped), cursor=None, fallback_since=fallback_since
            )
            mode = "fallback"
            recovery_state = "journal_rotation"
            error = fallback_error
        if error:
            warning = f"{warning}; {error}" if warning else error
            finished_at = _utc_now()
            with db._transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO systemd_journal_checkpoints(
                        hostname,journal_scope,journal_cursor,boot_id,realtime_usec,updated_at_utc,
                        recovery_state,recovery_warning,fallback_since_utc,last_entries_seen,last_entries_inserted
                    ) VALUES (?,?,?,?,?,?,'error',?,?,0,0)
                    ON CONFLICT(hostname,journal_scope) DO UPDATE SET
                        updated_at_utc=excluded.updated_at_utc,recovery_state='error',
                        recovery_warning=excluded.recovery_warning,fallback_since_utc=excluded.fallback_since_utc,
                        last_entries_seen=0,last_entries_inserted=0
                    """,
                    (
                        hostname, scope, cursor, checkpoint and checkpoint.get("boot_id"),
                        checkpoint and checkpoint.get("realtime_usec"), finished_at, warning,
                        fallback_since if mode == "fallback" else None,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO systemd_journal_imports(
                        started_at_utc,finished_at_utc,hostname,journal_scope,mode,outcome,recovery_state,
                        recovery_warning,entries_seen,entries_inserted,runs_touched,cursor_before,boot_id_before
                    ) VALUES (?,?,?,?,?,'error','error',?,0,0,0,?,?)
                    """,
                    (started_at, finished_at, hostname, scope, mode, warning, cursor, checkpoint and checkpoint.get("boot_id")),
                )
            results.append({"scope": scope, "mode": mode, "recovery_state": "error", "warning": warning, "entries_seen": 0, "entries_inserted": 0, "runs_touched": 0})
            continue
        raw_boots = [_scalar(item.get("_BOOT_ID")) for item in entries]
        raw_boots = [item for item in raw_boots if item]
        if cursor and raw_boots and checkpoint and checkpoint.get("boot_id") != raw_boots[-1]:
            recovery_state = "reboot"
        results.append(
            _persist_scope(
                db, entries, hostname=hostname, scope=scope, catalog=scoped, checkpoint=checkpoint,
                mode=mode, recovery_state=recovery_state, warning=warning, started_at=started_at,
                fallback_since=fallback_since,
            )
        )
    return {
        "ok": bool(results) and all(item["recovery_state"] != "error" for item in results),
        "hostname": hostname,
        "database": str(db.path),
        "scopes": results,
        "entries_inserted": sum(int(item["entries_inserted"]) for item in results),
    }


def import_history(
    database: Database | str | Path,
    *,
    journalctl: str = "journalctl",
    collector: Path = DEFAULT_COLLECTOR,
    registry: Path = DEFAULT_REGISTRY,
    system_unit_dir: Path | None = None,
    user_unit_dir: Path | None = None,
    hostname: str | None = None,
    initial_lookback_hours: int = 24,
    fallback_lookback_hours: int = 168,
    initial_since: str | None = None,
    fallback_since: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """One-shot import using the monitor database and bounded recovery windows."""

    owned = not isinstance(database, Database)
    db = database if isinstance(database, Database) else Database(database, hostname=hostname)
    env = dict(os.environ if environment is None else environment)
    env["MEGAVAULT_REGISTRY_PATH"] = str(registry)
    if system_unit_dir is not None:
        env["SYSTEM_UNIT_DIR"] = str(system_unit_dir)
    if user_unit_dir is not None:
        env["USER_UNIT_DIR"] = str(user_unit_dir)
    try:
        payload = _import_history_db(
            db,
            collector=collector,
            journalctl=journalctl,
            fallback_since=fallback_since or f"{fallback_lookback_hours} hours ago",
            initial_since=initial_since or f"{initial_lookback_hours} hours ago",
            environment=env,
        )
    finally:
        if owned:
            db.close()
    scopes: dict[str, dict[str, Any]] = {}
    for result in payload["scopes"]:
        item = dict(result)
        item["state"] = item["recovery_state"]
        scopes[str(item["scope"])] = item
    payload["scopes"] = scopes
    payload["passed"] = payload["ok"]
    return payload


def history_status(path: Path, *, limit: int = 20) -> dict[str, Any]:
    """Read back checkpoints and recent Datasette-facing execution rows."""

    if not path.exists():
        return {"ok": False, "database": str(path), "error": "database does not exist"}
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        try:
            checkpoints = [dict(row) for row in connection.execute(
                "SELECT * FROM systemd_journal_checkpoints ORDER BY hostname,journal_scope"
            )]
            executions = [dict(row) for row in connection.execute(
                "SELECT * FROM systemd_executions_summary ORDER BY started DESC LIMIT ?", (limit,)
            )]
            counts = {
                "executions": int(connection.execute("SELECT COUNT(*) FROM systemd_executions").fetchone()[0]),
                "entries": int(connection.execute("SELECT COUNT(*) FROM systemd_execution_entries").fetchone()[0]),
                "imports": int(connection.execute("SELECT COUNT(*) FROM systemd_journal_imports").fetchone()[0]),
            }
        except sqlite3.Error as exc:
            return {"ok": False, "database": str(path), "error": redact_text(exc)}
    finally:
        connection.close()
    return {"ok": True, "database": str(path), "counts": counts, "checkpoints": checkpoints, "executions": executions}


__all__ = [
    "add_cli_subcommand",
    "DEFAULT_COLLECTOR",
    "DEFAULT_FALLBACK_SINCE",
    "DEFAULT_REGISTRY",
    "UnitIdentity",
    "discover_units",
    "history_status",
    "ingest_entries",
    "import_history",
]
