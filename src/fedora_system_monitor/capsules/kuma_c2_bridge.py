"""Capture Uptime Kuma DOWN transitions in C2's canonical issue inbox."""

from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Any, Callable, Iterable, Mapping


SSH_HELPER = Path("/home/daniele/projects/vm_oracle/scripts/oracle_ssh.sh")
CAPTURE_SCRIPT = Path("/home/daniele/projects/codex-roadmap/tools/c2_issue_capture.py")
C3_DB = Path.home() / '.local/state/c3-control/roadmap.sqlite'
REMOTE_QUERY = (
    "sudo -n sqlite3 -readonly -json /opt/uptime-kuma/data/kuma.db "
    "\"SELECT 'event' AS row_kind,h.id AS heartbeat_id,h.monitor_id,m.name AS monitor_name,"
    "m.active,h.status,h.msg,h.time FROM heartbeat h JOIN monitor m ON m.id=h.monitor_id "
    "WHERE h.id>{cursor} UNION ALL SELECT 'watermark',COALESCE(MAX(id),0),NULL,NULL,NULL,NULL,NULL,NULL "
    "FROM heartbeat ORDER BY heartbeat_id;\""
)
REMOTE_BASELINE_QUERY = (
    "sudo -n sqlite3 -readonly -json /opt/uptime-kuma/data/kuma.db "
    "\"WITH latest AS (SELECT monitor_id,MAX(id) AS heartbeat_id FROM heartbeat GROUP BY monitor_id) "
    "SELECT 'event' AS row_kind,h.id AS heartbeat_id,h.monitor_id,m.name AS monitor_name,m.active,"
    "h.status,h.msg,h.time FROM monitor m JOIN latest l ON l.monitor_id=m.id "
    "JOIN heartbeat h ON h.id=l.heartbeat_id UNION ALL "
    "SELECT 'watermark',COALESCE(MAX(id),0),NULL,NULL,NULL,NULL,NULL,NULL FROM heartbeat "
    "ORDER BY heartbeat_id;\""
)


def default_state_path() -> Path:
    configured = os.environ.get("KUMA_C2_BRIDGE_STATE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local/state/fedora-system-monitor-kuma-c2-bridge/state.sqlite3"


def issue_id_for(monitor_id: int, heartbeat_id: int) -> str:
    seed = f"uptime-kuma:{monitor_id}:{heartbeat_id}".encode("ascii")
    return "issue:" + hashlib.sha256(seed).hexdigest()[:32]


def _ensure_state(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    connection = sqlite3.connect(path, timeout=10)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS bridge_state ("
        "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS monitor_state ("
        "monitor_id INTEGER PRIMARY KEY, monitor_name TEXT NOT NULL, "
        "is_down INTEGER NOT NULL, issue_id TEXT, heartbeat_id INTEGER NOT NULL)"
    )
    connection.commit()
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return connection


def _read_cursor(connection: sqlite3.Connection) -> int | None:
    row = connection.execute("SELECT value FROM bridge_state WHERE key='heartbeat_cursor'").fetchone()
    return int(row[0]) if row else None


def _fetch_json(command: str, helper: Path = SSH_HELPER) -> Any:
    result = subprocess.run(
        [str(helper), command], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=25, check=False,
    )
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "remote query failed"
        raise RuntimeError(f"Kuma read failed: {detail}")
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Kuma returned invalid heartbeat JSON") from exc


def fetch_events(cursor: int | None, helper: Path = SSH_HELPER) -> tuple[list[dict[str, Any]], int]:
    if cursor is None:
        rows = _fetch_json(REMOTE_BASELINE_QUERY, helper)
        if not isinstance(rows, list):
            raise RuntimeError("Kuma baseline response is not a list")
    else:
        rows = _fetch_json(REMOTE_QUERY.format(cursor=int(cursor)), helper)
        if not isinstance(rows, list):
            raise RuntimeError("Kuma event response is not a list")
    watermark_rows = [row for row in rows if isinstance(row, Mapping) and row.get("row_kind") == "watermark"]
    if len(watermark_rows) != 1:
        raise RuntimeError("Kuma heartbeat watermark is missing or ambiguous")
    try:
        watermark = int(watermark_rows[0]["heartbeat_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Kuma heartbeat watermark is invalid") from exc
    event_rows = [row for row in rows if isinstance(row, Mapping) and row.get("row_kind") == "event"]
    normalized: list[dict[str, Any]] = []
    for row in event_rows:
        if not isinstance(row, Mapping):
            raise RuntimeError("Kuma heartbeat row is invalid")
        try:
            normalized.append({
                "heartbeat_id": int(row["heartbeat_id"]),
                "monitor_id": int(row["monitor_id"]),
                "monitor_name": str(row["monitor_name"]),
                "active": bool(int(row["active"])),
                "status": int(row["status"]),
                "msg": str(row.get("msg") or ""),
                "time": str(row.get("time") or ""),
            })
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Kuma heartbeat row is incomplete") from exc
    normalized.sort(key=lambda item: item["heartbeat_id"])
    return normalized, watermark


def _context(event: Mapping[str, Any]) -> str:
    message = str(event.get("msg") or "(no failure message supplied)").strip()
    return (
        "Uptime Kuma monitor transitioned to DOWN.\n"
        f"Monitor: {event['monitor_name']} (id {event['monitor_id']})\n"
        f"Heartbeat: {event['time']} (row {event['heartbeat_id']})\n"
        f"Failure context: {message[:2000]}"
    )


def capture(event: Mapping[str, Any], issue_id: str, script: Path = CAPTURE_SCRIPT) -> None:
    result = subprocess.run(
        [sys.executable, str(script), "--stdin", "--issue-id", issue_id],
        input=_context(event), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=45, check=False,
    )
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "C2 capture failed"
        raise RuntimeError(f"C2 Inbox capture failed: {detail}")
    try:
        receipt = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("C2 Inbox capture returned invalid receipt JSON") from exc
    if receipt.get("issue_id") != issue_id:
        raise RuntimeError("C2 Inbox capture returned a different issue identity")


def _load_states(connection: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    rows = connection.execute(
        "SELECT monitor_id,monitor_name,is_down,issue_id,heartbeat_id FROM monitor_state"
    )
    return {
        int(row[0]): {
            "monitor_name": str(row[1]), "is_down": bool(row[2]),
            "issue_id": row[3], "heartbeat_id": int(row[4]),
        }
        for row in rows
    }


def incident_open(issue_id: str) -> bool:
    """Keep one actionable observation per monitor until C3 resolves it.

    Unknown/unavailable lifecycle is not permission to create duplicates.
    This read-only lookup never triages, starts or finishes work.
    """
    try:
        with closing(sqlite3.connect(C3_DB.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            row = db.execute('SELECT status,work_item_id FROM issue_inbox WHERE issue_id=?', (issue_id,)).fetchone()
            if not row:
                return True
            if row[0] == 'pending':
                return True
            if row[0] == 'promoted' and row[1]:
                item = db.execute('SELECT status FROM work_items WHERE work_item_id=?', (row[1],)).fetchone()
                return not item or item[0] not in ('completed','cancelled','superseded')
            return False
    except (OSError, sqlite3.Error):
        return True


def _apply_event(
    event: Mapping[str, Any], states: dict[int, dict[str, Any]],
    capture_fn: Callable[[Mapping[str, Any], str], None],
    incident_open_fn: Callable[[str], bool] = incident_open,
) -> str | None:
    monitor_id = int(event["monitor_id"])
    state = states.get(monitor_id, {
        "monitor_name": str(event["monitor_name"]), "is_down": False,
        "issue_id": None, "heartbeat_id": 0,
    })
    status = int(event["status"])
    if status == 0 and bool(event["active"]) and not state["is_down"]:
        retained = state.get('issue_id')
        issue_id = retained if retained and incident_open_fn(retained) else issue_id_for(monitor_id, int(event["heartbeat_id"]))
        if issue_id != retained:
            capture_fn(event, issue_id)
        state["is_down"] = True
        state["issue_id"] = issue_id
        outcome = "deduplicated" if issue_id == retained else "captured"
    elif status == 1:
        was_down = state["is_down"]
        state["is_down"] = False
        # Recovery is observed, but does not resolve the C3 observation/work.
        # Retain its identity across flaps until the owning lifecycle is closed.
        outcome = "recovered" if was_down else None
    else:
        outcome = None
    state["monitor_name"] = str(event["monitor_name"])
    state["heartbeat_id"] = int(event["heartbeat_id"])
    states[monitor_id] = state
    return outcome


def run_once(
    state_path: Path | None = None,
    *, helper: Path = SSH_HELPER,
    capture_script: Path = CAPTURE_SCRIPT,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    path = state_path or default_state_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        connection = _ensure_state(path)
        try:
            cursor = _read_cursor(connection)
            events, watermark = fetch_events(cursor, helper)
            if cursor is not None and watermark < cursor:
                events, watermark = fetch_events(None, helper)
                cursor = None
            states = _load_states(connection)
            actions: list[dict[str, Any]] = []

            def capture_event(event: Mapping[str, Any], issue_id: str) -> None:
                if not dry_run:
                    capture(event, issue_id, capture_script)
                actions.append({
                    "action": "would_capture" if dry_run else "captured",
                    "monitor_id": int(event["monitor_id"]),
                    "monitor_name": str(event["monitor_name"]),
                    "heartbeat_id": int(event["heartbeat_id"]),
                    "issue_id": issue_id,
                })

            for event in events:
                outcome = _apply_event(
                    event, states, capture_event,
                )
                if outcome == "recovered":
                    actions.append({
                        "action": "recovered",
                        "monitor_id": int(event["monitor_id"]),
                        "monitor_name": str(event["monitor_name"]),
                        "heartbeat_id": int(event["heartbeat_id"]),
                    })

            if dry_run:
                return actions
            with connection:
                connection.execute("DELETE FROM monitor_state")
                connection.executemany(
                    "INSERT INTO monitor_state(monitor_id,monitor_name,is_down,issue_id,heartbeat_id) "
                    "VALUES(?,?,?,?,?)",
                    [
                        (monitor_id, state["monitor_name"], int(state["is_down"]),
                         state["issue_id"], state["heartbeat_id"])
                        for monitor_id, state in states.items()
                    ],
                )
                connection.execute(
                    "INSERT INTO bridge_state(key,value) VALUES('heartbeat_cursor',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(watermark),),
                )
            return actions
        finally:
            connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    actions = run_once(args.state, dry_run=args.dry_run)
    print(json.dumps({"actions": actions}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
