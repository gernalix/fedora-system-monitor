"""Record Uptime Kuma DOWN/UP transitions in MegaVault incidents, never Pn."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from typing import Callable

SSH_HELPER = Path("/home/daniele/projects/vm_oracle/scripts/oracle_ssh.sh")
MEGAVAULT = Path("/home/daniele/MegaVault/megavault.py")
REGISTRY = Path("/home/daniele/MegaVault/megavault.sqlite")
STATE = Path.home() / ".local/state/fedora-system-monitor/kuma-pn-checkpoint.sqlite3"
BATCH_SIZE = 500
RECOVERY_GRACE_SECONDS = 600

# Deliberately never transfer h.msg: arbitrary monitor output could contain secrets.
_BASE_QUERY = (
    "WITH latest AS (SELECT monitor_id,MAX(id) AS heartbeat_id "
    "FROM heartbeat GROUP BY monitor_id) "
    "SELECT 'event' AS kind,h.id AS heartbeat_id,h.monitor_id,m.name AS monitor_name,"
    "m.active,h.status,h.time FROM latest l JOIN heartbeat h ON h.id=l.heartbeat_id "
    "JOIN monitor m ON m.id=l.monitor_id "
    "UNION ALL SELECT 'watermark',COALESCE(MAX(id),0),NULL,NULL,NULL,NULL,NULL "
    "FROM heartbeat ORDER BY heartbeat_id"
)
_DELTA_QUERY = (
    "WITH batch AS (SELECT id,monitor_id,status,time FROM heartbeat "
    "WHERE id>{cursor} ORDER BY id LIMIT {limit}) "
    "SELECT 'event' AS kind,b.id AS heartbeat_id,b.monitor_id,m.name AS monitor_name,"
    "m.active,b.status,b.time FROM batch b JOIN monitor m ON m.id=b.monitor_id "
    "UNION ALL SELECT 'watermark',COALESCE(MAX(id),0),NULL,NULL,NULL,NULL,NULL "
    "FROM heartbeat ORDER BY heartbeat_id"
)


def _readonly_db(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)


def fetch_events(cursor: int | None, helper: Path = SSH_HELPER) -> tuple[list[dict], int]:
    sql = _BASE_QUERY if cursor is None else _DELTA_QUERY.format(
        cursor=int(cursor), limit=BATCH_SIZE
    )
    command = 'sudo -n sqlite3 -readonly -json /opt/uptime-kuma/data/kuma.db ' + (
        '"' + sql.replace('"', '\\"') + '"'
    )
    try:
        result = subprocess.run(
            [str(helper), command], capture_output=True, text=True, timeout=35, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Kuma read-only SSH query unavailable") from exc
    if result.returncode:
        # Do not relay remote stderr: it can contain arbitrary diagnostic content.
        raise RuntimeError(f"Kuma SSH query failed (exit={result.returncode})")
    try:
        rows = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Kuma returned invalid JSON") from exc
    if not isinstance(rows, list):
        raise RuntimeError("Kuma response is not an array")
    marks = [r for r in rows if isinstance(r, dict) and r.get("kind") == "watermark"]
    if len(marks) != 1:
        raise RuntimeError("Kuma watermark missing or ambiguous")
    watermark = int(marks[0]["heartbeat_id"])
    events = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("Kuma returned malformed heartbeat")
        if row.get("kind") != "event":
            continue
        try:
            event = dict(
                heartbeat_id=int(row["heartbeat_id"]),
                monitor_id=int(row["monitor_id"]),
                monitor_name=str(row["monitor_name"]),
                active=bool(int(row["active"])),
                status=int(row["status"]),
                time=str(row["time"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Kuma heartbeat missing required fields") from exc
        events.append(event)
    events.sort(key=lambda e: e["heartbeat_id"])
    return events, watermark


INVENTORY_REFRESH_SECONDS = 24 * 3600
INVENTORY_RETRY_SECONDS = 3600
INVENTORY_ATTEMPT_KEY = "kuma_inventory_attempt_utc"


def _utc_timestamp(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return value.astimezone(timezone.utc) if value.tzinfo else None
    except ValueError:
        return None


def fetch_monitor_inventory(helper: Path = SSH_HELPER) -> list[dict]:
    """Retrieve only bounded monitor metadata; never persist raw URLs or tokens."""
    sql = "SELECT id,name,type,active,hostname,port,url FROM monitor ORDER BY id"
    command = 'sudo -n sqlite3 -readonly -json /opt/uptime-kuma/data/kuma.db "' + sql + '"'
    try:
        result = subprocess.run([str(helper), command], text=True, capture_output=True,
                                timeout=35, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Kuma inventory source unavailable") from exc
    if result.returncode or len(result.stdout) > 200_000:
        raise RuntimeError("Kuma inventory source unavailable or oversized")
    try:
        source = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Kuma inventory payload invalid") from exc
    if not isinstance(source, list) or not 1 <= len(source) <= 500:
        raise RuntimeError("Kuma inventory count invalid")
    clean, seen = [], set()
    for row in source:
        if not isinstance(row, dict) or not {"id", "name"} <= row.keys():
            raise RuntimeError("Kuma monitor record invalid")
        monitor_id = int(row["id"])
        name = str(row["name"])
        if monitor_id <= 0 or monitor_id in seen or not 1 <= len(name) <= 256:
            raise RuntimeError("Kuma monitor identity invalid")
        seen.add(monitor_id)
        item = {"id": monitor_id, "name": name}
        for key in ("type", "active"):
            if row.get(key) is not None:
                item[key] = row[key]
        hostname = row.get("hostname")
        if hostname and len(str(hostname)) <= 255:
            item["hostname"] = str(hostname)
            if row.get("port") is not None and 1 <= int(row["port"]) <= 65535:
                item["port"] = int(row["port"])
        if row.get("url"):
            url = urlsplit(str(row["url"]))
            if url.scheme.lower() in ("http", "https") and url.hostname:
                host = url.hostname
                host = "[" + host + "]" if ":" in host and not host.startswith("[") else host
                item["url"] = url.scheme.lower() + "://" + host
                if url.port is not None:
                    item["url"] += ":" + str(url.port)
        clean.append(item)
    return clean


def apply_monitor_inventory(rows: list[dict], executable: Path = MEGAVAULT,
                            registry: Path = REGISTRY) -> None:
    """Use existing MegaVault writer; never create another service or inventory."""
    lock_path = Path.home() / ".local/state/megavault/canonical-update.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kuma-inventory-") as tmp:
        payload = Path(tmp) / "monitors.json"
        payload.write_text(json.dumps({"monitors": rows}, ensure_ascii=False))
        payload.chmod(0o600)
        with lock_path.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            def owner(*args: str) -> None:
                run = subprocess.run([sys.executable, str(executable), *args],
                                     text=True, capture_output=True, timeout=60,
                                     env=env, check=False)
                if run.returncode:
                    raise RuntimeError("MegaVault inventory reconciliation failed")
            owner("kuma-sync-json", "--source-json", str(payload))
            with closing(_readonly_db(registry)) as db:
                status = db.execute("SELECT status FROM operational_inventory_meta "
                                    "WHERE inventory_key='kuma_monitors'").fetchone()
                count = db.execute("SELECT count(*) FROM kuma_monitors "
                                   "WHERE seen_in_last_sync=1").fetchone()[0]
            if not status or count != len(rows):
                raise RuntimeError("Kuma inventory readback mismatch")
            if status[0] == "READY_TO_FINALIZE":
                owner("kuma-finalize")


def refresh_inventory_if_due(state: Path = STATE, registry: Path = REGISTRY,
                             fetch: Callable[[], list[dict]] = fetch_monitor_inventory,
                             apply: Callable[[list[dict]], None] = apply_monitor_inventory,
                             now: datetime | None = None) -> bool:
    """Daily refresh on the existing incident timer; failed attempts retry hourly."""
    current = now or datetime.now(timezone.utc)
    with closing(_readonly_db(registry)) as db:
        row = db.execute("SELECT last_synced_at FROM operational_inventory_meta "
                         "WHERE inventory_key='kuma_monitors'").fetchone()
    synced = _utc_timestamp(row[0]) if row else None
    if synced and 0 <= (current - synced).total_seconds() < INVENTORY_REFRESH_SECONDS:
        return False
    with closing(sqlite3.connect(state, timeout=10)) as db:
        row = db.execute("SELECT value FROM cursor_state WHERE key=?",
                         (INVENTORY_ATTEMPT_KEY,)).fetchone()
        attempted = _utc_timestamp(row[0]) if row else None
        if attempted and 0 <= (current - attempted).total_seconds() < INVENTORY_RETRY_SECONDS:
            return False
        with db:
            db.execute("INSERT INTO cursor_state(key,value) VALUES(?,?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (INVENTORY_ATTEMPT_KEY, current.isoformat()))
    apply(fetch())
    return True


def _schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS cursor_state (
          key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS monitor_checkpoint (
          monitor_id INTEGER PRIMARY KEY,
          monitor_name TEXT NOT NULL,
          last_heartbeat_id INTEGER NOT NULL,
          is_down INTEGER NOT NULL,
          pn_id TEXT,
          incident_id INTEGER,
          down_heartbeat_id INTEGER,
          recovered_at TEXT
        );
        """
    )

    if 'incident_id' not in {row[1] for row in db.execute('pragma table_info(monitor_checkpoint)')}:
        db.execute('alter table monitor_checkpoint add column incident_id integer')


def _cursor(db: sqlite3.Connection) -> int | None:
    row = db.execute("SELECT value FROM cursor_state WHERE key='heartbeat'").fetchone()
    return int(row[0]) if row else None


def _save_cursor(db: sqlite3.Connection, value: int) -> None:
    db.execute(
        "INSERT INTO cursor_state(key,value) VALUES('heartbeat',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(value),),
    )


def project_for_monitor(monitor_id: int, registry: Path = REGISTRY) -> int:
    """Use canonical Kuma -> project mapping; ambiguity belongs to FSM itself."""
    with closing(_readonly_db(registry)) as db:
        rows = db.execute(
            "SELECT DISTINCT m.project_id FROM monitoring_targets m "
            "JOIN projects p ON p.project_id=m.project_id "
            "WHERE m.kuma_monitor_key=? AND COALESCE(p.archived,0)=0",
            (f"INT0002:{monitor_id}",),
        ).fetchall()
        if len(rows) == 1:
            return int(rows[0][0])
        owner = db.execute(
            "SELECT project_id FROM projects "
            "WHERE slug='fedora-system-monitor' AND COALESCE(archived,0)=0"
        ).fetchone()
    if owner is None:
        raise RuntimeError("Canonical Fedora System Monitor project not found")
    return int(owner[0])


def record_transition(event: dict, project_id: int, incident_id=None, executable: Path = MEGAVAULT) -> int:
    # Transfer only bounded metadata; heartbeat messages may contain credentials.
    safe = {key: event[key] for key in ('monitor_id','heartbeat_id','status','active','time','monitor_name')}
    argv = [sys.executable, str(executable), 'kuma-event', '--project-id', str(project_id)]
    if incident_id is not None:
        argv += ['--incident-id', str(incident_id)]
    result = subprocess.run(argv, input=json.dumps(safe), capture_output=True,
                            text=True, check=False, timeout=80)
    if result.returncode:
        raise RuntimeError('Canonical incident writer rejected transition')
    try:
        receipt = json.loads(result.stdout)
        if receipt.get('status') != 'RECORDED' or type(receipt.get('incident_id')) is not int:
            raise ValueError('invalid receipt')
        return receipt['incident_id']
    except (ValueError, TypeError) as exc:
        raise RuntimeError('Canonical incident receipt failed verification') from exc


def register_incident(event: dict, project_id: int) -> int:
    return record_transition(event, project_id)


def _elapsed_since_recovery(event_time: str, recovered_at: str) -> float:
    try:
        return (datetime.fromisoformat(event_time) -
                datetime.fromisoformat(recovered_at)).total_seconds()
    except ValueError as exc:
        raise RuntimeError("Kuma recovery timestamps are not comparable") from exc


def handle_event(
    db: sqlite3.Connection, event: dict,
    create: Callable[[dict, int], str] = register_incident,
    resolve_project: Callable[[int], int] = project_for_monitor,
    update: Callable = record_transition,
) -> dict | None:
    monitor_id = event["monitor_id"]
    row = db.execute(
        "SELECT last_heartbeat_id,is_down,incident_id,down_heartbeat_id,recovered_at "
        "FROM monitor_checkpoint WHERE monitor_id=?", (monitor_id,)
    ).fetchone()
    if row and event["heartbeat_id"] <= row[0]:
        return None
    is_down, incident_id, down_hb, recovered_at = (
        (bool(row[1]), row[2], row[3], row[4]) if row else (False, None, None, None)
    )
    action = None
    if event["active"] and event["status"] == 0:
        new_incident = incident_id is None or (
            not is_down and recovered_at is not None
            and _elapsed_since_recovery(event["time"], recovered_at) >= RECOVERY_GRACE_SECONDS
        )
        if new_incident:
            incident_id = create(event, resolve_project(monitor_id))
            down_hb = event["heartbeat_id"]
            action = "incident_created"
        elif not is_down:
            update(event, resolve_project(monitor_id), incident_id)
            action = "down_deduplicated"
        is_down, recovered_at = True, None
    elif event["status"] == 1 and event["active"]:
        if is_down and incident_id is not None:
            update(event, resolve_project(monitor_id), incident_id)
            action = "recovered"
            recovered_at = event["time"]
        is_down = False
    # PENDING and disabled monitors neither create a Pn nor close an outage.
    db.execute(
        "INSERT INTO monitor_checkpoint("
        "monitor_id,monitor_name,last_heartbeat_id,is_down,incident_id,down_heartbeat_id,recovered_at"
        ") VALUES(?,?,?,?,?,?,?) ON CONFLICT(monitor_id) DO UPDATE SET "
        "monitor_name=excluded.monitor_name,last_heartbeat_id=excluded.last_heartbeat_id,"
        "is_down=excluded.is_down,incident_id=excluded.incident_id,"
        "down_heartbeat_id=excluded.down_heartbeat_id,recovered_at=excluded.recovered_at",
        (monitor_id, event["monitor_name"], event["heartbeat_id"],
         int(is_down), incident_id, down_hb, recovered_at),
    )
    if action:
        return {"action": action, "monitor_id": monitor_id, "heartbeat_id":
                event["heartbeat_id"], "incident_id": incident_id}
    return None


def run_once(
    state: Path = STATE,
    *,
    fetch: Callable[[int | None], tuple[list[dict], int]] = fetch_events,
    create: Callable[[dict, int], str] = register_incident,
    resolve_project: Callable[[int], int] = project_for_monitor,
    update: Callable = record_transition,
    dry_run: bool = False,
) -> list[dict]:
    state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not dry_run:
        state.parent.chmod(0o700)
    lock_path = state.with_suffix(".lock")
    with lock_path.open("a") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if dry_run:
            db = sqlite3.connect(":memory:")
            if state.exists():
                with closing(_readonly_db(state)) as source:
                    source.backup(db)
        else:
            db = sqlite3.connect(state, timeout=10)
            state.chmod(0o600)
        try:
            _schema(db)
            cursor = _cursor(db)
            events, watermark = fetch(cursor)
            if cursor is not None and watermark < cursor:
                raise RuntimeError("Kuma heartbeat IDs decreased; manual reconciliation required")
            actions = []
            for event in events:
                if dry_run:
                    def preview(row: dict, project_id: int) -> str:
                        return f"would_create_for_project_{project_id}"
                    created = preview
                else:
                    created = create
                with db:
                    action = handle_event(db, event, created, resolve_project,
                                          (lambda *a: None) if dry_run else update)
                    if cursor is not None:
                        _save_cursor(db, event["heartbeat_id"])
                if action:
                    if dry_run and action["action"] == "incident_created":
                        action["action"] = "would_create"
                    actions.append(action)
            # Baseline skips ancient history; incremental advances only to
            # the last processed row until the bounded batch catches up.
            if cursor is None or not events or events[-1]["heartbeat_id"] >= watermark:
                next_cursor = watermark
            else:
                next_cursor = events[-1]["heartbeat_id"]
            with db:
                _save_cursor(db, next_cursor)
            return actions
        finally:
            db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=STATE)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    actions = run_once(args.state, dry_run=args.dry_run)
    if not args.dry_run:
        try:
            if refresh_inventory_if_due(args.state):
                print("KUMA_INVENTORY_SYNC=PASS", file=sys.stderr)
        except Exception:
            # A failed inventory refresh must not interrupt incident processing.
            print("KUMA_INVENTORY_SYNC=RETRY_LATER", file=sys.stderr)
    print(json.dumps({"actions": actions}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
