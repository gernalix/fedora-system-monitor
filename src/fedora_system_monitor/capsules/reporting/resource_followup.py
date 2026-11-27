"""Operator-side durable verification receipts and resumable scanner transitions."""
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import uuid

from . import _connection
from . import resource_triage as triage


@contextmanager
def ledger():
    folder = triage.receipt_path("", "").parent
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = folder / "interventions.sqlite3"
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    with closing(sqlite3.connect(path, timeout=5)) as db, db:
        db.row_factory = sqlite3.Row
        db.execute("""CREATE TABLE IF NOT EXISTS checks (
            token TEXT PRIMARY KEY, source TEXT, case_id INTEGER, opened TEXT, label TEXT,
            requested TEXT, result TEXT, UNIQUE(source,case_id,opened,label))""")
        db.execute("""CREATE TABLE IF NOT EXISTS finished (
            id INTEGER PRIMARY KEY, token TEXT NOT NULL UNIQUE)""")
        db.execute("""CREATE TABLE IF NOT EXISTS pending (
            token TEXT PRIMARY KEY, deadline REAL NOT NULL, baseline TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS pending_deadline ON pending(deadline)")
        stale = db.execute("SELECT token,baseline FROM pending WHERE deadline<?", (time.time(),)).fetchall()
        for row in stale:
            result = dict(status="VERIFICA_INTERROTTA", functional_status="NON_MISURATO",
                          before=json.loads(row["baseline"]), ended=triage.iso(time.time()), exit_code=2)
            record_result(db, row["token"], result)
        db.commit()
        yield db


def source(args):
    return str(Path(args.db).resolve())


def latest(args, item, token=None):
    with ledger() as db:
        row = db.execute("""SELECT * FROM checks WHERE source=? AND case_id=? AND opened=?
            AND (? IS NULL OR token=?) ORDER BY rowid DESC LIMIT 1""",
            (source(args), item["id"], item["opened"], token, token)).fetchone()
    return summary(row) if row else None


def summary(row):
    result = json.loads(row["result"]) if row["result"] else {"status": "IN_ATTESA"}
    return dict(intervention=row["label"], token=row["token"], **result)


def record_result(db, token, result):
    updated = db.execute("UPDATE checks SET result=? WHERE token=? AND result IS NULL", (json.dumps(result), token))
    if updated.rowcount:
        db.execute("INSERT INTO finished(token) VALUES(?)", (token,))
        db.execute("DELETE FROM pending WHERE token=?", (token,))


def verify(args, item, check):
    token = args.worker or uuid.uuid4().hex
    label = args.intervention or token
    key = (source(args), item["id"], item["opened"])
    before = dict(opened=item["opened"], last_seen=item["seen"], value=item["value"], threshold=item["threshold"])
    with ledger() as db:
        if args.worker:
            row = db.execute("SELECT * FROM checks WHERE token=? AND source=? AND case_id=? AND opened=?",
                             (token, *key)).fetchone()
            if not row or row["result"]:
                raise ValueError("Intervento assente o già concluso")
            label = row["label"]
            pending = db.execute("SELECT baseline FROM pending WHERE token=?", (token,)).fetchone()
            if pending:
                before = json.loads(pending[0])
        else:
            cursor = db.execute("INSERT OR IGNORE INTO checks VALUES(?,?,?,?,?,?,NULL)",
                                (token, *key, label, triage.iso(time.time())))
            if not cursor.rowcount:
                row = db.execute("SELECT * FROM checks WHERE source=? AND case_id=? AND opened=? AND label=?",
                                 (*key, label)).fetchone()
                result = summary(row)
                return result, result.get("exit_code", 0)
            db.execute("INSERT INTO pending VALUES(?,?,?)",
                       (token, time.time()+args.timeout+90, json.dumps(before)))
    try:
        if args.background:
            script = Path(__file__).resolve().parents[4] / "scripts/fsm-resources"
            subprocess.run(["systemd-run", "--user", "--quiet", "--collect",
                            "--unit", f"fsm-case-{token}", "--property", "Nice=10",
                            "--setenv=XDG_STATE_HOME=" + str(triage.receipt_path("", "").parents[2]),
                            str(script), "case", "--id", str(item["id"]), "--verify", "--worker", token,
                            "--db", key[0], "--config", str(Path(args.config).resolve()),
                            "--minutes", str(args.minutes), "--timeout", str(args.timeout),
                            *(["--expect-change"] if args.expect_change else []),
                            *(["--probe", *args.probe] if args.probe else [])], check=True)
            return dict(status="IN_ATTESA", case_id=item["id"], token=token, intervention=label), 0
        result, code = check()
    except Exception as exc:
        result, code = dict(status="VERIFICA_INTERROTTA", error_type=type(exc).__name__), 2
    result.update(case_id=item["id"], unit=item["unit"], metric=item["metric"],
                  before=before, ended=triage.iso(time.time()), exit_code=code)
    result["functional_status"] = ("NON_MISURATO" if result.get("probe") is None else
                                   "SUPERATO" if result["probe"]["passed"] else "FALLITO")
    if args.expect_change and result["functional_status"] == "SUPERATO" and not result["probe"].get("changed"):
        result["functional_status"] = "CICLO_NON_CONFERMATO"
    with ledger() as db:
        record_result(db, token, result)
    result["latest_series_receipt"] = triage.save_receipt(result)
    return dict(intervention=label, token=token, **result), code


def changes(args):
    """Independent append-only event/receipt cursors avoid timestamp ties and late checks."""
    with _connection(args.db) as db, ledger() as local:
        db.execute("BEGIN")
        local.execute("BEGIN")
        if args.cursor:
            parts = args.cursor.split(".")
            if len(parts) != 2 or not all(p.isascii() and p.isdecimal() and len(p)<19 for p in parts):
                raise ValueError("Cursore non valido")
            event_id, check_id = map(int, parts)
        else:
            since = triage.iso(time.time()-args.minutes*60).replace("+00:00", "Z")
            row = db.execute("SELECT id FROM events WHERE timestamp_utc>=? ORDER BY timestamp_utc,id LIMIT 1",
                             (since,)).fetchone()
            event_id = row[0]-1 if row else db.execute("SELECT coalesce(max(id),0) FROM events").fetchone()[0]
            # Start at the first recent completion, including simultaneous results.
            row = local.execute("""SELECT min(f.id) FROM finished f JOIN checks c ON c.token=f.token
                WHERE c.source=? AND json_extract(c.result,'$.ended')>=?""",
                (source(args), since.replace("Z","+00:00"))).fetchone()
            check_id = row[0]-1 if row[0] else local.execute("SELECT coalesce(max(id),0) FROM finished").fetchone()[0]
        events = []
        for r in db.execute("""SELECT id,name,timestamp_utc,device_id,details_json FROM events NOT INDEXED
              WHERE id>? AND category='alert' AND name IN ('alert_opened','alert_recovered')
              AND json_extract(details_json,'$.name') GLOB 'service.resource.*'
              ORDER BY id LIMIT ?""", (event_id, args.limit)):
            detail = json.loads(r["details_json"])
            opened = r["name"] == "alert_opened"
            stamp = r["timestamp_utc"]
            column = "first_seen_utc" if opened else "recovered_at_utc"
            case = db.execute(f"""SELECT id FROM alerts WHERE alert_key=?
                AND {column}=? ORDER BY id DESC LIMIT 1""",
                (detail["alert_key"], stamp)).fetchone()
            relapse = opened and db.execute("""SELECT 1 FROM alerts WHERE alert_key=?
                AND recovered_at_utc<=? AND first_seen_utc<? LIMIT 1""",
                (detail["alert_key"],stamp,stamp)).fetchone()
            events.append(dict(time=stamp, kind="RICADUTA" if relapse else "APERTO" if opened else "RIENTRATO",
                               unit=r["device_id"], metric=detail["name"].removeprefix("service.resource."),
                               case_id=case["id"] if case else None))
            event_id = r["id"]
        if len(events)<args.limit:
            event_id = max(event_id, db.execute("SELECT coalesce(max(id),0) FROM events").fetchone()[0])
        for r in local.execute("""SELECT f.id,c.* FROM finished f JOIN checks c ON c.token=f.token
                WHERE f.id>? AND c.source=? ORDER BY f.id LIMIT ?""", (check_id,source(args),args.limit)):
            result = summary(r)
            events.append(dict(time=result["ended"], kind="VERIFICA", case_id=r["case_id"],
                               intervention=r["label"], token=r["token"], status=result["status"],
                               functional_status=result["functional_status"]))
            check_id = r["id"]
        return dict(cursor=f"{event_id}.{check_id}", changes=sorted(events,key=lambda x:(x["time"][:19],x["kind"]=="VERIFICA"))), 0
