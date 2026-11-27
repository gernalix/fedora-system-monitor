"""Rank FSM observations and verify one repair using the existing minute scanner."""
import argparse
import hashlib
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

from ..collectors import unit_repairs
from ..collectors.common import operator_identity
from ..collectors.unit_resources import BOOT, LIMITS, MEMORY_ADJUSTED, RELATIVE_FLOORS, STATE, rates, split_unit
from ..config import load_config
from . import _connection

METRICS = tuple(RELATIVE_FLOORS)
DEFAULT_DB = "/var/lib/fedora-system-monitor/monitor.sqlite3"


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds")


def history(db, metric, minutes, now):
    # The composite index starts with category and name. Bound the work by time
    # and row count even when a large historical warehouse is mounted.
    rows = db.execute("""
        SELECT timestamp_utc,details_json FROM periodic_metrics
        WHERE category='service' AND name='service.resource_scan' AND timestamp_utc>=?
        ORDER BY timestamp_utc DESC LIMIT ?
    """, (iso(now - minutes * 60).replace("+00:00", "Z"), minutes + 1))
    frames = []
    memory_basis = None
    for stamp, raw in rows:
        detail = json.loads(raw)
        if metric == "memory_mib":
            basis = detail.get("memory_basis", "total")
            if memory_basis is None:
                memory_basis = basis
            elif basis != memory_basis:
                break
        frames.append((stamp, {unit: value for value, unit in detail["top"].get(metric, [])}))
    return frames


def threshold(unit, metric, policy, explicit, previous=None):
    if explicit is not None:
        return explicit
    overrides = policy.get("units", {}).get(unit, {})
    limit = overrides.get(metric, policy.get(metric, LIMITS[metric]))
    if previous is not None and metric not in overrides:
        count, reference = previous.get("baseline", {}).get(metric, (0, None))
        if count >= 15 and reference is not None:
            limit = min(limit, max(RELATIVE_FLOORS[metric], 4 * reference))
    return limit


def rank(frames, metric, policy, explicit, order, limit):
    rows = {}
    for index, (_, frame) in enumerate(frames):
        for unit, value in frame.items():
            cutoff = threshold(unit, metric, policy, explicit)
            item = rows.setdefault(unit, dict(unit=unit, latest=None, peak=value,
                                              seen=0, high=0, threshold=cutoff))
            if index == 0:
                item["latest"] = value
            item["peak"] = max(value, item["peak"])
            item["seen"] += 1
            item["high"] += int(value >= cutoff)
    candidates = [r for r in rows.values() if order != "latest" or r["latest"] is not None]
    def sort_key(row):
        primary = row["high"] if order == "persistent" else row[order]
        return -primary, -row["peak"], row["unit"]
    return sorted(candidates, key=sort_key)[:limit]


def state(path):
    with _connection(path) as db:
        row = db.execute("SELECT state_json FROM dedup_state WHERE namespace='collector' AND state_key=?",
                         (STATE,)).fetchone()
    if row is None:
        raise ValueError("Stato del campionatore FSM assente")
    return json.loads(row[0])


def pairs(path, deadline):
    prior = state(path)
    while time.monotonic() < deadline:
        # Reopen a read snapshot only near/after the expected timer tick.
        delay = min(55, max(3, prior["wall"] + 57 - time.time()), deadline - time.monotonic())
        if delay <= 0:
            break
        time.sleep(delay)
        current = state(path)
        if (current["mono"], current["boot"]) == (prior["mono"], prior["boot"]):
            continue
        elapsed = current["mono"] - prior["mono"]
        valid = (current["boot"] == prior["boot"] and 20 <= elapsed <= 90 and
                 0 <= time.time() - current["wall"] <= 90)
        yield prior, current, elapsed if valid else None
        prior = current


def observed(prior, current, elapsed, metric, unit=None):
    if elapsed is None:
        return {}
    values = {}
    old = prior["samples"]
    for key, snap in current["samples"].items():
        if unit is not None and key != unit:
            continue
        prev = old.get(key)
        if not prev or snap.get("inode") != prev.get("inode"):
            continue
        if metric == "memory_mib" and (MEMORY_ADJUSTED in snap) != (MEMORY_ADJUSTED in prev):
            continue
        value = rates(snap, prev, elapsed).get(metric)
        if value is not None:
            values[key] = value
    return values


def io_devices(prior, current, unit, elapsed):
    before = prior["samples"][unit]["io"]
    after = current["samples"][unit]["io"]
    # The scanner has already removed stacked dm-crypt devices.
    result = {}
    for device, count in after.items():
        path = Path("/sys/dev/block") / device
        name = path.resolve().name if path.exists() else device
        result[name] = round((count - before.get(device, 0)) * 60 / elapsed, 2)
    return result


def verify_point(prior, current, elapsed, args, policy):
    values = observed(prior, current, elapsed, args.metric, args.unit)
    cutoff = threshold(args.unit, args.metric, policy, args.threshold,
                       prior["samples"].get(args.unit, {}))
    value = values.get(args.unit)
    point = dict(end=iso(current["wall"]), value=round(value, 3) if value is not None else None,
                threshold=cutoff, below_recovery=value is not None and value < .8 * cutoff)
    if value is not None and args.metric == "io_ops_min":
        point["devices"] = io_devices(prior, current, args.unit, elapsed)
    return point


def probe(command):
    """Run the explicitly supplied owner check. Never put its output in a report."""
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return False, None
        if result.returncode or output.tell() > 65536:
            return False, None
        output.seek(0)
        return True, hashlib.sha256(output.read()).digest()


def next_incident(db, recipes, metric_filter=None, *, summary_only=False):
    records = db.execute("""
        SELECT id,device_id,name,last_seen_utc,details_json FROM alerts
        WHERE status='active' AND source='unit_resource_scanner'
    """)
    candidates = []
    now = time.time()
    for row in records:
        detail = json.loads(row["details_json"])
        value, limit = detail.get("value"), detail.get("limit")
        if value is None or limit is None or limit <= 0:
            continue
        seen = datetime.fromisoformat(row["last_seen_utc"]).timestamp()
        unit = row["device_id"]
        metric = row["name"].removeprefix("service.resource.")
        if metric_filter and metric != metric_filter:
            continue
        candidates.append(dict(id=row["id"], unit=unit, metric=metric, value=value, threshold=limit,
                               ratio=round(value/limit, 3), last_seen=row["last_seen_utc"],
                               fresh=0 <= now-seen <= 180))
    if not candidates:
        return {"status": "NESSUN_AVVISO_APERTO"}
    candidates.sort(key=lambda r: (not r["fresh"], -r["ratio"], r["unit"], r["metric"]))
    item = candidates[0]
    if summary_only:
        return {"incident": item}
    saved = db.execute("SELECT state_json FROM dedup_state WHERE namespace='collector' AND state_key=?",
                       (unit_repairs.STATE,)).fetchone()
    attempt = json.loads(saved[0]).get(item["unit"], {}) if saved else {}
    return dict(status="DA_ESAMINARE" if item["fresh"] else "ULTIMO_RISCONTRO_STORICO",
                incident=item, open_signals=len(candidates),
                last_verification=last_verification(item["unit"], item["metric"]),
                configured_recipe=recipes.get(item["unit"], {}).get(item["metric"]),
                repair_attempt={k:v for k, v in attempt.items() if k in ("checked", "recipe", "metric")},
                processes_by_cpu=process_rows(db, item["unit"], 5))


def verification(path, args, policy):
    started = time.time()
    deadline = time.monotonic() + args.timeout
    evidence = []
    gaps = 0
    initial_digest = None
    change_observed_at = None
    proof = None
    status = "DATI_INSUFFICIENTI"
    with _connection(path) as db:
        frames = history(db, args.metric, args.minutes, started)
    baseline = [v[args.unit] for _, v in frames if args.unit in v]
    for prior, current, elapsed in pairs(path, deadline):
        # The first complete interval must begin after the operator's invocation.
        point = verify_point(prior, current, elapsed, args, policy)
        if point["value"] is None:
            evidence.clear()
            initial_digest = change_observed_at = None
            gaps += 1
            continue
        if prior["wall"] >= started:
            evidence.append(point)
        if args.expect_change:
            if change_observed_at is None:
                ok, digest = probe(args.probe)
                proof = dict(passed=ok, changed=False)
                if not ok:
                    status = "TEST_FUNZIONALE_FALLITO"
                    break
                if initial_digest is None:
                    initial_digest = digest
                    evidence.clear()
                elif initial_digest != digest:
                    change_observed_at = time.time()
                    proof["changed"] = True
            # The tick AFTER the observed change accounts for the whole cycle.
            if change_observed_at is None or current["wall"] < change_observed_at:
                continue
        if len(evidence) >= args.samples:
            status = "SOTTO_SOGLIA" if all(p["below_recovery"] for p in evidence) else "NON_RIENTRATO"
            break
    if args.expect_change and status == "DATI_INSUFFICIENTI" and len(evidence) >= args.samples:
        status = "CICLO_NON_CONFERMATO"
    if args.probe and not args.expect_change:
        ok, _ = probe(args.probe)
        proof = dict(passed=ok)
        if not ok:
            status = "TEST_FUNZIONALE_FALLITO"
    codes = {"SOTTO_SOGLIA": 0, "NON_RIENTRATO": 1, "TEST_FUNZIONALE_FALLITO": 1,
             "CICLO_NON_CONFERMATO": 2, "DATI_INSUFFICIENTI": 2}
    return dict(status=status, unit=args.unit, metric=args.metric, started=iso(started), probe=proof,
                historical_peak=max(baseline, default=None), historical_observed=len(baseline),
                samples=evidence, gaps=gaps), codes[status]


def same_process(row, unit):
    proc = Path("/proc") / str(row["pid"])
    try:
        prefix, leaf = split_unit(unit)
        group = next(line[3:] for line in (proc / "cgroup").read_text().splitlines() if line.startswith("0::"))
        parts = Path(group).parts
        managers = [p[5:-8] for p in parts if p.startswith("user@") and p.endswith(".service") and p[5:-8].isdecimal()]
        owner = "user:" + managers[-1] if managers else "system"
        if leaf.startswith("user@") and leaf.endswith(".service") and leaf == parts[-1]:
            owner = "system"
        start = int((proc / "stat").read_text().rsplit(")", 1)[1].split()[19])
        return prefix == owner and leaf in parts and start == row["start_ticks"]
    except (OSError, StopIteration, IndexError, ValueError):
        return False


def process_rows(db, unit, limit):
    scan = db.execute("SELECT id,timestamp,boot_id FROM process_scans ORDER BY id DESC LIMIT 1").fetchone()
    if not scan or scan["boot_id"] != BOOT.read_text().strip() or not 0 <= time.time() - scan["timestamp"] <= 120:
        return []
    _, leaf = split_unit(unit)
    rows = db.execute("""SELECT i.pid,i.start_ticks,i.name,s.cpu_percent,s.rss_bytes,
        s.read_delta,s.write_delta FROM process_samples s JOIN process_identities i ON i.id=s.identity_id
        WHERE s.scan_id=? AND i.unit=? ORDER BY s.cpu_percent DESC,i.pid""", (scan["id"], leaf))
    found = []
    for row in rows:
        if same_process(row, unit):
            found.append(dict(row))
            if len(found) == limit:
                break
    return found


def pid_io_reading(row, unit):
    try:
        path = Path("/proc") / str(row["pid"]) / "io"
        counters = dict(line.split(": ") for line in path.read_text().splitlines())
        values = int(counters["read_bytes"]), int(counters["write_bytes"])
    except (OSError, KeyError, ValueError):
        return None
    return values if same_process(row, unit) else None


def process_io(rows, unit, seconds, limit):
    start = time.monotonic()
    first = {r["pid"]: pid_io_reading(r, unit) for r in rows}
    measured = []
    if any(counts is not None for counts in first.values()):
        time.sleep(seconds)
        for row in rows:
            before = first[row["pid"]]
            if before is None:
                continue
            after = pid_io_reading(row, unit)
            if after is None:
                continue
            read, written = after[0] - before[0], after[1] - before[1]
            if read >= 0 and written >= 0:
                measured.append(dict(pid=row["pid"], name=row["name"], read_bytes=read, write_bytes=written))
    measured.sort(key=lambda r: (-(r["read_bytes"] + r["write_bytes"]), r["pid"]))
    return dict(elapsed_seconds=round(time.monotonic() - start, 3), candidates=len(rows),
                measured=len(measured), rows=measured[:limit])


def receipt_path(unit, metric):
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    key = hashlib.sha256(f"{unit}\n{metric}".encode()).hexdigest()
    return base / "fedora-system-monitor" / "resource-triage" / f"{key}.json"


def save_receipt(report):
    target = receipt_path(report["unit"], report["metric"])
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False, mode="w") as stream:
        temporary = Path(stream.name)
        try:
            json.dump(report, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    return str(target)


def last_verification(unit, metric):
    try:
        data = json.loads(receipt_path(unit, metric).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or (data.get("unit"), data.get("metric")) != (unit, metric):
        return None
    return {key: data.get(key) for key in ("status", "started", "ended", "probe")}


def run(args):
    if args.command == "changes":
        from .resource_followup import changes
        return changes(args)
    if args.command == "boot":
        from .resource_boot import compare
        return compare(args)
    config = load_config(args.config)
    policy = config["unit_resources"]
    if args.command == "case":
        from .resource_case import report
        return report(args, policy, operator_identity(config)[2])
    if args.command == "verify":
        result, code = verification(args.db, args, policy)
        result["ended"] = iso(time.time())
        result["receipt"] = save_receipt(result)
        return result, code
    with _connection(args.db) as db:
        if args.command == "next":
            uid = operator_identity(config)[2]
            return next_incident(db, unit_repairs.configured_recipes(policy, uid), args.metric), 0
        frames = history(db, args.metric, args.minutes, time.time())
        if args.command == "inspect":
            processes = process_rows(db, args.unit, None if args.io_seconds else args.limit)
    if args.command == "inspect":
        result = dict(unit=args.unit, metric=args.metric, frames=len(frames),
                      last_verification=last_verification(args.unit, args.metric),
                      timeline=[dict(end=t, value=f.get(args.unit)) for t, f in frames],
                      processes_by_cpu=processes[:args.limit])
        if args.io_seconds:
            result["sampled_pid_io"] = process_io(processes, args.unit, args.io_seconds, args.limit)
        return result, 0
    coverage = "top5"
    if args.full:
        frames = []
        last_pair = None
        for prior, current, elapsed in pairs(args.db, time.monotonic() + args.timeout):
            frame = observed(prior, current, elapsed, args.metric)
            if not frame:
                frames.clear()
                last_pair = None
                continue
            frames.append((iso(current["wall"]), frame))
            last_pair = prior, current, elapsed
            if len(frames) == args.samples:
                break
        frames.reverse()
        coverage = "all_measured"
    rows = rank(frames, args.metric, policy, args.threshold, args.order, args.limit)
    if args.full and last_pair and args.metric == "io_ops_min":
        prior, current, elapsed = last_pair
        for item in rows:
            if item["latest"] is not None:
                item["devices"] = io_devices(prior, current, item["unit"], elapsed)
    latest_at = frames[0][0] if frames else None
    fresh = bool(latest_at and 0 <= time.time() - datetime.fromisoformat(latest_at).timestamp() <= 120)
    return dict(metric=args.metric, coverage=coverage, order=args.order, frames=len(frames),
                latest_at=latest_at, fresh=fresh, rows=rows), 0 if fresh and (not args.full or len(frames) == args.samples) else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Classifica, attribuzione e verifica dai campioni esistenti di FSM.")
    commands = parser.add_subparsers(dest="command", required=True)
    ranking = commands.add_parser("rank", help="classifica più recente, per picco o persistenza")
    inspect = commands.add_parser("inspect", help="campioni storici e PID del gruppo")
    queue = commands.add_parser("next", help="incidente FSM aperto con maggiore superamento relativo")
    verify = commands.add_parser("verify", help="misura finestre complete dopo una correzione")
    case = commands.add_parser("case", help="riepilogo compatto o verifica dello stesso incidente dopo una modifica")
    changes = commands.add_parser("changes", help="transizioni e verifiche dopo il cursore")
    changes.add_argument("--cursor")
    changes.add_argument("--minutes", type=int, default=15)
    changes.add_argument("--limit", type=int, default=50)
    boot = commands.add_parser("boot", help="confronta la stessa finestra dalla partenza")
    boot.add_argument("--backups", help="directory delle copie FSM per gli avvii usciti dalla storia recente")
    boot.add_argument("--compare", type=int, choices=range(1, 11), default=3)
    boot.add_argument("--minutes", type=int, choices=range(1,61), default=15)
    boot.add_argument("--limit", type=int, default=5)
    case.add_argument("--background", action="store_true")
    case.add_argument("--intervention", help="etichetta univoca per intervento nello stesso caso")
    case.add_argument("--receipt", help="legge una specifica verifica del caso tramite token")
    case.add_argument("--expect-change", action="store_true")
    case.add_argument("--probe", nargs=argparse.REMAINDER, help="controllo funzionale, ultimo argomento")
    case.add_argument("--worker", help=argparse.SUPPRESS)
    case.add_argument("--id", type=int, help="ID stabile dell’avviso FSM")
    case.add_argument("--memory", action="store_true", help="misura RAM, swap, pressione e PSS dei membri diretti")
    case.add_argument("--io-seconds", type=int, choices=range(1, 61), metavar="1..60",
                      help="campiona i membri diretti del cgroup una volta al secondo")
    case.add_argument("--verify", action="store_true", help="verifica dopo una modifica, richiede --id")
    case.add_argument("--metric", choices=tuple(LIMITS), help="filtra la selezione automatica")
    case.add_argument("--minutes", type=int, default=15)
    case.add_argument("--timeout", type=int, default=450)
    for cmd in (ranking, inspect, queue, verify, case, changes, boot):
        cmd.add_argument("--db", default=DEFAULT_DB)
        cmd.add_argument("--config", default="/etc/fedora-system-monitor/config.toml")
        cmd.add_argument("--json", action="store_true")
    for cmd in (ranking, inspect, verify):
        cmd.add_argument("--metric", choices=METRICS, default="io_ops_min")
        cmd.add_argument("--minutes", type=int, default=15)
    inspect.add_argument("--io-seconds", type=int, choices=range(1, 61), metavar="1..60",
                         help="misura su richiesta i byte I/O dei PID già identificati da FSM")
    queue.add_argument("--metric", choices=tuple(LIMITS), help="filtra i soli avvisi di questa metrica")
    for cmd in (inspect, verify):
        cmd.add_argument("--unit", required=True)
    for cmd in (ranking, inspect):
        cmd.add_argument("--limit", type=int, default=10)
    for cmd in (ranking, verify):
        cmd.add_argument("--threshold", type=float)
        cmd.add_argument("--timeout", type=int, help="tempo massimo di attesa dei campioni, in secondi")
    ranking.add_argument("--order", choices=("latest", "peak", "persistent"), default="latest")
    ranking.add_argument("--full", action="store_true", help="classifica completa dal prossimo intervallo FSM")
    ranking.add_argument("--samples", type=int, default=1, help="finestre consecutive per --full")
    verify.add_argument("--samples", type=int, default=3)
    verify.add_argument("--expect-change", action="store_true",
                        help="osserva un nuovo identificativo di ciclo dal controllo del proprietario")
    verify.add_argument("--probe", nargs=argparse.REMAINDER, help="comando di verifica, come ultimo argomento")
    args = parser.parse_args(argv)
    if hasattr(args, "timeout") and args.timeout is None:
        args.timeout = (args.samples + 1) * 75 if args.command == "rank" else (args.samples + 2) * 90
    for key, maximum in (("limit", 1000), ("minutes", 1440), ("samples", 120), ("timeout", 14400)):
        if not 1 <= getattr(args, key, 1) <= maximum:
            parser.error(f"--{key} deve essere compreso fra 1 e {maximum}")
    cutoff = getattr(args, "threshold", None)
    if cutoff is not None and (not math.isfinite(cutoff) or cutoff <= 0):
        parser.error("--threshold deve essere positivo e finito")
    if hasattr(args, "unit"):
        try:
            split_unit(args.unit)
        except ValueError as error:
            parser.error(str(error))
    if args.command in ("case", "verify") and (args.probe == [] or (args.expect_change and not args.probe)):
        parser.error("--expect-change richiede --probe seguito dal comando del proprietario")
    if args.command == "case" and ((args.background or args.intervention or args.worker or args.probe) and not args.verify or args.background and args.worker):
        parser.error("--background e --intervention richiedono case --verify")
    if args.command == "case" and args.receipt and (not args.id or args.verify or args.memory or args.io_seconds):
        parser.error("--receipt richiede soltanto un ID di incidente")
    if args.command == "case" and args.verify and (args.io_seconds or args.memory):
        parser.error("--io-seconds e --memory sono opzioni di diagnosi")
    if args.command == "case" and ((args.verify and not args.id) or (args.id is not None and (args.id < 1 or args.metric))):
        parser.error("case --verify richiede --id positivo; usare --metric solo per scegliere un caso")
    if args.command == "rank" and not args.full and args.samples != 1:
        parser.error("--samples richiede --full con rank")
    try:
        result, code = run(args)
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.json or args.command != "rank":
        print(json.dumps(result, ensure_ascii=False, indent=None if args.json else 2))
    else:
        print(f"{result['latest_at']}  {args.metric}  campioni={result['frames']}  copertura={result['coverage']}  recente={result['fresh']}")
        print("   ULTIMO      PICCO   SOPRA   VISTO  UNITÀ")
        for r in result["rows"]:
            last = f"{r['latest']:.1f}" if r["latest"] is not None else "?"
            print(f"{last:>9}  {r['peak']:9.1f}  {r['high']:6}  {r['seen']:5}  {r['unit']}")
    return code
