"""Compare retained boot windows without starting a sampler."""
from datetime import datetime
import json
from . import _connection
from . import resource_triage as triage

# Process names are the sanitized comm field recorded by FSM, including its truncation.
APPS = {"chrome", "firefox", "chromium", "studio", "studio.sh", "idea", "code", "codex-desktop",
        "libreoffice", "soffice.bin", "thunderbird", "nautilus", "gnome-text-edit"}


def ranked(series, limit, threshold):
    out = []
    for unit, points in series.items():
        highest = max(points.values())
        longest = streak = 0
        last = None
        for t, value in sorted(points.items()):
            streak = (streak+1 if last is not None and 20 <= t-last <= 90 else 1) if value >= threshold else 0
            last = t
            longest = max(longest, streak)
        out.append(dict(unit=unit, peak=round(highest, 1), observed=len(points),
                        high=sum(v>=threshold for v in points.values()), consecutive_high=longest))
    return sorted(out, key=lambda r: (-r["peak"], r["unit"]))[:limit]


def window(db, boot, recorded, minutes, limit):
    seconds = minutes * 60
    stamp = datetime.fromisoformat(recorded).timestamp()
    # The lifecycle event may be later than the kernel boot. Derive epoch from
    # the stored CLOCK_BOOTTIME of the first process scan of this boot.
    first = db.execute("SELECT id,timestamp FROM process_scans WHERE boot_id=? ORDER BY id LIMIT 1",
                       (boot,)).fetchone()
    if first:
        age = db.execute("SELECT min(clock) FROM process_samples WHERE scan_id=?", (first["id"],)).fetchone()[0]
        if age is not None:
            stamp = first["timestamp"]-age
    cpu, block = {}, {}
    apps = {}
    observed = []
    complete = unreadable = 0
    previous = None
    covered = 0.0
    for scan in db.execute("""SELECT * FROM process_scans WHERE timestamp BETWEEN ? AND ? AND boot_id=?
                              ORDER BY timestamp""", (stamp-1, stamp+seconds+1, boot)):
        rows = db.execute("""SELECT i.name,i.unit,s.clock,s.cpu_percent,s.interval_seconds
                 FROM process_samples s JOIN process_identities i ON i.id=s.identity_id WHERE scan_id=?""",
                          (scan["id"],))
        totals = {}
        t = None
        for row in rows:
            age = row["clock"]
            if not 0 <= age <= seconds:
                continue
            t = age if t is None else min(t, age)
            name = row["name"].lower()
            if name in APPS:
                apps[name] = min(age,apps.get(name,age))
            elapsed = row["interval_seconds"]
            if (row["cpu_percent"] is not None and elapsed is not None and 0 < elapsed <= 90
                    and age-elapsed >= 0 and row["unit"]):
                unit = row["unit"]
                totals[unit] = totals.get(unit,0.0)+row["cpu_percent"]
        if t is None:
            continue
        observed.append(t)
        complete += int(scan["complete"])
        unreadable += scan["unreadable"]
        if previous is not None and 0 < t-previous <= 90:
            covered += t-previous
        previous = t
        for unit, value in totals.items():
            cpu.setdefault(unit,{})[t] = value
    # Check uptime as well as UTC so delayed lifecycle events cannot pull a
    # later minute into the window. Only continuous scanner deltas are usable.
    frames = 0
    for (raw,) in db.execute("""SELECT details_json FROM periodic_metrics WHERE category='service'
            AND name='service.resource_scan' AND timestamp_utc BETWEEN ? AND ?""",
            (triage.iso(stamp-120).replace("+00:00","Z"), triage.iso(stamp+seconds+120).replace("+00:00","Z"))):
        detail = json.loads(raw)
        age = detail.get("uptime_seconds")
        if detail.get("boot_id") != boot or age is None or not 0 <= age <= seconds or not detail.get("continuous"):
            continue
        frames += 1
        for value,unit in detail["top"].get("io_ops_min", []):
            block.setdefault(unit,{})[age] = value
    return dict(boot_id=boot, boot_recorded=recorded, scans=len(observed), complete_scans=complete,
                unreadable_process_observations=unreadable, covered_seconds=round(covered,1),
                first_scan_seconds=round(observed[0],1) if observed else None,
                last_scan_seconds=round(observed[-1],1) if observed else None,
                first_desktop_observations_seconds={n:round(t,1) for n,t in sorted(apps.items(),key=lambda a:(a[1],a[0]))},
                unit_cpu_percent=ranked(cpu,limit,100), io_top5_frames=frames,
                unit_io_ops_min=ranked(block,limit,6000))


def compare(args):
    reports = []
    with _connection(args.db) as db:
        for r in db.execute("""SELECT timestamp_utc,details_json FROM events WHERE category='system'
                AND name='system_boot' ORDER BY timestamp_utc DESC LIMIT ?""",(args.compare,)):
            boot = json.loads(r["details_json"]).get("boot_id")
            if boot:
                reports.append(window(db,boot,r["timestamp_utc"],args.minutes,args.limit))
    measured = sum(bool(r["scans"] or r["io_top5_frames"]) for r in reports)
    return dict(minutes=args.minutes, requested_boots=args.compare, measured_boots=measured, boots=reports), 0 if measured else 2
