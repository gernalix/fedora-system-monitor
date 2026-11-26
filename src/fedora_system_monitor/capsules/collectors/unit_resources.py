"""Minute accounting for live cgroups and systemd manager events."""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

from . import unit_repairs
from ..config import DEFAULT_CONFIG
from .common import external
from .model import CollectionResult, record

CGROUP = Path("/sys/fs/cgroup")
DEVICES = Path("/sys/dev/block")
BOOT = Path("/proc/sys/kernel/random/boot_id")
STATE = "service.resource_assessment.v1"
RESTART = "5eb03494b6584870a536b337290809b3"
USAGE = "ae8f7b866b0347b9af31fe1c80b127c0"
STARTED = "39f53479d3a045ac8e11786248231fbf"
LIMITS = {k: v for k, v in DEFAULT_CONFIG["unit_resources"].items() if isinstance(v, (int, float))}
RELATIVE_FLOORS = {"cpu_percent": 20, "io_ops_min": 1500, "io_mib_s": 10, "memory_mib": 512}


def block_counters(raw, physical):
    ops, size = {}, {}
    for line in raw.splitlines():
        device, *entries = line.split()
        if device in physical:
            values = dict(entry.split("=") for entry in entries)
            ops[device] = int(values["rios"]) + int(values["wios"])
            size[device] = int(values["rbytes"]) + int(values["wbytes"])
    return ops, size


def read_cgroups(root=CGROUP, devices=DEVICES):
    # Select leaf block devices once so dm-crypt and its backing disk do
    # not both charge the same operation. Missing accounting stays unknown.
    physical = {d.name for d in devices.iterdir()
                if (d / "slaves").is_dir() and not any((d / "slaves").iterdir())}
    samples = {}
    skipped = 0

    def visit(directory, manager):
        nonlocal skipped
        for path in directory.iterdir():
            name = path.name
            try:
                if name.endswith(".slice"):
                    visit(path, manager)
                    continue
                if name.startswith("user@") and name.endswith(".service"):
                    uid = name[5:-8]
                    if uid.isdecimal():
                        visit(path, f"user:{uid}:")
                        continue
                if not name.endswith((".service", ".scope")):
                    continue
                inode = path.stat().st_ino
                sample = {"inode": inode}
                for key, filename in (("cpu", "cpu.stat"), ("memory", "memory.current"),
                                      ("io", "io.stat")):
                    try:
                        raw = (path / filename).read_text()
                        if key == "cpu":
                            sample[key] = int(dict(line.split() for line in raw.splitlines())["usage_usec"])
                        elif key == "memory":
                            sample[key] = int(raw)
                        else:
                            sample["io"], sample["io_bytes"] = block_counters(raw, physical)
                    except (FileNotFoundError, PermissionError, KeyError, ValueError):
                        continue
                if path.stat().st_ino == inode and len(sample) > 1:
                    samples[manager + name] = sample
                else:
                    skipped += 1
            except (FileNotFoundError, PermissionError):
                skipped += 1
    visit(root, "system:")
    return samples, skipped


def journal_window(config, since, until):
    fields = "MESSAGE_ID,UNIT,USER_UNIT,_UID,_PID,_SYSTEMD_USER_UNIT,CPU_USAGE_NSEC"
    cmd = ["journalctl", "-b", "--no-pager", "-q", "-o", "json",
           f"--output-fields={fields}", f"--since=@{since:.6f}", f"--until=@{until:.6f}",
           "--lines=4097", "_COMM=systemd", f"MESSAGE_ID={USAGE}", f"MESSAGE_ID={RESTART}",
           f"MESSAGE_ID={STARTED}"]
    result = external(config, cmd, timeout=5, max_output=4_000_000)
    lines = result.stdout.splitlines()
    if not result.ok or len(lines) > 4096 or len(result.stdout) >= 4_000_000:
        return None
    units = {}
    for line in lines:
        event = json.loads(line)
        name = event.get("USER_UNIT")
        if name and event.get("_SYSTEMD_USER_UNIT") == "init.scope":
            identity = f"user:{event['_UID']}:{name}"
        elif event.get("_PID") == "1" and (name := event.get("UNIT")):
            identity = "system:" + name
        else:
            continue
        if not name.endswith((".service", ".scope")):
            continue
        counters = units.setdefault(identity, Counter())
        kind = event["MESSAGE_ID"]
        if kind == USAGE and "CPU_USAGE_NSEC" in event:
            counters["completed_cpu_seconds"] += int(event["CPU_USAGE_NSEC"]) / 1e9
        elif kind == RESTART:
            counters["restarts"] += 1
        elif kind == STARTED:
            counters["starts"] += 1
    return units


def rates(sample, previous, seconds):
    values = {}
    if "memory" in sample:
        values["memory_mib"] = sample["memory"] / 1048576
    if not seconds or sample.get("inode") != previous.get("inode"):
        return values
    if "cpu" in sample and "cpu" in previous and sample["cpu"] >= previous["cpu"]:
        values["cpu_percent"] = (sample["cpu"] - previous["cpu"]) / (10000 * seconds)
    for field, unit, scale in (("io", "io_ops_min", 60), ("io_bytes", "io_mib_s", 1/1048576)):
        if field in sample and field in previous:
            old, new = previous[field], sample[field]
            if all(d in new and new[d] >= n for d, n in old.items()):
                values[unit] = (sum(new.values()) - sum(old.values())) * scale / seconds
    return values


def assess(config, previous, samples, journal, *, boot, now, wall, skipped):
    same_boot = boot == previous.get("boot")
    elapsed = now - previous.get("mono", now)
    continuous = same_boot and 20 <= elapsed <= 180
    prior = previous.get("samples", {}) if continuous else {}
    policy = config.get("unit_resources", {})
    old_findings = previous.get("findings", {})
    findings = {}
    peaks = {key: [] for key in LIMITS}
    result = CollectionResult("minute")
    for unit in sorted(samples.keys() | (journal or {}).keys() | old_findings.keys()):
        snapshot = samples.get(unit, {})
        values = rates(snapshot, prior.get(unit, {}), elapsed if continuous else 0)
        if journal is not None and continuous:
            activity = journal.get(unit, {})
            values.update({key + "_min": activity.get(key, 0) * 60 / elapsed
                           for key in ("starts", "restarts")})
            # Completion charges belong to the whole invocation; never add
            # these to the interval CPU rate of a still-running invocation.
            if "completed_cpu_seconds" in activity:
                values["completed_cpu_seconds"] = activity["completed_cpu_seconds"]
        overrides = policy.get("units", {}).get(unit, {})
        # A missing service is not evidence of a healthy restart. Journal
        # silence counts only alongside a live unit or a completion record.
        if not snapshot and not (journal or {}).get(unit):
            values.pop("starts_min", None)
            values.pop("restarts_min", None)
        for key, default in LIMITS.items():
            old = old_findings.get(unit, {}).get(key, {})
            limit = overrides.get(key, policy.get(key, default))
            value = values.get(key)
            # Learn a quiet reference per unit and counter over at least 15
            # observed samples. Freeze it during a breach to avoid learning a leak.
            reference = None
            if key in RELATIVE_FLOORS and snapshot:
                count, reference = prior.get(unit, {}).get("baseline", {}).get(key, (0, None))
                if count >= 15 and key not in overrides:
                    limit = min(limit, max(RELATIVE_FLOORS[key], 4 * reference))
                if value is not None and value < limit:
                    reference = value if not count else reference + (value - reference) / min(30, count + 1)
                    count = min(count + 1, 30)
                snapshot.setdefault("baseline", {})[key] = (count, reference)
            if value is not None and value > 0:
                peaks[key].append((round(value, 2), unit))
            opened = old.get("open", False)
            if key == "completed_cpu_seconds" and value is None:
                # Oneshots may finish several minutes apart. Compare successive
                # completions and expire unconfirmed suspicions after one day.
                if opened or (old and same_boot and wall - old.get("seen", 0) < 86400):
                    findings.setdefault(unit, {})[key] = old
                continue
            hot = value is not None and value >= limit
            calm = value is not None and value < limit * .8
            # A recreated cgroup needs fresh continuous evidence for rates.
            run = old.get("run", 0) if continuous else 0
            if key in RELATIVE_FLOORS and snapshot.get("inode") != prior.get(unit, {}).get("inode"):
                run = 0
            if hot:
                run = max(run, 0) + 1
            elif calm:
                run = min(run, 0) - 1
            else:
                run = 0
            sustained = min(3, max(-3, run))
            # Three restarts / many starts in one complete minute are already repeated
            # observations. For completed jobs require a second expensive completion.
            required = 1 if key in ("restarts_min", "starts_min") else 2 if key == "completed_cpu_seconds" else 3
            active = sustained >= required or (opened and sustained > -2)
            if active or hot:
                findings.setdefault(unit, {})[key] = {"run": sustained, "open": active, "seen": wall}
            if (active and value is not None) or (opened and not active):
                result.metrics.append(record(60, "service", "service.resource." + key, round(value, 2),
                    key, source="unit_resource_scanner", device_id=unit,
                    severity="warning" if active else "info",
                    details={"active": active, "limit": round(limit, 2), "samples": abs(sustained),
                             "baseline": round(reference, 2) if reference is not None else None,
                             "window_seconds": round(elapsed, 2), "boot_id": boot}))
    result.metrics.append(record(60, "service", "service.resource_scan", len(samples), "cgroups",
        source="unit_resource_scanner", details={"boot_id": boot, "uptime_seconds": round(now),
            "system": sum(u.startswith("system:") for u in samples),
            "user": sum(u.startswith("user:") for u in samples), "skipped": skipped,
            "observed": {k: sum(k in s for s in samples.values()) for k in ("cpu", "io", "memory")},
            "journal_units": len(journal) if journal is not None else None,
            "continuous": continuous, "top": {k: sorted(v, reverse=True)[:5] for k,v in peaks.items()}}))
    return result, {"boot": boot, "mono": now, "wall": wall, "samples": samples, "findings": findings}


def collect_unit_resources(scope, config, db):
    boot = BOOT.read_text().strip()
    now = time.clock_gettime(time.CLOCK_BOOTTIME)
    wall = time.time()
    previous = db.get_state(STATE, {}, namespace="collector")
    # Reconcile with durable alerts if a prior worker exited between writing
    # its delta state and committing the alert transition.
    prior_findings = previous.setdefault("findings", {})
    for row in db.query("SELECT device_id,name FROM alerts WHERE status='active' AND source='unit_resource_scanner'"):
        key = row["name"].removeprefix("service.resource.")
        if key in LIMITS:
            prior_findings.setdefault(row["device_id"], {}).setdefault(key, {})["open"] = True
    samples, skipped = read_cgroups()
    elapsed = now - previous.get("mono", now)
    since = previous.get("wall", wall)
    journal = None
    expected = previous.get("boot") == boot and 20 <= elapsed <= 180 and abs(wall - since - elapsed) < 2
    if expected:
        journal = journal_window(config, since + .000001, wall)
    result, state = assess(config, previous, samples, journal, boot=boot, now=now, wall=wall, skipped=skipped)
    if not samples or (expected and journal is None):
        result.errors.append("unit resource accounting incomplete: cgroups or manager journal unavailable")
    db.set_state(STATE, state, namespace="collector")
    if unit_repairs.in_fast_service():
        unit_repairs.reconcile(result, state["findings"], config, db)
    return result
