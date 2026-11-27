"""Minute accounting for live cgroups and systemd manager events."""
from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

from . import unit_repairs
from ..config import DEFAULT_CONFIG
from ..resource_rescue.pressure import fields
from .common import external
from .model import CollectionResult, record
from .periodic import _parse_systemctl_show

CGROUP = Path("/sys/fs/cgroup")
DEVICES = Path("/sys/dev/block")
BOOT = Path("/proc/sys/kernel/random/boot_id")
STATE = "service.resource_assessment.v1"
RESTART = "5eb03494b6584870a536b337290809b3"
USAGE = "ae8f7b866b0347b9af31fe1c80b127c0"
STARTED = "39f53479d3a045ac8e11786248231fbf"
FAILED = "d9b373ed55a64feb8242e02dbe79a49c"
LIMITS = {k: v for k, v in DEFAULT_CONFIG["unit_resources"].items() if isinstance(v, (int, float))}
COMPLETION_METRICS = ("completed_cpu_seconds", "completed_memory_peak_mib")
RELATIVE_FLOORS = {"cpu_percent": 20, "io_ops_min": 1500, "io_mib_s": 10, "memory_mib": 512}
MEMORY_ADJUSTED = "memory_clean_inactive"


def split_unit(identity):
    """Return the manager and exact name, including colons in D-Bus units."""
    match = re.fullmatch(r"(system|user:[0-9]+):([^/\s\x00-\x1f\x7f]+\.(?:service|scope))", identity)
    if match is None:
        raise ValueError("Identità incompleta. Esempi: system:example.service, user:1000:example.scope")
    return match.groups()


def clean_inactive_file(total, stats):
    """Estimate the inactive file cache available without writeback or unmapping."""
    keys = ("inactive_file", "file_dirty", "file_writeback", "file_mapped", "shmem")
    if any(key not in stats for key in keys) or not 0 <= stats["inactive_file"] <= total:
        return None
    inactive, dirty, writeback, mapped, shared = (int(stats[key]) for key in keys)
    return max(0, inactive - dirty - writeback - mapped - shared)


def leaf_devices(devices):
    # Do not charge dm-crypt and its backing device for the same operation.
    return {d.name for d in devices.iterdir()
            if (d / "slaves").is_dir() and not any((d / "slaves").iterdir())}


def block_rows(raw, physical):
    for line in raw.splitlines():
        device, *entries = line.split()
        if device in physical:
            values = dict(entry.split("=") for entry in entries)
            # Linux omits the entire group of four fields when all are zero.
            if not values.keys() & {"rios", "wios", "rbytes", "wbytes"}:
                yield device, 0, 0, 0, 0
            else:
                yield device, int(values["rios"]), int(values["wios"]), int(values["rbytes"]), int(values["wbytes"])


def block_counters(raw, physical):
    ops, size = {}, {}
    for device, reads, writes, read_bytes, write_bytes in block_rows(raw, physical):
        ops[device] = reads + writes
        size[device] = read_bytes + write_bytes
    return ops, size


def read_cgroups(root=CGROUP, devices=DEVICES):
    physical = leaf_devices(devices)
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
                            inactive = clean_inactive_file(sample[key], fields(path / "memory.stat"))
                            if inactive is not None:
                                sample[MEMORY_ADJUSTED] = inactive
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


def _usage_counter(event, field):
    try:
        value = int(event[field])
    except (KeyError, TypeError, ValueError):
        return None
    return value if 0 <= value < 2**64 - 1 else None


def journal_window(config, since, until):
    fields = "MESSAGE_ID,UNIT,USER_UNIT,_UID,_PID,_SYSTEMD_USER_UNIT,CPU_USAGE_NSEC,MEMORY_PEAK"
    cmd = ["journalctl", "-b", "--no-pager", "-q", "-o", "json",
           f"--output-fields={fields}", f"--since=@{since:.6f}", f"--until=@{until:.6f}",
           "--lines=4097", "_COMM=systemd", f"MESSAGE_ID={USAGE}", f"MESSAGE_ID={RESTART}",
           f"MESSAGE_ID={STARTED}", f"MESSAGE_ID={FAILED}"]
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
        if kind == USAGE:
            cpu = _usage_counter(event, "CPU_USAGE_NSEC")
            if cpu is not None:
                counters["completed_cpu_seconds"] += cpu / 1e9
            peak = _usage_counter(event, "MEMORY_PEAK")
            if peak is not None:
                counters["completed_memory_peak_mib"] = max(counters["completed_memory_peak_mib"], peak / 1048576)
        elif kind == FAILED:
            counters["failed_runs"] += 1
        elif kind == RESTART:
            counters["restarts"] += 1
        elif kind == STARTED:
            counters["starts"] += 1
    return units


def rates(sample, previous, seconds):
    values = {}
    if "memory" in sample:
        values["memory_mib"] = (sample["memory"] - sample.get(MEMORY_ADJUSTED, 0)) / 1048576
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


def observe_running_services(config, findings, samples, journal):
    """Query only live services with an open failure and a quiet manager window."""
    managers = defaultdict(list)
    for unit, metrics in findings.items():
        if not metrics.get("failed_runs", {}).get("open") or unit not in samples:
            continue
        try:
            manager, name = split_unit(unit)
        except ValueError:
            continue
        activity = journal.get(unit, {})
        if name.endswith(".service") and not any(activity.get(k) for k in ("failed_runs", "starts", "restarts")):
            managers[manager].append(name)
    for manager, names in managers.items():
        command = ["systemctl"]
        if manager.startswith("user:") and manager[5:].isdecimal():
            command.extend(["--user", f"--machine={manager[5:]}@.host"])
        elif manager != "system":
            continue
        command.extend(["show", "--property=Id,Type,ActiveState,SubState,Result,MainPID,InvocationID", "--", *names])
        result = external(config, command, timeout=3)
        if not result.ok:
            continue
        for row in _parse_systemctl_show(result.stdout):
            name = row.get("Id")
            invocation = row.get("InvocationID", "")
            if (name in names and row.get("ActiveState") == "active" and row.get("SubState") == "running"
                    and row.get("Result") == "success" and row.get("Type") not in (None, "", "oneshot")
                    and row.get("MainPID", "").isdecimal() and int(row["MainPID"]) > 0
                    and len(invocation) == 32 and all(c in "0123456789abcdef" for c in invocation)
                    and invocation != "0" * 32):
                samples[f"{manager}:{name}"]["running_invocation"] = invocation


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
        previous_sample = prior.get(unit, {})
        values = rates(snapshot, previous_sample, elapsed if continuous else 0)
        memory_changed = (MEMORY_ADJUSTED in snapshot) != (MEMORY_ADJUSTED in previous_sample)
        if journal is not None and continuous:
            activity = journal.get(unit, {})
            values.update({key + "_min": activity.get(key, 0) * 60 / elapsed
                           for key in ("starts", "restarts")})
            # A completed start or failure is positive evidence for a short-lived
            # unit. A silent window cannot certify that a failed job recovered.
            if activity.get("failed_runs") or activity.get("starts"):
                values["failed_runs"] = activity.get("failed_runs", 0)
            elif (snapshot.get("running_invocation") and not activity.get("restarts")
                  and snapshot.get("inode") == prior.get(unit, {}).get("inode")
                  and snapshot["running_invocation"] == prior.get(unit, {}).get("running_invocation")):
                # Same running daemon at both ends of a complete, failure-free window.
                values["failed_runs"] = 0
            # Completion charges belong to the whole invocation; never add
            # these to the interval CPU rate of a still-running invocation.
            for key in COMPLETION_METRICS:
                if key in activity:
                    values[key] = activity[key]
        overrides = policy.get("units", {}).get(unit, {})
        # A missing service is not evidence of a healthy restart. Journal
        # silence counts only alongside a live unit or a completion record.
        if not snapshot and not (journal or {}).get(unit):
            values.pop("starts_min", None)
            values.pop("restarts_min", None)
        # A unit absent at both ends of a complete, quiet interval cannot
        # sustain a live resource gauge. Keep completion and failure alerts
        # dependent on their own positive recovery evidence.
        idle_absence = (continuous and skipped == 0 and bool(samples) and bool(prior)
                        and journal is not None and unit not in journal
                        and not snapshot and not previous_sample)
        for key, default in LIMITS.items():
            old = old_findings.get(unit, {}).get(key, {})
            limit = overrides.get(key, policy.get(key, default))
            value = values.get(key)
            absent_gauge = idle_absence and key in RELATIVE_FLOORS and old.get("open", False)
            if absent_gauge:
                value = 0
            # Learn a quiet reference per unit and counter over at least 15
            # observed samples. Freeze it during a breach to avoid learning a leak.
            reference = None
            if key in RELATIVE_FLOORS and snapshot:
                if key == "memory_mib" and memory_changed:
                    count = 0
                else:
                    count, reference = previous_sample.get("baseline", {}).get(key, (0, None))
                if count >= 15 and key not in overrides:
                    limit = min(limit, max(RELATIVE_FLOORS[key], 4 * reference))
                if value is not None and value < limit:
                    reference = value if not count else reference + (value - reference) / min(30, count + 1)
                    count = min(count + 1, 30)
                snapshot.setdefault("baseline", {})[key] = (count, reference)
            if value is not None and value > 0:
                peaks[key].append((round(value, 2), unit))
            opened = old.get("open", False)
            if key in COMPLETION_METRICS and value is None:
                # Oneshots may finish several minutes apart. Compare successive
                # completions and expire unconfirmed suspicions after one day.
                if opened or (old and same_boot and wall - old.get("seen", 0) < 86400):
                    findings.setdefault(unit, {})[key] = old
                continue
            hot = value is not None and value >= limit
            calm = value is not None and value < limit * .8
            # A recreated cgroup needs fresh continuous evidence for rates.
            run = old.get("run", 0) if continuous else 0
            if ((key in RELATIVE_FLOORS and snapshot.get("inode") != previous_sample.get("inode"))
                    or (key == "memory_mib" and memory_changed)):
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
            required = 1 if key in ("restarts_min", "starts_min") else 2 if key in COMPLETION_METRICS else 3
            active = sustained >= required or (opened and sustained > -2)
            if active or hot:
                findings.setdefault(unit, {})[key] = {"run": sustained, "open": active, "seen": wall}
            if (active and value is not None) or (opened and not active):
                details = {"active": active, "limit": round(limit, 2), "samples": abs(sustained),
                           "baseline": round(reference, 2) if reference is not None else None,
                           "window_seconds": round(elapsed, 2), "boot_id": boot}
                if absent_gauge:
                    details["observation"] = "absent_cgroup_and_quiet_journal"
                if key == "memory_mib" and "memory" in snapshot:
                    details["memory_total_mib"] = round(snapshot["memory"] / 1048576, 2)
                    details["memory_basis"] = "minus_clean_inactive" if MEMORY_ADJUSTED in snapshot else "total"
                result.metrics.append(record(60, "service", "service.resource." + key, round(value, 2),
                    key, source="unit_resource_scanner", device_id=unit,
                    severity="warning" if active else "info", details=details))
    result.metrics.append(record(60, "service", "service.resource_scan", len(samples), "cgroups",
        source="unit_resource_scanner", details={"boot_id": boot, "uptime_seconds": round(now),
            "system": sum(u.startswith("system:") for u in samples),
            "user": sum(u.startswith("user:") for u in samples), "skipped": skipped,
            "observed": {k: sum(k in s for s in samples.values()) for k in ("cpu", "io", "memory")},
            "journal_units": len(journal) if journal is not None else None,
            "continuous": continuous, "memory_basis": "minus_clean_inactive_when_available",
            "top": {k: sorted(v, reverse=True)[:5] for k,v in peaks.items()}}))
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
        if journal is not None:
            observe_running_services(config, prior_findings, samples, journal)
    result, state = assess(config, previous, samples, journal, boot=boot, now=now, wall=wall, skipped=skipped)
    if not samples or (expected and journal is None):
        result.errors.append("unit resource accounting incomplete: cgroups or manager journal unavailable")
    db.set_state(STATE, state, namespace="collector")
    if unit_repairs.in_fast_service():
        unit_repairs.reconcile(result, state["findings"], config, db)
    return result
