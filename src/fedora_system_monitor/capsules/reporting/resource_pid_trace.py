"""Bounded on-demand read of direct cgroup members, including newly started PIDs."""
from collections import Counter
import os
from pathlib import Path
import subprocess
import time


from ..collectors.unit_resources import DEVICES, block_rows, leaf_devices, split_unit


def group_path(unit):
    manager, name = split_unit(unit)
    if manager not in ("system", f"user:{os.getuid()}"):
        raise ValueError("Il manager richiesto appartiene a un altro utente")
    cmd = ["systemctl"]
    if manager != "system":
        cmd.append("--user")
    result = subprocess.run([*cmd, "show", "-p", "ControlGroup", "--value", "--", name],
                            capture_output=True, text=True, timeout=5, check=False)
    relative = Path(result.stdout.strip())
    if result.returncode or not relative.is_absolute() or relative.name != name or ".." in relative.parts:
        raise ValueError("Cgroup dell’incidente assente")
    return Path("/sys/fs/cgroup") / relative.relative_to("/"), str(relative)


def snapshot(directory, relative):
    data = {}
    skipped = 0
    for pid in (directory / "cgroup.procs").read_text().split():
        proc = Path("/proc") / pid
        try:
            start = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
            executable = Path(os.readlink(proc / "exe")).name
            raw = dict(line.split(": ") for line in (proc / "io").read_text().splitlines())
            if (proc / "cgroup").read_text().splitlines().count("0::" + relative) != 1:
                continue
            if (proc / "stat").read_text().rsplit(")", 1)[1].split()[19] != start:
                continue
            data[pid, int(start)] = executable, int(raw["read_bytes"]), int(raw["write_bytes"])
        except (OSError, IndexError, KeyError, ValueError):
            skipped += 1
    return data, skipped


def device_snapshot(directory, devices=DEVICES):
    try:
        physical = leaf_devices(devices)
        raw = (directory / "io.stat").read_text()
        return {(device, (devices / device).resolve(strict=True).name): (r, w, rb, wb)
                for device, r, w, rb, wb in block_rows(raw, physical)}
    except (OSError, KeyError, ValueError):
        return None


def device_changes(before, after, elapsed):
    report = dict(status="unavailable", devices=[])
    if before is None or after is None:
        return report
    report["status"] = "complete" if before.keys() == after.keys() else "partial"
    for key in before.keys() & after.keys():
        reads, writes, read_bytes, write_bytes = (b-a for a,b in zip(before[key], after[key]))
        if min(reads, writes, read_bytes, write_bytes) < 0:
            report["status"] = "partial"
            continue
        device, name = key
        report["devices"].append(dict(device=device, name=name, reads=reads, writes=writes,
                                      read_bytes=read_bytes, write_bytes=write_bytes,
                                      ops_min=round((reads+writes)*60/elapsed, 2)))
    report["devices"].sort(key=lambda row: (-row["ops_min"], row["device"]))
    return report


def attribution(unit, seconds):
    directory, relative = group_path(unit)
    stat = directory.stat()
    ticks = os.sysconf("SC_CLK_TCK")
    first_tick = time.clock_gettime(time.CLOCK_BOOTTIME) * ticks
    start = time.monotonic()
    cpu = time.process_time()
    before = device_snapshot(directory)
    device_start = time.monotonic()
    last, skipped = snapshot(directory, relative)
    totals = {}
    gaps = 0
    for step in range(1, seconds + 1):
        time.sleep(max(0, start + step - time.monotonic()))
        current, missed = snapshot(directory, relative)
        if directory.stat().st_ino != stat.st_ino:
            raise ValueError("Cgroup ricreato durante la misura")
        skipped += missed
        for key, (name, read, written) in current.items():
            previous = last.get(key)
            if previous is None and key[1] <= first_tick:
                gaps += 1
                continue
            old_name, old_read, old_written = previous or (name, 0, 0)
            if old_name != name or read < old_read or written < old_written:
                gaps += 1
                continue
            tally = totals.setdefault(name, Counter())
            tally.update(read_bytes=read-old_read, write_bytes=written-old_written)
        # Only count creation-to-first-observation for processes born since
        # the last scan. A migrated/unreadable older process needs a baseline.
        first_tick = time.clock_gettime(time.CLOCK_BOOTTIME) * ticks
        last = current
    after = device_snapshot(directory)
    devices = device_changes(before, after, time.monotonic()-device_start)
    if directory.stat().st_ino != stat.st_ino:
        raise ValueError("Cgroup ricreato durante la misura")
    ranked = sorted(totals, key=lambda name: (-(totals[name]["read_bytes"] + totals[name]["write_bytes"]), name))
    return dict(elapsed=round(time.monotonic()-start, 3), observer_cpu=round(time.process_time()-cpu, 4),
                unreadable_observations=skipped, baseline_gaps=gaps, block_io=devices,
                executables=[dict(name=name, **totals[name]) for name in ranked[:5]])
