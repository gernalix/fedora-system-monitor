"""On-demand explanation of a cgroup memory charge and its direct members."""
from collections import defaultdict
from pathlib import Path
import time

from ..resource_rescue.pressure import fields, psi
from ..collectors.unit_resources import clean_inactive_file
from .resource_pid_trace import group_path


def memory_report(unit, *, proc=Path("/proc")):
    directory, group = group_path(unit)
    inode = directory.stat().st_ino
    start = time.monotonic()
    cpu = time.process_time()
    stat = fields(directory / "memory.stat")
    counts = {"current": int((directory / "memory.current").read_text())}
    inactive = clean_inactive_file(counts["current"], stat)
    if inactive is not None:
        counts.update(clean_inactive_file=inactive, counted=counts["current"] - inactive)
    for key in ("anon", "file", "kernel", "shmem", "active_file", "inactive_file", "file_dirty"):
        if key in stat:
            counts[key] = stat[key]
    try:
        counts["swap"] = int((directory / "memory.swap.current").read_text())
    except OSError:
        pass

    totals = defaultdict(lambda: [0, 0, 0])
    pids = (directory / "cgroup.procs").read_text().split()
    attempted = measured = 0
    for pid in pids[:256]:
        if time.monotonic() - start > 1:
            break
        attempted += 1
        member = proc / pid
        try:
            identity = (member / "stat").read_text().rsplit(")", 1)[1].split()[19]
            name = (member / "exe").readlink().name
            rollup = fields(member / "smaps_rollup")
            if "0::" + group not in (member / "cgroup").read_text().splitlines():
                continue
            if (member / "stat").read_text().rsplit(")", 1)[1].split()[19] != identity:
                continue
            pss, swap_pss = rollup["Pss"], rollup["SwapPss"]
        except (OSError, ValueError, IndexError, KeyError):
            continue
        row = totals[name]
        row[0] += 1
        row[1] += pss
        row[2] += swap_pss
        measured += 1
    if directory.stat().st_ino != inode:
        raise ValueError("Cgroup ricreato durante la misura")

    def ranking(index):
        return [dict(name=n, pids=totals[n][0], pss_mib=round(totals[n][1]/1024, 1),
                     swap_pss_mib=round(totals[n][2]/1024, 1))
                for n in sorted(totals, key=lambda n: (-totals[n][index], n))[:5] if totals[n][index] > 0]

    try:
        available = round(fields(proc / "meminfo")["MemAvailable"] / 1024, 1)
    except (OSError, KeyError):
        available = None
    return dict(cgroup_mib={k: round(n / 1048576, 1) for k, n in counts.items()},
                host_available_mib=available,
                host_memory_full_avg60=psi(proc / "pressure/memory").get("full_avg60"),
                group_memory_full_avg60=psi(directory / "memory.pressure").get("full_avg60"),
                direct_pids=len(pids), attempted=attempted, measured=measured,
                by_resident_pss=ranking(1), by_swap_pss=ranking(2),
                elapsed=round(time.monotonic()-start, 3), observer_cpu=round(time.process_time()-cpu, 4))
