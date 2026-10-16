"""One bounded /proc scan per minute. Never read cmdline, environ or fd targets."""
import os
from pathlib import Path
import re
import time
import uuid

from .model import CollectionResult
from ..database.process_history import previous


def _read(path, limit=16384):
    with path.open('rb') as handle:
        data = handle.read(limit+1)
    if len(data)>limit:
        raise ValueError('oversize proc field')
    return data.decode('utf-8', errors='replace')


def _stat(text):
    end = text.rfind(')')
    start = text.index('(')
    fields = text[end+2:].split()
    if end < start or len(fields)<22:
        raise ValueError('invalid stat')
    name = ''.join(c if c.isprintable() else '?' for c in text[start+1:end].rsplit('/',1)[-1])[:64]
    return name, int(fields[19]), int(fields[11])+int(fields[12]), int(fields[21])


def _unit(text):
    # Only a unit basename, never the cgroup hierarchy or personal paths.
    units = re.findall(r'(?:^|/)([A-Za-z0-9_.@:\\-]{1,128}\.(?:service|scope))(?:/|$)', text.strip())
    return units[-1] if units else None


def scan_processes(db, options, *, root=Path('/proc'), clock=None, wall=None):
    clock = clock or (lambda: time.clock_gettime(time.CLOCK_BOOTTIME))
    wall = time.time if wall is None else wall
    started = clock()
    now = wall()
    boot = str(uuid.UUID(_read(root/'sys/kernel/random/boot_id').strip()))
    last, baseline = previous(db)
    if last and last['boot_id']==boot and 0 <= now-last['timestamp'] < options['interval_seconds']-1:
        return None
    total = None
    try:
        total = int(re.search(r'^MemTotal:\s+(\d+)',_read(root/'meminfo'),re.M)[1])*1024
    except (OSError, ValueError, TypeError):
        pass
    users = {}
    try:
        for line in _read(Path('/etc/passwd'), 262144).splitlines():
            parts = line.split(':')
            if len(parts)>2 and parts[2].isdigit():
                users[int(parts[2])] = parts[0][:64]
    except (OSError, ValueError):
        pass
    hz, page = os.sysconf('SC_CLK_TCK'), os.sysconf('SC_PAGE_SIZE')
    rows, visible, unreadable, complete = [], 0, 0, True
    # scandir is streaming; no PID cap silently drops idle processes.
    with os.scandir(root) as entries:
        for entry in entries:
            if clock()-started > options['max_scan_seconds']:
                complete = False
                break
            if not entry.name.isdecimal():
                continue
            visible += 1
            path = root/entry.name
            try:
                name, start, ticks, rss = _stat(_read(path/'stat'))
                stamp = clock()
                uid = None
                try:
                    match = re.search(r'^Uid:\s+(\d+)',_read(path/'status'),re.M)
                    uid = int(match[1]) if match else None
                except (OSError, ValueError):
                    pass
                reads = writes = None
                try:
                    io = dict(line.split(':',1) for line in _read(path/'io').splitlines() if ':' in line)
                    reads = int(io['read_bytes']) if 'read_bytes' in io else None
                    writes = int(io['write_bytes']) if 'write_bytes' in io else None
                except (OSError, ValueError):
                    pass
                unit = None
                try:
                    unit = _unit(_read(path/'cgroup'))
                except (OSError, ValueError):
                    pass
                # Detect exit/reuse during the multi-file read before committing identity.
                if _stat(_read(path/'stat'))[1] != start:
                    raise ValueError('pid reused during read')
                old = baseline.get((boot,int(entry.name),start))
                elapsed = stamp-old['clock'] if old else None
                valid = elapsed is not None and elapsed>0
                cpu = (ticks-old['cpu_ticks'])/hz/elapsed*100 if valid and ticks>=old['cpu_ticks'] else None
                def delta(value, key):
                    before = old[key] if old else None
                    return value-before if valid and value is not None and before is not None and value>=before else None
                rss_bytes = rss*page if rss>=0 else None
                rows.append(dict(boot_id=boot,pid=int(entry.name),start_ticks=start,uid=uid,
                    user=users.get(uid),name=name,unit=unit,clock=stamp,cpu_ticks=ticks,
                    rss_bytes=rss_bytes,ram_percent=rss_bytes/total*100 if rss_bytes is not None and total else None,
                    read_bytes=reads,write_bytes=writes,interval_seconds=elapsed if valid else None,
                    cpu_percent=cpu,read_delta=delta(reads,'read_bytes'),write_delta=delta(writes,'write_bytes')))
            except (OSError,ValueError,IndexError):
                unreadable += 1
    return dict(timestamp=now,boot_id=boot,complete=complete,visible=visible,
                unreadable=unreadable,duration_ms=(clock()-started)*1000,rows=rows)


def collect_process_history(scope, config, db):
    result = CollectionResult(scope)
    result.process_snapshot = scan_processes(db, config['process_history'])
    if result.process_snapshot and not result.process_snapshot['complete']:
        result.errors.append('process_history: scan deadline exceeded; coverage incomplete')
    return result
