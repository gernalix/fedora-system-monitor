"""Bounded, read-only current/raw/hourly process queries."""
from datetime import datetime, timezone
import time
import sqlite3
from . import _connection, _rows


def add_parser(subparsers):
    p = subparsers.add_parser('process-history', help='current, raw and hourly process CPU/RAM/disk history')
    p.add_argument('view', choices=('current','raw','hourly'), nargs='?', default='current')
    p.add_argument('--name', default='')
    p.add_argument('--pid', type=int)
    p.add_argument('--unit', default='')
    p.add_argument('--boot-id', default='')
    p.add_argument('--since-hours', type=float, default=24)
    p.add_argument('--limit', type=int, default=100)
    p.add_argument('--offset', type=int, default=0)
    p.add_argument('--sort', choices=('time','cpu','ram','read','write'), default='time')


def report(path, args):
    try:
        return _report(path, args)
    except sqlite3.OperationalError as exc:
        if str(exc) == 'interrupted':
            raise ValueError('process history query deadline exceeded; narrow the time range or filters') from exc
        raise ValueError('process history database unavailable or incompatible') from exc


def _report(path, args):
    if not 1 <= args.limit <= 1000 or not 0 <= args.offset <= 100000 or not 0 < args.since_hours <= 24*365:
        raise ValueError('limit 1..1000, offset 0..100000, since-hours >0..8760 required')
    if args.view == 'hourly' and (args.pid is not None or args.boot_id):
        raise ValueError('hourly data groups by name/user/unit; PID and boot filters require raw')
    clauses, params = [], []
    hourly = args.view == 'hourly'
    for flag, column in ((args.name,'name'),(args.unit,'unit')):
        if flag:
            clauses.append(f'i.{column} LIKE ? ESCAPE "\\"')
            params.append('%'+flag.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%')
    if args.pid is not None:
        clauses.append('i.pid=?'); params.append(args.pid)
    if args.boot_id:
        clauses.append('i.boot_id=?'); params.append(args.boot_id)
    with _connection(path) as c:
        c.set_progress_handler(lambda: int(time.monotonic()>deadline),10000)
        deadline = time.monotonic()+2
        if not c.execute("SELECT 1 FROM sqlite_master WHERE name='process_scans'").fetchone():
            return {'available':False, 'reason':'process history schema not installed', 'rows':[]}
        scan = c.execute('SELECT * FROM process_scans ORDER BY id DESC LIMIT 1').fetchone()
        if hourly:
            clauses.append('i.hour>=?'); params.append(time.time()-args.since_hours*3600)
            sort = {'time':'hour','cpu':'cpu_peak_percent','ram':'rss_peak_bytes','read':'read_bytes','write':'write_bytes'}[args.sort]
            sql = 'SELECT i.* FROM process_hourly i'
        else:
            if args.view == 'current':
                clauses.append('s.scan_id=?'); params.append(scan['id'] if scan else -1)
            else:
                clauses.append('b.timestamp>=?'); params.append(time.time()-args.since_hours*3600)
            sort = {'time':'b.timestamp','cpu':'s.cpu_percent','ram':'s.rss_bytes','read':'s.read_delta/s.interval_seconds','write':'s.write_delta/s.interval_seconds'}[args.sort]
            sql = '''SELECT b.timestamp,b.complete,b.unreadable,i.boot_id,i.pid,i.start_ticks,
                i.uid,i.user,i.name,i.unit,s.rss_bytes,s.ram_percent,s.cpu_percent,
                s.read_bytes,s.write_bytes,s.interval_seconds,s.read_delta,s.write_delta,
                s.read_delta/s.interval_seconds AS read_bytes_per_second,
                s.write_delta/s.interval_seconds AS write_bytes_per_second
                FROM process_samples s JOIN process_scans b ON b.id=s.scan_id
                JOIN process_identities i ON i.id=s.identity_id'''
        # Stable tie breakers make offset pagination deterministic at a fixed snapshot.
        tie = 'i.hour,i.name,i.uid,i.unit' if hourly else 's.scan_id,i.id'
        rows = _rows(c,sql+' WHERE '+' AND '.join(clauses or ['1=1'])+f' ORDER BY {sort} DESC,{tie} LIMIT ? OFFSET ?',(*params,args.limit+1,args.offset))
        more = len(rows)>args.limit
        rows = rows[:args.limit]
        for row in rows:
            stamp = row.get('timestamp',row.get('hour'))
            row['timestamp_utc'] = datetime.fromtimestamp(stamp,timezone.utc).isoformat()
        return {'available':True,'view':args.view,'latest_scan':dict(scan) if scan else None,
            'cpu_convention':'100% = one logical CPU; multicore can exceed 100%; null = unavailable',
            'rows':rows,'limit':args.limit,'offset':args.offset,
            'next_offset':args.offset+args.limit if more else None}
