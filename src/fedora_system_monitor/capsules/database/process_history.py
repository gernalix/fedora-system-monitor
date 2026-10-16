"""Compact process history in the monitor's existing database; no generic metrics."""
from datetime import datetime, timezone

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS process_scans (
        id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, boot_id TEXT NOT NULL,
        complete INTEGER NOT NULL, visible INTEGER NOT NULL, unreadable INTEGER NOT NULL,
        duration_ms REAL NOT NULL, rolled INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX IF NOT EXISTS idx_process_scans_time ON process_scans(timestamp)",
    """CREATE TABLE IF NOT EXISTS process_identities (
        id INTEGER PRIMARY KEY, boot_id TEXT NOT NULL, pid INTEGER NOT NULL,
        start_ticks INTEGER NOT NULL, uid INTEGER, user TEXT, name TEXT NOT NULL, unit TEXT,
        UNIQUE(boot_id,pid,start_ticks,uid,name,unit))""",
    "CREATE INDEX IF NOT EXISTS idx_process_identity_pid ON process_identities(pid)",
    "CREATE INDEX IF NOT EXISTS idx_process_identity_name ON process_identities(name)",
    "CREATE INDEX IF NOT EXISTS idx_process_identity_unit ON process_identities(unit)",
    """CREATE TABLE IF NOT EXISTS process_samples (
        scan_id INTEGER NOT NULL REFERENCES process_scans(id) ON DELETE CASCADE,
        identity_id INTEGER NOT NULL REFERENCES process_identities(id),
        clock REAL NOT NULL, cpu_ticks INTEGER NOT NULL, rss_bytes INTEGER,
        ram_percent REAL, read_bytes INTEGER, write_bytes INTEGER,
        interval_seconds REAL, cpu_percent REAL, read_delta INTEGER, write_delta INTEGER,
        PRIMARY KEY(scan_id,identity_id)) WITHOUT ROWID""",
    "CREATE INDEX IF NOT EXISTS idx_process_samples_identity ON process_samples(identity_id,scan_id)",
    """CREATE TABLE IF NOT EXISTS process_hourly (
        hour REAL NOT NULL, name TEXT NOT NULL, uid INTEGER NOT NULL, user TEXT NOT NULL,
        unit TEXT NOT NULL, samples INTEGER NOT NULL, cpu_samples INTEGER NOT NULL,
        cpu_seconds REAL, cpu_peak_percent REAL, rss_samples INTEGER NOT NULL,
        rss_avg_bytes REAL, rss_peak_bytes INTEGER, ram_peak_percent REAL,
        read_samples INTEGER NOT NULL, read_bytes INTEGER, write_samples INTEGER NOT NULL,
        write_bytes INTEGER, interval_seconds REAL,
        PRIMARY KEY(hour,name,uid,unit)) WITHOUT ROWID""",
)


def previous(db):
    """One indexed snapshot, never a per-PID query or a separate baseline store."""
    scans = db.query('SELECT * FROM process_scans ORDER BY id DESC LIMIT 1')
    if not scans:
        return None, {}
    scan = scans[0]
    rows = db.query('''SELECT i.*,s.* FROM process_samples s JOIN process_identities i
                       ON i.id=s.identity_id WHERE scan_id=?''', (scan['id'],))
    return scan, {(r['boot_id'], r['pid'], r['start_ticks']): r for r in rows}


def persist(connection, snapshot):
    scan = connection.execute('''INSERT INTO process_scans
        (timestamp,boot_id,complete,visible,unreadable,duration_ms) VALUES(?,?,?,?,?,?)''',
        tuple(snapshot[k] for k in ('timestamp','boot_id','complete','visible','unreadable','duration_ms'))).lastrowid
    # Metadata is usually unchanged for thousands of samples; cache once per batch.
    identities = {tuple(r[1:]): r[0] for r in connection.execute(
        'SELECT id,boot_id,pid,start_ticks,uid,user,name,unit FROM process_identities')}
    values = []
    for row in snapshot['rows']:
        key = tuple(row[k] for k in ('boot_id','pid','start_ticks','uid','user','name','unit'))
        identity = identities.get(key)
        if identity is None:
            identity = connection.execute('''INSERT INTO process_identities
                (boot_id,pid,start_ticks,uid,user,name,unit) VALUES(?,?,?,?,?,?,?)''', key).lastrowid
            identities[key] = identity
        values.append((scan, identity, *(row[k] for k in (
            'clock','cpu_ticks','rss_bytes','ram_percent','read_bytes','write_bytes',
            'interval_seconds','cpu_percent','read_delta','write_delta'))))
    connection.executemany('INSERT INTO process_samples VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', values)
    return len(values)


def maintain(connection, *, now, raw_hours, aggregate_days):
    """Rebuild at most 24 closed UTC hours per run, including late batches.

    Rollup and pruning share the sample transaction. Never delete unrolled rows.
    Rebuilding from retained raw rows makes exact retries and late data idempotent.
    """
    closed = int(now // 3600) * 3600
    hours = [r[0] for r in connection.execute('''SELECT DISTINCT
        CAST(timestamp/3600 AS INTEGER)*3600 AS hour FROM process_scans
        WHERE rolled=0 AND timestamp<? ORDER BY hour LIMIT 24''', (closed,))]
    for hour in hours:
        connection.execute('DELETE FROM process_hourly WHERE hour=?', (hour,))
        connection.execute('''INSERT INTO process_hourly
            SELECT ?,i.name,COALESCE(i.uid,-1),COALESCE(i.user,''),COALESCE(i.unit,''),
                COUNT(*),COUNT(s.cpu_percent),SUM(s.cpu_percent*s.interval_seconds/100.0),
                MAX(s.cpu_percent),COUNT(s.rss_bytes),AVG(s.rss_bytes),MAX(s.rss_bytes),
                MAX(s.ram_percent),COUNT(s.read_delta),SUM(s.read_delta),
                COUNT(s.write_delta),SUM(s.write_delta),SUM(s.interval_seconds)
            FROM process_samples s JOIN process_scans b ON b.id=s.scan_id
            JOIN process_identities i ON i.id=s.identity_id
            WHERE b.timestamp>=? AND b.timestamp<?
            GROUP BY i.name,COALESCE(i.uid,-1),COALESCE(i.unit,'')''', (hour,hour,hour+3600))
        connection.execute('UPDATE process_scans SET rolled=1 WHERE timestamp>=? AND timestamp<?',
                           (hour,hour+3600))
    # Whole hours avoid partially pruning a bucket that might be rebuilt later.
    cutoff = int((now-raw_hours*3600)//3600)*3600
    removed = connection.execute('DELETE FROM process_scans WHERE timestamp<? AND rolled=1', (cutoff,)).rowcount
    connection.execute('DELETE FROM process_hourly WHERE hour<?', (now-aggregate_days*86400,))
    if removed:
        connection.execute('''DELETE FROM process_identities WHERE NOT EXISTS
            (SELECT 1 FROM process_samples WHERE identity_id=process_identities.id)''')
    return {'rolled_hours':len(hours), 'pruned_scans':removed}
