"""Opt-in reproducible fixture benchmark; no live collector or runtime writes.

PYTHONPATH=src:tests python3 tests/benchmark_process_history.py
"""
from pathlib import Path
import json
import tempfile
import time
import tracemalloc
from test_process_history import proc, BOOT, OPTIONS
from fedora_system_monitor.capsules.collectors.process_history import scan_processes
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.database.process_history import persist, maintain


def benchmark(processes=600, minutes=2880):
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)/'proc';(root/'sys/kernel/random').mkdir(parents=True)
        (root/'sys/kernel/random/boot_id').write_text(BOOT)
        (root/'meminfo').write_text('MemTotal: 16000000 kB\n')
        for pid in range(processes):
            proc(root,pid,name=f'worker-{pid%60}',unit=f'worker-{pid%60}.service')
        db=Database(Path(tmp)/'monitor.sqlite3')
        try:
            stamp=int(time.time()//3600)*3600-48*3600
            cpu_start=time.process_time()
            start=time.perf_counter()
            snap=scan_processes(db,OPTIONS,root=root,wall=lambda:stamp)
            scan_ms=(time.perf_counter()-start)*1000
            scan_cpu_ms=(time.process_time()-cpu_start)*1000
            tracemalloc.start()
            scan_processes(db,OPTIONS,root=root,wall=lambda:stamp)
            _, scan_peak=tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert snap['complete'] and len(snap['rows'])==processes
            start=time.perf_counter();db.insert_process_snapshot(snap,OPTIONS)
            first_write_ms=(time.perf_counter()-start)*1000
            # Same private DB and owner functions; batch transaction avoids measuring
            # 2,880 filesystem fsyncs while retaining the actual row/index costs.
            start=time.perf_counter()
            with db._transaction() as c:
                for minute in range(1,minutes):
                    snap['timestamp']=stamp+minute*60
                    for row in snap['rows']:
                        if minute%60==0 and row['pid']%100==0:
                            row['start_ticks']+=1  # 1% hourly PID churn
                        row.update(clock=minute*60,cpu_ticks=minute*10,interval_seconds=60,
                            cpu_percent=(row['pid']%10)/10,read_bytes=minute*4096,
                            write_bytes=minute*8192,read_delta=4096,write_delta=8192)
                    persist(c,snap)
                    maintain(c,now=snap['timestamp'],raw_hours=48,aggregate_days=90)
            elapsed=time.perf_counter()-start
            db.query('PRAGMA wal_checkpoint(TRUNCATE)')
            raw_bytes=db.path.stat().st_size
            with db._transaction() as c:
                # Fill 90 days of grouped hourly rows with actual SQLite encoding.
                c.execute('CREATE TEMP TABLE hourly_template AS SELECT * FROM process_hourly WHERE hour=?',(stamp,))
                for hour in range(48,90*24):
                    c.execute('INSERT INTO process_hourly SELECT ?,name,uid,user,unit,samples,cpu_samples,cpu_seconds,cpu_peak_percent,rss_samples,rss_avg_bytes,rss_peak_bytes,ram_peak_percent,read_samples,read_bytes,write_samples,write_bytes,interval_seconds FROM hourly_template',(stamp+hour*3600,))
            db.query('PRAGMA wal_checkpoint(TRUNCATE)')
            return dict(processes=processes,minutes=minutes,samples=processes*minutes,
                fixture_scan_ms=round(scan_ms,2),fixture_scan_cpu_ms=round(scan_cpu_ms,2),
                fixture_scan_peak_python_bytes=scan_peak,first_batch_write_ms=round(first_write_ms,2),
                replay_seconds=round(elapsed,2),replay_ms_per_minute=round(elapsed/minutes*1000,2),
                database_48h_bytes=raw_bytes,database_48h_plus_90d_bytes=db.path.stat().st_size,
                bytes_per_raw_sample=round(raw_bytes/(processes*minutes),2),
                hourly_rows=db.query('SELECT COUNT(*) n FROM process_hourly')[0]['n'])
        finally:
            db.close()

if __name__=='__main__': print(json.dumps(benchmark(),sort_keys=True))
