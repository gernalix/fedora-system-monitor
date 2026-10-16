from argparse import Namespace
from copy import deepcopy
from pathlib import Path
import io
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout, closing

from fedora_system_monitor.capsules.collectors.process_history import scan_processes, _stat, _unit
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.database.process_history import maintain
from fedora_system_monitor.capsules.config import load_config, validate_config
from fedora_system_monitor.capsules.reporting.process_history import report
from fedora_system_monitor.app import main

OPTIONS = dict(interval_seconds=60,max_scan_seconds=5,raw_hours=48,aggregate_days=90)
BOOT = '12345678-1234-1234-1234-123456789abc'


def proc(root,pid=42,*,start=100,ticks=100,reads=0,writes=0,name='prompt-history-sync',unit='prompt-history-sync.service'):
    p=root/str(pid);p.mkdir(exist_ok=True)
    fields = ['S']+['0']*21
    fields[11]=str(ticks);fields[19]=str(start);fields[21]='10'
    (p/'stat').write_text(f'{pid} ({name}) '+ ' '.join(fields))
    (p/'status').write_text('Uid:\t1000\t1000\t1000\t1000\n')
    (p/'io').write_text(f'read_bytes: {reads}\nwrite_bytes: {writes}\n')
    (p/'cgroup').write_text(f'0::/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}\n')
    return p


class ProcessHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'proc'; self.root.mkdir()
        (self.root/'sys/kernel/random').mkdir(parents=True)
        (self.root/'sys/kernel/random/boot_id').write_text(BOOT)
        (self.root/'meminfo').write_text('MemTotal: 1000 kB\n')
        self.db=Database(Path(self.tmp.name)/'db'); self.addCleanup(self.db.close)
        self.wall=time.time(); self.tick=1000.

    def scan(self, persist=True):
        snap=scan_processes(self.db,OPTIONS,root=self.root,clock=lambda:self.tick,wall=lambda:self.wall)
        if persist and snap:
            self.db.insert_process_snapshot(snap,OPTIONS)
        return snap

    def advance(self):
        self.tick+=60; self.wall+=60

    def args(self,**kwargs):
        return Namespace(**(dict(view='current',name='',pid=None,unit='',boot_id='',since_hours=24,
                                limit=100,offset=0,sort='time')|kwargs))

    def test_delta_multicore_rss_io_and_queries(self):
        proc(self.root)
        first=self.scan()['rows'][0]
        self.assertIsNone(first['cpu_percent']);self.assertIsNone(first['read_delta'])
        self.advance();proc(self.root,ticks=100+os.sysconf('SC_CLK_TCK')*120,reads=600,writes=1200)
        r=self.scan()['rows'][0]
        self.assertEqual(r['cpu_percent'],200); self.assertEqual(r['read_delta'],600)
        self.assertEqual(r['rss_bytes'],10*os.sysconf('SC_PAGE_SIZE'))
        self.assertAlmostEqual(r['ram_percent'],r['rss_bytes']/1024000*100)
        self.db.query("PRAGMA wal_checkpoint(TRUNCATE)")
        found=report(self.db.path,self.args(name='prompt-history',unit='history-sync',pid=42))['rows']
        self.assertEqual(len(found),1);self.assertEqual(found[0]['read_bytes_per_second'],10)
        self.assertEqual(found[0]['unit'],'prompt-history-sync.service')
        self.assertNotIn('/user.slice',json.dumps(found))

    def test_unavailable_zero_reset_exit_pid_reuse_and_reboot(self):
        p=proc(self.root);self.scan();self.advance()
        proc(self.root);r=self.scan()['rows'][0]
        self.assertEqual(r['cpu_percent'],0);self.assertEqual(r['read_delta'],0)
        self.advance();(p/'io').unlink();(p/'status').unlink()
        r=self.scan()['rows'][0];self.assertIsNone(r['read_bytes']);self.assertIsNone(r['uid'])
        self.advance();proc(self.root,ticks=50,reads=100);r=self.scan()['rows'][0]
        self.assertIsNone(r['cpu_percent']);self.assertIsNone(r['read_delta'])
        self.advance();proc(self.root,start=200);r=self.scan()['rows'][0]
        self.assertIsNone(r['cpu_percent'])
        self.advance();(self.root/'sys/kernel/random/boot_id').write_text('22345678-1234-1234-1234-123456789abc')
        r=self.scan()['rows'][0];self.assertIsNone(r['cpu_percent'])
        self.advance();(p/'stat').unlink();snap=self.scan()
        self.assertEqual(snap['rows'],[]);self.assertEqual(snap['unreadable'],1)
        self.assertEqual(snap['visible'],1)
        self.assertIsNone(self.scan()) # cadence gate

    def test_permissions_and_incomplete_scan_are_explicit(self):
        p=proc(self.root)
        from fedora_system_monitor.capsules.collectors import process_history as mod
        read=mod._read
        def guarded(path,*args):
            if path==p/'io': raise PermissionError('fixture')
            return read(path,*args)
        with patch.object(mod,'_read',side_effect=guarded):
            snap=self.scan(False)
        self.assertIsNone(snap['rows'][0]['read_bytes'])
        with patch.object(mod,'_read',side_effect=guarded):
            ticks=iter([0,10,10])
            snap=scan_processes(self.db,OPTIONS,root=self.root,clock=lambda:next(ticks),wall=lambda:self.wall)
        self.assertFalse(snap['complete']);self.assertEqual(snap['rows'],[])

    def test_pid_reused_mid_read_is_discarded_and_stat_with_parentheses(self):
        p=proc(self.root,name='a ) b (c)')
        self.assertEqual(_stat((p/'stat').read_text())[0],'a ) b (c)')
        from fedora_system_monitor.capsules.collectors import process_history as mod
        read=mod._read; count=0
        def changing(path,*args):
            nonlocal count
            if path==p/'stat':
                count+=1
                if count==2: proc(self.root,start=999)
            return read(path,*args)
        with patch.object(mod,'_read',side_effect=changing):
            snap=self.scan(False)
        self.assertEqual(snap['unreadable'],1);self.assertEqual(snap['rows'],[])
        self.assertIsNone(_unit('0::/personal/private/file'))

    def test_hourly_rollup_late_sample_idempotence_and_retention(self):
        self.wall=int(time.time()//3600)*3600-7200
        proc(self.root);self.scan();self.advance()
        proc(self.root,ticks=100+os.sysconf('SC_CLK_TCK')*60,reads=300)
        self.scan()
        hour=int(self.wall//3600)*3600
        def maintenance(now):
            with self.db._transaction() as c:
                return maintain(c,now=now,raw_hours=48,aggregate_days=90)
        maintenance(hour+3600)
        rows=self.db.query('SELECT * FROM process_hourly')
        self.assertEqual(rows[0]['samples'],2);self.assertEqual(rows[0]['cpu_seconds'],60)
        self.assertEqual(rows[0]['read_bytes'],300);self.assertEqual(rows[0]['read_samples'],1)
        maintenance(hour+3600);self.assertEqual(rows,self.db.query('SELECT * FROM process_hourly'))
        self.advance();proc(self.root,ticks=100+os.sysconf('SC_CLK_TCK')*60,reads=300);self.scan()
        maintenance(hour+3600)
        self.assertEqual(self.db.query('SELECT samples FROM process_hourly')[0]['samples'],3)
        maintenance(hour+49*3600)
        self.assertEqual(self.db.query('SELECT * FROM process_samples'),[])
        self.assertEqual(self.db.query('SELECT * FROM process_identities'),[])
        self.assertTrue(self.db.query('SELECT * FROM process_hourly'))
        maintenance(hour+91*86400);self.assertEqual(self.db.query('SELECT * FROM process_hourly'),[])
        self.assertTrue(self.db.db_check()['ok'])

    def test_additive_migration_backup_preservation_and_retry(self):
        self.db.insert_metrics({'name':'kept','value':42},cadence_seconds=60)
        with self.db._transaction() as c:
            for table in ('process_samples','process_identities','process_scans','process_hourly'):
                c.execute(f'DROP TABLE {table}')
            c.execute('DELETE FROM schema_versions WHERE version=6')
        self.db.initialize()
        backups=list(self.db.path.parent.glob('db.pre-v6-*.bak'));self.assertEqual(len(backups),1)
        with closing(sqlite3.connect(backups[0])) as c:
            self.assertEqual(c.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(c.execute('SELECT MAX(version) FROM schema_versions').fetchone()[0],5)
        self.assertEqual(self.db.query('SELECT value FROM periodic_metrics')[0]['value'],42)
        self.db.initialize();self.assertEqual(len(list(self.db.path.parent.glob('db.pre-v6-*.bak'))),1)
        self.assertEqual(self.db.path.stat().st_mode & 0o777,0o640)

    def test_cli_readonly_pagination_literal_filters_and_config_bounds(self):
        for pid in range(10): proc(self.root,pid)
        self.scan();self.db.query("PRAGMA wal_checkpoint(TRUNCATE)")
        before=self.db.path.read_bytes();out=io.StringIO()
        config=Path(__file__).resolve().parents[1]/'config/fedora-system-monitor.toml'
        with redirect_stdout(out):
            result=main(['--config',str(config),'--database',str(self.db.path),'process-history','--json','--limit','3'])
        self.assertEqual(result,0);data=json.loads(out.getvalue())
        self.assertEqual(len(data['rows']),3);self.assertEqual(data['next_offset'],3)
        page=report(self.db.path,self.args(limit=3,offset=3))['rows']
        self.assertTrue(set(r['pid'] for r in page).isdisjoint(r['pid'] for r in data['rows']))
        self.assertEqual(report(self.db.path,self.args(name="%' OR 1=1 --"))['rows'],[])
        self.assertEqual(self.db.path.read_bytes(),before)
        with self.assertRaises(ValueError): report(self.db.path,self.args(limit=1001))
        with self.assertRaises(ValueError): report(self.db.path,self.args(view='hourly',pid=42))
        config=load_config(None);config['process_history']['max_scan_seconds']=100
        self.assertTrue(validate_config(config))

    def test_coordinator_persists_all_fixture_processes(self):
        from fedora_system_monitor.capsules.collectors.model import CollectionResult
        from fedora_system_monitor.capsules.runtime.coordinator import _run_scope
        for pid in range(12): proc(self.root,pid)
        fixture=CollectionResult("minute",process_snapshot=self.scan(False))
        config=load_config(None)
        with patch("fedora_system_monitor.capsules.runtime.coordinator.collect_scope",return_value=fixture), patch("fedora_system_monitor.capsules.runtime.coordinator._persist_signals",return_value=[]):
            output=_run_scope('minute',config,self.db)
        self.assertEqual(output['maintenance']['process_history']['samples'],12)
        self.assertEqual(self.db.query('SELECT COUNT(*) n FROM process_samples')[0]['n'],12)

    def test_privacy_allowlist_and_transaction_rollback(self):
        proc(self.root)
        from fedora_system_monitor.capsules.collectors import process_history as mod
        read=mod._read; observed=[]
        def tracked(path,*args):
            observed.append(path.name)
            return read(path,*args)
        with patch.object(mod,'_read',side_effect=tracked):
            snap=self.scan(False)
        self.assertTrue(set(observed)<= {'boot_id','meminfo','passwd','stat','status','io','cgroup'})
        with patch('fedora_system_monitor.capsules.database.process_history.maintain',side_effect=RuntimeError('fixture')):
            with self.assertRaises(RuntimeError): self.db.insert_process_snapshot(snap,OPTIONS)
        self.assertEqual(self.db.query('SELECT * FROM process_scans'),[])
        self.assertEqual(self.db.query('SELECT * FROM process_samples'),[])

    def test_minute_registration_and_unchanged_top_five(self):
        from fedora_system_monitor.capsules import collectors
        from fedora_system_monitor.capsules.collectors import periodic
        from fedora_system_monitor.capsules.command import CommandResult
        self.assertIn(('process_history',collectors.collect_process_history),collectors._COLLECTORS['minute'])
        text='\n'.join(f'{p} test executable {p}.0 1.0 S' for p in range(10))
        with patch.object(periodic,'external',return_value=CommandResult(('ps',),0,text,'',1)):
            result=periodic.collect_processes('five_minute',{'collection':{'top_process_limit':5}},None)
        top=next(r for r in result.metrics if r['name']=='top_cpu_process_count')
        self.assertEqual(len(top['details']['processes']),5)
        self.assertEqual(top['details']['processes'][0]['pid'],9)

if __name__=='__main__': unittest.main()
