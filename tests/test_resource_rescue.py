from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
from contextlib import redirect_stdout
import io
import json
import os
import signal
import subprocess
import tempfile
import time
import unittest

from fedora_system_monitor.capsules.resource_rescue.pressure import Sample,Risk,Gate,classify,clearly_healthy,sample
from fedora_system_monitor.capsules.resource_rescue.targets import Identity,Candidate,Snapshot,same,protected,terminate,candidates
from fedora_system_monitor.capsules.resource_rescue.watch import session_unlocked,oomd_status,watch
from fedora_system_monitor.capsules.config import load_config,validate_config
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.app import main

CFG=load_config(None)['resource_rescue']

def metrics(at=100,**values):
    return replace(Sample(at,50,0,0,0,1024,0,0,0),**values)

def target(**values):
    return replace(Identity('boot',999999,100,1000,'firefox','0::/user.slice/app-fixture.scope',1024),**values)


class PressureTests(unittest.TestCase):
    def test_allocated_ram_swap_or_cpu_alone_are_not_oom(self):
        for s in (metrics(swap_used=90*1024**3),metrics(available=8),metrics(memory_some=.5)):
            self.assertEqual(classify(s,CFG).level,0)

    def test_warning_precedes_existing_critical_threshold(self):
        g=Gate(CFG)
        self.assertEqual(g.step(metrics(100,available=12,memory_some=4))[0],'debounce')
        event,risk=g.step(metrics(106,available=12,memory_some=4))
        self.assertEqual(event,'open');self.assertEqual(risk.level,1)
        self.assertGreater(12,CFG['emergency_available'])
        self.assertEqual(classify(metrics(available=4,memory_some=4),CFG).level,2)
        self.assertEqual(classify(metrics(oom=1),CFG).level,2)

    def test_psi_event_wakes_early_with_low_available(self):
        self.assertEqual(classify(metrics(available=12,memory_some=0),CFG,triggered=True).level,1)
        self.assertEqual(classify(metrics(available=50,memory_some=0),CFG,triggered=True).level,0)

    def test_missing_and_reset_metrics_do_not_become_zero(self):
        self.assertEqual(classify(metrics(available=None),CFG).kind,'unknown')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'pressure').mkdir()
            (root/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 1000 kB\nSwapFree: 100 kB\n')
            (root/'vmstat').write_text('pswpout 1\noom_kill 0\npgscan_kswapd 2\n')
            s,state=sample(root=root,volumes=(),now=100)
            self.assertIsNone(s.swap_out);self.assertIsNone(s.memory_some)
            s,_=sample((99,{'pswpout':5,'oom_kill':4}),root=root,volumes=(),now=101)
            self.assertIsNone(s.swap_out);self.assertIsNone(s.oom)
            self.assertEqual(s.swap_used,900*1024)

    def test_debounce_snooze_escalation_recovery_and_relapse(self):
        g=Gate(CFG)
        bad=lambda at:metrics(at,available=12,memory_some=4)
        g.step(bad(100));self.assertEqual(g.step(bad(106))[0],'open')
        g.dismissed(106)
        self.assertEqual(g.step(bad(300))[0],'snoozed')
        self.assertEqual(g.step(metrics(300,available=2,memory_some=4))[0],'open')
        self.assertEqual(g.step(metrics(301))[0],'healthy')
        self.assertEqual(g.step(metrics(306))[0],'healthy')
        self.assertEqual(g.step(metrics(311))[0],'recovered')
        g.step(bad(1000));self.assertEqual(g.step(bad(1006))[0],'open')

    def test_single_dialog_no_popup_storm_or_fake_recovery(self):
        g=Gate(CFG)
        bad=lambda at:metrics(at,memory_full=8)
        self.assertEqual(g.step(bad(100))[0],'open')
        for at in range(101,200): self.assertEqual(g.step(bad(at),dialog_active=True)[0],'active')
        self.assertEqual(g.step(metrics(201,available=16))[0],'healthy')
        self.assertNotEqual(g.step(metrics(210,available=16))[0],'recovered') # hysteresis
        self.assertEqual(g.step(metrics(211,memory_full=None))[0],'unknown')

    def test_disk_and_io_get_distinct_remedies(self):
        v={'mount':'/','free_percent':1,'free_bytes':100,'inode_percent':50}
        self.assertEqual(classify(metrics(volumes=[v]),CFG).kind,'disk')
        self.assertEqual(classify(metrics(io_full=20),CFG).kind,'io')
        self.assertFalse(clearly_healthy(metrics(volumes=[v]),CFG))

    def test_small_efi_volume_does_not_trigger_absolute_gib_floor(self):
        v={'mount':'/boot/efi','total_bytes':600*1024**2,'free_bytes':300*1024**2,'free_percent':50,'inode_percent':None}
        self.assertEqual(classify(metrics(volumes=[v]),CFG).kind,'healthy')
        self.assertTrue(clearly_healthy(metrics(volumes=[v]),CFG))
        v['free_percent']=1
        self.assertEqual(classify(metrics(volumes=[v]),CFG).kind,'disk')

    def test_locked_pending_then_unlocked_dispatch(self):
        g=Gate(CFG)
        self.assertEqual(g.step(metrics(memory_full=8),locked=True)[0],'pending')
        self.assertTrue(g.state['pending'])
        self.assertEqual(g.step(metrics(106,memory_full=8),locked=False)[0],'open')


class TargetTests(unittest.TestCase):
    def test_protected_names_users_and_work_sessions(self):
        for name in ('gnome-shell','systemd','sshd','bash','zsh','tmux','codex','python3','node','fedora-system-monitor'):
            self.assertTrue(protected(target(name=name),1000),name)
        self.assertTrue(protected(target(uid=0),1000))
        self.assertTrue(protected(target(cgroup='0::/app-gnome-terminal.scope'),1000))
        self.assertTrue(protected(target(cgroup='0::/app-codex.scope'),1000))
        self.assertFalse(protected(target(cgroup='0::/app-gnome-firefox.scope'),1000))
        self.assertFalse(protected(target(name='gnome-text-edit'),1000))

    def test_pid_boot_cgroup_name_uid_reuse(self):
        a=target()
        for b in (replace(a,start=2),replace(a,boot='new'),replace(a,uid=0),replace(a,cgroup='changed'),replace(a,name='replaced')):
            self.assertFalse(same(a,b))

    def snapshot(self):
        i=target();return Snapshot('token',100,(Candidate(i,(i,),1024,'fixture'),))

    def test_explicit_confirmation_staleness_and_invalid_number(self):
        for number,confirmed,clock,error in ((1,False,100,PermissionError),(0,True,100,ValueError),(1,True,121,ValueError)):
            with patch('os.pidfd_open') as opener:
                with self.assertRaises(error):terminate(self.snapshot(),number,1000,confirmed=confirmed,clock=lambda:clock)
                opener.assert_not_called()

    def test_reused_identity_no_signal_even_with_open_pidfd(self):
        with patch('os.pidfd_open',return_value=123),patch('os.close'),patch('select.poll') as poll,patch('fedora_system_monitor.capsules.resource_rescue.targets.identity',return_value=target(start=200)),patch('signal.pidfd_send_signal') as send:
            poll.return_value.poll.return_value=[]
            with self.assertRaises(PermissionError):terminate(self.snapshot(),1,1000,confirmed=True,clock=lambda:101)
            send.assert_not_called()

    def test_permission_denied_and_exit_failure_no_sigkill(self):
        with patch('os.pidfd_open',side_effect=PermissionError),patch('signal.pidfd_send_signal') as send:
            with self.assertRaises(PermissionError):terminate(self.snapshot(),1,1000,confirmed=True,clock=lambda:101)
            send.assert_not_called()
        with patch('os.pidfd_open',return_value=123),patch('os.close'),patch('select.poll') as poll,patch('fedora_system_monitor.capsules.resource_rescue.targets.identity',return_value=target()),patch('signal.pidfd_send_signal') as send:
            poll.return_value.poll.return_value=[]
            self.assertEqual(terminate(self.snapshot(),1,1000,confirmed=True,clock=lambda:101,timeout=0),'not_exited')
            send.assert_called_once_with(123,signal.SIGTERM)

    def test_real_pidfd_on_disposable_child_only(self):
        # A child created by this test, never a user's existing application.
        child=subprocess.Popen(['sleep','30'])
        self.addCleanup(lambda:child.poll() is None and child.terminate())
        from fedora_system_monitor.capsules.resource_rescue.targets import identity
        original=identity(child.pid)
        i=replace(original,cgroup='0::/app-fixture.scope')
        snap=Snapshot('fixture',time.monotonic(),(Candidate(i,(i,),0,'fixture'),))
        calls=0
        def controlled_identity(pid,root):
            nonlocal calls
            calls+=1
            if calls>1 and child.poll() is not None: raise ProcessLookupError()
            return i
        with patch('fedora_system_monitor.capsules.resource_rescue.targets.identity',side_effect=controlled_identity):
            self.assertEqual(terminate(snap,1,os.getuid(),confirmed=True,timeout=3),'exited')
        child.wait(timeout=3);self.assertEqual(child.returncode,-signal.SIGTERM)

    def test_private_memory_no_shared_rss_sum_and_io_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            items=[target(pid=501,rss=1000),target(pid=502,start=101,rss=1000)]
            for i in items:
                p=root/str(i.pid);p.mkdir()
                (p/'smaps_rollup').write_text('Private_Clean: 1 kB\nPrivate_Dirty: 2 kB\n')
                (p/'io').write_text('read_bytes: 4096\nwrite_bytes: 4096\n')
            def ident(pid,root): return next(i for i in items if i.pid==pid)
            with patch('fedora_system_monitor.capsules.resource_rescue.targets.identity',side_effect=ident):
                s=candidates(1000,root=root)
                self.assertEqual(len(s.candidates),1)
                self.assertEqual(s.candidates[0].estimated_bytes,6*1024)
                self.assertEqual(s.candidates[0].basis,'privata stimata (USS)')
                (root/'501'/'smaps_rollup').unlink();(root/'502'/'smaps_rollup').unlink()
                s=candidates(1000,root=root)
                self.assertEqual(s.candidates[0].estimated_bytes,1000) # max RSS, never sum
                self.assertIn('incerto',s.candidates[0].basis)


class IntegrationTests(unittest.TestCase):
    def test_cli_status_readonly_and_no_browser_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'db';db=Database(p)
            db.set_state('incident',{'level':1,'sample':{'available':12}},namespace='resource_rescue');db.close()
            out=io.StringIO();config=Path(tmp)/'config.toml';config.write_text('')
            with redirect_stdout(out): code=main(['--config',str(config),'--database',str(p),'resource-rescue','status','--json'])
            self.assertEqual(code,0);self.assertEqual(json.loads(out.getvalue())['incident']['level'],1)
            text=out.getvalue();self.assertNotIn('title',text);self.assertNotIn('url',text)

    def test_session_gates_missing_locked_inactive_and_wayland(self):
        def result(out,rc=0):return SimpleNamespace(stdout=out,returncode=rc)
        for state,expected in [('Type=wayland\nActive=yes\nLockedHint=no\nRemote=no',True),('Type=wayland\nActive=yes\nLockedHint=yes\nRemote=no',False),('Type=tty\nActive=yes\nLockedHint=no\nRemote=no',False),('',False)]:
            with patch('fedora_system_monitor.capsules.resource_rescue.watch.command',side_effect=[result('3'),result(state)]):
                self.assertEqual(session_unlocked('fixture'),expected)

    def test_disabled_watch_has_no_side_effects(self):
        config=load_config(None);config['resource_rescue']['enabled']=False
        db=Mock();watch(config,db,Mock());db.set_state.assert_not_called()

    def test_config_bounds(self):
        for key,value in [('idle_seconds',.01),('active_seconds',0),('minimum_popup_seconds',1),('dialog_timeout_seconds',9999)]:
            cfg=load_config(None);cfg['resource_rescue'][key]=value
            self.assertTrue(validate_config(cfg),key)

    def test_native_capabilities_reject_personal_data_and_bound_frames(self):
        import struct
        from fedora_system_monitor.capsules.resource_rescue.chrome_host import receive,persist
        value={'session':'a'*32,'processes_exposed':False,'tabs_available':True,'browser_major':153}
        def frame(value):
            b=json.dumps(value).encode();return io.BytesIO(struct.pack('<I',len(b))+b)
        self.assertEqual(receive(frame(value)),value)
        with self.assertRaises(ValueError):receive(frame({**value,'title':'private'}))
        with self.assertRaises(ValueError):receive(frame({**value,'url':'https://private.test'}))
        with self.assertRaises(ValueError):receive(io.BytesIO(struct.pack('<I',999999)))
        with tempfile.TemporaryDirectory() as tmp:
            persist(value,tmp);p=Path(tmp)/'fsm-chrome-capabilities.json'
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertNotIn('private',p.read_text())

    def test_normal_close_does_not_fall_back_to_signal(self):
        i=target();snap=Snapshot('token',100,(Candidate(i,(i,),1,'fixture'),))
        close=Mock(return_value=True)
        with patch('os.pidfd_open',return_value=123),patch('os.close'),patch('select.poll') as poll,patch('fedora_system_monitor.capsules.resource_rescue.targets.identity',return_value=i),patch('signal.pidfd_send_signal') as send:
            poll.return_value.poll.return_value=[]
            self.assertEqual(terminate(snap,1,1000,confirmed=True,clock=lambda:101,timeout=0,normal_close=close),'not_exited')
            send.assert_not_called();close.assert_called_once()

    def test_watcher_uses_existing_fsm_database_and_one_dialog(self):
        from itertools import count
        class Stop:
            calls=0
            def is_set(self):self.calls+=1;return self.calls>5
            def wait(self,_):pass
        class DB:
            states=[];events=[]
            def get_state(self,*args,**kwargs):return {}
            def set_state(self,key,value,**kwargs):self.states.append((key,value))
            def insert_events(self,value):self.events.append(value)
        db=DB();ticks=count(100,10)
        def take(*args,**kwargs):return metrics(next(ticks),memory_full=8),None
        result=SimpleNamespace(stdout='',returncode=0)
        calls=[]
        def cmd(args):
            calls.append(args)
            if 'show' in args:return SimpleNamespace(stdout='ActiveState=activating\nExecMainStatus=0',returncode=0)
            return result
        with patch('fedora_system_monitor.capsules.resource_rescue.watch.psi_triggers',return_value=[]),patch('fedora_system_monitor.capsules.resource_rescue.watch.oomd_status',return_value={}),patch('fedora_system_monitor.capsules.resource_rescue.watch.session_unlocked',return_value=True),patch('fedora_system_monitor.capsules.resource_rescue.watch.time.monotonic',side_effect=lambda:next(ticks)),patch('fedora_system_monitor.capsules.resource_rescue.watch.sample',side_effect=take),patch('fedora_system_monitor.capsules.resource_rescue.watch.command',side_effect=cmd):
            watch(load_config(None),db,Stop())
        self.assertEqual(sum('start' in c for c in calls),1)
        self.assertTrue(any(key=='incident' for key,value in db.states))
        self.assertNotIn('title',json.dumps(db.states))

    def test_browser_minimal_permissions_and_no_persistence(self):
        root=Path(__file__).resolve().parents[1]/'chrome/resource-rescue'
        manifest=json.loads((root/'manifest.json').read_text())
        self.assertEqual(manifest['permissions'],['tabs','nativeMessaging']);self.assertNotIn('host_permissions',manifest)
        source=(root/'popup.js').read_text()+(root/'model.js').read_text()
        self.assertNotIn('chrome.storage',source);self.assertNotIn('localStorage',source)
        self.assertNotIn('fetch(',source);self.assertNotIn('chrome.debugger',source)

if __name__=='__main__':unittest.main()
