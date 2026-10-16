"""PSI and adaptive checks inside FSM's existing event daemon, no new poller."""
from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import os
import re
import select
import subprocess
import time

from .pressure import sample, Gate, classify


def command(args):
    return subprocess.run(args,capture_output=True,text=True,timeout=3,check=False)


def session_unlocked(user):
    try:
        result=command(['loginctl','show-user',str(user),'-p','Sessions','--value'])
        if result.returncode: return False
        for session in result.stdout.split()[:12]:
            state=command(['loginctl','show-session',session,'-p','Type','-p','Active','-p','LockedHint','-p','Remote'])
            fields=dict(line.split('=',1) for line in state.stdout.splitlines() if '=' in line)
            if state.returncode==0 and fields.get('Type') in {'wayland','x11'} and fields.get('Active')=='yes' and fields.get('LockedHint')=='no' and fields.get('Remote')=='no':
                return True
    except (OSError,subprocess.TimeoutExpired): pass
    return False


def oomd_status():
    result={'active':'unknown','pressure_limit_percent':None,'swap_limit_percent':None}
    try:
        state=command(['systemctl','show','systemd-oomd.service','-p','ActiveState','--value'])
        if state.returncode==0: result['active']=state.stdout.strip()
        values=command(['oomctl','--no-pager','dump'])
        # Only numeric global limits cross the privacy boundary, never cgroups.
        for key,pattern in [('pressure_limit_percent',r'Default Memory Pressure Limit:\s*([\d.]+)%'),('swap_limit_percent',r'Swap Used Limit:\s*([\d.]+)%')]:
            match=re.search(pattern,values.stdout)
            if match: result[key]=float(match[1])
    except (OSError,subprocess.TimeoutExpired): pass
    return result


def psi_triggers():
    fds=[]
    for resource,trigger in [('memory',b'some 100000 2000000'),('io',b'full 200000 2000000')]:
        fd=None
        try:
            fd=os.open('/proc/pressure/'+resource,os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
            os.write(fd,trigger);fds.append(fd)
        except OSError:
            if fd is not None: os.close(fd)
    return fds


def collector_volumes(db, paths, now):
    """Read bounded, fresh host measurements; ProtectHome hides live statvfs."""
    cutoff=datetime.fromtimestamp(now-180,timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
    rows=db.query("SELECT timestamp_utc,name,value,details_json FROM periodic_metrics "
        "WHERE timestamp_utc>=? AND name IN ('filesystem.free_percent','filesystem.inode_free_percent') "
        "AND outcome='ok' ORDER BY timestamp_utc DESC,id DESC LIMIT 240",(cutoff,))
    values={};seen=set()
    for row in rows:
        try:
            data=json.loads(row['details_json']);path=data.get('mount_point')
            observed=datetime.fromisoformat(row['timestamp_utc'].replace('Z','+00:00')).timestamp()
            value=float(row['value']);key=(path,row['name'])
            if path not in paths or key in seen or not now-180<=observed<=now+5 or not math.isfinite(value) or not 0<=value<=100: continue
            seen.add(key)
            if row['name']=='filesystem.free_percent':
                free,total=int(data['free_bytes']),int(data['total_bytes'])
                if not 0<=free<=total or total<=0: continue
                values[path]={'mount':path,'free_percent':value,'free_bytes':free,'total_bytes':total,
                    'inode_percent':None,'observed_at_utc':observed,'source':'existing_collector'}
        except (KeyError,TypeError,ValueError,OverflowError): continue
    # Inodes may precede capacity rows in descending row order.
    for row in rows:
        try:
            data=json.loads(row['details_json']);path=data.get('mount_point')
            if row['name']!='filesystem.inode_free_percent' or path not in values or values[path]['inode_percent'] is not None: continue
            observed=datetime.fromisoformat(row['timestamp_utc'].replace('Z','+00:00')).timestamp()
            value=float(row['value'])
            if now-180<=observed<=now+5 and math.isfinite(value) and 0<=value<=100:
                values[path]['inode_percent']=value
        except (KeyError,TypeError,ValueError,OverflowError): continue
    return list(values.values())


def watch(config,db,stop):
    cfg=config['resource_rescue']
    if not cfg['enabled']: return
    user=config['monitor']['operator_user']
    if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',user): raise ValueError('unsafe operator user')
    unit=f'fedora-system-monitor-resource-dialog@{user}.service'
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    state=db.get_state('incident',{},namespace='resource_rescue')
    if state.get('boot')!=boot: state={'boot':boot}
    gate=Gate(cfg,state);previous=None;active=False;last_status=None;last_saved=None;last_persisted=-1e9;sample_count=0
    fds=psi_triggers();poll=select.poll()
    for fd in fds: poll.register(fd,select.POLLPRI)
    descriptor={'psi_triggers':len(fds),'fallback_seconds':cfg['idle_seconds'],'oomd':oomd_status()}
    db.set_state('capabilities',descriptor,namespace='resource_rescue')
    due=0.;triggered=False;volumes=[];volume_due=0.
    try:
        while not stop.is_set():
            now=time.monotonic()
            if now<due:
                if fds:
                    events=poll.poll(min(3000,max(1,int((due-now)*1000))))
                    if events:
                        for fd,mask in events:
                            if mask & (select.POLLERR|select.POLLHUP|select.POLLNVAL):
                                poll.unregister(fd);os.close(fd);fds.remove(fd)
                            elif mask & select.POLLPRI:
                                triggered=True;due=now
                else: stop.wait(min(3,due-now))
                continue
            try:
                measured=time.perf_counter()
                s,previous=sample(previous,volumes=())
                wall=time.time()
                if now>=volume_due:
                    try: volumes=collector_volumes(db,config['collection']['critical_filesystems'],wall)
                    except Exception: volumes=[]
                    volume_due=now+60
                s.volumes=[v for v in volumes if wall-v['observed_at_utc']<=180]
                s.volumes_fresh=bool(s.volumes)
                sample_ms=(time.perf_counter()-measured)*1000;sample_count+=1
                risk=classify(s,cfg,triggered=triggered)
                unlocked=session_unlocked(user) if risk.level>0 or active or gate.state.get('pending_recap') else False
                if active:
                    result=command(['systemctl','show',unit,'-p','ActiveState','-p','ExecMainStatus'])
                    info=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
                    if result.returncode==0 and info.get('ActiveState') in {'inactive','failed'}:
                        active=False
                        gate.dismissed(s.at)
                        last_status=info.get('ExecMainStatus','unknown')
                        if last_status=='3':
                            gate.state.update(pending=True,last_opened=-1e9,snooze_until=0)
                was_pending=gate.state.get('pending',False)
                event,risk=gate.step(s,triggered=triggered,locked=not unlocked,dialog_active=active)
                if event=='recovered' and was_pending:
                    gate.state['pending_recap']=True
                if risk.level==0 and gate.state.get('pending_recap') and unlocked and not active and s.at>=gate.state.get('snooze_until',0) and s.at>=gate.state.get('last_opened',-1e9)+cfg['minimum_popup_seconds']:
                    event='recap';gate.state.update(pending_recap=False,last_opened=s.at)
                if event in {'open','recap'}:
                    result=command(['systemctl','start','--no-block',unit])
                    active=result.returncode==0
                    if not active:
                        gate.dismissed(s.at);last_status='launch_failed'
                        if event=='recap':gate.state['pending_recap']=True
                record={'boot':boot,**gate.state,'event':event,'kind':risk.kind,'level':risk.level,
                    'last_ui_status':last_status,'last_ui_reason':{'0':'recovered','2':'dismissed_or_timeout','3':'session_locked_or_absent','4':'dialog_failed','5':'dialog_already_running','launch_failed':'systemd_dialog_launch_failed'}.get(last_status,'unknown' if last_status else None),'sample':asdict(s),'observed_at_utc':time.time(),'checks':sample_count,'sample_duration_ms':sample_ms}
                # Persistent numeric incident data, never app targets or browser metadata.
                if (risk.kind,risk.level,event)!=last_saved or risk.level>0 or s.at-last_persisted>=60:
                    db.set_state('incident',record,namespace='resource_rescue')
                    if (risk.kind,risk.level,event)!=last_saved:
                        db.insert_events({'name':'resource_rescue_state','category':'memory' if risk.kind=='memory' else 'system',
                            'severity':'critical' if risk.level==2 else 'warning' if risk.level==1 else 'info',
                            'source':'resource_rescue','details':{'state':event,'kind':risk.kind,'level':risk.level}})
                    last_saved=(risk.kind,risk.level,event);last_persisted=s.at
                triggered=False
                due=s.at+(cfg['active_seconds'] if risk.level>0 or active else cfg['idle_seconds'])
            except Exception:
                # A UI/SQLite/PSI failure must not kill journal collection or busy-loop.
                due=time.monotonic()+cfg['idle_seconds']
    finally:
        for fd in fds: os.close(fd)
