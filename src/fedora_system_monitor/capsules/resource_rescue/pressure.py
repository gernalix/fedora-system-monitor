"""Small read-only live resource samples, independent of minute history latency."""
from dataclasses import dataclass, field
from pathlib import Path
import os
import time


def fields(path):
    with Path(path).open() as f:
        text=f.read(32768)
    return {p[0].rstrip(':'):float(p[1]) for line in text.splitlines()
            if len(p:=line.split())>=2 and p[1].replace('.','',1).isdigit()}


def psi(path):
    result={}
    try:
        with Path(path).open() as f:
            for line in f.read(2048).splitlines():
                parts=line.split()
                for value in parts[1:]:
                    k,v=value.split('=');result[parts[0]+'_'+k]=float(v)
    except (OSError,ValueError):
        pass
    return result


@dataclass
class Sample:
    at: float
    available: float | None
    memory_some: float | None
    memory_full: float | None
    io_full: float | None
    swap_used: float | None
    swap_out: float | None
    reclaim: float | None
    oom: float | None
    volumes: list = field(default_factory=list)
    zram: dict = field(default_factory=dict)


def sample(previous=None, *, root=Path('/proc'), volumes=('/', '/home','/var'), now=None, sys_root=Path('/sys')):
    now=time.monotonic() if now is None else now
    try: mem=fields(root/'meminfo')
    except (OSError,ValueError): mem={}
    try: vm=fields(root/'vmstat')
    except (OSError,ValueError): vm={}
    mp,ip=psi(root/'pressure/memory'),psi(root/'pressure/io')
    elapsed=now-previous[0] if previous else 0
    def delta(key):
        old=previous[1].get(key) if previous else None
        val=vm.get(key)
        return val-old if elapsed>0 and old is not None and val is not None and val>=old else None
    def rate(key):
        d=delta(key);return d/elapsed if d is not None else None
    total=mem.get('MemTotal');avail=mem.get('MemAvailable')
    swaps=mem.get('SwapTotal');free=mem.get('SwapFree')
    paths=[];seen=set()
    for path in volumes[:12]:
        try:
            dev=os.stat(path).st_dev
            if dev in seen: continue
            seen.add(dev);v=os.statvfs(path)
            paths.append({'mount':str(path),'free_percent':v.f_bavail/v.f_blocks*100 if v.f_blocks else None,
                'free_bytes':v.f_bavail*v.f_frsize,'inode_percent':v.f_favail/v.f_files*100 if v.f_files else None})
        except OSError: pass
    scans=[rate(k) for k in vm if k.startswith('pgscan_')]
    # Some kernels expose both totals and subtypes. Do not sum overlapping totals.
    reclaim=rate('pgscan_kswapd')
    direct=rate('pgscan_direct')
    reclaim=(reclaim or 0)+(direct or 0) if reclaim is not None or direct is not None else None
    swap_rate=rate('pswpout')
    result=Sample(now,avail/total*100 if total and avail is not None else None,
        mp.get('some_avg10'),mp.get('full_avg10'),ip.get('full_avg10'),
        (swaps-free)*1024 if swaps is not None and free is not None else None,
        swap_rate*os.sysconf('SC_PAGE_SIZE') if swap_rate is not None else None,
        reclaim,delta('oom_kill'),paths)
    if result.available is not None and result.available<20:
        for path in sorted((sys_root/'block').glob('zram*/mm_stat'))[:8]:
            try:
                values=path.read_text().split()
                result.zram[path.parent.name]={'original_bytes':int(values[0]),'compressed_bytes':int(values[1]),'memory_bytes':int(values[2])}
            except (OSError,ValueError,IndexError): pass
    return result,(now,vm)


@dataclass(frozen=True)
class Risk:
    kind: str
    level: int
    explanation: str


def classify(s, cfg, *, triggered=False):
    # Missing data is UNKNOWN, never a fabricated healthy zero.
    if s.available is None or s.memory_some is None or s.memory_full is None:
        return Risk('unknown',-1,'Misure RAM/PSI non disponibili: recupero non verificabile.')
    supporting=triggered or s.memory_some>=cfg['support_psi_percent'] or (s.swap_out or 0)>=cfg['swap_out_mib_s']*1024**2 or (s.reclaim or 0)>=cfg['reclaim_pages_s']
    if (s.oom or 0)>0 or s.memory_full>=cfg['emergency_psi_full'] or (s.available<cfg['emergency_available'] and supporting):
        return Risk('memory',2,'Pressione RAM grave: rischio di blocco/OOM, senza garanzia di preavviso.')
    if (s.available<cfg['warning_available'] and supporting) or s.memory_some>=cfg['warning_psi_some']:
        return Risk('memory',1,'RAM disponibile bassa con stall/reclaim, oppure PSI RAM sostenuta.')
    for volume in s.volumes:
        free,inodes=volume['free_percent'],volume['inode_percent']
        if (free is not None and free<cfg['disk_free_percent']) or (inodes is not None and inodes<cfg['inode_free_percent']) or volume['free_bytes']<cfg['disk_free_mib']*1024**2:
            return Risk('disk',2 if (free is not None and free<2) or (inodes is not None and inodes<2) else 1,
                'Spazio/inode critici: chiudere applicazioni non garantisce spazio. Nessuna cancellazione automatica.')
    if s.io_full is not None and s.io_full>=cfg['io_psi_full']:
        return Risk('io',1,'Stall I/O sostenuti: verificare le operazioni responsabili; CPU alta da sola non è una prova.')
    return Risk('healthy',0,'Pressione rientrata.')


def clearly_healthy(s,cfg):
    return (s.available is not None and s.available>=cfg['warning_available']+cfg['hysteresis_percent']
        and s.memory_some is not None and s.memory_some<cfg['warning_psi_some']/2
        and s.memory_full is not None and s.memory_full<cfg['emergency_psi_full']/2
        and s.io_full is not None and s.io_full<cfg['io_psi_full']/2
        and all((v['free_percent'] is None or v['free_percent']>=cfg['disk_free_percent']+cfg['hysteresis_percent'])
            and (v['inode_percent'] is None or v['inode_percent']>=cfg['inode_free_percent']+cfg['hysteresis_percent'])
            and v['free_bytes']>=cfg['disk_free_mib']*1024**2*1.5 for v in s.volumes))


class Gate:
    """Debounce, escalation, recovery hysteresis and snooze; serializable in FSM state."""
    def __init__(self,cfg,state=None):
        self.cfg=cfg;self.state=state or {};self.since=None;self.healthy=0;self.pending=None

    def step(self,s,*,triggered=False,locked=False,dialog_active=False):
        risk=classify(s,self.cfg,triggered=triggered)
        signature=(risk.kind,risk.level)
        if risk.level<0: return 'unknown',risk
        if risk.level==0:
            self.since=None;self.pending=None
            self.healthy=self.healthy+1 if clearly_healthy(s,self.cfg) else 0
            if self.healthy>=self.cfg['recovery_samples'] and self.state.get('incident'):
                self.state.update(incident=False,pending=False,level=0)
                return 'recovered',risk
            return 'healthy',risk
        self.healthy=0
        if signature!=self.pending:
            self.pending=signature;self.since=s.at
        if s.at-(self.since if self.since is not None else s.at)<(0 if risk.level==2 else self.cfg['debounce_seconds']):
            return 'debounce',risk
        worsened=risk.level>self.state.get('level',0) or risk.kind!=self.state.get('kind',risk.kind)
        self.state.update(incident=True,kind=risk.kind,level=risk.level)
        if locked:
            self.state['pending']=True
            return 'pending',risk
        if dialog_active: return 'active',risk
        if not worsened and s.at<self.state.get('snooze_until',0): return 'snoozed',risk
        if s.at<self.state.get('last_opened',-1e9)+self.cfg['minimum_popup_seconds']: return 'rate_limited',risk
        self.state.update(last_opened=s.at,pending=False)
        return 'open',risk

    def dismissed(self,now):
        self.state['snooze_until']=now+self.cfg['snooze_seconds']
