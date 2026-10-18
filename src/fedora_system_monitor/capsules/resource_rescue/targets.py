"""Ephemeral, user-owned GUI candidates. pidfds prevent PID reuse at signal time."""
from dataclasses import dataclass
from pathlib import Path
import os
import re
import select
import signal
import time
import uuid

from ..collectors.process_history import _stat, _read

# Conservatively protect work sessions and interpreter/service infrastructure.
PROTECTED=re.compile(r'(?:^|[-_. ])(?:gnome-shell|gnome-session|systemd|dbus|ssh|sshd|bash|zsh|fish|sh|terminal|tmux|screen|codex|megavault|monitor|fsm|python\d*|node|runuser|sudo|login|gdm|pipewire|wireplumber|wayland|xwayland)(?:$|[-_. ])',re.I)
GUI=re.compile(r'^(chrome|firefox|code|gedit|gnome-text-edit|libreoffice|soffice|evince|loupe|nautilus|vlc|mpv|gimp|inkscape|obsidian|zed)',re.I)


@dataclass(frozen=True)
class Identity:
    boot: str
    pid: int
    start: int
    uid: int
    name: str
    cgroup: str
    rss: int


def identity(pid, root=Path('/proc')):
    p=root/str(pid)
    name,start,_,rss=_stat(_read(p/'stat'))
    match=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',_read(p/'status'),re.M)
    if not match or len(set(match.groups()))!=1: raise PermissionError('elevated/unknown identity')
    cg=_read(p/'cgroup').strip()
    boot=str(uuid.UUID(_read(root/'sys/kernel/random/boot_id').strip()))
    return Identity(boot,pid,start,int(match[1]),name,cg,rss*os.sysconf('SC_PAGE_SIZE'))


def same(a,b):
    return (a.boot,a.pid,a.start,a.uid,a.name,a.cgroup)==(b.boot,b.pid,b.start,b.uid,b.name,b.cgroup)


def protected(i,uid):
    return i.uid!=uid or i.pid in {0,1,os.getpid(),os.getppid()} or bool(PROTECTED.search(i.name)) or bool(re.search(r'codex|megavault|fedora-system-monitor|terminal|org.gnome.Shell|gnome-session|ssh|tmux',i.cgroup,re.I))


@dataclass(frozen=True)
class Candidate:
    leader: Identity
    members: tuple
    estimated_bytes: int
    basis: str
    io_bps: float | None = None


@dataclass(frozen=True)
class Snapshot:
    token: str
    at: float
    candidates: tuple
    io_counters: tuple = ()


def candidates(uid,*,root=Path('/proc'),now=None,io_previous=None,kind="memory"):
    io_previous=io_previous or {}
    io_current={}
    started=time.monotonic();groups={};unsafe=set()
    for p in root.iterdir():
        if not p.name.isdecimal(): continue
        if time.monotonic()-started>2: raise TimeoutError('Elenco incompleto: nessuna azione consentita.')
        try:
            i=identity(int(p.name),root)
            if i.uid!=uid: continue
            # A common session/app.slice is never itself a kill group.
            scope=re.search(r'/(app-[A-Za-z0-9_.@:\\-]+\.scope)(?:/|$)',i.cgroup)
            if not scope and not GUI.match(i.name): continue
            key=i.cgroup if scope else f'pid:{i.pid}'
            groups.setdefault(key,[]).append(i)
            if protected(i,uid): unsafe.add(key)
        except (OSError,ValueError,IndexError): continue
    result=[]
    for key,group in groups.items():
        if key in unsafe: continue
        leader=min(group,key=lambda i:i.start)
        if not GUI.match(leader.name) and not key.startswith('0::/'): # cgroup v2 safe app scopes only
            continue
        private=[];rates=[]
        for member in group:
            if time.monotonic()-started>2: break
            try:
                values=dict(line.split(':',1) for line in _read(root/str(member.pid)/'io').splitlines() if ':' in line)
                counter=int(values['read_bytes'])+int(values['write_bytes'])
                stamp=time.monotonic();key=(member.boot,member.pid,member.start)
                io_current[key]=(stamp,counter)
                before=io_previous.get(key)
                if before and stamp>before[0] and counter>=before[1]: rates.append((counter-before[1])/(stamp-before[0]))
            except (OSError,ValueError,KeyError): pass
            try:
                text=_read(root/str(member.pid)/'smaps_rollup')
                vals=[int(v)*1024 for v in re.findall(r'^Private_(?:Clean|Dirty|Hugetlb):\s+(\d+)',text,re.M)]
                if vals: private.append(sum(vals))
            except (OSError,ValueError): pass
        # Never sum RSS or attribute a shared renderer to one tab.
        complete=len(private)==len(group)
        amount=sum(private) if private else max(i.rss for i in group)
        basis='privata stimata (USS)' if complete else 'privata parziale; stima incerta' if private else 'RSS massimo; recupero incerto, memoria condivisa non sommata'
        result.append(Candidate(leader,tuple(group),amount,basis,sum(rates) if rates and len(rates)==len(group) else None))
    if kind=='io':
        result=[c for c in result if c.io_bps is not None and c.io_bps>0]
        result.sort(key=lambda c:c.io_bps,reverse=True)
    else: result.sort(key=lambda c:c.estimated_bytes,reverse=True)
    return Snapshot(uuid.uuid4().hex,time.monotonic() if now is None else now,tuple(result[:30]),tuple(io_current.items()))


def terminate(snapshot,number,uid,*,confirmed=False,root=Path('/proc'),clock=time.monotonic,timeout=12,normal_close=None):
    if not confirmed: raise PermissionError('Serve conferma esplicita per possibili dati non salvati.')
    if not 1<=number<=len(snapshot.candidates) or clock()-snapshot.at>20:
        raise ValueError('Elenco scaduto: scegliere da una nuova classifica.')
    target=snapshot.candidates[number-1]
    # Open first: later PID reuse cannot redirect this handle to a replacement.
    fd=os.pidfd_open(target.leader.pid)
    try:
        poll=select.poll();poll.register(fd,select.POLLIN)
        if poll.poll(0): raise ProcessLookupError('Processo già terminato.')
        for old in target.members:
            current=identity(old.pid,root)
            if protected(current,uid) or not same(old,current):
                raise PermissionError('Identità/gruppo/titolarità cambiati; nessun segnale inviato.')
        if poll.poll(0): raise ProcessLookupError('Processo già terminato.')
        requested=normal_close(target) if normal_close else False
        if not requested: signal.pidfd_send_signal(fd,signal.SIGTERM)
        # Never SIGKILL. A failure to exit is not reported as recovered memory.
        end=clock()+timeout
        while clock()<end:
            if poll.poll(100):
                survivors=[]
                for old in target.members:
                    try:
                        if same(old,identity(old.pid,root)): survivors.append(old.pid)
                    except (OSError,ValueError): pass
                if not survivors: return 'exited'
            time.sleep(.1)
        return 'not_exited'
    finally: os.close(fd)
