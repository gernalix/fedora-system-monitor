"""One native message, capabilities only, then exit. Never a browser agent/poller."""
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import time


def receive(stream):
    header=stream.read(4)
    if len(header)!=4: raise ValueError('missing frame')
    length=struct.unpack('<I',header)[0]
    if not 1<=length<=4096: raise ValueError('frame limit')
    data=stream.read(length)
    if len(data)!=length: raise ValueError('incomplete frame')
    value=json.loads(data)
    if set(value)!={'session','processes_exposed','tabs_available','browser_major'}: raise ValueError('unknown keys')
    if not isinstance(value['session'],str) or not re.fullmatch('[a-f0-9-]{32,36}',value['session']):raise ValueError('session')
    if type(value['processes_exposed']) is not bool or type(value['tabs_available']) is not bool:raise ValueError('capabilities')
    if type(value['browser_major']) is not int or not 100<=value['browser_major']<=999:raise ValueError('version')
    return value


def persist(value,root):
    uid=os.getuid();root=Path(root)
    if root.stat().st_uid!=uid or root.stat().st_mode&0o077:raise PermissionError('private runtime required')
    value={**value,'observed_at_utc':time.time(),'cpu_per_tab':None,'rss_per_tab':None,'io_per_tab':None}
    with tempfile.NamedTemporaryFile('w',dir=root,prefix='.fsm-chrome-',delete=False) as f:
        os.chmod(f.name,0o600);json.dump(value,f);temp=f.name
    os.replace(temp,root/'fsm-chrome-capabilities.json')
    return value


def main():
    try:
        if os.getuid()==0:raise PermissionError('user host only')
        value=receive(sys.stdin.buffer)
        persist(value,f'/run/user/{os.getuid()}')
        result={'ok':True,'metrics':'not_available','stored':'capabilities_only'}
    except Exception:
        result={'ok':False,'error':'invalid capabilities message'}
    data=json.dumps(result).encode();sys.stdout.buffer.write(struct.pack('<I',len(data))+data);sys.stdout.buffer.flush()
    return 0

if __name__=='__main__':raise SystemExit(main())
