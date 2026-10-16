"""Resource rescue CLI adapter; optional GTK is imported only in the user dialog."""


def add_parser(subparsers):
    p=subparsers.add_parser('resource-rescue',help='resource incident status and user-session rescue')
    p.add_argument('action',choices=('status','dialog'),default='status',nargs='?')
    p.add_argument('--fixture',action='store_true',help='controlled GUI demonstration: real targets and signals disabled')


def execute(args,config):
    if args.action=='dialog':
        from .dialog import run
        return run(config,fixture=args.fixture)
    import json
    from ..reporting import _connection
    with _connection(config['monitor']['database_path']) as c:
        rows=c.execute("SELECT state_key,state_json FROM dedup_state WHERE namespace='resource_rescue'").fetchall()
    result={r[0]:json.loads(r[1]) for r in rows}
    import os,time
    from pathlib import Path
    path=Path(f'/run/user/{os.getuid()}/fsm-chrome-capabilities.json')
    try:
        value=json.loads(path.read_text())
        result['chrome_capabilities']=value if time.time()-value['observed_at_utc']<3600 else {"stale":True}
    except (OSError,ValueError,KeyError):result['chrome_capabilities']={"available":False}
    return result
