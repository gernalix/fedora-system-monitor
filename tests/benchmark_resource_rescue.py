"""Fixture-only pressure sampling overhead; no live collector invocation."""
from pathlib import Path
import json
import tempfile
import time
import tracemalloc
from fedora_system_monitor.capsules.resource_rescue.pressure import sample,classify
from fedora_system_monitor.capsules.config import load_config

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);(root/'pressure').mkdir()
    (root/'meminfo').write_text('MemTotal: 16000000 kB\nMemAvailable: 2000000 kB\nSwapTotal: 8000000 kB\nSwapFree: 5000000 kB\n')
    (root/'vmstat').write_text('pswpout 10\npgscan_kswapd 100\npgscan_direct 0\noom_kill 0\n')
    for resource in ('memory','io'):
        (root/'pressure'/resource).write_text('some avg10=2.00 avg60=1.00 avg300=0.50 total=10000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n')
    before=None;cfg=load_config(None)['resource_rescue']
    start=time.perf_counter();cpu=time.process_time()
    for n in range(1000):
        s,before=sample(before,root=root,sys_root=root,volumes=(tmp,),now=n*10)
        classify(s,cfg)
    elapsed=time.perf_counter()-start;cpu=time.process_time()-cpu
    tracemalloc.start();sample(root=root,sys_root=root,volumes=(tmp,));_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    print(json.dumps({'samples':1000,'elapsed_ms_per_check':elapsed,'cpu_ms_per_check':cpu,'peak_python_bytes':peak,'projected_cpu_percent_at_10s':cpu/10/1000*100}))
