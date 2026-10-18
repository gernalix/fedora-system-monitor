"""Opt-in real GTK4/Wayland E2E. Only a fake app is shown; signals disabled.

PYTHONPATH=src python3 tests/e2e_resource_dialog.py
"""
import json
import os
from pathlib import Path
import resource

from fedora_system_monitor.capsules.config import load_config
from fedora_system_monitor.capsules.resource_rescue.dialog import Dialog,user_environment,singleton


def main():
    runtime=user_environment();fd=singleton(runtime)
    if fd is None: raise RuntimeError('Another resource dialog is active; do not disturb it.')
    dialog=Dialog(load_config(None),fixture=True)
    evidence={};phase=0;failure=[]
    def step():
        nonlocal phase
        try:
            from gi.repository import Gdk
            if phase==0:
                assert dialog.window.get_mapped()
                assert 'Wayland' in type(Gdk.Display.get_default()).__name__
                assert dialog.snapshot and len(dialog.snapshot.candidates)==1
                evidence['wayland_window_mapped']=True
                evidence['sample_identity']=dialog.snapshot.token
                dialog.entry.set_text('99');dialog.entry.emit('activate')
                assert 'Numero non valido' in dialog.status.get_text()
                evidence['invalid_number_rejected']=True
                dialog.entry.set_text('1');dialog.entry.emit('activate')
                assert dialog.confirmation.get_visible()
                phase=1;return True
            if phase==1:
                assert dialog.confirmation.get_mapped()
                dialog.confirm_cancel.emit('clicked')
                assert dialog.actions==0 and 'Annullato' in dialog.status.get_text()
                evidence['confirmation_cancelled_no_action']=True
                dialog.entry.set_text('1');dialog.entry.emit('activate')
                dialog.confirm_accept.emit('clicked')
                phase=2;return True
            if phase==2:
                # Worker + the explicit settling timer must finish first.
                if dialog.busy: return True
                assert dialog.window.get_mapped() and dialog.actions==0
                assert dialog.snapshot.token=='fixture'
                evidence['confirmed_fixture_never_signals']=True
                evidence['single_application_window']=sum(1 for w in dialog.app.get_windows() if w.get_visible())==1
                assert evidence['single_application_window']
                private=[]
                for line in Path('/proc/self/smaps_rollup').read_text().splitlines():
                    if line.startswith('Rss:'): evidence['current_rss_kib']=int(line.split()[1])
                    if line.startswith('Pss:'): evidence['pss_kib']=int(line.split()[1])
                    if line.startswith(('Private_Clean:','Private_Dirty:','Private_Hugetlb:')):private.append(int(line.split()[1]))
                evidence['private_kib']=sum(private)
                dialog.finish(0);return False
        except Exception as exc:
            failure.append(type(exc).__name__+': '+str(exc));dialog.finish(4);return False
    dialog.app.connect('activate',lambda *_:dialog.GLib.timeout_add(800,step))
    # Bound failure even if a GTK worker callback stalls.
    dialog.GLib.timeout_add_seconds(15,lambda:dialog.finish(4))
    try: code=dialog.run()
    finally:os.close(fd)
    if code or failure: raise RuntimeError(str(failure) or 'E2E timeout')
    print(json.dumps({'controlled_wayland_e2e':'PASS',**evidence},sort_keys=True))

if __name__=='__main__':main()
