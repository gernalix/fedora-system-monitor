"""Opt-in isolated Xvfb GTK smoke test, no real process signals or tabs altered.

Run: PYTHONPATH=src dbus-run-session -- xvfb-run -a env GDK_BACKEND=x11 GSK_RENDERER=cairo python3 tests/e2e_resource_dialog_x11.py
"""
import os
import time
from unittest.mock import patch
from gi.repository import GLib

from fedora_system_monitor.capsules.config import load_config
from fedora_system_monitor.capsules.resource_rescue.dialog import Dialog
from fedora_system_monitor.capsules.resource_rescue.pressure import Sample
from fedora_system_monitor.capsules.resource_rescue.targets import Candidate, Identity, Snapshot


def main():
    config=load_config(None)
    dialog=Dialog(config)
    dialog.app.register(None)
    dialog.build()
    proc=Identity('mock', 45678, 100, os.getuid(), 'chrome', 'mock', 1024*1024)
    result=Snapshot('mock',time.monotonic(),(Candidate(proc,(proc,),1024*1024,'mock',253013),))
    titles={'kind':'tabs','session':'b'*32,'total':14,'observed_at_utc':100,'age_seconds':52,
            'tabs':[{'title':f'Scheda {x}','active':x==0,'discarded':False} for x in range(14)]}
    s=Sample(time.monotonic(),53.51016036865788,.16,.16,37.11,10888839168,0,0,0)
    with patch('fedora_system_monitor.capsules.resource_rescue.dialog.session_unlocked',return_value=True), \
         patch.object(dialog,'live',return_value=s), \
         patch('fedora_system_monitor.capsules.resource_rescue.dialog.candidates',return_value=result), \
         patch('fedora_system_monitor.capsules.resource_rescue.dialog.read_recent_tabs',return_value=titles):
        assert dialog.refresh() is True
    assert dialog.heading.get_text()=='Attese disco/I/O elevate'
    assert '53.5%' in dialog.metrics.get_text()
    assert '37.1%' in dialog.metrics.get_text()
    assert dialog.pages.get_n_pages()==2
    assert dialog.pages.get_current_page()==0
    assert dialog.process_list.get_row_at_index(0) is not None
    assert dialog.process_list.get_row_at_index(1) is None
    assert dialog.chrome_list.get_row_at_index(13) is not None
    assert dialog.chrome_list.get_row_at_index(14) is None
    for _ in range(30):
        while GLib.MainContext.default().pending():
            GLib.MainContext.default().iteration(False)
    width,height=dialog.window.get_width(),dialog.window.get_height()
    assert width<=800 and height<=520,(width,height)
    assert dialog.choose_button.get_sensitive() is False
    dialog.process_list.select_row(dialog.process_list.get_row_at_index(0))
    assert dialog.choose_button.get_sensitive() is True
    dialog.choose()
    assert 'browser' in dialog.confirmation.get_child().get_first_child().get_label()
    dialog.confirm_cancel.emit('clicked')
    assert dialog.actions==0
    assert 'Annullato' in dialog.status.get_text()
    assert dialog.choose_button.get_sensitive() is False
    dialog.pages.set_current_page(1)
    assert dialog.pages.get_current_page()==1
    dialog.window.destroy()
    print('GTK Xvfb isolated two-page UI, 14 titles, readable metrics, click-to-select and cancel: PASS')


if __name__=='__main__':
    main()
