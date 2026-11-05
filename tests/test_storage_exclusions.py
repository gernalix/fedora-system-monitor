from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fedora_system_monitor.capsules.alerting import AlertSignal, storage_alert_ignored
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.runtime.coordinator import _derived_recoveries, _persist_signals

MOUNT = '/run/media/daniele/VEEAMRE'
CONFIG = {'storage': {'ignore_alert_mountpoints': [MOUNT]}}


class StorageExclusionTests(unittest.TestCase):
    def test_exclusion_matches_only_exact_attributed_storage_mount(self):
        self.assertTrue(storage_alert_ignored('hardware', {'mount_point':MOUNT}, CONFIG))
        self.assertTrue(storage_alert_ignored('filesystem', {'mount_point':MOUNT}, CONFIG))
        for category,details in [('storage',{'mount_point':MOUNT+'-other'}), ('hardware',{}),
                                 ('storage',{'mount_point':'/mnt/T7_BACKUP'}), ('service',{'mount_point':MOUNT})]:
            self.assertFalse(storage_alert_ignored(category,details,CONFIG))
        self.assertFalse(storage_alert_ignored('hardware', {'mount_point':MOUNT}, {}))

    def test_future_signal_cannot_open_alert_but_other_mount_still_can(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Database(Path(temp)/'state.sqlite')
            try:
                ignored=AlertSignal(key='ignored',category='hardware',name='unsafe_device_removal',severity='warning',
                                    active=True,message='unsafe removal',source='fixture',details={'mount_point':MOUNT})
                other=AlertSignal(key='other',category='hardware',name='unsafe_device_removal',severity='warning',
                                  active=True,message='unsafe removal',source='fixture',details={'mount_point':'/mnt/other'})
                with patch('fedora_system_monitor.capsules.runtime.coordinator._flush_transition_notifications'):
                    transitions=_persist_signals(db,[ignored,other],CONFIG)
                self.assertEqual([row['alert_key'] for row in db.active_alerts()],['other'])
                self.assertEqual([s.key for s in transitions],['other'])
            finally:
                db.close()

    def test_existing_excluded_alert_recovers_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Database(Path(temp)/'state.sqlite')
            try:
                for key,mount in [('ignored',MOUNT),('other','/mnt/other')]:
                    db.open_alert_transition(key,category='hardware',name='unsafe_device_removal',severity='warning',
                                             source='fixture',details={'mount_point':mount},message='original incident')
                with patch('fedora_system_monitor.capsules.runtime.coordinator.run_command',
                           return_value=SimpleNamespace(ok=False,stdout='')):
                    signals=_derived_recoveries(db,[],scope='five_minute',config=CONFIG)
                self.assertEqual([s.key for s in signals],['ignored'])
                self.assertEqual(signals[0].details['recovery_source'],'configured_mountpoint_exclusion')
                with patch('fedora_system_monitor.capsules.runtime.coordinator._flush_transition_notifications'):
                    _persist_signals(db,signals,CONFIG)
                rows=db.query('SELECT alert_key,status,details_json FROM alerts ORDER BY alert_key')
                self.assertEqual([(r['alert_key'],r['status']) for r in rows],[('ignored','recovered'),('other','active')])
                self.assertEqual(json.loads(rows[0]['details_json'])['mount_point'],MOUNT)
            finally:
                db.close()

    def test_containing_root_mount_does_not_recover_missing_usb_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Database(Path(temp)/'state.sqlite')
            try:
                db.open_alert_transition('other',category='hardware',name='unsafe_device_removal',severity='warning',
                                         source='fixture',details={'mount_point':'/mnt/other'},message='unsafe removal')
                with patch('fedora_system_monitor.capsules.runtime.coordinator.run_command',
                           return_value=SimpleNamespace(ok=True,stdout=json.dumps({'filesystems':[{'target':'/'}]}))) as run:
                    self.assertEqual(_derived_recoveries(db,[],scope='five_minute'),[])
                self.assertIn('--mountpoint',run.call_args.args[0])
                self.assertNotIn('--target',run.call_args.args[0])
            finally:
                db.close()
