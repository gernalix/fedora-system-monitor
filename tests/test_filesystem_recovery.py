from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.runtime.filesystem_recovery import recovered_uuid, readonly_recoveries

BOOT = 'a' * 32
UUID = '11111111-2222-3333-4444-555555555555'
OTHER = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
DETAILS = {'kernel_device': 'sdc1', 'boot_id': BOOT, 'journal_cursor': 'synthetic', 'monotonic_usec': '1000000'}


def entry(mono, message, boot=BOOT):
    return {'_BOOT_ID': boot, '__MONOTONIC_TIMESTAMP': str(mono), 'MESSAGE': message}


def lifecycle(uuid=UUID, node='sdc1', mode='r/w'):
    return [entry(1100000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.'),
            entry(8000000, f'EXT4-fs ({node}): mounted filesystem {uuid} {mode} with ordered data mode. Quota mode: none.')]


class FilesystemRecoveryTests(unittest.TestCase):
    def test_same_uuid_survives_kernel_name_change(self):
        self.assertEqual(recovered_uuid(DETAILS, lifecycle(node='sde1'), BOOT), UUID)

    def test_read_only_during_unmount(self):
        records = [entry(900000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.'),
                   lifecycle(node='sde1')[1]]
        self.assertEqual(recovered_uuid(DETAILS, records, BOOT), UUID)
        reuse = entry(950000, f'EXT4-fs (sdc1): mounted filesystem {OTHER} r/w')
        self.assertIsNone(recovered_uuid(DETAILS, records + [reuse], BOOT))

    def test_read_only_while_mounted_uses_the_mount_in_effect_at_failure(self):
        details = dict(DETAILS, monotonic_usec='20000000')
        records = [
            entry(1000000, f'EXT4-fs (sdc1): mounted filesystem {UUID} r/w'),
            entry(30000000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.'),
            entry(40000000, f'EXT4-fs (sde1): mounted filesystem {UUID} r/w'),
        ]
        self.assertEqual(recovered_uuid(details, records, BOOT), UUID)
        earlier_unmount = entry(3000000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.')
        self.assertIsNone(recovered_uuid(details, records + [earlier_unmount], BOOT))

    def test_recovers_across_reboot_only_with_same_uuid_in_current_boot(self):
        current_boot = 'b' * 32
        old_boot = [entry(900000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.')]
        current = [entry(100, f'EXT4-fs (dm-1): mounted filesystem {UUID} r/w', current_boot)]
        self.assertEqual(recovered_uuid(DETAILS, old_boot, current_boot, current), UUID)
        self.assertIsNone(recovered_uuid(DETAILS, [], current_boot, current))
        self.assertIsNone(recovered_uuid(DETAILS, old_boot, current_boot, current + [
            entry(200, f'EXT4-fs (dm-1): unmounting filesystem {UUID}.', current_boot)]))

    def test_requires_identity_timing_boot_and_later_writable_mount(self):
        for records in ([], lifecycle(uuid=OTHER), lifecycle(mode='r/o'),
                        lifecycle()[1:], [entry(7000000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.')]+lifecycle()[1:],
                        lifecycle()+[entry(9000000, f'EXT4-fs (sdc1): unmounting filesystem {UUID}.')]):
            with self.subTest(records=records):
                self.assertIsNone(recovered_uuid(DETAILS, records, BOOT))
        self.assertIsNone(recovered_uuid(DETAILS, lifecycle(), 'b'*32))
        self.assertIsNone(recovered_uuid({}, lifecycle(), BOOT))

    def test_legacy_eventing_identity_is_supported(self):
        details = {'kernel_device':'sdc1','journal_identity':{'boot_id':BOOT,'cursor':'synthetic','monotonic':1000000}}
        self.assertEqual(recovered_uuid(details, lifecycle(), BOOT), UUID)

    def test_live_mount_and_complete_valid_journal_both_required(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Database(Path(temp)/'state.sqlite')
            try:
                for name in ('filesystem_read_only','filesystem_remounted_read_only'):
                    db.open_alert_transition(name,category='storage',name=name,severity='critical',source='kernel',
                                             device_id='kernel:sdc1',details=DETAILS,message='read only')
                def run(mounted_uuid=UUID, options='rw,relatime', valid=True, journal_ok=True):
                    mounts=SimpleNamespace(ok=True,stdout=json.dumps({'filesystems':[{'uuid':mounted_uuid,'options':options}]}))
                    journal=SimpleNamespace(ok=journal_ok,stdout='\n'.join(json.dumps(r) for r in lifecycle()) if valid else '{')
                    with patch('fedora_system_monitor.capsules.runtime.filesystem_recovery.Path.read_text',return_value=BOOT), \
                         patch('fedora_system_monitor.capsules.runtime.filesystem_recovery.run_command',side_effect=[mounts,journal]) as command:
                        recovered = readonly_recoveries(db)
                        self.assertEqual(command.call_args_list[0].args[0][:3], ['findmnt', '--task', '1'])
                        return recovered
                self.assertEqual(len(run()),2)
                self.assertEqual(run(mounted_uuid=OTHER),[])
                self.assertEqual(run(options='ro,relatime'),[])
                self.assertEqual(run(valid=False),[])
                self.assertEqual(run(journal_ok=False),[])
                # Deriving evidence never closes or edits an alert itself.
                self.assertEqual(len(db.query("SELECT * FROM alerts WHERE status='active'")),2)
            finally:
                db.close()
