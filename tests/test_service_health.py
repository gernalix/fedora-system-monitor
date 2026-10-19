from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from fedora_system_monitor.capsules.notifications import NotificationResult
from fedora_system_monitor.capsules.service_health import (
    send_service_heartbeats,
    service_monitor_key,
    service_monitor_spec,
)


class _DB:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters=()):
        self.sql = sql
        self.parameters = parameters
        return list(self.rows)


class ServiceHealthTests(unittest.TestCase):
    @mock.patch('fedora_system_monitor.capsules.service_health.configured_push_keys')
    @mock.patch('fedora_system_monitor.capsules.service_health.send_named_heartbeat')
    def test_retired_service_never_sends_from_historical_sample(self, sender, keys):
        identity = 'user:workflowy-roadmap-sync.service'
        keys.return_value = {service_monitor_key(identity)}
        result = send_service_heartbeats({'services': {'retired': [identity]}},
                                         _DB([{'device_id': identity}]))
        self.assertEqual([], result)
        sender.assert_not_called()

    def test_monitor_key_is_stable_and_toml_safe(self):
        key = service_monitor_key("user:chrome-codex-switcher.service")
        self.assertEqual(key, service_monitor_key("user:chrome-codex-switcher.service"))
        self.assertRegex(key, r"^service_[a-z0-9_]+_[0-9a-f]{10}$")
        self.assertNotEqual(key, service_monitor_key("chrome-codex-switcher.service"))

    def test_monitor_spec_uses_independent_push_identity(self):
        spec = service_monitor_spec("example.service")
        self.assertEqual(spec.key, service_monitor_key("example.service"))
        self.assertIn("example.service", spec.name)

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_pushes_only_provisioned_service_and_accepts_successful_oneshot(self, keys, sender):
        identity = "example.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 21, 20, 0, tzinfo=timezone.utc)
        rows = [
            {
                "device_id": identity,
                "value": 0,
                "timestamp_utc": now.isoformat(),
                "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":true}',
            },
            {
                "device_id": "unprovisioned.service",
                "value": 1,
                "timestamp_utc": now.isoformat(),
                "details_json": '{"active_state":"active","sub_state":"running","result":"success"}',
            },
        ]
        results = send_service_heartbeats({}, _DB(rows), now=now)

        self.assertEqual(len(results), 1)
        sender.assert_called_once()
        self.assertTrue(sender.call_args.kwargs["healthy"])
        self.assertEqual(sender.call_args.args[1], service_monitor_key(identity))

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_stale_scheduled_oneshot_is_down(self, keys, sender):
        identity = "user:workflowy-roadmap-sync.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 24, 1, 0, tzinfo=timezone.utc)
        rows = [{
            "device_id": identity,
            "value": 0,
            "timestamp_utc": now.isoformat(),
            "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":true,"freshness_seconds":300,"last_success_age_seconds":901,"freshness_ok":false}',
        }]

        send_service_heartbeats({}, _DB(rows), now=now)

        self.assertFalse(sender.call_args.kwargs["healthy"])
        self.assertIn("freshness stale", sender.call_args.kwargs["message"])

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_fresh_scheduled_oneshot_is_up(self, keys, sender):
        identity = "user:workflowy-roadmap-sync.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 24, 1, 0, tzinfo=timezone.utc)
        rows = [{
            "device_id": identity,
            "value": 0,
            "timestamp_utc": now.isoformat(),
            "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":true,"freshness_seconds":300,"last_success_age_seconds":75,"freshness_ok":true}',
        }]

        send_service_heartbeats({}, _DB(rows), now=now)

        self.assertTrue(sender.call_args.kwargs["healthy"])

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch("fedora_system_monitor.capsules.service_health.configured_push_keys")
    def test_running_scheduled_oneshot_requires_previous_fresh_success(self, keys, sender):
        identity = "user:github-autosync.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 24, 1, 0, tzinfo=timezone.utc)
        row = {"device_id": identity, "value": 0, "timestamp_utc": now.isoformat(),
               "details_json": '{"active_state":"activating","sub_state":"start","result":"success","running_oneshot":true,"freshness_ok":true}'}
        send_service_heartbeats({}, _DB([row]), now=now)
        self.assertTrue(sender.call_args.kwargs["healthy"])
        row["details_json"] = row["details_json"].replace('"freshness_ok":true', '"freshness_ok":false')
        send_service_heartbeats({}, _DB([row]), now=now)
        self.assertFalse(sender.call_args.kwargs["healthy"])

    @mock.patch(
        "fedora_system_monitor.capsules.service_health.send_named_heartbeat",
        return_value=NotificationResult("uptime-kuma", "service_x", True, True, "delivered"),
    )
    @mock.patch(
        "fedora_system_monitor.capsules.service_health.configured_push_keys",
    )
    def test_inactive_long_running_service_is_down(self, keys, sender):
        identity = "example.service"
        keys.return_value = {service_monitor_key(identity)}
        now = datetime(2026, 9, 21, 20, 0, tzinfo=timezone.utc)
        rows = [{
            "device_id": identity,
            "value": 0,
            "timestamp_utc": now.isoformat(),
            "details_json": '{"active_state":"inactive","sub_state":"dead","result":"success","successful_inactive_oneshot":false}',
        }]

        send_service_heartbeats({}, _DB(rows), now=now)

        self.assertFalse(sender.call_args.kwargs["healthy"])


    def test_report_refresh_during_slow_sends_uses_current_clock(self):
        start = datetime(2026, 10, 19, 17, 0, tzinfo=timezone.utc)
        later = start + timedelta(seconds=90)
        identities = ['earlier.service', 'user:grindr-snapshot-health.service']
        details = json.dumps(dict(active_state='inactive', sub_state='dead',
                                  result='success', successful_inactive_oneshot=True))
        rows = [dict(device_id=identity, timestamp_utc=start.isoformat(),
                     details_json=details) for identity in identities]
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / 'report.json'
            report.write_text(json.dumps(dict(observed_at=later.timestamp(),
                                              healthy=True, message='Fresh report')))
            config = {'services': {'health_reports': {
                identities[1]: {'path': str(report), 'label': 'Snapshot Grindr'}}}}
            with mock.patch('fedora_system_monitor.capsules.service_health.configured_push_keys',
                            return_value={service_monitor_key(v) for v in identities}), \
                 mock.patch('fedora_system_monitor.capsules.service_health.send_named_heartbeat') as sender, \
                 mock.patch('fedora_system_monitor.capsules.service_health.datetime') as clock:
                clock.now.side_effect = [start, later]
                clock.fromisoformat.side_effect = datetime.fromisoformat
                send_service_heartbeats(config, _DB(rows))
            self.assertTrue(sender.call_args_list[1].kwargs['healthy'])
            self.assertEqual('Fresh report', sender.call_args_list[1].kwargs['message'])

    def test_custom_report_failures_remain_down(self):
        now = datetime(2026, 10, 19, 17, 0, tzinfo=timezone.utc)
        identity = 'user:grindr-snapshot-health.service'
        row = dict(device_id=identity, timestamp_utc=now.isoformat(),
                   details_json=json.dumps(dict(active_state='inactive', result='success',
                                                successful_inactive_oneshot=True)))
        cases = [
            ('fresh', dict(observed_at=now.timestamp(), healthy=True, message='Healthy'), True),
            ('stale', dict(observed_at=now.timestamp()-181, healthy=True, message='Old'), False),
            ('future', dict(observed_at=now.timestamp()+31, healthy=True, message='Future'), False),
            ('unhealthy', dict(observed_at=now.timestamp(), healthy=False, message='Not healthy'), False),
            ('invalid', dict(observed_at=now.timestamp(), healthy='true', message='Invalid'), False),
            ('missing', None, False),
        ]
        for label, body, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                report = Path(temporary) / 'report.json'
                if body is not None:
                    report.write_text(json.dumps(body))
                config = {'services': {'health_reports': {
                    identity: {'path': str(report), 'label': 'Snapshot Grindr'}}}}
                with mock.patch('fedora_system_monitor.capsules.service_health.configured_push_keys',
                                return_value={service_monitor_key(identity)}), \
                     mock.patch('fedora_system_monitor.capsules.service_health.send_named_heartbeat') as sender:
                    send_service_heartbeats(config, _DB([row]), now=now)
                self.assertEqual(expected, sender.call_args.kwargs['healthy'])

    def test_service_sample_that_expires_during_sends_remains_down(self):
        start = datetime(2026, 10, 19, 17, 0, tzinfo=timezone.utc)
        identities = ['earlier.service', 'later.service']
        rows = [dict(device_id=identity, timestamp_utc=start.isoformat(),
                     details_json='{"active_state":"active","result":"success"}')
                for identity in identities]
        with mock.patch('fedora_system_monitor.capsules.service_health.configured_push_keys',
                        return_value={service_monitor_key(v) for v in identities}), \
             mock.patch('fedora_system_monitor.capsules.service_health.send_named_heartbeat') as sender, \
             mock.patch('fedora_system_monitor.capsules.service_health.datetime') as clock:
            clock.now.side_effect = [start, start + timedelta(seconds=181)]
            clock.fromisoformat.side_effect = datetime.fromisoformat
            send_service_heartbeats({}, _DB(rows))
        self.assertTrue(sender.call_args_list[0].kwargs['healthy'])
        self.assertFalse(sender.call_args_list[1].kwargs['healthy'])


if __name__ == "__main__":
    unittest.main()
