"""A held maintenance lock must not hide current minute health."""
from argparse import Namespace
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fedora_system_monitor.capsules.command import exclusive_lock
from fedora_system_monitor.capsules.notifications import NotificationResult
from fedora_system_monitor.capsules.runtime import coordinator


class FastHeartbeatTests(unittest.TestCase):
    def test_busy_slow_collection_defers_without_losing_heartbeat_or_clearing_alerts(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            db = Mock(path=root / 'db.sqlite')
            db.get_state.return_value = 0
            db.active_alerts.return_value = [{'category': 'storage'}]
            config = {'monitor': {'lock_path': str(root / 'collector.lock')}}
            run = stack.enter_context(patch.object(coordinator, '_run_isolated_scope',
                side_effect=lambda args, scope, config, db:
                    {'scope': scope, 'outcome': 'ok', 'duration_ms': 1}))
            sent = NotificationResult('uptime-kuma', 'fixture', True, True, 'delivered')
            heartbeat = stack.enter_context(patch.object(coordinator, 'send_category_heartbeat', return_value=sent))
            stack.enter_context(patch.object(coordinator, '_endpoint_alert_snapshot', return_value=({}, [])))
            stack.enter_context(patch.object(coordinator, '_discord_exporter_service_health', return_value=(True, 'fixture')))
            stack.enter_context(patch.object(coordinator, 'prompt_history_freshness', return_value=(True, 'fixture')))
            stack.enter_context(patch.object(coordinator, 'send_named_heartbeat', return_value=sent))
            services = stack.enter_context(patch.object(coordinator, 'send_service_heartbeats', return_value=[]))
            stack.enter_context(patch.object(coordinator, 'send_event_job_heartbeats', return_value=[]))
            with exclusive_lock(root / 'collector.lock.slow', timeout=0):
                report = coordinator._collect_command_with_kuma_snapshot(Namespace(scope='fast'), config, db)
            self.assertEqual([(r['scope'], r['outcome']) for r in report['results']],
                             [('minute', 'ok'), ('five_minute', 'deferred'), ('fifteen_minute', 'deferred')])
            self.assertEqual([call.args[1] for call in run.call_args_list], ['minute'])
            successes = [call.args[0] for call in db.set_state.call_args_list if call.args[0].startswith('last-success:')]
            self.assertEqual(successes, ['last-success:minute'])
            storage = next(call for call in heartbeat.call_args_list if call.args[1] == 'storage')
            self.assertFalse(storage.kwargs['healthy'])
            services.assert_called_once()
            self.assertFalse(services.call_args.kwargs['collector_failed'])
            # The unchanged due timestamps allow the next ordinary tick to retry.
            run.reset_mock()
            report = coordinator._collect_command_with_kuma_snapshot(Namespace(scope='fast'), config, db)
            self.assertEqual([call.args[1] for call in run.call_args_list], ['minute', 'five_minute', 'fifteen_minute'])
            self.assertTrue(all(r['outcome'] == 'ok' for r in report['results']))
