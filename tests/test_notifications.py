from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import patch

from fedora_system_monitor.capsules.alerting import AlertSignal
from fedora_system_monitor.capsules.database import Database
from fedora_system_monitor.capsules.notifications import (
    NotificationResult,
    endpoint_key,
    integration_status,
    notify_filesystem_free_changes,
    notify_signals,
    send_category_heartbeat,
    send_telegram_message,
)


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _State:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], object] = {}

    def get_state(self, key: str, default: object = None, *, namespace: str = "application") -> object:
        return self.values.get((namespace, key), default)

    def set_state(self, key: str, value: object, *, namespace: str = "application") -> None:
        self.values[(namespace, key)] = value


def _filesystem_metric(identity: str, mount_point: str, free_bytes: int) -> dict[str, object]:
    return {
        "name": "filesystem_free_bytes",
        "value": free_bytes,
        "device_id": f"{identity}:view:test",
        "details": {
            "filesystem_id": identity,
            "mount_point": mount_point,
        },
    }


class NotificationTests(unittest.TestCase):
    def test_requires_private_https_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "kuma.toml"
            path.write_text('[push]\nheartbeat="http://example.test/api/push/token"\n', encoding="utf-8")
            path.chmod(0o600)
            config = {"notifications": {"uptime_kuma_credentials": str(path)}}
            self.assertFalse(integration_status(config)["configured"])

    @patch.dict(os.environ, {}, clear=True)
    def test_default_kuma_rotates_without_process_restart(self) -> None:
        from fedora_system_monitor.capsules import notifications as module
        with patch.object(module, '_vault_kuma_data', side_effect=[
            {'push': {'system': 'https://example.test/first'}},
            {'push': {'system': 'https://example.test/second'}},
        ]) as vault:
            self.assertEqual(module._load_endpoints({})['system'], 'https://example.test/first')
            self.assertEqual(module._load_endpoints({})['system'], 'https://example.test/second')
            self.assertEqual(vault.call_count, 2)

    @patch.dict(os.environ, {}, clear=True)
    def test_collection_snapshot_reads_once_then_refreshes_next_cycle(self) -> None:
        from fedora_system_monitor.capsules import notifications as module
        first = {'push': {'system': 'https://example.test/first'}}
        second = {'push': {'system': 'https://example.test/second'}}
        with patch.object(module, '_vault_kuma_data', side_effect=[first, second]) as vault:
            with module.kuma_snapshot():
                for _ in range(27):
                    self.assertEqual(module._load_endpoints({})['system'], 'https://example.test/first')
                self.assertEqual(vault.call_count, 1)
            with module.kuma_snapshot():
                self.assertEqual(module._load_endpoints({})['system'], 'https://example.test/second')
            self.assertEqual(vault.call_count, 2)

    @patch.dict(os.environ, {}, clear=True)
    def test_collection_snapshot_does_not_retry_or_fall_back_after_vault_failure(self) -> None:
        from fedora_system_monitor.capsules import notifications as module
        with patch.object(module, '_vault_kuma_data', side_effect=[ValueError('unavailable'),
                          {'push': {'system': 'https://example.test/new'}}]) as vault:
            with module.kuma_snapshot(), patch.object(Path, 'read_text', side_effect=AssertionError('local file read')):
                self.assertEqual(module._load_endpoints({}), {})
                self.assertEqual(module._load_endpoints({}), {})
                self.assertEqual(vault.call_count, 1)
            with module.kuma_snapshot():
                self.assertEqual(module._load_endpoints({})['system'], 'https://example.test/new')
            self.assertEqual(vault.call_count, 2)

    @patch.dict(os.environ, {}, clear=True)
    def test_collector_opens_and_closes_snapshot(self) -> None:
        from fedora_system_monitor.capsules import notifications as module
        from fedora_system_monitor.capsules.runtime import coordinator
        def collect(*args):
            return [module._load_endpoints({}), module._load_endpoints({})]
        with patch.object(module, '_vault_kuma_data', return_value={'push': {'system': 'https://example.test/x'}}) as vault, \
             patch.object(coordinator, '_collect_command_with_kuma_snapshot', side_effect=collect):
            self.assertEqual(len(coordinator._collect_command(None, {}, None)), 2)
            self.assertEqual(vault.call_count, 1)
            module._load_endpoints({})
            self.assertEqual(vault.call_count, 2)

    @patch.dict(os.environ, {}, clear=True)
    def test_default_kuma_never_falls_back_when_vault_fails(self) -> None:
        from fedora_system_monitor.capsules import notifications as module
        with patch.object(module, '_vault_kuma_data', side_effect=ValueError('unavailable')):
            with patch.object(Path, 'read_text', side_effect=AssertionError('local file read')):
                self.assertEqual(module._load_endpoints({}), {})
                self.assertFalse(integration_status({})['configured'])

    def test_kuma_vault_uses_selected_field_and_host_runtime(self) -> None:
        import base64
        from fedora_system_monitor.capsules import notifications as module
        for uid in (0, 1000):
            runtime = SimpleNamespace(load_reference=mock.Mock(return_value={
                'KUMA_TOML_BASE64': base64.b64encode(b'[push]\nsystem="https://example.test/current"\n').decode()
            }))
            loader = SimpleNamespace(exec_module=mock.Mock())
            spec = SimpleNamespace(loader=loader)
            with self.subTest(uid=uid), patch.object(module.os, 'geteuid', return_value=uid), \
                 patch.object(module.importlib.util, 'spec_from_file_location', return_value=spec) as get_spec, \
                 patch.object(module.importlib.util, 'module_from_spec', return_value=runtime), \
                 patch.object(Path, 'read_text', return_value='{"references":{}}'):
                self.assertIn('system', module._vault_kuma_data()['push'])
                runtime.load_reference.assert_called_once_with(
                    {'references': {}}, 'FEDORA_SYSTEM_MONITOR_KUMA_ENV', {'KUMA_TOML_BASE64'})
                expected = Path('/usr/local/lib/bitwarden-fedora') if uid == 0 else Path.home() / '.local/lib/bitwarden'
                self.assertEqual(get_spec.call_args.args[1], expected / 'credential_runtime.py')

    def test_native_kuma_file_precedes_default_vault(self) -> None:
        from fedora_system_monitor.capsules import notifications as module
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'uptime-kuma.toml'
            path.write_text('[push]\nsystem="https://example.test/native"\n')
            path.chmod(0o600)
            with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': temp}), \
                 patch.object(module, '_vault_kuma_data', side_effect=AssertionError('unexpected vault')):
                self.assertEqual(module._load_endpoints({})['system'], 'https://example.test/native')

    def test_endpoint_routing(self) -> None:
        self.assertEqual(endpoint_key("filesystem"), "storage")
        self.assertEqual(endpoint_key("service"), "services")
        self.assertEqual(endpoint_key("discord_exporter"), "discord_exporter")
        self.assertEqual(endpoint_key("memory"), "system")

    def test_explicit_root_only_http_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "kuma.toml"
            path.write_text('[push]\nsystem="http://example.test/api/push/value"\n[transport]\nallow_insecure_http=true\n', encoding="utf-8")
            path.chmod(0o600)
            config = {"notifications": {"uptime_kuma_credentials": str(path)}}
            status = integration_status(config)
            self.assertTrue(status["configured"])
            self.assertFalse(status["secure"])

    @patch("urllib.request.urlopen", return_value=_Response())
    def test_result_never_contains_endpoint(self, mocked) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "kuma.toml"
            secret = "secret-token-value"
            path.write_text(f'[push]\nsystem="https://example.test/api/push/{secret}"\n', encoding="utf-8")
            path.chmod(0o600)
            config = {"notifications": {"uptime_kuma_credentials": str(path), "timeout_seconds": 1}}
            signal = AlertSignal("key", "system", "test", "warning", True, "test alert", "test")
            result = notify_signals([signal], config)[0]
            self.assertTrue(result.delivered)
            self.assertNotIn(secret, repr(result))

    @patch("fedora_system_monitor.capsules.notifications._push", return_value=(True, "delivered"))
    def test_unhealthy_category_heartbeat_does_not_claim_recovery(self, mocked) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "kuma.toml"
            path.write_text('[push]\nstorage="https://example.test/api/push/value"\n', encoding="utf-8")
            path.chmod(0o600)
            config = {"notifications": {"uptime_kuma_credentials": str(path), "timeout_seconds": 1}}
            result = send_category_heartbeat(
                config,
                "storage",
                healthy=False,
                message="storage: collectors complete; active alerts=1",
                ping_ms=25,
            )

        self.assertTrue(result.delivered)
        mocked.assert_called_once()
        self.assertFalse(mocked.call_args.kwargs["up"])
        self.assertEqual(mocked.call_args.kwargs["message"], "storage: collectors complete; active alerts=1")

    @patch("fedora_system_monitor.capsules.notifications._push", return_value=(True, "delivered"))
    def test_inverted_category_reports_opposite_status_once(self, mocked) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "kuma.toml"
            path.write_text('[push]\nstorage="https://example.test/api/push/value"\n', encoding="utf-8")
            path.chmod(0o600)
            config = {
                "notifications": {
                    "uptime_kuma_credentials": str(path),
                    "timeout_seconds": 1,
                    "inverted_categories": ["storage"],
                }
            }
            result = send_category_heartbeat(
                config,
                "storage",
                healthy=False,
                message="storage: collectors complete; active alerts=1",
                ping_ms=25,
            )

        self.assertTrue(result.delivered)
        self.assertEqual(mocked.call_count, 1)
        self.assertTrue(mocked.call_args.kwargs["up"])
        self.assertEqual(mocked.call_args.kwargs["message"], "storage: collectors complete; active alerts=1")

    def test_default_telegram_uses_vault_and_restores_environment(self) -> None:
        seen = []
        def read_vault():
            self.assertNotIn('TELEGRAM_BOT_TOKEN', os.environ)
            self.assertNotIn('TELEGRAM_NOTIFY_CONFIG', os.environ)
            return 'vault-token', 'vault-chat'
        def send(*args, **kwargs):
            seen.append((os.environ.get('TELEGRAM_INSERT_BOT_NOISY_BOT_TOKEN'),
                         os.environ.get('TELEGRAM_INSERT_BOT_NOISY_CHAT_ID')))
            return 'suppressed'
        helper = SimpleNamespace(config=SimpleNamespace(get_config=mock.Mock(side_effect=read_vault)),
                                 load_config_files=mock.Mock(), validate_config=mock.Mock(),
                                 send_alert=mock.Mock(side_effect=send))
        with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'stale',
                                     'TELEGRAM_NOTIFY_CONFIG': 'old'}, clear=True), \
                patch.dict(sys.modules, {'telegram_notify': helper}):
            result = send_telegram_message({}, 'test')
            self.assertEqual(os.environ['TELEGRAM_BOT_TOKEN'], 'stale')
            self.assertEqual(os.environ['TELEGRAM_NOTIFY_CONFIG'], 'old')
            self.assertNotIn('TELEGRAM_INSERT_BOT_NOISY_BOT_TOKEN', os.environ)
        self.assertEqual(seen, [('vault-token', 'vault-chat')])
        self.assertEqual(result.status, 'suppressed')

    def test_default_telegram_fails_closed_when_vault_is_unavailable(self) -> None:
        helper = SimpleNamespace(config=SimpleNamespace(get_config=mock.Mock(side_effect=RuntimeError('private details'))),
                                 load_config_files=mock.Mock(), validate_config=mock.Mock(),
                                 send_alert=mock.Mock())
        with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'stale'}, clear=True), \
                patch.dict(sys.modules, {'telegram_notify': helper}):
            result = send_telegram_message({}, 'test')
        self.assertFalse(result.delivered)
        self.assertEqual(result.status, 'RuntimeError')
        self.assertNotIn('private details', repr(result))
        helper.send_alert.assert_not_called()

    def test_telegram_prefers_systemd_credential_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            credential = Path(temp) / "telegram.env"
            credential.write_text(
                "TELEGRAM_BOT_TOKEN=test-token\nTELEGRAM_CHAT_ID=123\n",
                encoding="utf-8",
            )
            credential.chmod(0o600)
            config = {
                "notifications": {
                    "telegram_credentials": "/legacy/should-not-be-used.env",
                    "timeout_seconds": 1,
                }
            }
            observed: list[str] = []

            def capture_config_path() -> None:
                observed.append(os.environ.get("TELEGRAM_NOTIFY_CONFIG", ""))

            helper = SimpleNamespace(
                load_config_files=mock.Mock(side_effect=capture_config_path),
                validate_config=mock.Mock(),
                send_alert=mock.Mock(return_value="sent"),
            )
            with patch.dict(
                os.environ,
                {"CREDENTIALS_DIRECTORY": temp},
                clear=False,
            ), patch.dict(sys.modules, {"telegram_notify": helper}):
                result = send_telegram_message(config, "test")

            self.assertTrue(result.delivered)
            self.assertEqual(observed, [str(credential)])

    def test_telegram_result_never_contains_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "telegram.env"
            token = "123456:secret-token-value"
            chat_id = "998877"
            path.write_text(
                f"TELEGRAM_BOT_TOKEN={token}\nTELEGRAM_CHAT_ID={chat_id}\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            config = {
                "notifications": {
                    "telegram_credentials": str(path),
                    "timeout_seconds": 1,
                }
            }
            helper = SimpleNamespace(
                load_config_files=mock.Mock(),
                validate_config=mock.Mock(),
                send_alert=mock.Mock(return_value="sent"),
            )
            with patch.dict(sys.modules, {"telegram_notify": helper}):
                result = send_telegram_message(config, "test")
            self.assertTrue(result.delivered)
            helper.send_alert.assert_called_once()
            self.assertEqual(helper.send_alert.call_args.kwargs["severity"], "info")
            self.assertNotIn(token, repr(result))
            self.assertNotIn(chat_id, repr(result))

    def test_legacy_helper_does_not_bypass_missing_shared_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "telegram.env"
            path.write_text("synthetic credentials", encoding="utf-8")
            path.chmod(0o600)
            helper = SimpleNamespace(
                load_config_files=mock.Mock(),
                validate_config=mock.Mock(),
                send_message=mock.Mock(),
            )
            with patch.dict(sys.modules, {"telegram_notify": helper}), patch.dict(
                os.environ, {"TELEGRAM_NOTIFY_CONFIG": "previous-config"}
            ):
                result = send_telegram_message(
                    {"notifications": {"telegram_credentials": str(path)}}, "test"
                )
                self.assertEqual(os.environ["TELEGRAM_NOTIFY_CONFIG"], "previous-config")
            self.assertFalse(result.attempted)
            self.assertFalse(result.delivered)
            self.assertEqual(result.status, "shared alert policy unavailable")
            helper.load_config_files.assert_not_called()
            helper.validate_config.assert_not_called()
            helper.send_message.assert_not_called()

    def test_policy_suppression_is_not_reported_as_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "telegram.env"
            path.write_text("synthetic credentials", encoding="utf-8")
            path.chmod(0o600)
            helper = SimpleNamespace(
                load_config_files=mock.Mock(), validate_config=mock.Mock(),
                send_alert=mock.Mock(return_value="suppressed"),
            )
            with patch.dict(sys.modules, {"telegram_notify": helper}), patch.dict(
                os.environ, {"STATE_DIRECTORY": temp}
            ):
                result = send_telegram_message(
                    {"notifications": {"telegram_credentials": str(path)}}, "test",
                    event_key="filesystem-free:synthetic-volume", severity="warning",
                )
            self.assertTrue(result.attempted)
            self.assertFalse(result.delivered)
            self.assertEqual((result.status, result.error), ("suppressed", ""))
            helper.send_alert.assert_called_once_with(
                "Spazio su Fedora", "test",
                event_key="fedora_system_monitor:filesystem-free:synthetic-volume",
                severity="warning", state_path=Path(temp) / "telegram_alert_policy.sqlite",
            )

    @patch(
        "fedora_system_monitor.capsules.notifications.send_telegram_message",
        return_value=NotificationResult("telegram", "filesystem", True, False, "suppressed"),
    )
    def test_suppressed_observation_advances_baseline_without_retries(self, sender) -> None:
        gib = 1024**3
        db = _State()
        config = {"notifications": {"filesystem_free_change_gib": 1.0}}
        initial = [_filesystem_metric("fsuuid:one", "/", 10 * gib)]
        changed = [_filesystem_metric("fsuuid:one", "/", 8 * gib)]
        notify_filesystem_free_changes(initial, config, db)
        first = notify_filesystem_free_changes(changed, config, db)
        self.assertFalse(first[0].delivered)
        self.assertEqual(notify_filesystem_free_changes(changed, config, db), [])
        sender.assert_called_once()
        self.assertEqual(sender.call_args.kwargs["severity"], "warning")
        self.assertEqual(sender.call_args.kwargs["event_key"], "filesystem-free:fsuuid:one")

    @patch(
        "fedora_system_monitor.capsules.notifications.send_telegram_message",
        return_value=NotificationResult("telegram", "filesystem", True, True, "delivered"),
    )
    def test_cumulative_decrease_and_no_duplicate(self, sender) -> None:
        gib = 1024**3
        db = _State()
        config = {"notifications": {"filesystem_free_change_gib": 1.0}}
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:one", "/data", 10 * gib)], config, db)
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:one", "/data", 10 * gib - 400 * 1024**2)], config, db)
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:one", "/data", 10 * gib - 800 * 1024**2)], config, db)
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:one", "/data", 10 * gib - 1100 * 1024**2)], config, db)
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:one", "/data", 10 * gib - 1100 * 1024**2)], config, db)
        self.assertEqual(sender.call_count, 1)
        self.assertIn("diminuito di 1.07 GiB", sender.call_args.args[1])
        self.assertEqual(config["notifications"]["filesystem_free_change_gib"], 1.0)

    @patch(
        "fedora_system_monitor.capsules.notifications.send_telegram_message",
        return_value=NotificationResult("telegram", "filesystem", True, True, "delivered"),
    )
    def test_increase_and_multiple_filesystems(self, sender) -> None:
        gib = 1024**3
        db = _State()
        config = {"notifications": {"filesystem_free_change_gib": 1.0}}
        initial = [
            _filesystem_metric("fsuuid:one", "/", 10 * gib),
            _filesystem_metric("fsuuid:two", "/external", 20 * gib),
        ]
        notify_filesystem_free_changes(initial, config, db)
        changed = [
            _filesystem_metric("fsuuid:one", "/", 12 * gib),
            _filesystem_metric("fsuuid:two", "/external", 18 * gib),
        ]
        notify_filesystem_free_changes(changed, config, db)
        self.assertEqual(sender.call_count, 2)
        messages = [call.args[1] for call in sender.call_args_list]
        self.assertTrue(any("aumentato di 2.00 GiB" in message for message in messages))
        self.assertTrue(any("diminuito di 2.00 GiB" in message for message in messages))

    @patch(
        "fedora_system_monitor.capsules.notifications.send_telegram_message",
        return_value=NotificationResult("telegram", "filesystem", True, True, "delivered"),
    )
    def test_unmounted_then_remounted_at_different_path_keeps_uuid_state(self, sender) -> None:
        gib = 1024**3
        db = _State()
        config = {"notifications": {"filesystem_free_change_gib": 1.0}}
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:portable", "/media/old", 10 * gib)], config, db)
        notify_filesystem_free_changes([], config, db)
        notify_filesystem_free_changes([_filesystem_metric("fsuuid:portable", "/media/new", 8 * gib)], config, db)
        self.assertEqual(sender.call_count, 1)
        self.assertIn("su /media/new è diminuito", sender.call_args.args[1])

    @patch(
        "fedora_system_monitor.capsules.notifications.send_telegram_message",
        return_value=NotificationResult("telegram", "filesystem", True, True, "delivered"),
    )
    def test_state_survives_database_reopen(self, sender) -> None:
        gib = 1024**3
        config = {"notifications": {"filesystem_free_change_gib": 1.0}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "monitor.sqlite3"
            first = Database(path, hostname="test", timezone_name="UTC")
            notify_filesystem_free_changes(
                [_filesystem_metric("fsuuid:persistent", "/data", 10 * gib)],
                config,
                first,
            )
            second = Database(path, hostname="test", timezone_name="UTC")
            notify_filesystem_free_changes(
                [_filesystem_metric("fsuuid:persistent", "/data", 8 * gib)],
                config,
                second,
            )
        self.assertEqual(sender.call_count, 1)

    @patch(
        "fedora_system_monitor.capsules.notifications.send_telegram_message",
        side_effect=[
            NotificationResult("telegram", "filesystem", True, False, "timeout", "timeout"),
            NotificationResult("telegram", "filesystem", True, True, "delivered"),
        ],
    )
    def test_failed_send_keeps_reference_and_success_stops_retry(self, sender) -> None:
        gib = 1024**3
        db = _State()
        config = {"notifications": {"filesystem_free_change_gib": 1.0}}
        initial = [_filesystem_metric("fsuuid:one", "/", 10 * gib)]
        changed = [_filesystem_metric("fsuuid:one", "/", 8 * gib)]
        notify_filesystem_free_changes(initial, config, db)
        notify_filesystem_free_changes(changed, config, db)
        notify_filesystem_free_changes(changed, config, db)
        notify_filesystem_free_changes(changed, config, db)
        self.assertEqual(sender.call_count, 2)


if __name__ == "__main__":
    unittest.main()
