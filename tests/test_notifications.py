from __future__ import annotations

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

    def test_endpoint_routing(self) -> None:
        self.assertEqual(endpoint_key("filesystem"), "storage")
        self.assertEqual(endpoint_key("service"), "services")
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
    def test_unhealthy_category_heartbeat_keeps_push_liveness(self, mocked) -> None:
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
        self.assertEqual(mocked.call_count, 2)
        self.assertTrue(mocked.call_args_list[0].kwargs["up"])
        self.assertEqual(mocked.call_args_list[0].kwargs["message"], "storage: heartbeat live; alert state follows")
        self.assertFalse(mocked.call_args_list[1].kwargs["up"])
        self.assertEqual(mocked.call_args_list[1].kwargs["message"], "storage: collectors complete; active alerts=1")

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
                send_message=mock.Mock(),
            )
            with patch.dict(sys.modules, {"telegram_notify": helper}):
                result = send_telegram_message(config, "test")
            self.assertTrue(result.delivered)
            helper.send_message.assert_called_once_with("Fedora System Monitor", "test", project_id=15)
            self.assertNotIn(token, repr(result))
            self.assertNotIn(chat_id, repr(result))

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
        self.assertIn("variazione -1.07 GiB", sender.call_args.args[1])
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
        self.assertTrue(any("variazione +2.00 GiB" in message for message in messages))
        self.assertTrue(any("variazione -2.00 GiB" in message for message in messages))

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
        self.assertIn("💾 /media/new:", sender.call_args.args[1])

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
