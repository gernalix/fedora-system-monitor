from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.capsules.alerting import AlertSignal
from fedora_system_monitor.capsules.notifications import endpoint_key, integration_status, notify_signals


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


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


if __name__ == "__main__":
    unittest.main()
