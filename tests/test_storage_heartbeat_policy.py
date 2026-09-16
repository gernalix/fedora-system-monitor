from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from fedora_system_monitor.capsules.notifications import NotificationResult
from fedora_system_monitor.capsules.runtime.coordinator import _collect_command


class _FakeDatabase:
    def __init__(self, root: Path) -> None:
        self.path = root / "monitor.sqlite3"
        self._state: dict[str, object] = {}

    def active_alerts(self) -> list[dict[str, object]]:
        return []

    def get_state(self, key: str, default: object = None, *, namespace: str = "runtime") -> object:
        del namespace
        return self._state.get(key, default)

    def set_state(self, key: str, value: object, *, namespace: str = "runtime") -> None:
        del namespace
        self._state[key] = value


class StorageHeartbeatPolicyTests(unittest.TestCase):
    def test_minute_collection_keeps_storage_push_alive(self) -> None:
        """Storage DOWN uses Kuma retry_interval=180s, so minute runs must refresh it."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = _FakeDatabase(root)
            config = {"monitor": {"lock_path": str(root / "collector.lock")}}
            calls: list[tuple[str, bool, str]] = []

            def fake_collect(*_: object, **__: object) -> dict[str, object]:
                return {"outcome": "ok", "duration_ms": 25}

            def fake_heartbeat(
                _: object,
                category: str,
                *,
                healthy: bool,
                message: str,
                ping_ms: int | None = None,
            ) -> NotificationResult:
                del ping_ms
                calls.append((category, healthy, message))
                return NotificationResult("uptime-kuma", category, True, False, "test")

            with (
                patch("fedora_system_monitor.capsules.runtime.coordinator._run_isolated_scope", fake_collect),
                patch("fedora_system_monitor.capsules.runtime.coordinator.send_category_heartbeat", fake_heartbeat),
            ):
                output = _collect_command(Namespace(scope="minute"), config, database)  # type: ignore[arg-type]

        categories = {category for category, _, _ in calls}
        self.assertEqual(categories, {"network", "services", "storage", "system"})
        self.assertEqual(output["results"][0]["outcome"], "ok")
        storage = [call for call in calls if call[0] == "storage"]
        self.assertEqual(len(storage), 1)
        self.assertTrue(storage[0][1])
        self.assertEqual(storage[0][2], "storage: collectors complete; active alerts=0")


if __name__ == "__main__":
    unittest.main()
