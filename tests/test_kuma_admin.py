from __future__ import annotations

import unittest

from fedora_system_monitor.capsules.kuma_admin import (
    KumaMonitorSpec,
    _monitor_payload,
    _monitor_upside_down,
)


class KumaAdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = KumaMonitorSpec(
            "storage",
            "Fedora Storage",
            "Storage health",
            480,
            180,
            2,
        )

    def test_payload_can_preserve_upside_down(self) -> None:
        payload = _monitor_payload(
            self.spec,
            "token",
            {},
            upside_down=True,
        )
        self.assertTrue(payload["upsideDown"])

    def test_existing_upside_down_aliases_are_preserved(self) -> None:
        self.assertTrue(_monitor_upside_down({"upsideDown": True}))
        self.assertTrue(_monitor_upside_down({"upside_down": 1}))
        self.assertFalse(_monitor_upside_down({"upsideDown": False}))
        self.assertFalse(_monitor_upside_down(None))


if __name__ == "__main__":
    unittest.main()
