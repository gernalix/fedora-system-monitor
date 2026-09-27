from __future__ import annotations

import unittest

from fedora_system_monitor.capsules.kuma_c2_bridge import _apply_event, issue_id_for


def event(heartbeat_id: int, status: int, *, active: bool = True) -> dict[str, object]:
    return {
        "heartbeat_id": heartbeat_id,
        "monitor_id": 40,
        "monitor_name": "Fedora Storage",
        "active": active,
        "status": status,
        "msg": "storage: collectors complete; active alerts=8",
        "time": "2026-09-27 19:33:19.481",
    }


class KumaC2BridgeTests(unittest.TestCase):
    def test_repeated_down_is_one_capture_and_up_allows_a_new_incident(self) -> None:
        states = {}
        captures = []
        capture = lambda item, identity: captures.append((item["heartbeat_id"], identity))

        self.assertEqual(_apply_event(event(10, 0), states, capture), "captured")
        self.assertIsNone(_apply_event(event(11, 0), states, capture))
        self.assertEqual(_apply_event(event(12, 1), states, capture), "recovered")
        self.assertEqual(_apply_event(event(13, 0), states, capture), "captured")

        self.assertEqual([row[0] for row in captures], [10, 13])
        self.assertNotEqual(captures[0][1], captures[1][1])

    def test_pending_does_not_clear_an_active_outage(self) -> None:
        states = {}
        captures = []
        capture = lambda item, identity: captures.append(identity)

        _apply_event(event(10, 0), states, capture)
        self.assertIsNone(_apply_event(event(11, 2), states, capture))
        self.assertIsNone(_apply_event(event(12, 0), states, capture))

        self.assertEqual(len(captures), 1)
        self.assertTrue(states[40]["is_down"])

    def test_inactive_monitor_does_not_open_an_incident(self) -> None:
        states = {}
        captures = []
        self.assertIsNone(_apply_event(event(10, 0, active=False), states, lambda *args: captures.append(args)))
        self.assertEqual(captures, [])
        self.assertFalse(states[40]["is_down"])

    def test_issue_identity_is_stable_for_the_same_down_heartbeat(self) -> None:
        self.assertEqual(issue_id_for(40, 1234), issue_id_for(40, 1234))
        self.assertNotEqual(issue_id_for(40, 1234), issue_id_for(40, 1235))


if __name__ == "__main__":
    unittest.main()
