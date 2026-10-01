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
    def test_repeated_down_and_flapping_keep_one_unresolved_incident(self) -> None:
        states = {}
        captures = []
        capture = lambda item, identity: captures.append((item["heartbeat_id"], identity))

        self.assertEqual(_apply_event(event(10, 0), states, capture), "captured")
        self.assertIsNone(_apply_event(event(11, 0), states, capture))
        self.assertEqual(_apply_event(event(12, 1), states, capture), "recovered")
        self.assertEqual(_apply_event(event(13, 0), states, capture, lambda _:True), "deduplicated")

        self.assertEqual([row[0] for row in captures], [10])
        _apply_event(event(14,1),states,capture)
        self.assertEqual('captured',_apply_event(event(15,0),states,capture,lambda _:False))
        self.assertEqual([10,15],[row[0] for row in captures])
        self.assertNotEqual(captures[0][1],captures[1][1])

    def test_long_flapping_storm_is_one_observation(self):
        states={}; captures=[]
        capture=lambda item,identity:captures.append(identity)
        for heartbeat in range(200):
            _apply_event(event(heartbeat,heartbeat%2),states,capture,lambda _:True)
        self.assertEqual(1,len(captures))

    def test_canonical_pending_and_promoted_work_define_incident_liveness(self):
        import tempfile,sqlite3
        from pathlib import Path
        from unittest.mock import patch
        from fedora_system_monitor.capsules import kuma_c2_bridge as bridge
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'c3.sqlite'
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE issue_inbox(issue_id,state,promoted_work_item_id,matched_work_item_id); CREATE TABLE work_items(work_item_id,status);")
                db.execute("INSERT INTO issue_inbox VALUES('issue:test','pending',NULL,NULL)")
            with patch.object(bridge,'C3_DB',path):
                self.assertTrue(bridge.incident_open('issue:test'))
                with sqlite3.connect(path) as db:
                    db.execute("UPDATE issue_inbox SET state='promoted',promoted_work_item_id='wi:test'")
                    db.execute("INSERT INTO work_items VALUES('wi:test','running')")
                self.assertTrue(bridge.incident_open('issue:test'))
                with sqlite3.connect(path) as db:
                    db.execute("UPDATE work_items SET status='completed'")
                self.assertFalse(bridge.incident_open('issue:test'))
                self.assertTrue(bridge.incident_open('missing'))
            with patch.object(bridge,'C3_DB',Path(tmp)/'missing.sqlite'):
                self.assertTrue(bridge.incident_open('issue:test'))

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
