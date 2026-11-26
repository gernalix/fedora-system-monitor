from unittest import TestCase
from fedora_system_monitor.capsules.collectors.chrome_assessment import assess

LIMITS = {"cpu_percent": 80, "io_mib_s": 50, "memory_mib": 2048}


class ChromeAssessment(TestCase):
    def test_three_samples_same_dimension_and_no_aggregate_rss(self):
        row = dict(uid=1000, name="chrome", interval_seconds=60, cpu_percent=45,
                   read_delta=0, write_delta=0, rss_bytes=1200 * 1048576)
        snap = dict(boot_id="boot", complete=True, unreadable=0,
                    rows=[row, row, dict(row, uid=99), dict(row, name="gnome-shell")])
        prev = {}
        for t in range(4):
            prev, crossed = assess(dict(snap, timestamp=1000 + t*60), 1000, LIMITS, prev)
            self.assertEqual(crossed, t == 2)
            self.assertEqual(prev["observed_chrome"], 2)
            self.assertEqual(prev["values"]["largest_process_rss_mib"], 1200)
        prev, crossed = assess(dict(snap, timestamp=1400), 1000, LIMITS, prev)
        self.assertFalse(crossed)
        self.assertEqual(prev["streak"]["cpu_percent"], 1)
        prev, _ = assess(dict(snap, complete=False, timestamp=1460), 1000, LIMITS, prev)
        self.assertEqual(prev["streak"]["cpu_percent"], 0)

    def test_missing_interval_and_missing_io(self):
        row = dict(uid=1000, name="chrome", interval_seconds=None, cpu_percent=350,
                   rss_bytes=None, read_delta=None, write_delta=None)
        d, crossed = assess(dict(boot_id="a", complete=True, unreadable=3, timestamp=10,
                                rows=[row]), 1000, LIMITS, {})
        self.assertFalse(crossed)
        self.assertTrue(all(v is None for v in d["values"].values()))
