from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.collectors import periodic
from test_collectors import FakeDatabase


class TemperatureIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hwmon = self.root / "class/hwmon"
        self.hwmon.mkdir(parents=True)
        self.db = FakeDatabase()
        self.patcher = patch.object(periodic, "SYS_ROOT", self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def sensor(self, name, device, temperature, alarm=0):
        physical = self.root / "devices" / device
        physical.mkdir(parents=True, exist_ok=True)
        node = self.hwmon / name
        node.mkdir()
        (node / "device").symlink_to(physical, target_is_directory=True)
        (node / "name").write_text("spd5118\n")
        (node / "temp1_input").write_text(str(temperature * 1000))
        (node / "temp1_alarm").write_text(str(alarm))
        return node

    def collect(self):
        return periodic.collect_temperatures("five_minute", {}, self.db).metrics

    def temperatures(self):
        return {m["device_id"]: m["value"] for m in self.collect() if m["name"] == "temperature"}

    def test_equal_labels_keep_both_modules_and_independent_alarms(self):
        self.sensor("hwmon1", "bus-0050", 55, 0)
        self.sensor("hwmon2", "bus-0051", 66, 1)
        metrics = self.collect()
        temperatures = [m for m in metrics if m["name"] == "temperature"]
        self.assertEqual({m["value"] for m in temperatures}, {55, 66})
        self.assertEqual(len({m["device_id"] for m in temperatures}), 2)
        alarms = {m["device_id"]: m["value"] for m in metrics if m["name"] == "sensor.alarm"}
        self.assertEqual(alarms["spd5118:sensor_1"], 0)
        self.assertEqual(sum(alarms.values()), 1)

    def test_reordering_or_losing_primary_does_not_reassign_series(self):
        first = self.sensor("hwmon1", "bus-0050", 55)
        second = self.sensor("hwmon2", "bus-0051", 66)
        before = self.temperatures()
        first.rename(self.hwmon / "hwmon9")
        second.rename(self.hwmon / "hwmon0")
        self.assertEqual(self.temperatures(), before)
        (self.hwmon / "hwmon9").rename(self.root / "disconnected")
        remaining = self.temperatures()
        self.assertEqual(remaining, {k:v for k,v in before.items() if v == 66})

    def test_duplicate_alias_is_deduplicated_by_physical_channel(self):
        self.sensor("hwmon1", "bus-0050", 55)
        self.sensor("hwmon2", "bus-0050", 55)
        self.assertEqual(len(self.temperatures()), 1)

    def test_two_chip_interfaces_on_same_device_do_not_alias(self):
        self.sensor("hwmon1", "bus-0050", 55)
        other = self.sensor("hwmon2", "bus-0050", 66)
        (other / "name").write_text("other_driver\n")
        self.assertEqual(set(self.temperatures().values()), {55, 66})

    def test_channels_with_equal_labels_on_same_chip_remain_distinct(self):
        node = self.sensor("hwmon1", "bus-0050", 55)
        (node / "temp1_label").write_text("DIMM\n")
        (node / "temp2_input").write_text("66000")
        (node / "temp2_label").write_text("DIMM\n")
        result = self.temperatures()
        self.assertEqual(set(result.values()), {55, 66})
        self.assertEqual(len(result), 2)
