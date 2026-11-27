from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fedora_system_monitor.capsules.reporting import resource_memory


class MemoryCaseTest(unittest.TestCase):
    def test_separate_resident_and_swap_rankings_and_coverage(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            group = root / "group"
            group.mkdir()
            (group / "memory.current").write_text("10485760")
            (group / "memory.stat").write_text("anon 1048576\nfile 5242880\ninactive_file 3145728\n")
            (group / "cgroup.procs").write_text("1\n2\n3\n4\n")
            (root / "meminfo").write_text("MemAvailable: 8192 kB\n")
            for pid, name, pss, swap in ((1,"one",2048,5), (2,"two",128,3000), (3,"gone",8000,8000)):
                proc = root / str(pid)
                proc.mkdir()
                (proc / "stat").write_text("1 (name) " + " ".join(["0"]*20))
                (proc / "exe").symlink_to("/usr/bin/" + name)
                (proc / "smaps_rollup").write_text(f"Pss: {pss} kB\nSwapPss: {swap} kB\n")
                (proc / "cgroup").write_text("0::/group" if pid != 3 else "0::/elsewhere")
            with patch.object(resource_memory, "group_path", return_value=(group, "/group")):
                data = resource_memory.memory_report("system:example.service", proc=root)
            self.assertEqual((data["direct_pids"],data["attempted"],data["measured"]), (4,4,2))
            self.assertEqual(data["by_swap_pss"][0]["name"], "two")
            self.assertEqual(data["by_resident_pss"][0]["name"], "one")
            self.assertEqual(data["cgroup_mib"]["inactive_file"], 3)
            self.assertNotIn("swap", data["cgroup_mib"])
            self.assertEqual(data["host_available_mib"], 8)
            self.assertIsNone(data["group_memory_full_avg60"])
