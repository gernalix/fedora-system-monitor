from __future__ import annotations

from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src" / "fedora_system_monitor"


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_composition_root_only_parses_and_delegates(self) -> None:
        text = (SOURCE / "app.py").read_text(encoding="utf-8")
        self.assertLessEqual(len(text.splitlines()), 125)
        self.assertIn("from fedora_system_monitor.capsules.runtime.coordinator import", text)
        self.assertIn("execute,", text)
        self.assertNotIn("collect_scope", text)
        self.assertNotIn("evaluate_metric_alerts", text)
        self.assertNotIn("stream_journal", text)
        self.assertNotIn("insert_events", text)

    def test_only_cli_adapters_live_outside_capsules(self) -> None:
        root_modules = {path.name for path in SOURCE.glob("*.py")}
        self.assertEqual(root_modules, {"__init__.py", "__main__.py", "app.py"})

    def test_dnf_history_has_its_own_domain_module(self) -> None:
        text = (SOURCE / "capsules" / "collectors" / "dnf.py").read_text(encoding="utf-8")
        self.assertIn("def collect_history", text)
        self.assertIn("for package in packages:", text)
        self.assertNotIn("packages[:25]", text)


if __name__ == "__main__":
    unittest.main()
