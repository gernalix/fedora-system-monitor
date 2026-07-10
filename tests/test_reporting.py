from __future__ import annotations

import unittest

from fedora_system_monitor.capsules.reporting import render


class ReportingTests(unittest.TestCase):
    def test_json_redacts_secret(self) -> None:
        output = render({"token": "token=very-secret-value"}, output_format="json")
        self.assertNotIn("very-secret-value", output)

    def test_csv(self) -> None:
        output = render([{"name": "cpu", "value": 1.5}], output_format="csv")
        self.assertIn("name", output)
        self.assertIn("cpu", output)


if __name__ == "__main__":
    unittest.main()
