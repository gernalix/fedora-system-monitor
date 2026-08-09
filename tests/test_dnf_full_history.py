from __future__ import annotations

import json
import unittest
from unittest import mock

from fedora_system_monitor.capsules.command import CommandResult
from fedora_system_monitor.capsules.collectors import dnf


class FakeDatabase:
    def __init__(self) -> None:
        self.state: dict[tuple[str, str], object] = {}

    def get_state(self, key: str, default: object = None, *, namespace: str = "application") -> object:
        return self.state.get((namespace, key), default)

    def set_state(self, key: str, value: object, *, namespace: str = "application", **_: object) -> None:
        self.state[(namespace, key)] = value

    def query(self, _sql: str) -> list[dict[str, object]]:
        return []


def command_result(stdout: str = "", *, returncode: int = 0) -> CommandResult:
    return CommandResult(("mock",), returncode, stdout, "", 1)


class DnfFullHistoryTests(unittest.TestCase):
    def test_bulk_transaction_keeps_every_package_event(self) -> None:
        packages = [
            {
                "nevra": f"pkg{index}-0:1.0-{index + 1}.fc44.x86_64",
                "action": "Install",
                "repository": "updates",
            }
            for index in range(30)
        ]
        listing = json.dumps([{"id": 101}])
        info = json.dumps({"id": 101, "user_id": 1000, "status": "Ok", "packages": packages})

        def fake_external(config: object, args: list[str], **kwargs: object) -> CommandResult:
            del config, kwargs
            if args[:3] == ["dnf", "history", "list"]:
                return command_result(listing)
            if args[:3] == ["dnf", "history", "info"]:
                return command_result(info)
            raise AssertionError(f"unexpected command: {args}")

        database = FakeDatabase()
        with mock.patch.object(dnf, "external", side_effect=fake_external):
            result = dnf.collect_history("software_event", {}, database)

        package_events = [event for event in result.events if event["name"] == "package_install"]
        self.assertEqual(len(package_events), len(packages))
        self.assertEqual({event["details"]["name"] for event in package_events}, {f"pkg{index}" for index in range(30)})

        bulk = next(event for event in result.events if event["name"] == "dnf_bulk_transaction")
        self.assertEqual(bulk["details"]["package_count"], len(packages))
        self.assertEqual(bulk["details"]["detailed_package_count"], len(packages))


if __name__ == "__main__":
    unittest.main()
