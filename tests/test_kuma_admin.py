from __future__ import annotations

import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import fedora_system_monitor.capsules.kuma_admin as kuma_admin
from fedora_system_monitor.capsules.kuma_admin import (
    KumaMonitorSpec,
    _monitor_payload,
    _monitor_upside_down,
    recover_chrome_session_token,
    runtime_descriptor,
)


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


class _FakeKumaClient:
    def __init__(self, replies: list[object]) -> None:
        self.replies = list(replies)
        self.tokens: list[str] = []

    def call(self, event: str, token: str, *, timeout: int) -> object:
        self.assert_login_call(event, timeout)
        self.tokens.append(token)
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    @staticmethod
    def assert_login_call(event: str, timeout: int) -> None:
        if event != "loginByToken" or timeout != 30:
            raise AssertionError((event, timeout))


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

    def test_runtime_descriptor_exposes_canonical_non_secret_paths(self) -> None:
        with mock.patch.object(
            kuma_admin,
            "_remote_output",
            side_effect=[
                '[{"Type":"bind","Source":"/srv/kuma-data","Destination":"/app/data","RW":true}]',
                '{"com.docker.compose.project.working_dir":"/srv/kuma-compose"}',
                "abc123|/uptime-kuma|louislam/uptime-kuma:2.4.0|running",
            ],
        ):
            descriptor = runtime_descriptor()
        self.assertEqual(
            descriptor["ssh_helper"],
            "/home/daniele/projects/vm_oracle/scripts/oracle_ssh.sh",
        )
        self.assertEqual(descriptor["instance"], "uptime-kuma")
        self.assertEqual(descriptor["status"], "running")
        self.assertEqual(descriptor["compose_directory"], "/srv/kuma-compose")
        self.assertEqual(descriptor["database_path"], "/srv/kuma-data/kuma.db")
        self.assertEqual(
            descriptor["backup_path_template"],
            "/srv/kuma-data/kuma.db.backup-<UTC_TIMESTAMP>",
        )

    def test_runtime_descriptor_rejects_ambiguous_data_mount(self) -> None:
        with mock.patch.object(
            kuma_admin,
            "_remote_output",
            side_effect=["[]", "{}", "abc123|/uptime-kuma|image|running"],
        ):
            with self.assertRaisesRegex(RuntimeError, "missing or ambiguous"):
                runtime_descriptor()

    def test_runtime_descriptor_uses_canonical_root_for_restored_fedora_layout(self) -> None:
        with mock.patch.object(
            kuma_admin,
            "_remote_output",
            side_effect=[
                '[{"Type":"bind","Source":"/opt/uptime-kuma/data","Destination":"/app/data","RW":true}]',
                '{"com.docker.compose.project.working_dir":"/opt/uptime-kuma/backups/old"}',
                "abc123|/uptime-kuma|louislam/uptime-kuma:2.4.0|running",
            ],
        ):
            descriptor = runtime_descriptor()
        self.assertEqual(descriptor["compose_directory"], "/opt/uptime-kuma")

    def test_payload_can_preserve_upside_down(self) -> None:
        payload = _monitor_payload(
            self.spec,
            "token",
            {},
            upside_down=True,
        )
        self.assertTrue(payload["upsideDown"])

    def test_credential_provisioning_preserves_unselected_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "kuma.toml"
            path.write_text('[push]\nlegacy = "https://kuma.example/api/push/old"\n')
            kuma_admin._write_credentials(path, "https://kuma.example", {"new": "token"})
            with path.open("rb") as handle:
                push = tomllib.load(handle)["push"]
            self.assertEqual(push["legacy"], "https://kuma.example/api/push/old")
            self.assertEqual(push["new"], "https://kuma.example/api/push/token")

    def test_existing_upside_down_aliases_are_preserved(self) -> None:
        self.assertTrue(_monitor_upside_down({"upsideDown": True}))
        self.assertTrue(_monitor_upside_down({"upside_down": 1}))
        self.assertFalse(_monitor_upside_down({"upsideDown": False}))
        self.assertFalse(_monitor_upside_down(None))

    def test_recovers_fresh_token_from_leveldb_wal(self) -> None:
        origin = "https://kuma.example.test"
        token = "t" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "Default"
            leveldb = profile / "Local Storage/leveldb"
            leveldb.mkdir(parents=True)
            key = b"_" + origin.encode("utf-8") + b"\x00\x01token"
            value = b"\x01" + token.encode("utf-8")
            batch = (
                (100).to_bytes(8, "little")
                + (1).to_bytes(4, "little")
                + b"\x01"
                + _varint(len(key))
                + key
                + _varint(len(value))
                + value
            )
            wal_record = b"\x00" * 4 + len(batch).to_bytes(2, "little") + b"\x01" + batch
            (leveldb / "000001.log").write_bytes(wal_record)

            self.assertEqual(recover_chrome_session_token(root, origin), token)
            self.assertEqual(recover_chrome_session_token(profile, origin), token)

    def test_login_does_not_retry_identical_stale_token(self) -> None:
        token = "a" * 64
        client = _FakeKumaClient([{"ok": False}])
        with mock.patch.object(kuma_admin, "recover_chrome_session_token", side_effect=[token, token]):
            with self.assertRaisesRegex(RuntimeError, "Kuma rejected"):
                kuma_admin._login_with_chrome_session(client, "/tmp/profile", "https://kuma.example.test")

        self.assertEqual(client.tokens, [token])

    def test_login_retries_once_when_chrome_token_changed(self) -> None:
        first = "a" * 64
        refreshed = "b" * 64
        client = _FakeKumaClient([{"ok": False}, {"ok": True}])
        with mock.patch.object(kuma_admin, "recover_chrome_session_token", side_effect=[first, refreshed]):
            kuma_admin._login_with_chrome_session(client, "/tmp/profile", "https://kuma.example.test")

        self.assertEqual(client.tokens, [first, refreshed])


if __name__ == "__main__":
    unittest.main()
