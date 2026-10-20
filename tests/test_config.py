from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fedora_system_monitor.capsules.config import (
    ConfigError,
    DEFAULT_CONFIG,
    load_config,
    redact_text,
    validate_config,
)


class ConfigTests(unittest.TestCase):
    def test_defaults_are_valid_and_independent(self) -> None:
        first = load_config(None)
        second = load_config(None)
        self.assertEqual(validate_config(first), [])
        self.assertEqual(
            first["notifications"]["telegram_credentials"],
            "/home/daniele/.config/codex/secrets/telegram.env",
        )
        self.assertEqual(
            first["notifications"]["uptime_kuma_credentials"],
            "/home/daniele/.config/codex/secrets/fedora_system_monitor_uptime_kuma.toml",
        )
        self.assertEqual(first["notifications"]["inverted_categories"], [])
        expected_services = list(DEFAULT_CONFIG["services"]["secondary"])
        first["services"]["secondary"].append("example.service")
        self.assertEqual(second["services"]["secondary"], expected_services)
        self.assertEqual(DEFAULT_CONFIG["services"]["secondary"], expected_services)

    def test_toml_deep_merge_preserves_defaults(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "monitor.toml"
            path.write_text(
                """
[monitor]
log_level = "DEBUG"

[thresholds.disk]
warning_free_percent = 25.0

[services]
secondary = ["sshd.service"]
""",
                encoding="ascii",
            )
            config = load_config(path)
            self.assertEqual(config["monitor"]["log_level"], "DEBUG")
            self.assertEqual(config["monitor"]["timezone"], "Europe/Copenhagen")
            self.assertEqual(config["thresholds"]["disk"]["warning_free_percent"], 25.0)
            self.assertEqual(config["thresholds"]["disk"]["critical_free_percent"], 10.0)
            self.assertEqual(config["services"]["secondary"], ["sshd.service"])

    def test_legacy_swap_thresholds_are_ignored_during_load(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.toml"
            path.write_text(
                "[thresholds.memory]\nswap_warning_percent=20\nswap_critical_percent=50\n",
                encoding="ascii",
            )
            config = load_config(path)
        self.assertNotIn("swap_warning_percent", config["thresholds"]["memory"])
        self.assertNotIn("swap_critical_percent", config["thresholds"]["memory"])
        self.assertEqual(config["thresholds"]["memory"]["available_warning_percent"], 10.0)

    def test_rejects_bad_list_elements_unknown_keys_and_port(self) -> None:
        config = load_config(None)
        config["services"]["essential"] = [{"bad": "entry"}]
        config["collection"]["internet_port"] = 70000
        config["inventory"]["manual_paths"] = ["relative"]
        config["typo"] = True
        errors = validate_config(config)
        self.assertTrue(any("services.essential" in error for error in errors))
        self.assertTrue(any("internet_port" in error for error in errors))
        self.assertTrue(any("absolute" in error for error in errors))
        self.assertTrue(any("unknown configuration key" in error for error in errors))

    def test_health_report_overrides_preserve_validated_absolute_paths(self) -> None:
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "fsm.toml"
            config_path.write_text(
                '[services.health_reports."user:grindr-snapshot-health.service"]\n'
                'path = "/home/daniele/.local/state/grindr-favorites-monitor/snapshot-alert.json"\n'
                'label = "Snapshot Grindr"\n',
                encoding="utf-8",
            )
            config = load_config(config_path)
        self.assertEqual(validate_config(config), [])
        self.assertEqual(
            config["services"]["health_reports"]["user:grindr-snapshot-health.service"]["label"],
            "Snapshot Grindr",
        )

    def test_rejects_invalid_health_report_schema(self) -> None:
        config = load_config(None)
        config["services"]["health_reports"] = {
            "bad": {"path": "relative/report.json", "label": "", "other": "not allowed"},
            "invalid": {"label": "No path"},
        }
        errors = validate_config(config)
        self.assertTrue(any("bad.path must be an absolute path" in error for error in errors))
        self.assertTrue(any("bad.label must be a non-empty string" in error for error in errors))
        self.assertTrue(any("invalid.path must be an absolute path" in error for error in errors))
        self.assertTrue(any("bad.other" in error for error in errors))

    def test_invalid_thresholds_are_reported_and_load_raises(self) -> None:
        config = deepcopy(DEFAULT_CONFIG)
        config["thresholds"]["disk"]["warning_free_percent"] = 4.0
        errors = validate_config(config)
        self.assertTrue(any("thresholds.disk" in error for error in errors))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.toml"
            path.write_text(
                "[thresholds.disk]\nwarning_free_percent=4\ncritical_free_percent=10\n"
                "emergency_free_percent=5\n",
                encoding="ascii",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_uuid_capacity_override_validation(self) -> None:
        config = deepcopy(DEFAULT_CONFIG)
        config["storage"]["capacity_overrides"] = [{
            "filesystem_uuid": "22E02106E020E1B1",
            "warning_free_gib": 20,
            "critical_free_gib": 10,
            "emergency_free_gib": 5,
            "recovery_hysteresis_gib": 2,
        }]
        self.assertEqual(validate_config(config), [])
        config["storage"]["capacity_overrides"][0]["critical_free_gib"] = 25
        self.assertTrue(any("warning_free_gib" in error for error in validate_config(config)))

    def test_capacity_exemptions_require_nonempty_uuid_strings(self) -> None:
        config = deepcopy(DEFAULT_CONFIG)
        config["storage"]["capacity_alert_exempt_uuids"] = ["EXTERNAL"]
        self.assertEqual(validate_config(config), [])
        for invalid in ([""], [False], "EXTERNAL"):
            config["storage"]["capacity_alert_exempt_uuids"] = invalid
            self.assertTrue(any("capacity_alert_exempt_uuids" in error for error in validate_config(config)))

    def test_missing_and_malformed_files_raise_config_error(self) -> None:
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.toml"
            with self.assertRaises(ConfigError):
                load_config(missing)
            malformed = Path(directory) / "bad.toml"
            malformed.write_text("[invalid\n", encoding="ascii")
            with self.assertRaises(ConfigError):
                load_config(malformed)

    def test_redaction_targets_credentials_without_hiding_identifiers(self) -> None:
        text = (
            "https://localhost/api/push/very-secret-token?status=up "
            "token=abc123 Authorization: Bearer xyz987 "
            "device=123e4567-e89b-12d3-a456-426614174000"
        )
        redacted = redact_text(text)
        self.assertNotIn("very-secret-token", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("xyz987", redacted)
        self.assertIn("123e4567-e89b-12d3-a456-426614174000", redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 3)


if __name__ == "__main__":
    unittest.main()
