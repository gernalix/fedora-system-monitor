import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("telegram_api_credentials", Path(__file__).resolve().parents[1] / "scripts/telegram_api_credentials.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class VaultApiTest(unittest.TestCase):
    def test_vault_overrides_legacy_pair_and_preserves_session_reference(self):
        result = subprocess.CompletedProcess([], 0, '{"TELEGRAM_API_ID":"123","TELEGRAM_API_HASH":"new"}', '')
        with patch.object(api.subprocess, "run", return_value=result) as run:
            actual = api.with_vault_api({"TELEGRAM_API_ID":"1", "TELEGRAM_API_HASH":"old", "SESSION_FILE":"untouched"})
        self.assertEqual(actual, {"TELEGRAM_API_ID":"123", "TELEGRAM_API_HASH":"new", "SESSION_FILE":"untouched"})
        self.assertIn("FEDORA_TELEGRAM_API_ENV", run.call_args.args[0])

    def test_failure_never_uses_legacy_values_or_echoes_diagnostic(self):
        result = subprocess.CompletedProcess([], 1, 'sensitive', 'sensitive')
        with patch.object(api.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "^Telegram API credentials unavailable from Bitwarden; no local fallback$"):
                api.with_vault_api({"TELEGRAM_API_HASH":"old"})

    def test_missing_and_invalid_fields_rejected(self):
        for data in ('{}', '{"TELEGRAM_API_ID":"abc","TELEGRAM_API_HASH":"hash"}'):
            with self.subTest(data=data), patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, data, '')):
                with self.assertRaises(RuntimeError):
                    api.with_vault_api({})
