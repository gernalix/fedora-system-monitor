"""Selected Telegram API fields from the scoped Fedora vault; no session access."""
import json
from pathlib import Path
import subprocess
import sys

FIELDS = ("TELEGRAM_API_ID", "TELEGRAM_API_HASH")


def with_vault_api(config: dict[str, str]) -> dict[str, str]:
    runtime = str(Path.home() / ".local/bin/bws-credential")
    command = [runtime, "--ref", "FEDORA_TELEGRAM_API_ENV"]
    for name in FIELDS:
        command += ["--var", name]
    child = "import json,os; print(json.dumps({k:os.environ[k] for k in " + repr(FIELDS) + "}))"
    try:
        result = subprocess.run(command + ["--", sys.executable, "-c", child],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError()
        selected = json.loads(result.stdout)
        if set(selected) != set(FIELDS) or any(not isinstance(v, str) or not v for v in selected.values()):
            raise ValueError()
        if not selected["TELEGRAM_API_ID"].isdigit():
            raise ValueError()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeError("Telegram API credentials unavailable from Bitwarden; no local fallback") from None
    return {**config, **selected}
