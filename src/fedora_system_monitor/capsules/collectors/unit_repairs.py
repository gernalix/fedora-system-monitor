"""Invoke an owner-supplied oneshot once per confirmed resource incident."""
from pathlib import Path
import re

from .common import external, operator_external, operator_identity
from .model import record

STATE = "service.resource_repairs.v1"
CLIPMD = "clipboard-markdown-links-remote.service"


def configured_recipes(policy, uid):
    return {f"user:{uid}:{CLIPMD}": {"restarts_min": "clipboard-markdown-links-remote-repair.service"},
            **policy.get("repairs", {})}


def reconcile(result, findings, config, db):
    _, _, uid = operator_identity(config)
    recipes = configured_recipes(config.get("unit_resources", {}), uid)
    attempts = db.get_state(STATE, {}, namespace="collector")

    def event(unit, name, outcome, details):
        result.events.append(record(60, "service", name, source="unit_resource_scanner",
                                    device_id=unit, outcome=outcome, details=details))

    for unit in list(attempts):
        if unit in findings:
            continue
        attempt = attempts.pop(unit)
        if attempt.get("checked"):
            event(unit, "unit_repair_resources_recovered", "recovered", attempt)
        db.set_state(STATE, attempts, namespace="collector")

    for unit, conditions in sorted(findings.items()):
        if unit in attempts:
            continue
        repair = next((recipes.get(unit, {}).get(key) for key, condition in conditions.items()
                       if condition.get("open") and recipes.get(unit, {}).get(key)), None)
        if not repair or not re.fullmatch(r"[a-zA-Z0-9_.@-]+-repair\.service", repair):
            continue
        if unit.startswith("system:"):
            runner, manager = external, []
        elif unit.startswith(f"user:{uid}:"):
            runner, manager = operator_external, ["--user"]
        else:
            continue
        # Persist before dispatch. A lost response or worker interruption must
        # never cause a duplicate restart. Each recipe owns its functional test.
        attempt = {"recipe": repair, "checked": False}
        attempts[unit] = attempt
        db.set_state(STATE, attempts, namespace="collector")
        response = runner(config, ["systemctl", *manager, "--no-ask-password", "start", "--", repair],
                          timeout=8, max_output=2048)
        attempt["checked"] = response.ok
        db.set_state(STATE, attempts, namespace="collector")
        event(unit, "unit_repair_owner_check", "ok" if response.ok else "unverified", attempt)
        break


def in_fast_service():
    try:
        groups = Path("/proc/self/cgroup").read_text().splitlines()
        return any(line.startswith("0::") and line.rstrip("/").split("/")[-1]
                   == "fedora-system-monitor-collect@fast.service" for line in groups)
    except OSError:
        return False
