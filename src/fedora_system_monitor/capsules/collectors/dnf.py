"""DNF transaction-history collection and package-level event normalization."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any

from .common import command_problem, config_value, external, state_get, state_set
from .model import CADENCE_SECONDS, CollectionResult, record


_NEVRA_RE = re.compile(r"^(?P<name>.+)-(?P<epoch>\d+):(?P<version>.+)-(?P<release>[^-]+)\.(?P<arch>[^.]+)$")


def _parse_nevra(nevra: str) -> dict[str, str]:
    match = _NEVRA_RE.match(nevra)
    if not match:
        return {"package": nevra, "version": "", "architecture": ""}
    fields = match.groupdict()
    return {"package": fields["name"], "version": f"{fields['epoch']}:{fields['version']}-{fields['release']}", "architecture": fields["arch"]}


def collect_history(scope: str, config: Mapping[str, Any], db: object) -> CollectionResult:
    """Produce an individual package event for every terminal DNF transaction item."""
    cadence = CADENCE_SECONDS[scope]
    result = CollectionResult(scope)
    timeout = max(20, float(config_value(config, ("monitor", "command_timeout_seconds"), ("general", "command_timeout_seconds"), default=12)) * 2)
    listing = external(config, ["dnf", "history", "list", "--json"], timeout=timeout)
    if not listing.ok:
        result.errors.append(f"dnf history: {command_problem(listing)}")
        return result
    try:
        transactions = json.loads(listing.stdout or "[]")
    except json.JSONDecodeError:
        result.errors.append("dnf history: invalid JSON")
        return result
    if not isinstance(transactions, list):
        return result
    all_ids = sorted({int(item["id"]) for item in transactions if isinstance(item, Mapping) and str(item.get("id", "")).isdigit()})
    seen = state_get(db, "software.dnf_seen_ids", None)
    first_baseline = not isinstance(seen, list)
    seen_ids = {int(value) for value in seen if str(value).isdigit()} if isinstance(seen, list) else set()
    active_ids: set[int] = set()
    try:
        for row in db.query("SELECT device_id FROM alerts WHERE status='active' AND name='dnf_transaction_failed'"):
            device_id = str(row.get("device_id") or "")
            if device_id.startswith("dnf:") and device_id[4:].isdigit():
                active_ids.add(int(device_id[4:]))
    except (AttributeError, TypeError, ValueError):
        pass
    pending_ids = [item for item in all_ids if item not in seen_ids or item in active_ids]
    new_ids = pending_ids[-10:] if first_baseline else pending_ids[-50:]
    persisted_ids = set(seen_ids)
    if first_baseline:
        persisted_ids.update(set(all_ids) - set(new_ids))
    captured = 0
    for transaction_id in new_ids:
        info = external(config, ["dnf", "history", "info", str(transaction_id), "--json"], timeout=timeout)
        if not info.ok:
            result.errors.append(f"dnf transaction {transaction_id}: {command_problem(info)}")
            continue
        try:
            payload: Any = json.loads(info.stdout)
            if isinstance(payload, list):
                payload = payload[0] if payload else {}
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, Mapping):
            continue
        status = str(payload.get("status") or "unknown")
        normalized = status.strip().lower()
        successful = normalized in {"ok", "success", "succeeded", "complete", "completed"}
        failed = normalized in {"error", "failed", "failure", "aborted", "cancelled", "canceled"}
        if not successful and not failed:
            continue
        persisted_ids.add(transaction_id)
        packages = payload.get("packages")
        if successful and transaction_id in active_ids:
            result.events.append(record(cadence, "software", "dnf_transaction_recovered", 1, "transaction", source="dnf5_history", device_id=f"dnf:{transaction_id}", details={"transaction_id": transaction_id, "status": status, "user_id": payload.get("user_id")}, outcome="ok"))
            captured += 1
            continue
        if failed:
            result.events.append(record(cadence, "software", "dnf_transaction_failed", 1, "transaction", severity="warning", source="dnf5_history", device_id=f"dnf:{transaction_id}", details={"transaction_id": transaction_id, "status": status, "user_id": payload.get("user_id")}, outcome="error", error_message="package transaction did not complete successfully"))
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, Mapping):
                continue
            operation = str(package.get("action") or "change").lower()
            parsed = _parse_nevra(str(package.get("nevra") or ""))
            result.events.append(record(cadence, "software", f"package_{operation.replace(' ', '_')}", 1, "package", source="dnf5_history", device_id=f"rpm:{parsed['package']}:{parsed['architecture']}", details={"name": parsed["package"], "new_version": parsed["version"], "previous_version": None, "operation": operation, "repository": package.get("repository"), "architecture": parsed["architecture"], "user_id": payload.get("user_id"), "status": status, "transaction_id": transaction_id, "reboot_required": None}, outcome="ok" if successful else "error"))
            captured += 1
        if len(packages) > 25:
            actions: dict[str, int] = {}
            for package in packages:
                if isinstance(package, Mapping):
                    action = str(package.get("action") or "change").lower()
                    actions[action] = actions.get(action, 0) + 1
            result.events.append(record(cadence, "software", "dnf_bulk_transaction", len(packages), "packages", source="dnf5_history", device_id=f"dnf:{transaction_id}", details={"transaction_id": transaction_id, "status": status, "user_id": payload.get("user_id"), "package_count": len(packages), "actions": actions, "detailed_package_count": len(packages)}, outcome="ok" if successful else "error"))
            captured += 1
    state_set(db, "software.dnf_seen_ids", sorted(persisted_ids)[-2000:])
    result.metrics.append(record(cadence, "software", "dnf_history_events_captured", captured, "events", source="dnf5_history"))
    return result


__all__ = ["collect_history"]
