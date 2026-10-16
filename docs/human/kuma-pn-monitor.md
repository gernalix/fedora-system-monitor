# Uptime Kuma DOWN → MegaVault Pn

This monitor is owned by Fedora System Monitor. It uses the existing read-only Oracle SSH helper to inspect Kuma's heartbeat database every ~30 seconds and registers **Codex Pn without launching them**.

On the first run it inspects the most recent heartbeat for each Kuma monitor and registers current active DOWN incidents, without backfilling old outages. Later runs process new heartbeats in bounded batches of 500. New incidents use the deterministic idempotency key kuma-down:v1:<monitor_id>:<heartbeat_id>.

Repeated DOWN observations do not create duplicates. An UP observation is recorded locally as recovery; a new DOWN within 10 minutes reuses the existing Pn. A DOWN following at least 10 minutes of recovery creates a fresh Pn. Recovery is not proof that a Codex task is complete and does not cancel or alter the Pn.

The single checkpoint file ~/.local/state/fedora-system-monitor/kuma-pn-checkpoint.sqlite3 holds only the heartbeat cursor, last monitor status, recovery timestamp and Pn correlation. It is neither a task lifecycle registry nor a replacement for GitHub/Git.

Canonical MegaVault monitoring_targets identifies a unique project for a monitor. Missing or ambiguous mappings route registration to Fedora System Monitor, with explicit instructions in the Pn to resolve the correct repair owner. The canonical MegaVault prompt create command checks remote protocol freshness, immutable body/description hashes and valid registration. The generated Codex goal requires live diagnosis and targeted tests before any fix.

Heartbeat message content is deliberately excluded from transmitted metadata because it may contain credentials or private diagnostic details. The agent performing a fix accesses the authoritative system only when needed. No C2/C3 component is invoked or reenabled.

To deploy from a clean committed source checkout, run:

    bash scripts/deploy-kuma-pn-monitor-user-units.sh

The installer copies a small, isolated Python entrypoint into ~/.local/libexec/fedora-system-monitor-kuma-pn, installs the user service and timer, and starts one immediate check.

Check timer state with systemctl --user status fedora-system-monitor-kuma-pn.timer. Inspect recent results with journalctl --user -u fedora-system-monitor-kuma-pn.service -n 50. A read-only preview from the checkout is: PYTHONPATH=src python3 -m fedora_system_monitor.capsules.kuma_pn_monitor --dry-run.
