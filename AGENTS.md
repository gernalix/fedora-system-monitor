# Fedora System Monitor

## Purpose and boundaries
This repository implements a low-resource Fedora host monitor. It owns Python collectors, SQLite history and alerts, systemd units, native event hooks, configuration, and operator CLI. MegaVault owns canonical project identity and cross-project service inventory; Project Git/GitHub owns backlog; C3 is a frozen archive. The shared Telegram transport and Uptime Kuma are external services.

## Architecture and data
The CLI at `src/fedora_system_monitor/app.py` delegates to isolated collector and reporting modules under `src/fedora_system_monitor/capsules`. systemd timers schedule bounded collection; journal, udev, NetworkManager, and lifecycle hooks supply events. Data is stored in SQLite schema v2 with WAL, UTC and Europe/Copenhagen timestamps, and bounded retention. See `docs/ai/PROJECT.md`, `docs/ai/OPERATIONS.md`, and `docs/human/overview.md`.

## Safe development
Run tests with `PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -q`. Never expose or commit credentials, endpoint values, database files, backups, or logs. Tests should use temporary databases and mocked notification transports. Do not run live collector, install, uninstall, or system-mutating commands as validation. `scripts/uninstall.sh --purge-data` is destructive and requires explicit authorization. SMART collection must remain out of minute cadence and must not wake standby rotational media.
