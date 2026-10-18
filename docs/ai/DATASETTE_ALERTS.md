# Datasette Alerts preparation hook

New exports use `--private-archive` at
`~/.local/share/fedora-telegram-history/datasette-alerts/archive`. Original files
and checkpoints are durably replaced in order, with retry deduplication. No Git
operation runs in this mode; the historical Git archive is preserved untouched.
The collector uses the global Python runtime and the existing private
config/session, with pinned Telethon 1.45.0 (the already installed version).
Bootstrap the private archive from the verified historical export under the
existing session lock before cutover. Keep the old runtime script/units as
protected rollback copies, including the existing legacy environment.

The existing `telegram-notification-history.timer` remains the sole persistent
15-minute acquisition schedule for the authorized `datasette_alerts_bot` account
chat (peer 8598093378). A successful history service starts the new offline
`datasette-alerts-summary.service` through OnSuccess. Acquisition failure does
not trigger preparation. No unrelated autodelete or bot poller is changed.

The projection implementation belongs to `gernalix/telegram_insert_bot`,
`datasette_alerts.py`, with operator documentation `docs/DATASETTE_ALERTS.md`.
Activate the hookup only after that source has integrated and is installed from that verified integrated revision at
~/.local/libexec/datasette-alerts-summary/datasette_alerts.py. Create the private state directory (0700) and verified
peer receipt (0600) before installing units; user systemd cannot create the
ReadWritePaths directory under its read-only home sandbox.

Install the two service definitions through the existing owner path and reload
user systemd. Retain the existing enabled timer and its schedule. Summary runs
are bounded by a three-minute timeout, an application exclusion lock and at most
three starts per ten minutes; stdout exposes counts/status only. Originals and
state are local mode 0600, outside Git. No Telegram credentials/session are
available to this derived service and its address families are limited to Unix.

A supported native heartbeat in the existing Codex chat reads the verified
private generation and writes correlated delivery receipts. Neither systemd
unit directly invokes a model. Installation of the projection uses an immutable
Git blob from verified integrated main, leaving stale canonical worktrees alone. Thus preparation
success alone does not establish full P95 acceptance. Before claiming acceptance,
verify actual acquisition, service readback, idempotent restart, active existing
timer, preserved original checksums and the agreed delivery route.

Rollback restores the history service without its OnSuccess hook and stops only
the summary unit. Preserve all private originals, checkpoints and source
collector data/session. Never disable the unrelated autodelete service.
