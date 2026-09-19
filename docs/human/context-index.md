# Context Index

Fedora System Monitor can build a compact derived timeline that correlates the
host database with the local `gernalix/activity-watch-data` mirror.

The canonical sources are not replaced or copied wholesale. The index keeps all
monitor events and alerts, a small incident-oriented metric subset, and bounded
ActivityWatch foreground/AFK/tab context. Raw web URLs are intentionally not
materialized.

## Layout

The default output directory is `/home/daniele/projects/fedora-context-data`:

```text
metadata/
  sources.json
  last-sync.json
timeline/
  YYYY/MM/YYYY-MM-DD.jsonl
incidents/
  <incident-id>.json
summaries/
  YYYY-MM-DD.json
```

Each timeline row has a deterministic `record_id`, UTC timestamp, source,
kind, category, name, severity, device identity and bounded details. Re-running
an overlapping sync replaces that time slice instead of appending duplicates.

Incident bundles use schema
`fedora-system-monitor.incident-bundle.v1` and freeze the configured window
around any monitor event carrying `details.incident_id`. The default is 10
minutes before through 5 minutes after the incident.

## CLI

```bash
fedora-system-monitor context around "2026-09-19 22:59:29+02:00" --before-minutes 10 --after-minutes 5
fedora-system-monitor context incident gfx-20260919T205929...
fedora-system-monitor context latest --type graphics
fedora-system-monitor context sync --no-push
```

`context sync` normally resumes from `metadata/last-sync.json` with a small
overlap and caps catch-up at 48 hours. The system timer runs every 15 minutes.

## Git publication

Publication is disabled by default so installation remains safe before the
dedicated private repository exists. Once
`gernalix/fedora-context-data` is initialized at the configured output path,
set `context.git_push = true`.

The publisher is fail-closed: it requires the configured branch and exact
GitHub repository slug, refuses unrelated dirty files, fetches before
publication, uses bounded Git timeouts, and only stages
`metadata/`, `timeline/`, `incidents/`, and `summaries/`.

## Privacy

The derived repository is for diagnostics and should remain private. It may
contain application names and window/tab titles from ActivityWatch. Raw visited
URLs are excluded. Secret-like strings are passed through the monitor's
redaction layer.
