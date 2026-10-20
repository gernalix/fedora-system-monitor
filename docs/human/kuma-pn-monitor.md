# Kuma incident monitor

The existing unit name and private checkpoint remain compatible. DOWN/UP
transitions now feed MegaVault incidents and incident_events through the canonical
kuma-event writer. No Pn is created or launched. Existing Pn references remain
in the checkpoint as history. Short flaps reuse the incident and record both
transitions; a sustained recovery allows a new episode.

The writer deduplicates heartbeat identities before the collector advances its
cursor. A failed write remains retryable without losing the event or duplicating
an incident. Pending, disabled, missing or unreachable observations never count
as recovery. Heartbeat messages are never transferred.

Deploy with scripts/deploy-kuma-pn-monitor-user-units.sh after the MegaVault
kuma-event command is installed, then verify real event records in MegaVault.
