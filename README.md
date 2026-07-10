# Fedora System Monitor

Monitoraggio host locale per Fedora basato su Python 3, SQLite, systemd, journal,
udev e NetworkManager. Raccoglie metriche a bassa frequenza, conserva eventi e
inventari, gestisce alert con isteresi e recovery e invia lo stato a cinque Push
Monitor Uptime Kuma.

## Uso rapido

```bash
sudo ./scripts/install.sh
fedora-system-monitor status
fedora-system-monitor health
fedora-system-monitor alerts
fedora-system-monitor events --since-hours 24
sudo fedora-system-monitor collect five_minute
```

La configurazione operativa è `/etc/fedora-system-monitor/config.toml`; gli
endpoint Kuma sono in `/etc/fedora-system-monitor/uptime-kuma.toml` con permessi
`0600`. Vedere [overview](docs/human/overview.md),
[Kuma](docs/human/uptime-kuma.md) e
[troubleshooting](docs/human/troubleshooting.md).

## Sviluppo

```bash
PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -q
python3 -m compileall -q src
git diff --check
```

Versione: `1.0.1`. Attività: `593184`.
