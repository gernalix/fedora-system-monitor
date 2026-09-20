# Fedora System Monitor

Monitoraggio host locale per Fedora basato su Python 3, SQLite, systemd, journal,
udev e NetworkManager. Raccoglie metriche a bassa frequenza, conserva eventi e
inventari, gestisce alert con isteresi e recovery e invia lo stato a cinque Push
Monitor Uptime Kuma. Il collector filesystem esistente invia inoltre su Telegram
le variazioni cumulative di spazio libero di almeno 1 GiB.

## Uso rapido

```bash
sudo ./scripts/install.sh
fedora-system-monitor status
fedora-system-monitor health
fedora-system-monitor alerts
fedora-system-monitor events --since-hours 24
sudo fedora-system-monitor collect five_minute
fedora-system-monitor context latest --type graphics
fedora-system-monitor context incident <incident-id>
```

La configurazione operativa è `/etc/fedora-system-monitor/config.toml`.
Per i servizi systemd il percorso preferito per i segreti è
`$CREDENTIALS_DIRECTORY`: `uptime-kuma.toml` e `telegram.env` vengono letti
da lì quando presenti, così le unità possono usare `LoadCredential=` o
`LoadCredentialEncrypted=`. I vecchi file
`/home/daniele/.config/codex/secrets/fedora_system_monitor_uptime_kuma.toml` e
`/home/daniele/.config/codex/secrets/telegram.env` restano fallback di
compatibilità durante la migrazione e devono essere `0600`.
L’invio Telegram passa esclusivamente dal helper condiviso `telegram_notify.py`,
installato come pacchetto Python `telegram_notify`.
Il timer di context indexing correla inoltre il DB locale con il mirror ActivityWatch e produce timeline/bundle incidenti bounded; la pubblicazione Git del repo derivato è opzionale e fail-closed. Vedere [Context Index](docs/human/context-index.md).

Vedere [overview](docs/human/overview.md),
[Kuma](docs/human/uptime-kuma.md) e
[troubleshooting](docs/human/troubleshooting.md).

## Sviluppo

```bash
PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -q
python3 -m compileall -q src
git diff --check
```

Versione: `1.3.1`. Attività: `482731`.
