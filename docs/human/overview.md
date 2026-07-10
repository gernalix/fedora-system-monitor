# Fedora System Monitor

Il servizio monitora Fedora anche dopo logout e riavvio. Non richiede terminali,
Android Studio, sessioni grafiche o container. Usa timer systemd per i campioni e
fonti native per gli eventi, mantenendo la cronologia in SQLite.

## Stato e consultazione

```bash
fedora-system-monitor status
fedora-system-monitor health
fedora-system-monitor alerts
fedora-system-monitor events --since-hours 24
fedora-system-monitor metrics --limit 50
fedora-system-monitor disks
fedora-system-monitor network
fedora-system-monitor software
fedora-system-monitor services
fedora-system-monitor last-errors
fedora-system-monitor daily-summary
```

Aggiungere `--json` produce output per automazione. `export` supporta `json`,
`csv` e `text` con limiti espliciti.

## Frequenze

Il timer rapido si attiva ogni minuto e accorpa il lavoro dovuto a 5 e 15 minuti.
Esistono inoltre timer orario, giornaliero alle 03:15 e settimanale domenica alle
04:15, con tolleranza e ritardo casuale. Le modifiche alle directory software
sono event-driven tramite una path unit.

## Configurazione

Modificare `/etc/fedora-system-monitor/config.toml`, poi eseguire:

```bash
fedora-system-monitor config-check
sudo fedora-system-monitor collect minute
```

Per aggiungere un disco atteso, usare per esempio
`expected_devices = [{ label = "Ventoy", required = true }]` nella sezione
`storage`.
Per un servizio, usare `services.essential` o `services.secondary`. Per cambiare
una soglia, modificare la tabella `thresholds` corrispondente. Il file di
distribuzione è `/etc/fedora-system-monitor/config.toml.distribution`.

## Installazione e aggiornamento

```bash
sudo ./scripts/install.sh
```

L’installer crea prima un backup online, verifica le unità, aggiorna il runtime
in modo atomico, esegue il backfill idempotente e riavvia i componenti. Per
disinstallare preservando i dati:

```bash
sudo ./scripts/uninstall.sh
```

`--purge-data` elimina anche configurazione e database ed è intenzionalmente
distruttivo.

## Privacy e sicurezza

Non vengono raccolti contenuto di rete, URL, argomenti dei processi o contenuto
dei file personali. I processi top contengono solo nome, PID, CPU, RAM, utente e
cgroup. Le unità sono hardenizzate e scrivono solo nelle directory di stato. Gli
endpoint Kuma sono leggibili solo da root.

Per dettagli tecnici vedere [Kuma](uptime-kuma.md),
[troubleshooting](troubleshooting.md) e il [registro incidenti](INCIDENT_REGISTRY.md).
