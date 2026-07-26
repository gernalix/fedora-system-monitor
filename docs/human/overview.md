# Fedora System Monitor

Il servizio monitora Fedora anche dopo logout e riavvio. Non richiede terminali,
Android Studio, sessioni grafiche o container. Usa timer systemd per i campioni e
fonti native per gli eventi, mantenendo la cronologia in SQLite.

Versione installata: `1.3.0`. L’ultimo
[report tecnico](../ai/REPORT_418732.md) documenta il monitoraggio Telegram
cumulativo dello spazio libero; l’[audit Fedora 44](audit-962417.md) copre
pressione memoria, SMART, batteria e Btrfs.

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
fedora-system-monitor dashboard
fedora-system-monitor timeline --since-hours 24
fedora-system-monitor trends
fedora-system-monitor service-history --since-days 7
```

Aggiungere `--json` produce output per automazione. `export` supporta `json`,
`csv` e `text` con limiti espliciti.

## Frequenze

Il timer rapido si attiva ogni minuto e accorpa il lavoro dovuto a 5 e 15 minuti.
Esistono inoltre timer orario, giornaliero alle 03:15 e settimanale domenica alle
04:15, con tolleranza e ritardo casuale. Le modifiche alle directory software
sono event-driven tramite una path unit.

Ogni cinque minuti il collector filesystem già esistente controlla tutti i
filesystem locali reali montati. Quando lo spazio libero differisce di almeno
1 GiB dall’ultima notifica consegnata, invia:

`💾 <mount point>: libero <valore>; variazione <+/-delta>`

Le variazioni più piccole si accumulano. Il primo campione è silenzioso, gli
smontaggi non cancellano lo stato e un rimontaggio con percorso diverso mantiene
il riferimento tramite UUID. `tmpfs`, filesystem virtuali, overlay e immagini
compresse non sono monitorati.

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

La percentuale di zram è diagnostica: un alert memoria richiede evidenza da
MemAvailable, PSI, attività swap/reclaim oppure OOM. Un disco rotazionale in
standby non viene risvegliato per SMART.

Telegram riusa esclusivamente
`/home/daniele/.config/telegram-notify/telegram-notify.env` con permessi `0600`;
token e chat ID non devono essere copiati nella configurazione del progetto.
L’invio usa il helper condiviso `telegram_notify.py` tramite il pacchetto
`telegram_notify`; il monitor non implementa una seconda chiamata HTTP Telegram.

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

## Prometheus opzionale

L’endpoint non richiede pacchetti Prometheus e resta disabilitato per default:

```bash
sudo systemctl start fedora-system-monitor-prometheus.service
curl http://127.0.0.1:9109/metrics
```
