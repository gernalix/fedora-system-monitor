# Troubleshooting

## Controlli iniziali

```bash
fedora-system-monitor status
fedora-system-monitor health
sudo fedora-system-monitor db-check
sudo fedora-system-monitor test --system
systemctl list-timers 'fedora-system-monitor-*' --all
systemctl status fedora-system-monitor-events.service
journalctl -u fedora-system-monitor-events.service --since today
```

## Un collector fallisce

```bash
fedora-system-monitor last-errors
sudo fedora-system-monitor collect five_minute --json
journalctl -u 'fedora-system-monitor-collect@five_minute.service' -n 100
```

Un singolo comando mancante o in timeout non blocca gli altri collector. L’esito
può essere `partial`; il dettaglio resta in `collector_runs` ed `events`.

## Database

```bash
sudo fedora-system-monitor db-check
ls -lh /var/lib/fedora-system-monitor/backups
```

Non copiare a caldo il file SQLite con `cp`: usare i backup online creati dal
collector giornaliero. La CLI utente usa snapshot immutabili brevi; durante una
scrittura concorrente può mostrare per pochi istanti l’ultimo checkpoint.

Il file fisico non si riduce dopo retention perché il monitor evita il full
`VACUUM`, che bloccherebbe gli eventi. Controllare la freelist e il riuso con
`sudo sqlite3 /var/lib/fedora-system-monitor/monitor.sqlite3 'PRAGMA freelist_count;'`.

## Alert obsoleto

Verificare prima la condizione reale, poi risolvere una chiave specifica:

```bash
sudo fedora-system-monitor alerts --resolve 'chiave-alert'
```

La riga storica non viene eliminata. Il collector successivo invia lo stato
aggregato corrente a Kuma.

## Kuma

```bash
sudo fedora-system-monitor config-check
journalctl -u 'fedora-system-monitor-collect@*.service' --since today
```

La CLI eseguita senza root non può leggere il file `0600` e indica quindi lo
stato come protetto; è una proprietà di sicurezza, non un errore di runtime. Non
inserire mai URL push nei comandi di diagnostica o nei log.

Un monitor rosso con `delivered: true` non è un timeout: controllare prima
`fedora-system-monitor health`. Il push rappresenta gli alert attivi reali. Gli
stati DNF `Started` sono transitori e non devono essere risolti manualmente.

Per Host rosso controllare prima `swap.used_percent`: un valore sopra soglia
warning mantiene correttamente `Fedora Host` in `DOWN`. Per Storage rosso,
verificare sia percentuale libera sia byte liberi: 200 GB possono essere ancora
sotto soglia su un disco da più TiB. Gli alert `unsafe_device_removal` vengono
riconciliati automaticamente quando un collector sano conferma che il mount point
registrato è di nuovo presente.

## Telegram spazio libero

Lo stato cumulativo è nel database esistente
`/var/lib/fedora-system-monitor/monitor.sqlite3`, tabella `dedup_state`,
namespace `notification`. Non cancellare le chiavi `filesystem-free:*`: farlo
reinizializza silenziosamente le baseline.

Per verificare il flusso senza inviare notifiche:

```bash
sudo fedora-system-monitor collect five_minute
sudo fedora-system-monitor db-check
journalctl -u fedora-system-monitor-collect@five_minute.service -n 100
```

Un filesystem smontato non produce errori né reset. Se il delta supera 1 GiB ma
Telegram non è raggiungibile, la baseline notificata resta invariata e il
collector riprova al controllo successivo. Verificare soltanto esistenza e
permessi `0600` di
`/home/daniele/.config/telegram-notify/telegram-notify.env`; non stamparne,
copiarne o rigenerarne il contenuto. Verificare inoltre che
`python3 -c 'import telegram_notify'` riesca: l’invio deve sempre passare dal
helper condiviso `telegram_notify.py`, mai da un trasporto duplicato.

## Dashboard e Prometheus

```bash
fedora-system-monitor dashboard
fedora-system-monitor trends
sudo systemctl start fedora-system-monitor-prometheus.service
curl -f http://127.0.0.1:9109/metrics
```

L’unità Prometheus è intenzionalmente disabilitata per default.

## Sensori o SMART assenti

L’assenza di sensori o strumenti è tollerata. SMART dettagliato è giornaliero e
la lettura oraria evita di svegliare dischi meccanici inattivi. Non eseguire
`sensors-detect` in modo automatico o invasivo.
