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

## Sensori o SMART assenti

L’assenza di sensori o strumenti è tollerata. SMART dettagliato è giornaliero e
la lettura oraria evita di svegliare dischi meccanici inattivi. Non eseguire
`sensors-detect` in modo automatico o invasivo.
