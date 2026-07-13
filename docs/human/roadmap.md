# Roadmap

## Versione 1.0

- Sistema permanente installato e attivo su Fedora 44.
- Metriche, eventi, inventari, alert, retention, backup e CLI completati.
- Cinque monitor Uptime Kuma integrati e verificati.
- Suite automatica e prove live completate.

## Manutenzione futura

- Migrare l’istanza Kuma da HTTP a HTTPS.
- Rivedere le soglie dopo una base statistica sufficiente.
- Verificare compatibilità dopo aggiornamenti Fedora, systemd, DNF e Kuma.
- Indagare la causa fisica dell’incidente NTFS del 9 luglio 2026.
- Liberare spazio sul Seagate e riconnettere/diagnosticare il dispositivo rimosso in modo non sicuro prima di aspettarsi Storage verde.
- Rinnovare il login Kuma per un readback amministrativo delle definizioni.

Dashboard CLI, timeline, trend, storico servizi ed endpoint Prometheus opzionale sono completati nella versione 1.1.0. Non sono previsti container.
