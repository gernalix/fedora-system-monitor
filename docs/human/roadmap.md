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
- Ridurre swap usata sotto la soglia di recovery prima di aspettarsi Host verde.
- Liberare ulteriore spazio sul Seagate oltre la soglia di recovery prima di aspettarsi Storage verde.
- Usare il readback SQLite remoto via `oracle-vm` per verificare Kuma quando il browser/JWT non è disponibile.

Dashboard CLI, timeline, trend, storico servizi ed endpoint Prometheus opzionale sono completati dalla versione 1.1.0. Non sono previsti container.
