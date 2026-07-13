# Changelog

## 1.1.0 - 2026-07-13

- Corretti recovery Host, Network, Storage e Software senza modificare timeout,
  retry o heartbeat Kuma.
- Stabilizzata l’identità Wi-Fi e preservati i timestamp originali del replay.
- Corretti soglia assoluta filesystem, inode FUSE e recovery I/O su journal pulito.
- Corretta la race DNF `Started` con retry fino allo stato terminale.
- Aggiunte deduplicazione esatta e riconciliazione dello stato endpoint.
- Aggiunti dashboard, timeline, trend 24h/7d, storico servizi e Prometheus opzionale.
- Verificati 92 test, 17 self-check, tutti i collector reali, systemd, udev e SQLite.

Timeline: `2026-07-13|fedora-system-monitor|bugfix|P1|Kuma recovery|PENDING|activity:471852`.

## 1.0.1 - 2026-07-10

- Corretto escaping delle istanze udev e race della cache su remove immediato.
- Ridotte le capability: `CAP_SYS_ADMIN` solo sul daily; rimossa `CAP_SYS_RAWIO`.
- Rese atomiche e ordinate le notifiche alert concorrenti.
- Corretti bucket completi, merge, duplicati, null e contatori negli aggregati.
- Sostituito il full VACUUM automatico con checkpoint WAL e optimize.
- Aggiunti audit sintetico di crescita e test di concorrenza; 84 test PASS.

## 1.0.0 - 2026-07-10

- Attività 593184 completata con architettura Python, SQLite WAL e systemd.
- Aggiunti collector a 1, 5, 15, 60 minuti, giornalieri e settimanali.
- Aggiunti journal follower, udev, NetworkManager, lifecycle e sleep hooks.
- Aggiunti alert con durata, isteresi, deduplica, cooldown e recovery.
- Aggiunti inventari hardware e software, retention con aggregazione e backup.
- Aggiunta CLI amministrativa con output umano, JSON, CSV e testo.
- Creati e verificati cinque Push Monitor Uptime Kuma, ID 39-43.
- Corretto il replay journal mediante identità cursor persistente.
- Corretto il reporting SQLite non privilegiato in presenza di WAL.
- Registrato l’incidente host NTFS del 9 luglio 2026.
- Verificati 68 test automatici e tutti i collector reali con esito `ok`.

Timeline: `2026-07-10|fedora-system-monitor|infra|P1|Host monitor|PASS|activity:593184`.
