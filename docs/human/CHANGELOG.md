# Changelog

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
