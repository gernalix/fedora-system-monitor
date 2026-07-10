# Registro incidenti

## external-ntfs-disconnect-during-mounted-io

- **Stato:** aperto, causa fisica non ancora determinata.
- **Quando:** 9 luglio 2026, 19:07 CEST.
- **Gravità:** critica.
- **Evento:** un volume NTFS esterno montato è scomparso durante attività I/O;
  `ntfs-3g` ha registrato errori di sync e chiusura.
- **Impatto:** operazioni filesystem fallite fino alla ricomparsa e al remount,
  avvenuti circa dieci secondi dopo.
- **Mitigazione:** evento ricostruito, identità stabile, alert critico persistente,
  monitor Kuma Storage e recovery su riconnessione installati.
- **Prossimo controllo:** verificare cavo, alimentazione e diagnostica del disco
  prima di affidargli scritture lunghe.

Non è stato scollegato alcun dispositivo durante le prove e non è stata tentata
una riproduzione distruttiva.
