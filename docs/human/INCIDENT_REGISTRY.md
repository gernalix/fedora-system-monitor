# Registro incidenti

## smart-service-capability-false-positive

- **Stato:** risolto nella versione 1.3.1.
- **Impatto:** eventi warning SMART ripetuti per NVMe interno e Samsung T7,
  senza alert SMART attivo né transizione Kuma falsa.
- **Causa:** mancavano `CAP_SYS_ADMIN` per NVMe nativo e `CAP_SYS_RAWIO` per il
  bridge USB-NVMe ASMedia nelle condizioni del collector orario.
- **Correzione:** capability circoscritte a `hourly`/`daily`, diagnostica
  strutturata, skip dei dispositivi assenti/non compatibili e modalità sicura
  per i bridge `snt*`.
- **Evidenza:** [attività 482731](audit-482731.md).

## zram-occupancy-misclassified-as-memory-pressure

- **Stato:** risolto nella versione 1.2.0.
- **Impatto:** Fedora Host risultava rosso per la sola occupazione della zram,
  anche con memoria disponibile, PSI nullo e nessun OOM.
- **Causa:** `swap.used_percent` non distingue memoria compressa utile da reale
  pressione memoria.
- **Correzione:** zram è informativa; gli alert combinano MemAvailable, PSI,
  velocità swap, reclaim e OOM. Compressione e writeback restano osservabili.
- **Evidenza:** [audit 962417](audit-962417.md).

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

## kuma-stale-category-alerts

- **Stato:** risolto nella versione 1.1.0; restano due condizioni Storage reali.
- **Impatto:** recovery mancanti o indirizzate a chiavi diverse mantenevano Host,
  Network e Storage rossi; una race DNF generava anche falsi alert Software.
- **Causa:** sensore monodirezionale, identità Wi-Fi instabile, soglie filesystem
  incoerenti, inode FUSE sintetici, timestamp persi nel replay, recovery I/O
  incompleta e stato DNF `Started` trattato come fallimento.
- **Correzione:** recovery bidirezionale e verificabile, identità stabili,
  scansione journal pulita, retry DNF terminale e deduplicazione esatta.
- **Evidenza:** [audit 471852](audit-471852.md).

## kuma-host-storage-real-state-471853

- **Stato:** risolto nella versione 1.1.1; restano condizioni reali Host e Storage.
- **Impatto:** Host e Storage continuavano a risultare rossi dopo il cleanup del
  Seagate, con un alert Storage obsoleto nel testo.
- **Causa reale:** Host ha swap warning attivo; Storage ha Seagate al 5,2273%
  libero, ancora sotto soglia critical. Inoltre `unsafe_device_removal` era
  stale perché il mount point registrato era di nuovo presente.
- **Correzione:** refresh delle righe alert metriche attive senza notifiche
  duplicate e recovery automatica unsafe-removal quando `findmnt` conferma il
  mount point.
- **Evidenza:** [audit 471853](audit-471853.md).
