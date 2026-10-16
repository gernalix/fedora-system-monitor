# CPU, RAM e disco di tutti i processi

Il timer fast esistente avvia una scansione `/proc` nello scope minuto, ogni
60 secondi. Non ci sono nuovi timer o database. Il precedente top 5 a cinque
minuti, gli alert, Kuma e i collector SMART mantengono il comportamento esistente.

```sh
fedora-system-monitor process-history --sort cpu --limit 30
fedora-system-monitor process-history --sort ram --json
fedora-system-monitor process-history raw --unit prompt-history-sync.service --since-hours 48 --sort cpu
fedora-system-monitor process-history raw --pid 1234 --boot-id UUID --limit 100 --offset 100 --json
fedora-system-monitor process-history hourly --name prompt-history --since-hours 2160 --json
```

Le query sono read-only. I filtri nome/unità cercano sottostringhe letterali;
PID e boot ID sono disponibili sui dati dettagliati. `--sort` accetta time, cpu,
ram, read, write; nei dettagli read/write ordinano per byte al secondo, negli
aggregati per byte totali. Limite predefinito 100, massimo 1000, offset massimo
100000, tempo SQL massimo circa 2 secondi. `next_offset` permette la paginazione;
per pagine stabili dello storico evitare che nel frattempo cambi la finestra.
`current` contiene soltanto i processi dell'ultima scansione, con timestamp e
copertura: un processo uscito non appare falsamente come ancora attivo.

Identità: boot UUID + PID + starttime kernel in tick. UID reale e nome utente
locale sono opzionali; non viene interrogato NSS remoto. Il nome è il `comm`
del kernel (può essere abbreviato), privo di componenti di percorso. Dell'unità
systemd viene conservato soltanto il basename service/scope, quando ricavabile
dal cgroup; la gerarchia e i percorsi non sono conservati. Non si leggono argv,
environ, link fd, contenuti di file utente o percorsi dell'eseguibile.

CPU = delta(utime + stime) / CLK_TCK / secondi trascorsi × 100. Il tempo usa
CLOCK_BOOTTIME, include sospensione ed è specifico di ciascun processo. Il 100%
corrisponde a un core logico: un processo multicore può superarlo. Non include
CPU dei figli e non è la media dalla nascita usata da ps. RSS deriva dalle pagine
residenti di stat; percentuale rispetto a MemTotal, senza sommare falsamente
memoria condivisa come consumo esclusivo. I/O è read_bytes/write_bytes di
`/proc/PID/io` (disco attribuito dal kernel, non traffico logico rchar/wchar).
Contatori, delta e velocità byte/s sono disponibili nei dettagli.

`null` significa indisponibile: prima osservazione per i delta, permesso negato,
metrica assente, reset del contatore o tempo non valido. Zero significa zero
misurato. Un PID riutilizzato o un nuovo boot inizia senza delta. Se il PID
sparisce o cambia identità durante la lettura viene scartato e contato in
`unreadable`. Un processo assente nella scansione precedente non riceve un delta
inventato. Processi nati e terminati fra due scansioni possono sfuggire.
`visible` conta i PID incontrati; `complete=false` segnala il raggiungimento del
limite di durata, con outcome parziale del collector. Per-file read bounded a
16 KiB; nessun limite numerico elimina silenziosamente i processi meno attivi.

Configurazione opzionale (i vecchi config ricevono i default automaticamente):

```toml
[process_history]
interval_seconds = 60
max_scan_seconds = 5
raw_hours = 48
aggregate_days = 90
```

L'intervallo effettivo è arrotondato al successivo wake del timer da 60 secondi;
non può essere inferiore a 60. La durata massima configurabile è 10 secondi.
I dettagli sono conservati per 48 ore, con meno di un'ora extra per mantenere
interi i bucket UTC. Gli aggregati orari per nome/UID/unità rimangono 90 giorni;
PID e boot non sono dimensioni degli aggregati. Ogni ora chiusa viene ricostruita
atomicamente dai dettagli, anche con campioni tardivi, senza duplicazioni.
La CPU totale in secondi, picco CPU, RSS media/picco, RAM percentuale massima e
byte I/O sommati hanno conteggi di campioni validi separati; le medie RSS sono
medie dei campioni, non integrali temporali. L'intervallo è attribuito all'ora del
campione finale e può attraversarne il confine. Non si inventano minuti mancanti.
L'ora corrente resta nei dati raw fino alla chiusura.

Rollup/pruning avvengono nella stessa transazione batch del nuovo campione, al
massimo 24 ore arretrate per run. Dati non ancora aggregati non vengono eliminati;
backlog eccezionali possono temporaneamente superare la retention. Le pagine
liberate vengono riutilizzate, senza VACUUM periodico aggiuntivo.

La migrazione additiva v5→v6 crea un backup online verificato `.pre-v6-*.bak`
nella directory del DB prima del DDL, controlla SQLite e foreign key e mantiene
i permessi 0640. Il backup di migrazione viene preservato per recupero; non è un
secondo DB operativo. Il deploy runtime verifica lo schema preparato in memoria;
la migrazione live avviene dopo la sostituzione atomica del codice. Nessuna modifica a credenziali, notifiche o accessi SMART.

## Misura riproducibile su fixture

`PYTHONPATH=src:tests python3 tests/benchmark_process_history.py` usa `/proc`
simulato e una SQLite temporanea. Sul ThinkPad: 600 PID, 2.880 minuti,
1.728.000 campioni, 60 gruppi nome/utente/unità e ricambio PID dell’1% ogni ora:

- scansione completa: 35,83 ms (35,64 ms CPU); primo batch SQLite: 3,87 ms;
- replay di 48 ore con indici e rollup: 16,17 s (5,62 ms/minuto);
- picco di allocazioni Python nella scansione: 579.661 byte (misura separata con tracemalloc);
- database dettagli e aggregati iniziali: 128.032.768 byte (74,09 byte/campione);
- 48 ore di dettagli + 90 giorni orari: 143.450.112 byte (circa 137 MiB).

Il replay usa una transazione estesa per isolare il costo dati/indici dai 2.880
fsync; la misura del primo batch usa il percorso transazionale normale.
Sono misure di fixture, non timing del collector live. Spazio e backup crescono
con PID, churn delle identità e numero di gruppi; non sono una quota garantita.
La normale retention dei backup esistenti conserva copie dell'intero DB.
