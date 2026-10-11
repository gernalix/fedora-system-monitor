# Archivio esecuzioni — P35, fase 2 RDC e Codex

Fedora System Monitor, project_id 15, NV 4. Riutilizza archivio, CLI, hook,
SQLite/FTS e replay P34/P48. Non legge né importa chat, transcript Codex,
sessioni browser, cronologie Bash o backup. Nessun nuovo database, daemon,
monitor, timer o tmux.

## Installazione e controllo

```bash
python3 scripts/install-execution-archive.py
ea status
ea capture status
ea capture on                 # consenso esplicito per questa sessione
ea capture on --input         # include input ordinario applicativo con ECHO attivo
ea pause
ea resume
ea capture off
ea search testo
ea replay UUID --speed 2
```

Lo stesso installer imposta la `defaultShell` supportata di Remote Desktop
Commander su `~/.local/bin/fsm-ea-rdc-bash` e registra in
`~/.codex/hooks.json` un hook ufficiale Codex `PreToolUse`, matcher `Bash`, che
riscrive la chiamata verso `fsm-ea-codex-bash`. Codex richiede la propria review
di trust per hook utente nuovi o modificati; verificarla con `/hooks` in una
sessione visibile. L'installer non legge né modifica il trust store. RDC ricarica
la configurazione osservata senza una patch al pacchetto e senza riavvio del
servizio. Upgrade ripetuti sono idempotenti; il rollback ripristina la shell RDC
precedente e rimuove soltanto l'handler Codex esatto.

## Processi RDC e Codex

L'unico boundary di contenuto è l'adapter che avvia `/bin/bash` mantenendo stdin,
stdout, stderr ed exit status dell'operazione. Per comandi non esclusi conserva:

- PID adapter restituito dall'API, PID figlio, parent PID, host e timestamp;
- correlation UUID, source/origins e un solo evento anche nel percorso
  Codex → RDC → adapter;
- stdout e stderr originali separati, più lo stream combinato ordinato e timing
  incrementale per replay e recovery;
- output dei subprocessi che ereditano le pipe del comando padre.

Il comando completo e l'environment restano solo in memoria; il manifest salva
al massimo il basename dell'eseguibile. stdin di `interact_with_process` viene
inoltrato senza copie: RDC/Codex non segnalano in modo affidabile input segreto,
quindi archiviarlo non sarebbe sicuro. Comandi sensibili riconoscibili sono
metadata-only. Se un pattern di credenziale appare nell'output, tutti i contenuti
dell'evento vengono eliminati e resta solo il gap metadata-only. Output arbitrario
non etichettato mantiene un rischio residuo dichiarato: nessun filtro può provare
che sia privo di segreti.

`PostToolUse` Codex e `tool-history.jsonl` non sono fonti canoniche: il primo può
ricevere output già adattato al modello e il secondo tronca/ruota. L'hook non usa
mai `transcript_path`, prompt, messaggi o ragionamento. Gli hook coprono le
chiamate Bash supportate da Codex CLI/Desktop; tool non-Bash e processi avviati
fuori da quel boundary restano fuori copertura. I subprocessi sono correlati allo
stream padre, ma quelli brevi non hanno necessariamente un record PID autonomo.
Il contratto dell'hook è quello documentato in
[OpenAI Codex Hooks](https://developers.openai.com/codex/hooks/).

Le nuove shell Bash interattive TTY partono **safe**. Le sessioni già aperte
restano intatte; per i nuovi controlli occorre una nuova sessione con hook P48.
`bash -c`, `bash -ic COMANDO`, pipe, servizi e shell annidate non creano wrapper
ricorsivi. Alias, funzioni e DEBUG trap utente sono preservati; se DEBUG trap,
functrace o extdebug impediscono il guard, full viene rifiutato.

Il runtime è `~/.local/libexec/fsm-execution-archive`, CLI `~/.local/bin/ea`.
L'installer preserva il runtime precedente in `.previous`; ulteriori upgrade
usano un suffisso univoco senza sovrascrivere i backup. Non riavvia i servizi
system del monitor. Il rollback rimuove solo i due blocchi esatti di `.bashrc`,
preservando personalizzazioni, runtime e originali:

```bash
ea disable
ea enable
python3 scripts/install-execution-archive.py --rollback
```

Disabilitare blocca nuove registrazioni, mentre i metadati di una sessione già
attiva possono continuare fino all'uscita. Il runtime non chiama API di focus o
finestra e non invia notifiche.

Consenso persistente facoltativo, applicato solo a sessioni future:

```bash
ea capture on --new-sessions --consent --profile PROFILO
ea capture off --new-sessions --profile PROFILO
```

Il profilo usa `FSM_EA_PROFILE`, poi `PTYXIS_PROFILE`, poi `default`. Omettere
`--profile` autorizza tutte le nuove sessioni: richiede comunque `--consent`.
`--input` è un consenso aggiuntivo. La configurazione è locale in
`capture-policy.json`; nessun consenso globale è stato attivato durante il rollout.
Una modifica persistente non cambia le sessioni esistenti.

## Copertura, consenso e limiti

| Caso | Safe | Full con consenso |
| --- | --- | --- |
| echo, printf, Python e output generico | solo metadati | byte visibili PTY, timing e FTS |
| multilinea oltre 4 KiB, ANSI, stderr | solo metadati | originali fedeli, stdout/stderr/echo inseparabili |
| diagnostiche fisse date/uname/uptime | contenuto autorizzato | diagnostica e stream visibile della sessione |
| normale input applicativo | escluso | stream input separato solo con `--input` ed ECHO attivo |
| prompt e input di readline | esclusi | echo visibile differito finché il comando è classificato |
| input nascosto/non-echo | escluso | sospensione conservativa fino al comando successivo |
| comando o percorso sensibile riconosciuto | escluso | contenuto escluso, operazione normale |
| pausa/off | safe / metadati | nessun nuovo contenuto full |
| guard mancante, timeout o errore storage | metadati quando possibile | registrazione disabilitata, terminale continua |

Ogni shell ha un UUID principale; i segmenti full per comando hanno UUID e parent
proprio, consenso esplicito, scope/timestamp/input, `policy_level=full`,
`coverage=visible-pty`, `residual_risk=true` e `content_gaps=true`.
Il canale Bash privato passa comando e cwd solo in memoria per la classificazione;
non serializza argv, cwd sensibili, environment o history. I metadati dei comandi
mantengono label `excluded`. L'echo della riga può apparire nello stream full
quando il comando è autorizzato: non è una registrazione separata della history.

Le esclusioni obbligatorie riconoscono sorgenti chat/Codex, credential manager,
comandi di environment/segreti, login/SSH e percorsi sensibili. Sono estendibili:

```bash
ea policy --exclude-command '*mio-comando*' --sensitive-path /percorso/privato
```

Il guard verifica ECHO sulla PTY prima di acquisire output o input, attende la
classificazione prima di scrivere l'echo pendente e sospende anche per pattern
sensibili identificabili nell'output. Buffer e attese sono limitati; il contenuto
incerto viene scartato. Questi controlli **non garantiscono output arbitrario
privo di segreti**: un programma autorizzato può stampare credenziali non
riconoscibili, cambiare ECHO tra campioni o accedere indirettamente a dati privati.
Il consenso full accetta questo rischio residuo. Non promettiamo registrazione
universale, redazione infallibile o input nascosto archiviato. Le funzioni,
subshell, job asincroni e shell annidate non hanno sempre confini individuali;
quando non riconoscibili possono appartenere al comando full autorizzato.

Safe conserva le diagnostiche a argv esatto `date`, `date -u`, `uname`, `uname -a`,
`uptime`, `true`, `false` e `ea run demo` pubblico; ambiente minimo fisso, nessuno
stdin o file arbitrario. Wrapper automatici solo senza alias/funzioni esistenti.
`ea run` per altri comandi continua normalmente con soli metadati; l'eventuale
sessione full circostante può acquisirne output visibile.

## Dati, recupero e spazio

Root verificata sul filesystem locale home:
`~/.local/state/fedora-system-monitor/executions`. Directory 0700, file 0600.
Non si usano mount esterni, backup, rete o Git. Nessun invio di contenuti a
MegaVault, Telegram o GitHub. `--root` serve per test isolati e non deve puntare
a repository o sorgenti sensibili.

Ogni evento possiede `events/UUID/manifest.json`; i contenuti autorizzati hanno
`output.raw` e `timing.raw` durante l'esecuzione, poi `output.zst` e
`timing.zst`. Gli adapter di processo aggiungono `stdout`/`stderr` e i relativi
timing, mentre `output` conserva l'ordine combinato. Il consenso terminale
`--input` aggiunge stream separati `input` e
`input_timing` con lo stesso formato, hash, recupero e budget condiviso. Manifest e file compressi vengono sincronizzati e sostituiti
atomicamente prima di eliminare il raw. Il manifest contiene SHA256 di originali
e frame compressi, provenienza, copertura e riferimenti relativi. Replay verifica
entrambi gli hash e applica il timing originale, diviso per la velocità richiesta.
I raw incompleti sopravvivono a un crash di processo; il recupero taglia solo
la coda senza timing corrispondente e marca `interrupted` con exit code sconosciuto.
Le scritture attive non promettono durabilità contro perdita improvvisa di corrente.

SQLite WAL + FTS5 è un indice derivato di testo leggibile senza ANSI e metadati
normalizzati. Viene scritto per evento completato, mai per carattere. UUID e
sostituzione transazionale rendono recovery/reindex idempotenti. Non dipendere
dall'indice per gli originali: `ea recover --rebuild-index` può ricostruirlo dai
manifest. Il recupero automatico avviene all'avvio di una nuova sessione; non
esiste un timer aggiuntivo. `ea maintain` applica recupero e retention manualmente.

```bash
ea configure --quota-bytes 268435456 --retention-days 30 --event-bytes 8388608
ea recover --rebuild-index
ea maintain
```

Default: quota 256 MiB, 30 giorni, 8 MiB per contenuto. La rotazione avviene
per evento/command. Il superamento del limite tronca permanentemente la cattura
di quell'evento, senza perdere la sessione. Si eliminano prima gli eventi sigillati
più vecchi, mai eventi attivi. Quota indica il budget dei contenuti: index SQLite,
manifest e sessioni attive hanno un overhead minimo e possono superarlo; un budget
inferiore all'overhead può svuotare gli eventi completati. Non c'è pruning di
backup o dati preesistenti di altri servizi. Errori/contesa storage interrompono
la registrazione, non il terminale; attesa del lock limitata a 150 ms.

`ea status` riporta modalità, conteggi per copertura, eventi attivi, spazio e
limiti. Non attribuisce contenuti esclusi a cattura completa. Le invocazioni
amministrative interattive mostrano `NV`; `--json`, pipe, replay, run e servizi
mantengono il contratto macchina/stream senza banner.

## Verifica riproducibile

```bash
PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest tests.test_execution_archive -v
PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -q
bash -n hooks/execution-archive-entry.bash hooks/execution-archive-metadata.bash
```

Fixture solo pubblici sintetici: due PTY, output generico/multilinea/ANSI,
input applicativo, pause/resume/off, safe automatico, consenso persistente in
HOME temporanea, ECHO dinamico, percorsi sensibili, canary assenti in file,
originali decompressi e FTS, replay fedele e recupero di un segmento full aperto.
I test P34 verificano anche hash/Zstd, indice ricostruibile/deduplica, retention,
quota, permessi e compatibilità Bash. I test P35 aggiungono stream oltre 4 KiB,
stdin inoltrato, processo figlio, deduplica RDC/Codex, FTS/replay, fail-closed e
install/upgrade/rollback in HOME temporanea. Nessun test termina processi utente.

Verifica live P48, 2026-10-11: due schede Ptyxis reali, indipendenti e simultanee,
con driver pubblico su PTY e Bash normale che carica gli hook installati.
UUID `905390e9-7ff2-41b5-8cd6-64f8a98a6665` e
`8af94696-437b-4c25-8b41-4f8237471936`: entrambe osservate active insieme,
poi complete con exit 0. Safe iniziale; full autorizzato solo nelle due sessioni;
echo/printf/Python multilinea oltre 4 KiB, stderr/ANSI, input applicativo,
non-echo dinamico, pattern token sintetico, pausa/resume/off, FTS e replay PASS.
I canary esclusi sono assenti negli originali decompressi e nelle query FTS.
Nessuna scheda utente terminata, nessun consenso persistente sul desktop.
L'apertura delle schede ha presentato Ptyxis con autorizzazione esplicita utente;
non viene quindi rivendicata una misura di focus invariato durante il setup.
Il runtime non presenta finestre. I due servizi monitor verificati sono rimasti
active, NRestarts=0; runtime installato uguale al sorgente del task.

Validazione P48: 247 test PASS, inclusi 15 test dell'archivio; syntax Bash,
compilazione Python e diff-check PASS. Le prove di crash e consenso persistente
usano esclusivamente HOME temporanee, senza uccidere shell utente o applicare
retention all'archivio desktop.

## Verifica P35, 2026-10-12

Prerequisito fase 1: P34/P48 sono in `origin/main` `6a1c180`; runtime installato
uguale al sorgente e receipt MegaVault NV 3 presenti prima delle modifiche.

RDC 0.2.51 reale, servizio invariato sul PID 2510 con `NRestarts=0`: prova
headless tramite `start_process`, `interact_with_process` e
`read_process_output`, evento `3ec429a3-1fc3-4664-b517-642048b232bf`.
Conservati integralmente 6.072 byte stdout e 6.000 byte stderr, oltre 4 KiB,
figlio e risposta dopo input; exit 0, FTS unico e replay con SHA256
`b838fba283a621d7eff4c2bad3beeb9dec854770fe3d64ec74bc2bee69e163d4`.
stdin innocuo è stato inoltrato ma non archiviato. Il canary di output sensibile
ha prodotto l'evento metadata-only `eba8e079-df79-4f24-98ca-1b7b3fce8e73`,
senza file contenuto né match FTS.

Il contratto Codex installato è stato esercitato senza modello/quota: il hook
ha riscritto una chiamata Bash sintetica e l'adapter ha creato un solo evento
Codex `7cf110e6-dffc-43c6-9e76-bc2ebb93cb2f`. Il passaggio annidato RDC → Codex
ha prodotto un solo evento correlato `d294ecae-788e-484e-80be-bef95d460972`,
con `origins=[codex, rdc]`. `codex doctor --json` e `--strict-config` accettano
la configurazione; 253 test repository PASS, inclusi 21 test archivio.

Gap verificato: il client Codex richiede review/trust con `/hooks` e carica gli
hook nel contesto della sessione. La sessione corrente precede l'installazione;
lo steer P57 vieta una nuova chat e input simulato, quindi non è stata inventata
una prova end-to-end di un tool Bash prodotto dal modello. Fino alla review in
una futura sessione visibile, la copertura Codex effettiva resta PARTIAL; RDC e
il boundary/hook contract sono verificati.
