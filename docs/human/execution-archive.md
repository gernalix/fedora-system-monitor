# Archivio esecuzioni — P37, fasi 1–4

Fedora System Monitor, project_id 15, NV 7. Riutilizza archivio, CLI, hook,
SQLite/FTS e replay P34/P48/P35. Non legge né importa chat, transcript Codex,
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
ea sources inventory
ea sources collect-journal --scope user --unit nome.service
ea sources collect-podman
ea remote inventory
ea remote ssh --target ALIAS --include-output -- /usr/bin/comando argomento
ea remote adb --include-output -- /system/bin/comando argomento
ea remote github-run --repo owner/repo --run-id ID --include-logs
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

## Fase 3: esecuzioni locali non interattive

P36 aggiunge adapter **opportunistici** all'archivio esistente. Non installa un
secondo daemon, timer, watcher di processi, regola auditd/eBPF o listener. Ogni
passaggio è esplicito e limitato a una unità esatta oppure agli eventi nativi
Podman; i cursori privati avanzano soltanto dopo la persistenza riuscita. Una
seconda lettura dello stesso cursore è idempotente e il guasto dell'archivio non
blocca un comando avviato tramite wrapper.

Esempi:

```bash
# Metadati lifecycle; nessun MESSAGE viene conservato.
ea sources collect-journal --scope system --unit esempio.service

# Solo per una unità esatta e conosciuta sicura: MESSAGE reale del processo.
# Journald non dimostra la separazione stdout/stderr, quindi resta stream combinato.
ea sources collect-journal --scope user --unit esempio.service --include-output

# Eventi lifecycle Podman filtrati; attributi arbitrari e log non vengono salvati.
ea sources collect-podman

# Boundary opt-in: I/O ereditato e non registrato, argv ridotto al basename.
ea sources run --source git-hook --name pre-commit -- /percorso/hook
ea sources run --source ide --name gradle -- /percorso/gradle task
ea sources run --source launcher --name locale -- /percorso/launcher
```

Il collector journal conserva solo unità/scope, basename eseguibile, PID quando
presente, timestamp, risultato/exit status quando forniti nativamente, boot ID e
correlazione dell'invocation. Non legge `_CMDLINE`, environment o stdin. Journald
non fornisce il parent PID storico: il campo resta esplicitamente non coperto.
`--include-output` accetta soltanto `MESSAGE` dell'esatto processo della unità,
applica il filtro conservativo già usato dall'archivio e non denomina mai quello
stream “stdout completo”. Timing di replay e separazione stdout/stderr non sono
disponibili dalla sorgente journal.

### Matrice verificata fonte per fonte

| Fonte | Presenza P36 | Copertura effettiva | Output/limiti |
| --- | --- | --- | --- |
| systemd system | presente | comando filtrato al basename; PID+timestamp; exit code quando journal lo espone; correlazione invocation | stream journald combinato solo opt-in unità esatta; parent PID, stdin e stdout/stderr separati NOT COVERED |
| systemd user | presente | come system; cursore indipendente per unità | stessi limiti; nessuna scansione globale |
| timer system/user | presenti | esecuzione del service correlato tramite journal; trigger timer metadata-only | output del timer stesso non esiste; output service segue la riga systemd |
| cron/anacron | presenti | `crond.service` metadata-only su passaggio esplicito | stdout/stderr del job e mail cron NOT COVERED |
| udev | presente | eventi device già posseduti da Fedora System Monitor; journal udev metadata-only | argv/output dei `RUN` NOT COVERED; nessuna regola audit aggiunta |
| autostart | presente | inventario di presenza/count metadata-only | esecuzioni, argv e output NOT COVERED |
| Git hook | hook reali presenti, non riscritti | PID+parent+timestamp+exit solo con wrapper opt-in | I/O e argv completo NOT COVERED; hook esistenti preservati |
| Podman | installato, zero container al preflight | parser/eventi lifecycle nativi metadata-only | log/output NOT COVERED perché nessun container reale sicuro presente; attributi arbitrari esclusi |
| Docker | non installato | NOT COVERED | nessun connettore inventato |
| Android Studio/Gradle e IDE | presenti | PID+parent+timestamp+exit solo con wrapper opt-in | log IDE/daemon, file prodotti e output non mediato NOT COVERED |
| Chrome native messaging | manifest presenti | sola presenza/count metadata-only | contenuto pagine/messaggi/processi NOT COVERED e vietato |
| launcher/script | presenti | PID+parent+timestamp+exit solo con wrapper opt-in | I/O/argv completo NOT COVERED; nessuna riscrittura automatica |
| auditd/eBPF | auditctl presente | NOT ENABLED | intercettazione exec globale giudicata non necessaria e invasiva |

Un file scritto direttamente da un processo non è stdout e non viene importato.
Gli eventi P36 non generano un alert per processo: `ea status` e la health già
esistente restano le superfici operative. Retention, quota, rotazione e permessi
dell'archivio unico restano invariati.

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
I test P36 aggiungono matrice completa, journal system/user sintetico, cursore,
duplicato/ripresa, output consentito e sensibile, exit/correlazione, evento Podman,
wrapper Git/IDE/launcher e guasto archiver fail-open. Le prove live usano solo
unità transitorie P36 non critiche e fixture pubbliche.

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

## Verifica P36, 2026-10-12

Preflight: archivio fase 1/2 abilitato e utilizzabile; listener Fedora System
Monitor `active/running`, `Result=success`, `NRestarts=0`. L'inventario reale ha
confermato systemd system/user, timer, cron/anacron, udev, 15 Git hook nel common
Git dir, Podman senza container, Android Studio/Gradle, manifest native messaging
e launcher. Docker e bpftrace sono assenti; auditctl è presente ma non è stato
abilitato.

Tre unità transitorie pubbliche e non critiche hanno verificato un user oneshot,
un system oneshot e un job user pianificato. Nell'archivio installato: 9 eventi
inseriti, 5 stream journal reali (stdout e stderr combinati), correlazione stabile
per invocation e system exit code 0. Il journal user non ha esposto exit code o
parent PID: non vengono inventati. Un secondo passaggio sul cursore system ha
letto/inserito 0 eventi. Podman reale ha restituito 0 eventi perché non esistono
container; il parser lifecycle è coperto da fixture filtrata.

Overhead dei passaggi isolati: user 0,09 s / 35.036 KiB RSS e system 0,39 s /
34.136 KiB RSS; nessun polling permanente. 261 test repository, diff-check,
readback dei moduli installati/NV e ricerca FTS dei canary sono PASS. Il deploy
ha usato il backup/rollback dell'installer senza riavviare servizi; listener e
timer preesistenti sono rimasti sani.

Risultato di copertura P36: **PARTIAL intenzionale**. Output completo, parent PID
journal, exit code user non esposto, cron stdout/stderr, `RUN` udev, autostart,
log container assenti, IDE non mediati, native messaging e launcher non adottati
restano NOT COVERED secondo la matrice; nessuna sorgente viene promossa oltre
l'evidenza realmente osservata.

## Fase 4: SSH, GitHub Actions e ADB

Gli adapter remoti usano solo autenticazione nativa già configurata e invocazioni
esplicite. Non installano agent sulla VM, workflow, exporter, listener, timer o
servizi. `ea disable` sospende ogni nuova registrazione senza impedire al comando
SSH/ADB di funzionare; `ea enable` ripristina la registrazione. `ea search QUERY
--source ssh|adb|github-actions` applica lo stesso indice FTS5 dell'archivio unico.

### SSH e ADB

`ea remote ssh` accetta soltanto un alias SSH configurato, senza `user@host` o
endpoint, forza `BatchMode=yes` e chiude stdin. `ea remote adb` richiede un unico
device autorizzato oppure il suo SHA256 con `--device-sha256`; il seriale raw non
viene persistito. Entrambi salvano sempre timestamp, PID locale del trasporto,
parent PID, exit code e basename del comando. Il PID del processo remoto non è
esposto dal boundary e resta NOT COVERED.

Senza `--include-output` stdout/stderr sono ereditati e l'evento è metadata-only.
Con consenso esplicito l'adapter conserva stdout e stderr autentici separati,
stream combinato in ordine di ricezione e timing locale per replay; questo timing
non pretende di essere il tempo di generazione sul target. stdin è sempre chiuso
e mai archiviato. Comandi/output riconoscibili come sensibili degradano a
metadata-only; environment, credenziali e argv completo non vengono persistiti.

### GitHub Actions

`ea remote github-run` legge tramite `gh` un solo run esistente del repository
esatto. Conserva run/attempt ID, workflow, evento, stato/conclusione, head SHA,
timestamp, reference stabile e digest del log solo quando ammissibile. I log sono
opzionali, limitati alla quota evento e respinti integralmente se contengono
segreti riconoscibili, valori mascherati o `::add-mask::`.

La API restituisce un log aggregato: la copertura è `runner-log`, non stdout/stderr
separati, raw stream o timing. Non viene creato un timing zero e `ea replay` lo
rifiuta correttamente; FTS5 e digest restano disponibili. Run identico e stesso
attempt/update timestamp sono idempotenti. Nessun workflow o artifact viene
creato, modificato o scaricato indiscriminatamente.

### Matrice finale sintetica

| Fonte | Livello verificabile | Limiti dichiarati |
| --- | --- | --- |
| Bash terminale | metadata-only safe; PTY visibile+timing con consenso | stdout/stderr inseparabili nella PTY; hidden stdin escluso |
| RDC/Codex Bash | PID+parent+exit, stdout/stderr separati e replay | stdin inoltrato ma non salvato; Codex dipende dal trust hook/sessione |
| systemd system/user e timer | command basename, PID/timestamp/exit quando esposto; journal stream opt-in | parent PID e stdout/stderr separati NOT COVERED |
| cron/anacron, udev, autostart | metadata-only o NOT COVERED secondo P36 | output job, udev RUN e processi autostart non intercettati |
| Git hook, IDE, launcher | PID+parent+timestamp+exit con wrapper opt-in | I/O non coperto dal wrapper metadata-only |
| Podman | lifecycle metadata nativi | log non coperti senza container esatto sicuro; Docker assente |
| SSH | trasporto PID+parent+exit; stdout/stderr+timing opt-in | remote PID, stdin e timing remoto NOT COVERED |
| ADB | trasporto PID+parent+exit, device hash; stdout/stderr+timing opt-in | Android PID, stdin e file privati NOT COVERED |
| GitHub Actions | run metadata/reference/digest e log aggregato opt-in | stdout/stderr/raw timing/replay e secret-masked log NOT COVERED |
| Chrome native messaging, chat/browser | sola presenza metadata o esclusione | contenuto pagine/messaggi/chat sempre escluso |

La copertura finale è intenzionalmente non universale. Un file scritto da un
processo non è stdout, un log aggregato non è uno stream riproducibile e un PID
del client SSH/ADB non è il PID remoto.

### Collaudo finale P37 (2026-10-12)

Il preflight reale ha trovato l'alias SSH `oracle-vm` utilizzabile in
`BatchMode`, un solo device ADB autorizzato (in archivio compare soltanto il suo
SHA256), accesso `gh` al repository e il run CI esistente `38182651484` concluso
con successo. Non sono stati creati workflow, agent VM, listener o scheduler.

Nell'archivio installato NV7, le fixture innocue SSH e ADB hanno exit code 0,
stdout/stderr autentici separati, stream combinato e replay con timing locale.
Gli eventi sono rispettivamente
`b7fb7e30-c457-4103-8124-6fa67a6efe57` e
`22906c23-d647-473a-ab83-99bee21a4764`; una ricerca FTS5 unica trova entrambi.
Il run Actions è `c6ad1e97-10ee-51d0-826a-e34e79e7981a`: il log conteneva
materiale mascherato, quindi è stato conservato solo come metadata/reference e
il replay è stato rifiutato. Il secondo ingest ha prodotto 0 inserimenti e 1
duplicato.

La demo terminale Fedora ha verificato output PTY, timing, FTS5 e replay. Un job
systemd user pianificato ha prodotto un journal stream reale; il secondo
passaggio sul cursore ha letto e inserito 0 eventi. `ea disable` e `ea enable`
hanno sospeso e ripristinato la sola registrazione; `ea maintain` e `ea recover`
non hanno perso eventi. SQLite `integrity_check` è `ok`, l'archivio occupava
meno di 1 MiB e gli adapter isolati hanno raggiunto circa 25 MiB RSS per SSH/ADB
e 49 MiB per `gh`, senza polling permanente. Il listener Fedora System Monitor
è rimasto `active/running`, exit 0 e senza restart.

RDC 0.2.51 è `active/running`, usa la shell adapter installata e conserva prove
headless precedenti ricercabili e riproducibili. Il hook Codex installato ha
eventi metadata/stream precedenti, ma il collaudo live di questa sessione non è
stato ripetuto: P70 vieta nuove chat e input simulato, e non era esposta una
CLI/API client RDC supportata. Queste due verifiche live restano **PARTIAL**.
Anche GitHub Actions resta metadata-only per il run osservato; PID remoto SSH/ADB,
stdin, timing remoto e replay Actions restano NOT COVERED.

Verifica software: 37 test mirati e 269 test repository PASS, `diff --check`,
readback byte-per-byte del modulo installato e NV7 PASS. Il rollback supportato
è `python3 scripts/install-execution-archive.py --rollback`; non ferma gli
esecutori e conserva runtime e archivio privato.
