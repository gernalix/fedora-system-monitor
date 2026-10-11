# Archivio esecuzioni — P34, fase 1

L'archivio appartiene a Fedora System Monitor, project_id 15. Non legge journal,
archivi browser, chat ChatGPT/Codex, backup o cronologie Bash. Non è un secondo
monitor, collector o servizio. Le integrazioni non interattive saranno fasi
successive e **non sono operative** in questa versione.

## Installazione e controllo

Sul desktop Fedora verificato (Ptyxis, profilo con comando personalizzato
disabilitato, shell `/bin/bash`), come utente normale:

```bash
python3 scripts/install-execution-archive.py
ea status
ea search date --source diagnostic --since-hours 24
ea run demo
ea replay UUID --speed 2
ea disable
ea enable
python3 scripts/install-execution-archive.py --rollback
```

Gli hook si applicano solo alle nuove shell Bash interattive con stdin/stdout
TTY. Non aprono finestre, non usano tmux, non inviano notifiche e non chiamano
API di focus. Le sessioni già aperte restano intatte. `bash -c`, `bash -ic` con
comando esplicito, pipe e servizi non vengono convertiti in sessioni visibili.
Un Bash annidato riusa la sessione invece di creare acquisizioni ricorsive.
Altre shell non sono supportate. Disabilitare evita nuove sessioni e nuovi
contenuti, compresi i diagnostici nelle sessioni esistenti; i metadati della
sessione già avviata possono continuare fino all'uscita. Il rollback rimuove solo
i due blocchi esatti aggiunti a `.bashrc`, preservando altre personalizzazioni,
runtime e dati. L'installer non copia il contenuto di `.bashrc` nell'archivio:
conserva solo hash e receipt; il rollback dei blocchi è reversibile.

Il runtime utente è `~/.local/libexec/fsm-execution-archive`, il comando breve
è `~/.local/bin/ea`. Il sorgente offre anche
`fedora-system-monitor archive ...`; il CLI system installato in precedenza non
viene sostituito né vengono riavviati i servizi del monitor. L'installer preserva
un runtime precedente in `.previous` e rifiuta di sovrascriverne un altro.

## Copertura e confine sui segreti

La PTY della shell viene **solo inoltrata**, mai salvata, compressa, sottoposta
a hash o indicizzata. I tasti, input nascosto, prompt, variabili d'ambiente,
history, nomi/argomenti dei comandi generici e output arbitrario non vengono
serializzati. Il canale Bash privato comunica solo inizio/fine, PID e status.
Ogni comando semplice osservato ha UUID, parent/correlation di sessione,
source, host, PID, timestamp, esito e manifest; il suo nome è `excluded`.
Il DEBUG hook è limitato al livello principale: job asincroni, funzioni,
subshell e Bash annidati non garantiscono metadati individuali né status
per-processo. Lo status di una pipeline è quello osservato da Bash.

Solo diagnostiche con argv esatto e implementazione di sistema fissa producono
contenuto: `date`, `date -u`, `uname`, `uname -a`, `uptime`, `true`, `false`.
Il comando `ea run demo` produce esclusivamente frame pubblici fissi per QA.
I processi autorizzati ricevono un ambiente minimo fisso (PATH, LANG e TERM),
mai l'ambiente utente. Non leggono file arbitrari, stdin, chat o secret provider.
L'echo della loro PTY è disabilitato; non esiste un logger di input. Output e
stderr si fondono nella PTY: la separazione non è tecnicamente disponibile.
L'input ordinario rimane osservabile nella shell, ma **non viene archiviato**.

Bash avvolge automaticamente `date`, `uname`, `uptime` soltanto quando non
esistono già alias/funzioni utente. Argomenti diversi dalla lista esatta passano
al comando normale con soli metadati. `command date`, path assoluti e wrapper
personalizzati bypassano la cattura automatica. `ea run COMANDO ...` esegue i
comandi non riconosciuti senza intercettarne I/O o registrare argv. Non autorizza
uno script arbitrario alla cattura. Anche `echo`, `printf`, `env`, `cat`, `bw`,
shell, SSH, editor, `top` e CLI ChatGPT/Codex sono esclusi dal contenuto.

Non si usa redazione euristica e non si promette cattura del 100% o redazione
infallibile. Questo limite è intenzionale: l'output di un terminale arbitrario
può contenere credenziali o conversazioni anche senza input nascosto.
Personalizzazioni con DEBUG trap, functrace o extdebug conservano il loro
comportamento; per quelle shell resta solo il record di sessione.

## Dati, recupero e spazio

Root verificata sul filesystem locale home:
`~/.local/state/fedora-system-monitor/executions`. Directory 0700, file 0600.
Non si usano mount esterni, backup, rete o Git. Nessun invio di contenuti a
MegaVault, Telegram o GitHub. `--root` serve per test isolati e non deve puntare
a repository o sorgenti sensibili.

Ogni evento possiede `events/UUID/manifest.json`; i contenuti autorizzati hanno
`output.raw` e `timing.raw` durante l'esecuzione, poi `output.zst` e
`timing.zst`. Manifest e file compressi vengono sincronizzati e sostituiti
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

I test creano due PTY simultanee con gli stessi hook Bash: normale input,
stderr, input nascosto con canary sintetico pubblico, status/TTY, shell annidata,
personalizzazioni, shell non interattiva e comando `-ic`. Verificano output
screen/stderr fissi, Zstandard/hash, FTS filtrata, replay, crash/tail recovery,
deduplica, ricostruzione senza SQLite, permessi, disabilita/ripristina e quota/
retention. Nessun fixture contiene credenziali reali.

Verifica live del 2026-10-11: installer utente applicato; due schede **Ptyxis
reali** avviate contemporaneamente con Bash interattivo e prompt di QA pubblico,
due UUID distinti osservati `active`, poi entrambe `complete` con exit 0.
In ciascuna: diagnostica `date`, demo con frame/stderr, normale stdout/stderr e
input silenzioso sintetico. Il canary è assente anche dai contenuti decompressi.
Le schede di QA si chiudono tramite normale `exit`; le schede utente esistenti
non vengono terminate. La compatibilità di focus deriva dall'assenza di API di
finestra/focus nel runtime; non è una misura automatica di tutte le applicazioni
desktop. La prova di crash rimane su PTY isolata, senza uccidere terminali utente.
