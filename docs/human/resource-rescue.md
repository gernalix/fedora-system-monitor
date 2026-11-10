# Preavviso risorse e recupero interattivo (P247, NV 16)

Il daemon FSM già esistente registra trigger PSI RAM/I/O e controlla metriche
leggere ogni 2 secondi nel profilo host aggiornato il 6 novembre 2026. Se il kernel/sandbox
non permette i trigger, rimane il controllo periodico nello stesso thread del
daemon esistente. Non si aggiungono demoni o timer. Il dialogo è un **oneshot**
`fedora-system-monitor-resource-dialog@daniele.service`, solo quando necessario,
con UID dell'utente e senza capability. Le protezioni del daemon e del kernel restano invariate; il profilo oomd
opzionale descritto sotto anticipa le soglie del solo utente operatore.

La sola RAM allocata, swap/zram occupato o CPU alta non provano rischio OOM.
Il warning predefinito richiede MemAvailable <15% con PSI/reclaim/swap-out,
oppure PSI RAM some ≥10%; l'emergenza richiede PSI full ≥5%, OOM recente,
oppure MemAvailable <5% con pressione corroborante. I trigger kernel sono hint
some RAM 100 ms / 2 s e full I/O 200 ms / 2 s; non costituiscono da soli prova OOM.
Si rilevano anche capacità/inode critici e PSI I/O sostenuta. Il daemon mantiene
`ProtectHome=yes`: per capacità/inode riusa le misure del collector esistente,
aggiornando la cache ogni 60 secondi e scartando misure oltre 180 secondi.
I filesystem esclusi dalla policy del collector restano non misurati; nessun
valore è dedotto dal filesystem mascherato del sandbox. Se mancano tutte le
misure disco fresche, il recupero non viene dichiarato. Il dialogo utente può
ricampionare direttamente i filesystem nella propria vista in sola lettura. Il pavimento
assoluto in MiB non viene applicato ai filesystem ≤5 GiB, in coerenza con la
policy disco esistente, evitando falsi allarmi sulla partizione EFI. Stato e limiti
numerici globali esposti da oomd sono osservati all'avvio; assenti = unknown.
Non sono modificati né si promette di prevenire tutti i crash o gli OOM improvvisi.

```sh
fedora-system-monitor resource-rescue status --json
# Dimostrazione controllata, senza segnali verso applicazioni reali:
fedora-system-monitor resource-rescue dialog --fixture
```

## Finestra e azioni

Solo una sessione grafica Wayland locale, attiva e sbloccata riceve il dialogo.
Quando è bloccata/assente, la registrazione continua e l'avviso resta pendente;
al ritorno viene presentato, anche come riepilogo se nel frattempo rientrato.
Nessuna interazione è tentata con il lock screen. GTK4 già installato usa il
renderer Cairo del solo processo del dialogo, per evitare costose allocazioni GPU.

Il pop-up presenta ora un **riepilogo compatto del problema effettivo**:
per pressione I/O mostra «Attese disco/I/O elevate», senza suggerire falsamente
che la RAM sia esaurita. Percentuali e byte/s sono arrotondati a unità leggibili;
i contatori secondari sono nel pannello «Dettagli tecnici».

Le pagine «Processi» e «Schede Chrome» sono separate. La prima elenca solo
processi candidati con una selezione a clic (senza digitare numeri), poi richiede
una seconda conferma. La seconda mostra titoli Chrome in elenco scorrevole e
stato, senza associare schede ai processi né presumere il loro consumo.
Per scaricare una singola scheda si usa ancora il pannello dell'estensione.
Selezione e identità congelate scadono dopo 20 s. Nessuna app o scheda viene
chiusa automaticamente.

Per RAM usa memoria privata USS quando leggibile; se incompleta lo segnala,
altrimenti usa il massimo RSS di un processo come stima incerta, **mai la somma
RSS dei processi condivisi**. Per I/O usa delta disco dei processi del gruppo
solo se osservabili con baseline completa; se non attribuibili non propone kill
a caso. Disco/inode danno indicazioni di analisi manuale, senza promettere che
chiudere un'app liberi spazio e senza cancellazioni automatiche.

Selezionare la riga del processo e premere «Richiedi chiusura…» richiede
una seconda conferma sui dati non salvati. Nessuna selezione è implicita.
Il mapping riga/identità resta congelato fino alla scadenza di 20 secondi. Boot, PID/starttime, cgroup e UID sono
ricontrollati. pidfd impedisce che il segnale vada a un PID sostituito. Root,
altri utenti, GNOME Shell/sessione, FSM, shell/SSH/terminali e infrastrutture di
lavoro/interpreti sono esclusi; se un gruppo contiene processi protetti non è
proposto. La selezione conservativa può omettere app non identificabili come GUI.

Quando un'app espone un'azione GTK `quit`, ne verifica proprietario D-Bus,
UID e identità e richiede la chiusura normale. Altrimenti invia SIGTERM al solo
leader verificato. Mai SIGKILL, neppure dopo timeout. Attende anche i membri
osservati; se restano processi o la richiesta fallisce non dichiara miglioramenti.
Dopo tre secondi di assestamento crea una nuova finestra/classifica e ricampiona
la pressione. Il recupero richiede tre campioni sani con isteresi; viene mostrato
una volta. Rimandare/chiudere/ignorare dà snooze di 10 minuti; aperture distano
almeno 120 secondi, con nuova valutazione per aggravamento. Il dialogo termina
comunque entro 10 minuti. Le scelte non terminano mai automaticamente altre app.

## Chrome Stable: attribuzione dichiaratamente parziale

Sul sistema è stato verificato **Google Chrome Stable 153.0.8010.52**. La
[documentazione ufficiale di chrome.processes](https://developer.chrome.com/docs/extensions/reference/api/processes)
limita questa API al canale Dev. La
[API tabs](https://developer.chrome.com/docs/extensions/reference/api/tabs)
fornisce tabId/stato e discard/remove, non CPU, RSS/private footprint o I/O
attribuibili in modo affidabile alle singole schede. Non si usa JS heap come
RAM totale, non si divide arbitrariamente il totale Chrome fra schede e non si
termina un renderer condiviso. In questa integrazione quelle metriche e il
mapping a PID Linux sono **N/D**. La classifica è per inattività, non per consumo.

Il dialogo GTK ora mostra direttamente **titoli effimeri di schede Chrome**
in una sezione distinta dai processi. I nomi non sono attribuiti ai PID: per
identificare il processo di una scheda e le relative metriche aprire il Task
Manager Chrome (Maiusc+Esc, colonna PID). Se l'estensione non è attiva, il
dialogo dichiara che i titoli non sono disponibili anziché inventarli.

L'estensione FSM aggiorna un piccolo snapshot senza polling, solo su eventi
delle schede, all'avvio o quando si apre il suo pannello. Lo snapshot mostra
fino a 16 titoli (scheda attiva per prima, poi le inattive da meno recentemente
usate), stato e conteggio totale; nessuna classifica di consumo per tab.
L'host nativo **oneshot** riceve esclusivamente titoli limitati e flag
attiva/scaricata, senza URL, tabId o PID, e li conserva in un file 0600 nella
tmpfs privata `/run/user/UID/fsm-chrome-tabs.json`, leggibile per 30 minuti
dall'ultimo evento. Sono scartati payload malformati o troppo grandi.
L'host mantiene anche la receipt di capability
`/run/user/UID/fsm-chrome-capabilities.json`. Nessuna history, contenuto di
pagina, titolo o metrica personale passa al DB FSM o ai log, e non si crea un
secondo daemon, poller o database. Un browser senza modifiche alle schede per
oltre 30 minuti può richiedere di aprire il pannello estensione per aggiornare
l'elenco.

L'estensione richiede `tabs` e `nativeMessaging` solo per questo host, senza
host permissions, debugger, content script o accesso alle pagine. Ha ID stabile
`obbebjalncbgeghmpnpanmhidlejapbi`; il relativo host accetta solo tale origine.
Il service worker dell'estensione deve essere ricaricato dopo l'aggiornamento della cartella installata.
Ogni scaricamento/chiusura richiede numero e conferma ulteriore. Dopo la conferma
ricontrolla sessione, tabId, finestra e navigazione; cambiamenti invalidano
l'elenco. Scaricamento rifiutato per schede attive/audio/fissate/protette.
Verifica l'esito dell'API, ma non inventa la quantità di RAM liberata. Nessuna
scheda dell'utente viene chiusa o scaricata per test.

### Attivazione esplicita dell'estensione

Dopo il deploy, nella UI di Chrome Extensions caricare la cartella:
`/usr/local/libexec/fedora-system-monitor/chrome-resource-rescue`.
Poi aprire il pannello dall'icona FSM; non serve premere scarica/chiudi per
verificare la capability receipt. L'installazione non viene simulata né effettuata
tramite modifica dei profili Chrome. L'automazione browser disponibile ha negato
l'accesso a `chrome://extensions` per policy URL: serve questo passaggio manuale.
Il profilo normale non viene riavviato e non si apre debug remoto.

## Configurazione e verifica

La tabella `[resource_rescue]` nel config esistente sovrascrive i default:
`enabled`, `idle_seconds`, `active_seconds`, `warning_available`,
`emergency_available`, `support_psi_percent`, `warning_psi_some`,
`emergency_psi_full`, `io_psi_full`, `swap_out_mib_s`, `reclaim_pages_s`,
`hysteresis_percent`, `disk_free_percent`, `inode_free_percent`, `disk_free_mib`,
`debounce_seconds`, `recovery_samples`, `snooze_seconds`,
`minimum_popup_seconds`, `dialog_timeout_seconds`. Validazione con config-check.
Incidenti, transizioni e heartbeat numerici usano `dedup_state`/`events` della
SQLite già esistente, senza migrazioni. Nessun target o titolo browser persistito.

Test: `test_resource_rescue.py`, `node tests/test_chrome_rescue.mjs` e suite repo.
UI opt-in in sessione grafica isolata: `PYTHONPATH=src dbus-run-session -- xvfb-run -a env GDK_BACKEND=x11 GSK_RENDERER=cairo GTK_A11Y=none python3 tests/e2e_resource_dialog_x11.py`.
E2E opt-in: `PYTHONPATH=src python3 tests/e2e_resource_dialog.py`: finestra
Wayland reale con app simulata e segnali disabilitati, selezione obbligatoria,
annullamento, conferma, finestra unica e nuova classifica. I test PIDFD usano
solo un child `sleep` creato dal test. Lock/unlock, PSI e pressione sono simulati;
non si provoca OOM, né si bloccano sessioni o toccano app/schede dell'utente.

Misura fixture (1000 controlli): circa 0,093 ms CPU per controllo e 166 KB di
allocazioni Python di picco, esclusi avvio oomd/systemctl e scritture SQLite.
E2E Cairo: circa 77 MiB RSS, 43 MiB PSS e 38 MiB privati nella finestra attiva.
Il daemon non importa GTK; questa memoria esiste soltanto durante il dialogo.
Non sono garanzie di overhead identico sotto pressione reale. Il renderer
predefinito aveva mostrato circa 71 MiB privati; è stato sostituito solo nel
processo del dialogo. I limiti Chrome richiedono un esito finale PARTIAL, non
una promessa di diagnosi accurata per-tab.

## Profilo host anti-OOM — 6 novembre 2026

Il servizio eventi era operativo ma, senza capability PSI nel sandbox, usava il
fallback ogni 10 s (5 s durante incidenti). I dialoghi delle 14:39:50 e 17:10:00
CET sono partiti dopo i kernel OOM delle 14:39:49 e 17:09:53. Il dialogo richiede
una decisione umana, non libera memoria automaticamente. Impostare nel config
host esistente `[resource_rescue]` `idle_seconds = 2` e `active_seconds = 2`;
validare con `fedora-system-monitor config-check`, poi riavviare soltanto
`fedora-system-monitor-events.service`. I default del codice restano 10/5 per
installazioni che non applicano questo profilo esplicito.

`oomctl` mostrava pressione 80% per 20 s sul manager utente e nessun cgroup
monitorato per swap. Alle 14:39 restavano circa 487 MiB di swap; alle 17:09 ne
restavano 10,8 GiB: la sola soglia swap non copre entrambi gli eventi. Non esiste
una serie PSI storica sufficientemente fine per ricostruire l'esatta soglia al
momento dei kill. I processi Python che hanno richiesto l'allocazione non sono
per questo dimostrati responsabili principali del consumo.

Il file `config/oomd/60-fsm-memory-rescue.conf` è un drop-in esplicito del
**system manager**, da installare per il solo operatore, qui UID 1000:

```sh
sudo install -d -m 0755 /etc/systemd/system/user@1000.service.d
sudo install -m 0644 config/oomd/60-fsm-memory-rescue.conf /etc/systemd/system/user@1000.service.d/
sudo systemctl daemon-reload
oomctl
```

Non riavviare `user@1000.service`: terminerebbe la sessione. Verificare in
`oomctl` il percorso user@1000.service sia nella sezione swap sia con pressione
50% per 5 s. La soglia swap globale esistente resta 90%; il profilo non aggiunge
servizi, timer, capability o notifiche. oomd può terminare **interi cgroup**:
non garantisce che Chrome resti aperto, soprattutto se un launcher ha ospitato
l'intero browser in un servizio. Il servizio chatgpt-exporter-dashboard aveva
picchi registrati di 14,2 GiB RAM e 12,2 GiB swap (picchi non necessariamente
simultanei). Non impostare limiti arbitrari o immunità OOM sul browser personale.

Rollback: ripristinare il config host dal backup e il drop-in precedente (oppure
rimuovere soltanto questo file se prima assente), daemon-reload e restart del
solo daemon eventi. Nessuna prova deve saturare la RAM reale o chiudere schede.
Le verifiche di configurazione attestano applicazione, non una garanzia contro
picchi futuri. Registro canonico: incidente MegaVault, con riferimento al commit.
