# Preavviso risorse e recupero interattivo (P247, NV 16)

Il daemon FSM già esistente registra trigger PSI RAM/I/O e controlla metriche
leggere ogni 10 secondi; durante un incidente usa 5 secondi. Se il kernel/sandbox
non permette i trigger, rimane il controllo a 10 secondi nello stesso thread del
daemon esistente. Non si aggiungono demoni o timer. Il dialogo è un **oneshot**
`fedora-system-monitor-resource-dialog@daniele.service`, solo quando necessario,
con UID dell'utente e senza capability. Le protezioni del daemon, del kernel e
di systemd-oomd restano invariate.

La sola RAM allocata, swap/zram occupato o CPU alta non provano rischio OOM.
Il warning predefinito richiede MemAvailable <15% con PSI/reclaim/swap-out,
oppure PSI RAM some ≥10%; l'emergenza richiede PSI full ≥5%, OOM recente,
oppure MemAvailable <5% con pressione corroborante. I trigger kernel sono hint
some RAM 100 ms / 2 s e full I/O 200 ms / 2 s; non costituiscono da soli prova OOM.
Si rilevano anche capacità/inode critici e PSI I/O sostenuta. Il pavimento
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

Il pop-up mostra rischio, numeri e classifica di applicazioni GUI dell'utente.
Per RAM usa memoria privata USS quando leggibile; se incompleta lo segnala,
altrimenti usa il massimo RSS di un processo come stima incerta, **mai la somma
RSS dei processi condivisi**. Per I/O usa delta disco dei processi del gruppo
solo se osservabili con baseline completa; se non attribuibili non propone kill
a caso. Disco/inode danno indicazioni di analisi manuale, senza promettere che
chiudere un'app liberi spazio e senza cancellazioni automatiche.

Digitare un numero e Invio richiede una seconda conferma sui dati non salvati.
Nessuna selezione è implicita. Il mapping numeri/identità resta congelato mentre
si digita e scade dopo 20 secondi. Boot, PID/starttime, cgroup e UID sono
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

Il pulsante nel dialogo indica il pannello «FSM Schede Chrome» dell'estensione
FSM, separato dal totale browser. Il pannello è user-driven, senza polling in
background. Titoli/URL restano nella memoria della sua finestra; nessuna history,
contenuto di pagina o metrica personale passa al DB FSM. Un host nativo **oneshot**
accetta soltanto versione, session nonce e booleani di capability, scrive una
receipt 0600 in `/run/user/UID/fsm-chrome-capabilities.json` ed esce. Non riceve
né registra tabId, titoli o URL; niente secondo database o browser agent.

L'estensione richiede `tabs` e `nativeMessaging` solo per questo host, senza
host permissions, debugger, content script o accesso alle pagine. Ha ID stabile
`obbebjalncbgeghmpnpanmhidlejapbi`; il relativo host accetta solo tale origine.
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
E2E opt-in: `PYTHONPATH=src python3 tests/e2e_resource_dialog.py`: finestra
Wayland reale con app simulata e segnali disabilitati, invalidazione numero,
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
