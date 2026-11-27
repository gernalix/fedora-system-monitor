# Risorse delle unità systemd

Il timer FSM fast esegue lo scanner ogni minuto anche dopo il riavvio. Una
lettura dei cgroup v2 copre servizi e scope di sistema e dei manager utente.
Il percorso identifica l'UID. I discendenti delegati a un servizio sono inclusi
nei suoi contatori. Il journal del manager integra avvii, riavvii e CPU degli
incarichi conclusi fra due letture. Gli eventi disponibili dipendono dalla
contabilità e dalla conservazione del journal.

```sh
fedora-system-monitor metrics --name service.resource_scan --limit 5 --json
fedora-system-monitor alerts --json
fedora-system-monitor events --category service --since-hours 24 --json
```

Il riepilogo conserva copertura, uptime, disponibilità dei contatori e primi
cinque per misura. Cento per cento CPU equivale a un core. Le operazioni al
minuto sono letture e scritture del livello a blocchi, incluso zram quando
contabilizzato. Un dispositivo cifrato e il suo disco sono contati una volta.
Per le unità attive, FSM sottrae dalla carica del cgroup una stima prudente
della cache di file inattiva. Le pagine sporche, in scrittura e quelle mappate
o condivise restano nel conteggio. Se i dati sono incompleti, FSM usa la carica
totale. `case --memory` mostra anche il totale. La classifica RAM usa i campioni
della stessa definizione, e la soglia relativa si ricalibra al cambio di base.
Per i job conclusi il journal fornisce
la CPU dell’intera esecuzione e, quando disponibile, il picco di RAM. Se più
esecuzioni della stessa unità terminano in un minuto, FSM conserva il picco
maggiore. Due finestre con picchi di almeno 2.048 MiB aprono un avviso.
Il limite per unità si imposta con `completed_memory_peak_mib`. Il rientro
richiede due finestre con un picco osservato sotto l’80% del limite. Una scansione interrotta, un contatore
mancante, un cambio di boot o di cgroup interrompono il confronto pertinente.

Valori iniziali per l'indagine: 80% di un core, 6.000 operazioni al minuto,
50 MiB/s oppure 2.048 MiB per tre campioni, tre riavvii o 30 avvii in un minuto, oppure due
finestre con job conclusi per almeno 180 secondi CPU ciascuna. Tre finestre
consecutive con almeno un’esecuzione fallita generano un avviso anche per un
timer leggero che continua a ripetere lo stesso lavoro. Il rientro richiede due
finestre con avvii osservati e senza ulteriori fallimenti. Per un servizio che resta
in esecuzione, FSM può anche verificare due intervalli completi con la stessa
invocazione attiva, il processo principale presente e il journal senza fallimenti
o riavvii. Interroga il manager soltanto per i servizi con questo avviso aperto.
Dopo 15 campioni lo scanner considera anche una crescita di quattro
volte rispetto alla media mobile della singola unità, con soglie minime di
20% CPU, 1.500 I/O al minuto, 10 MiB/s e 512 MiB. I limiti espliciti
per unità prevalgono sulla soglia relativa. Un operatore
può inserire limiti specifici nel config FSM esistente, per esempio:

```toml
[unit_resources.units."system:example.service"]
cpu_percent = 25
io_ops_min = 1500
```

Un avviso contiene identità, valore, limite e finestra. Il rientro richiede
due misure sotto l'80% del limite. Per CPU, I/O e RAM di un cgroup terminato,
due intervalli completi senza cgroup ai due estremi e senza attività nel
journal confermano che il consumo è cessato. Gli avvisi sulle esecuzioni
fallite e sui consumi dei job conclusi richiedono le rispettive prove.
Verificare anche una funzione reale del
servizio prima di dichiarare risolto il difetto. Per un guasto nuovo si
individua la causa nel progetto proprietario, si prova lì la modifica e si
confrontano esecuzioni equivalenti sul sistema.

Un progetto può fornire un'unità oneshot di riparazione che riconosce la causa
specifica, applica la correzione, riavvia il servizio interessato se necessario,
prova la funzione e termina con stato zero a verifica riuscita. FSM ne richiede
una per volta e registra il tentativo prima dell'invio. Il comando attende
fino a otto secondi. Un esito incerto resta da verificare. FSM registra
separatamente la verifica del proprietario e il successivo rientro dei consumi.
La ricetta inclusa per il ciclo di riavvio ClipMD ripristina la definizione
nota e controlla il socket privato. Il percorso HTTPS richiede anche il proxy.

```toml
[unit_resources.repairs."system:example.service"]
cpu_percent = "example-repair.service"
```

Applicare solo ricette verificate del progetto proprietario. Gli scope degli
altri UID sono osservati. Le riparazioni utente passano per il manager
dell'operatore configurato. Il normale deploy del runtime FSM attiva la parte
scanner al successivo tick del timer fast.

## Chrome

La metrica `chrome.resource_assessment` riutilizza i campioni per processo del
collector FSM. Riporta la somma della CPU osservata, la velocità I/O osservata
e il massimo RSS di un singolo processo Chrome dell'operatore, con i rispettivi
conteggi di copertura. Include tutti i profili identificabili dal nome processo.
Il massimo RSS evita di sommare pagine condivise. L'aggregazione registra il
proprio tempo CPU e di parete in microsecondi, inclusa la lettura indicizzata
dello stato precedente. La persistenza usa una riga per campione.

Tre campioni consecutivi completi sopra soglia per la stessa misura producono
l'evento `chrome_sustained_resources`. L'operatore può allora scegliere
un'estensione, confrontare lo stesso carico prima e dopo una modifica manuale,
e ripristinarla prima di provarne un'altra. L'evento misura il browser nel suo
insieme. La scelta e la disattivazione dell'estensione spettano all'utente.

Misura locale del 26 novembre 2026, riproducibile con
`PYTHONPATH=src python3 -B tests/benchmark_chrome_assessment.py`. Su 20 campioni
Fedora già registrati (mediana 747 processi), 80 coppie con/senza controllo
hanno aggiunto in mediana 1,25 ms CPU e 1,27 ms di parete per campione. La
scansione /proc originale durava in mediana 129,86 ms. Il confronto include
aggregazione, rilettura dello stato, scrittura in SQLite temporanea e valutazione
delle metriche. Il costo sul database di produzione può variare.

## Classifica e verifica da terminale

`fsm-resources journal --minutes 8 --json` raggruppa per produttore il journal
accessibile con una sola lettura. Mostra conteggi, byte osservati, priorità,
trasporto e ripetizioni esatte senza riportare messaggi. Con `--unit` limita
la lettura al produttore richiesto. Il cursore riprende la lettura successiva
e resta fermo quando il limite delle righe ha tagliato la finestra. I byte
si riferiscono ai messaggi disponibili nell'output JSON di journald.

Dal checkout Fedora, `scripts/fsm-resources rank` mostra le unità dell’ultimo
campione ordinate per operazioni I/O al minuto. Il riepilogo storico contiene
i primi cinque per metrica. Un punto interrogativo indica un valore fuori
classifica o assente. I conteggi delle presenze e dei superamenti storici sono
limiti inferiori. La colonna SOPRA usa il limite configurato per unità o la
soglia indicata con `--threshold`.

```sh
fsm-resources rank --order persistent --minutes 15
fsm-resources rank --order peak --metric cpu_percent
fsm-resources rank --full --limit 1000 --json
fsm-resources rank --full --samples 15 --order persistent
fsm-resources next --metric io_ops_min
fsm-resources inspect --unit user:1000:prompt-history-dashboard.service
```

La classifica completa attende il prossimo campione del timer in funzione e
confronta i contatori di tutte le unità misurabili. Il JSON include il dettaglio
per dispositivo per distinguere SSD e zram. Il comando `next` sceglie un
avviso aperto privilegiando la misura recente col maggiore rapporto fra valore
e soglia. Mostra i PID ancora riconducibili all’unità, l’ultimo controllo
salvato e l’eventuale ricetta di riparazione. `inspect` riporta CPU, memoria e
letture/scritture in byte per i PID secondo la disponibilità dei contatori.
Con `inspect --unit … --io-seconds 10` il programma misura su richiesta i
byte letti e scritti dai PID, controllando identità e gruppo. Se mancano
contatori iniziali utilizzabili dalla cronologia, parte dai membri attuali
del cgroup. Il campo JSON `candidate_source` indica la fonte della misura.
I contatori del PID possono includere figli già attesi; le righe non vanno
sommate alla cieca. Il report indica quanti PID sono stati misurati.
L’attribuzione a una libreria richiede una diagnosi del processo interessato.

Dopo la correzione eseguire, per esempio:

```sh
fsm-resources verify --unit system:example.service --metric cpu_percent --samples 3
fsm-verify-prompt-history --json
```

La verifica legge finestre intere successive al comando e applica il margine
di rientro di FSM, comprese le soglie adattive. Un cambio di cgroup, un salto
di campionamento o un contatore mancante interrompe la serie. Il controllo
funzionale opzionale si passa come ultimo argomento con `--probe PROGRAMMA ARG...`.
Per un lavoro periodico, `--expect-change` chiede al controllo di restituire un
identificativo stabile per ciclo e attende anche il campione successivo al suo
cambio. Il comando dedicato alla dashboard usa la data di generazione dei dati
serviti e attende fino a 20 minuti. Il contenuto della risposta resta privato.

Il codice di uscita di `verify` vale 0 per il rientro osservato, 1 per consumi
ancora alti o test funzionale fallito, 2 per prove insufficienti. L’ultima
verifica di ogni coppia unità/metrica viene registrata atomicamente nello stato
privato dell’utente, sotto `fedora-system-monitor/resource-triage`. I comandi
usano il timer e la telemetria esistenti. Per l’uso diretto dal checkout
anteporre `scripts/` ai due nomi di comando.

### Una diagnosi ripetibile con pochi dati

`fsm-resources case --json` sceglie l’avviso aperto più urgente con la stessa
priorità di `next`. Restituisce ID, unità, misura e soglia, quante volte figura
nei primi cinque, picco osservato, tre PID per CPU, ricetta e ultima verifica
della coppia unità/metrica. Il timer fast continua a raccogliere i dati. La
diagnosi legge il database su richiesta. Per esaminare un consumo specifico:

```sh
fsm-resources case --metric io_ops_min --json
fsm-resources case --id 123 --io-seconds 15 --json
fsm-resources case --id 123 --verify --json
```

Sostituire 123 con l’ID restituito. Il secondo comando campiona ogni secondo
gli eseguibili nel cgroup diretto, comprende i nuovi PID osservati e indica
il costo CPU del controllo. Nella stessa finestra, `pid_io.block_io` elenca
letture, scritture, byte e operazioni al minuto per dispositivo del cgroup.
Per esempio, `zram0` indica RAM compressa, `nvme0n1` un dispositivo NVMe.
Lo stato `partial` indica un dispositivo comparso, scomparso o con contatori
azzerati. `unavailable` indica che i contatori non erano leggibili. Tenere conto di processi più brevi dell’intervallo,
sottogruppi delegati, permessi e I/O ereditato dai figli attesi. I byte per
eseguibile servono all’attribuzione e possono sovrapporsi. Le operazioni al
minuto restano quelle misurate sul cgroup. Eseguire il comando tramite
`systemd-run --user --wait --pipe --collect --quiet` quando lo si avvia
dallo stesso gruppo in esame.

Dopo una correzione, `--verify` confronta tre finestre intere per le misure
del cgroup. Per avvii, riavvii, fallimenti e lavori conclusi consulta le
misure registrate per l’unità e richiede due riscontri e la transizione di
rientro dello scanner per quello specifico avviso. Una chiusura manuale o
l’assenza del job lasciano l’esito insufficiente. L’uscita vale 0 per rientro,
1 per consumo persistente o prova funzionale fallita, 2 per dati insufficienti.
Il campo `probe` indica se è stata verificata la funzione del servizio.
Per la dashboard della cronologia prompt viene controllato anche il cambio di
ciclo. Usare `--timeout 1200` per attendere il suo aggiornamento periodico.

Per confrontare due versioni dell’archivio comandi installato, eseguire
`scripts/fsm-benchmark-command-archive` prima e dopo l’intervento. Ogni volta
il comando avvia un servizio utente transitorio, produce tre catture locali
di 38.400 byte di testo di prova, verifica il replay di stdout e output
combinato e restituisce CPU, durata e operazioni a blocchi con le mediane.
Un replay incompleto rende la prova inutilizzabile. L’archivio applica la
conservazione ordinaria ai tre eventi.

Per gli avvisi di memoria usare `fsm-resources case --metric memory_mib --memory`.
Il dettaglio mostra la carica del cgroup, la memoria anonima, quella associata a
file, lo swap, la RAM disponibile sull’host e la percentuale di stallo completo
per memoria (PSI a 60 secondi). Shmem, file attivi/inattivi e pagine sporche
sono dettagli della contabilità del kernel e possono sovrapporsi.
Le due classifiche raggruppano per eseguibile la memoria residente (PSS) e
quella in swap (SwapPss), ripartendo le pagine condivise. Riguardano i PID
diretti leggibili. Il comando indica copertura e costo della misura, limitata a
256 PID e con un budget di un secondo per avviare le letture. La raccolta
periodica continua a usare i soli contatori del cgroup.
