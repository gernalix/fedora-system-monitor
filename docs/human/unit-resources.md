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
La memoria è la carica del cgroup, cache inclusa. La CPU di un job concluso è
attribuita all'intera esecuzione. Una scansione interrotta, un contatore
mancante, un cambio di boot o di cgroup interrompono il confronto pertinente.

Valori iniziali per l'indagine: 80% di un core, 6.000 operazioni al minuto,
50 MiB/s oppure 2.048 MiB per tre campioni, tre riavvii o 30 avvii in un minuto, oppure due
finestre con job conclusi per almeno 180 secondi CPU ciascuna. Dopo 15 campioni lo scanner considera anche una crescita di quattro
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
due misure sotto l'80% del limite. Verificare anche una funzione reale del
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
