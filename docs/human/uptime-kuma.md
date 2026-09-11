# Integrazione Uptime Kuma

Sono presenti cinque Push Monitor, scelti per fornire segnali distinti senza
moltiplicare le notifiche:

| ID | Monitor | Heartbeat | Copertura |
|---:|---|---:|---|
| 39 | Fedora Host | 180 s | CPU, memoria, swap, temperature, kernel, OOM |
| 40 | Fedora Storage | 480 s | filesystem, SMART, I/O, mount, dispositivi |
| 41 | Fedora Network | 180 s | Internet, gateway, Wi-Fi, VPN, NetworkManager |
| 42 | Fedora Services | 180 s | unità failed, restart e restart loop, incluse le unità persistenti dei progetti Fedora |
| 43 | Fedora Software | 5400 s | aggiornamenti, transazioni e inventari |

Ogni monitor ha timeout 48 secondi, retry coerente con la frequenza, massimo due
retry e nessun reinvio periodico dello stesso stato. Gli alert sono aggregati per
categoria: una transizione apre `DOWN`, la recovery invia una sola transizione
`UP`, mentre gli heartbeat rappresentano lo stato complessivo corrente.

`Fedora Services` include esplicitamente anche
`fedora-diagnostics-telemetry.service`, `x-repost-downloader.service` e la unità
utente `codex-session-archive.service`. Questi servizi oneshot sono sani quando
l'ultima esecuzione ha `Result=success`; un fallimento rende rosso lo stesso
failure domain senza creare monitor duplicati per ogni unità.

Gli URL sono in `/home/daniele/.config/codex/secrets/fedora_system_monitor_uptime_kuma.toml`,
con modo `0600`. Non vanno mai stampati, copiati nei documenti o
committati. Il runtime non usa cookie o credenziali Kuma.

L'endpoint corrente è `https://kuma.danielegalati.com`. Cloudflare Tunnel porta
il traffico al reverse proxy Caddy sulla VM Oracle; Kuma e il precedente proxy
Nginx restano esposti solo su loopback. HTTP pubblico viene reindirizzato a
HTTPS e la porta pubblica `3001` è chiusa.

## Gate di verifica end-to-end

Per future migrazioni di endpoint, proxy, tunnel, DNS o TLS, una risposta HTTP
`2xx` al push non è da sola una prova di consegna: proxy o edge possono
rispondere senza che il nuovo heartbeat raggiunga Uptime Kuma.

Prima di dichiarare PASS:

1. inviare dal percorso producer reale un probe con un nonce/correlation marker
   univoco nel messaggio, senza esporre il token dell'endpoint;
2. verificare nel DB live/backup recente o nel log autorevole di Kuma che sia
   arrivato proprio quel marker e che monitor/timestamp siano quelli attesi;
3. verificare almeno due cicli reali quando il task modifica scheduling,
   heartbeat o timeout;
4. mantenere il percorso legacy finché questo readback non passa;
5. non ripetere lo stesso probe fallito senza nuova evidenza o una modifica del
   livello sospetto.

Il codice runtime continua a trattare `2xx` come conferma di trasporto per il
singolo invio ordinario; il gate sopra è una regola di acceptance per cutover e
diagnostica, non un readback remoto ad ogni heartbeat.

Il 10 luglio 2026 sono stati verificati heartbeat reali su tutti i monitor e una
sequenza controllata Software `DOWN`/`UP`, entrambe accettate con HTTP 200. La
sessione Chrome usata solo per creare i monitor è poi scaduta e non è stata
salvata. Per modificare in futuro le definizioni serve una nuova sessione Kuma
autenticata; nessuna credenziale è richiesta per il funzionamento ordinario.

L'11 settembre 2026 il readback remoto SQLite di Kuma sulla VM Oracle ha
verificato direttamente i monitor 39-43 tutti `UP`. Due alert rimasti attivi da
un boot precedente sono stati recuperati senza alterare le soglie: l'OOM era
riferito a un altro `boot_id`, mentre il filesystem quasi pieno non era più
montato né osservato. Il browser/JWT non serve per la verifica runtime.
