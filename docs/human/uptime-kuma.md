# Integrazione Uptime Kuma

Sono presenti cinque Push Monitor, scelti per fornire segnali distinti senza
moltiplicare le notifiche:

| ID | Monitor | Heartbeat | Copertura |
|---:|---|---:|---|
| 39 | Fedora Host | 180 s | CPU, memoria, swap, temperature, kernel, OOM |
| 40 | Fedora Storage | 480 s | filesystem, SMART, I/O, mount, dispositivi |
| 41 | Fedora Network | 180 s | Internet, gateway, Wi-Fi, VPN, NetworkManager |
| 42 | Fedora Services | 180 s | unità failed, restart e restart loop |
| 43 | Fedora Software | 5400 s | aggiornamenti, transazioni e inventari |

Ogni monitor ha timeout 48 secondi, retry coerente con la frequenza, massimo due
retry e nessun reinvio periodico dello stesso stato. Gli alert sono aggregati per
categoria: una transizione apre `DOWN`, la recovery invia una sola transizione
`UP`, mentre gli heartbeat rappresentano lo stato complessivo corrente.

Gli URL sono in `/etc/fedora-system-monitor/uptime-kuma.toml`, proprietà
`root:root`, modo `0600`. Non vanno mai stampati, copiati nei documenti o
committati. Il runtime non usa cookie o credenziali Kuma.

L’istanza attuale usa HTTP. La configurazione consente esplicitamente questo
trasporto perché è l’infrastruttura già presente, ma HTTPS resta necessario per
proteggere i push da osservatori sul percorso di rete.

Il 10 luglio 2026 sono stati verificati heartbeat reali su tutti i monitor e una
sequenza controllata Software `DOWN`/`UP`, entrambe accettate con HTTP 200. La
sessione Chrome usata solo per creare i monitor è poi scaduta e non è stata
salvata. Per modificare in futuro le definizioni serve una nuova sessione Kuma
autenticata; nessuna credenziale è richiesta per il funzionamento ordinario.

Il 14 luglio 2026 il readback remoto SQLite di Kuma sulla VM Oracle ha verificato
direttamente i monitor 39-43. Host è `DOWN` perché riceve heartbeat con
`active alerts=1` per swap warning. Storage è `DOWN` perché il Seagate ha circa
200 GB liberi ma solo il 5,2273% disponibile, ancora sotto la soglia critical del
10%. Network, Services e Software risultano `UP`. Il browser/JWT non serve per
la verifica runtime.
