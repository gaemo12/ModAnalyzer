# ModAnalyzer — scansione mod open source

ModAnalyzer (ex `ModScanOpen`) è un programma **open source (MIT)** per scansionare
**un file `.jar`** oppure **tutta la cartella `mods` di Minecraft**, in locale.
Nessuna licenza, nessun backend, nessun consenso remoto.

Due sole modalità, stessa UI web (WebView JavaFX):

- **File JAR** — analisi completa di un file (verdetto, punteggio, mappa delle classi, esplorazione dei rilevamenti, export del report HTML);
- **Cartella mods** — trova la cartella dal processo `javaw` attivo o a mano, elenca le mod con hash e flag di cheat noti, verifica l'hash sui database pubblici e approfondisce le singole mod.

## Uso (CLI)

```
ModScanOpen.bat scan --jar UnFile.jar
ModScanOpen.bat scan --mods auto
ModScanOpen.bat scan --jar a.jar --mods C:\...\mods --out results.json
```

- `--jar <file>` analizza un singolo JAR (bytecode, rete, offuscamento, API sospette, entropy, struttura).
- `--mods <cartella|auto>` con `auto` trova la cartella mods dal processo `javaw.exe` attivo, altrimenti usa `%APPDATA%\.minecraft\mods`.
- Esito **JSON su stdout** (o `--out nomefile.json`); exit code 0 = scansione eseguita.

Senza argomenti parte la GUI (doppio clic su `ModScanOpen.exe`).

## Verifica online delle mod

Oltre ai controlli locali, l'app consulta due database pubblici:

- **Modrinth**: `https://api.modrinth.com/v2/version_file/{sha1}`;
- **Megabase** (riserva): `https://megabase.vercel.app/api/query?hash={sha1}`.

Una mod trovata è marcata **VERIFIED** (nome, versione, URL progetto).
Stati possibili: **VERIFIED**, **SUSPICIOUS** (cheat noto), **UNVERIFIED** (nessuna corrispondenza).
Viene inviato solo l'hash SHA-1 del file, mai il file né percorsi né dati utente.

## Struttura repo

```
pom.xml              parent Maven (modanalyzer-parent 1.0.0)
common/              DTO / codec JSON condivisi (solo JDK)
scanners/            motore di scansione (JDK + ASM)
modscan-open/        app ModScanOpen (JavaFX) + UI web in resources/ui
scripts/             package-modscan-open.bat (exe + zip via jpackage)
```

## Build dalla sorgente

Requisiti: JDK 17+ (consigliato 21), Maven 3.9+.

```
mvn -q -DskipTests package -pl common,scanners,modscan-open -am
java -jar modscan-open/target/ModScanOpen.jar scan --mods auto
```

### Pacchetto Windows (.exe + .zip)

```
scripts\package-modscan-open.bat
```

Output:

- `dist/ModScanOpen/ModScanOpen.exe` (runtime Java incluso via jlink+jpackage)
- `dist/ModScanOpen.zip` (da allegare alle GitHub Release)

## Download

Scarica la versione già buildata dalle **[Release](../../releases)**:
`ModScanOpen.zip` → scompatta → avvia `ModScanOpen.exe`.

## Rilevamento (v1.7.0)

- **Dump mirato: le mod verificate non si dumpano**: l'agent salta (né
  ritrasforma né scrive) le classi delle mod VERIFIED su Modrinth/Megabase, i
  loro jar annidati estratti da Fabric in `.fabric/processedMods` (mappati per
  nome-base JiJ), le librerie del launcher (`meta/libraries`) e `theseus.jar`;
  le classi JDK erano già fuori scope. Sul pack reale restano in scope solo le
  classi del gioco e le poche mod non verificate (~6.000 su ~18.800 totali) e la
  retransform va a blocchi da 256 classi in una sola chiamata VM
  (prima: una chiamata per classe, ~17 minuti sul gioco avviato).
- **Avvio automatico e risultati nella lista**: all'apertura della sezione Mods
  partono da soli il controllo integrità e il dump memoria (checkbox
  "Automatico all'apertura", preferenza salvata). Gli esiti compaiono come chip
  su ogni mod: `dopo l'avvio`/`modificata` (journal), `mem N` colorato per
  gravità (dump), `dump ✓` per le mod saltate perché verificate. Riaprire la
  sezione non rifà il dump se è già pronto per la sessione di gioco.
- **Progresso reale**: la card Memoria legge `progress.txt` dell'agent
  (`GET /api/mem/progress`) e mostra fase e percentuale durante retransform,
  dump, impacchettamento e analisi; `GET /api/mem/result` recupera l'ultimo
  dump completato, il server risponde dalla cache per la stessa sessione.
- **Meno rumore**: "Base64 Encoded Strings Detected" da HIGH a MEDIUM (euristica
  debole; la rete nascosta ha una regola dedicata). Fix pacchetto:
  `js/journal.js` mancava dalla lista delle risorse copiate nella WebView.

## Rilevamento (v1.6.0)

- **Integrità mod dopo l'avvio di Minecraft**: nuova card nella sezione Mods
  (`GET /api/mods/journal`, CLI `journal`). Confronta creazione/modifica dei
  file della cartella mods con l'istante di avvio del processo javaw del gioco;
  con `--usn` legge anche il journal NTFS (eliminazioni e rinomine durante il
  gioco; senza privilegi di amministratore lo dice in modo esplicito).
- **Memory-dump ripulito**: scoping per origine (gioco, librerie, copie
  remappate Fabric, mod) — il rumore atteso è riassunto in un solo finding INFO;
  nuovo blocco `memoryScope` con attribuzione per mod e classi "bypassed"
  (senza file su disco o da percorsi esterni). Sul dump reale 3431 → 199 finding.
- **Falsi positivi corretti alla fonte**: `class-injection-risk` non scatta più
  per il solo uso di Mixin (nelle mod Fabric il bytecode caricato in memoria
  contiene già le firme Mixin); `xor-operation` portato a LOW; `ACC_SYNTHETIC`
  da solo non è più un'anomalia.
- **Reattività**: thread degli analyzer a priorità ridotta durante la scansione
  (la GUI non perde reattività sui dump grandi).

## Rilevamento (v1.5.3)

- 4 falsi positivi CRITICAL eliminati alla fonte (verificati sul dump IntelliJ,
  8→3): package ransomware solo su segmenti (`Decrypter` Maven non matcha più
  `crypter`); `javax.net.ssl.*` escluso dai wallet path; trasformazioni Cipher
  (`AES/CBC/...`) escluse dalle chiavi; TrustManager delegati esclusi dall'SSL bypass.
- Process picker: `GET /api/mem/processes` + select nella card Memoria (niente
  più auto cieco sul primo java).

## Rilevamento (v1.5.2)

- Meno falsi positivi sui dump: classi JDK scartate al pack (bootstrap/jrt +
  package `java/javax/jdk/sun/com.sun`); sulla vittima demo da 218 a 11 finding.
- Attribuzione origine: l'agent scrive `origins.txt` (CodeSource per classe),
  ogni finding ha campo `origin` e suffisso in location col jar di provenienza.

## Rilevamento (v1.5.1)

- Memory-dump spostato nella sezione Mods (niente terza tab): card dedicata
  con PID/auto, steps, verdetto, priorità, rilevamenti e mappa classi.
- Fix causa radice mappa assente: `J.fmtUptime` mancava e faceva fallire il
  render del verdetto processo (`report.js:122`).

## Rilevamento (v1.5.0)

- Memory-dump anche in GUI: terza modalità "Memoria" (PID o auto, endpoint
  `POST /api/mem/dump`, vista processo con `processInfo`), riuso del renderer
  report e della mappa classi.
- Fix bug reale: NPE in `InjectionAnalyzer` su `superName` null
  (`java/lang/Object` e interfacce) — falliva su ogni dump e su molti jar reali.

## Rilevamento (v1.4.0)

- Memory-dump opt-in (`scan --mem <pid|auto>`): nuovo modulo `memagent`
  (`MemAgent.jar`, osservatore puro con `premain`/`agentmain`, ritorna sempre
  `null`) agganciato via Attach API; il dump viene impacchettato e analizzato
  dal motore esistente. Mai esecuzione di codice del bersaglio. Nota: su JDK
  futuri il target potrebbe richiedere `-XX:+EnableDynamicAgentLoading`.
- Packaging: `MemAgent.jar` incluso nello stage + modulo `jdk.attach` nel runtime.

## Rilevamento (v1.3.0)

- Pulsante "Segnala bug" nell'header: copia un template diagnostico e apre
  le issue GitHub nel browser (`MsBridge.openIssues`, la WebView non naviga).
- Badge versione agganciato a `J.version` (era fermo a v1.0.0).
- Nota di attribuzione su `QUICK_FLAG_PREFIXES` (sovrapposizione con lo
  script Meow: da verificare prima di estenderla).

## Rilevamento (v1.2.0)

- Motore a regole IOC sul constant pool (`rules/ioc-rules.json`, dati non codice):
  webhook Discord con token, token Telegram/Discord, endpoint paste raw,
  PowerShell codificata, LOLBin, chiavi di persistenza, blob Base64 che
  decodificano in eseguibili. Ambiti rigidi (costanti di codice e risorse,
  mai metadati) e segreti sempre redatti nei report.
- Integrità archivio: zip-slip, dati accodati/preposti, nomi duplicati o in
  collisione di case, local/central header discordi, magia contro estensione.
- Punteggio: deduplica su regola+categoria+severità+titolo (prima tre HIGH
  diversi con `rule="unspecified"` contavano come uno solo).
- Self-test eseguibili: `scripts/run-selftests.bat` (22 controlli).

## Rilevamento (v1.1.0)

- Anti-evasione stringhe: match case-insensitive, ricomposizione `LDC` spezzate,
  decodifica Base64/hex con re-scan degli indicatori di rete.
- Voci oltre il limite analizzate sul campione iniziale (finding `oversize-sampled`),
  mai più punti ciechi silenziosi.
- Scansione ricorsiva dei JAR/ZIP annidati (profondità 2, budget 64 MB).
- Mod VERIFIED su Modrinth/Megabase: euristici declassati di un livello
  (campo `verifiedDowngrade` nel JSON).
- Punteggio pesato per categoria di evidenza; entropia top-5 voci +
  whitelist formati compressi.
- Meno falsi positivi: niente più flag su classi package-private, `jcmd.exe`,
  frasi comuni e identificatori scambiati per chiavi.

## Licenza

MIT — vedi [LICENSE](LICENSE).
Codice in `modscan-open/`, motore in `scanners/`, comuni in `common/`.
