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
pom.xml              parent Maven (modanalyzer-parent 1.3.1)
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

## Rilevamento (v1.3.1)

Release correttiva della v1.3.0: integra l'interfaccia riscritta in
linguaggio da giocatore (restata fuori dalla v1.3.0), aggiunge la storia
per file del journal con i file spariti e corregge un bug della GUI.

### UI in linguaggio da giocatore (`ui/js/explain.js`)

- Il risultato di ogni scansione (file JAR, singola mod, dump memoria) ora
  parte da un **verdetto in parole semplici** con anello colorato e icona,
  seguito dalla card **"Cosa abbiamo trovato"**: i rilevamenti raggruppati
  per argomento (può rubare account, controllo remoto, mining, funzioni da
  cheat, codice nascosto, connessioni, …) ciascuno con "cos'è" e "perché
  conta". Card **"Cosa fare"** con i passi concreti e l'avvertenza che un
  rosso non è una condanna. I dettagli tecnici restano, ripiegati in fondo.
- Mappa delle classi con tooltip arricchito (classe, livello, numero di
  segnalazioni); cliccare una cella apre i dettagli.
- Elenco mod con stati **Ufficiale / Non riconosciuta / Da controllare**,
  note riscritte in italiano semplice e pulsante "Controlla a fondo".
- Mapping titoli→gruppi verificato sui campioni del corpus; zip-slip ora nel
  gruppo "Legge o scrive file sul PC" (prima sotto la nota strutturale).

### Journal: storia per file e file spariti

- `journal.files`: per ogni mod ancora presente, la sequenza di eventi USN
  (scritto, rinominato con nome vecchio/nuovo accoppiati, attributi
  cambiati) mostrata anche sulla riga della mod ("Cosa è successo a questo
  file"); `journal.gone` + `counts.gone`: file **eliminati o rinominati**
  dopo l'avvio del gioco, con righe dedicate ("Spariti dopo l'avvio") e
  filtro **"Dopo l'avvio"** nell'elenco mod.
- Se `fsutil` riporta solo il nome file (senza percorso), gli eventi vengono
  attribuiti ai file presenti nella cartella: la storia non va persa.
- In GUI la lettura USN è attiva per impostazione predefinita: senza
  privilegi di amministratore compare l'avviso esplicito e il controllo
  prosegue sugli orari dei file (nessun crash).

### Correzioni

- **GUI v1.3.0**: `js/runtime.js` non era nell'elenco delle risorse estratte
  nella WebView (`WebUi.UI_RESOURCES`), quindi la card "Runtime" della
  v1.3.0 non partiva (CLI `runtime` funzionava). Ora l'elenco è completo e
  verificato: tutte le risorse referenziate da `index.html` vengono estratte.
- Con il gioco non attivo, il conteggio "segnali" del controllo runtime non
  conta più la nota informativa come un segnale.

## Rilevamento (v1.3.0)

Screening SS orientato al **confronto runtime**: cosa gira davvero rispetto a
cosa c'è su disco, più firme cheat sui dump e anti-spoofing dei metadati.

### Confronto runtime (nuova card "Runtime" + CLI `runtime`)

- **Mod caricate vs mod su disco**: parsing di `logs/latest.log` (Fabric/Quilt
  per id, Forge per nome file) e confronto con gli id dichiarati dai jar della
  cartella mods, **JiJ annidati inclusi** (profondità 3). Una mod caricata a
  runtime senza nessun jar su disco è il segnale classico del client ghost
  iniettato: MEDIUM, HIGH se l'id combacia con un indicatore di cheat noto.
  Anti-FP: builtin del loader (`minecraft`, `java`, `fabricloader`, …)
  esclusi, mod disabilitate/mai caricate riportate solo come nota, e un log
  più vecchio dell'avvio del gioco viene marcato "sessione precedente" con
  severità declassata.
- **Riga di comando del processo di gioco**: flag tipici dei ghost client —
  `-javaagent` (HIGH), `-Xbootclasspath` (HIGH), `-Djava.system.class.loader`
  (HIGH), `--tweakClass` non standard (MEDIUM; i tweaker storici di
  Forge/OptiFine/LiteLoader non generano finding), classpath con voci fuori
  dai launcher noti (MEDIUM), JDWP e `-XX:+DisableAttachMechanism` (MEDIUM).
- **Artefatti noti di cheat client** nella `.minecraft` (Meteor, Future, Vape,
  RusherHack, LiquidBounce, …): pattern in `rules/cheat-artifacts.json`
  (dati, non codice), solo nomi di cartelle/file, **mai il contenuto**
  (privacy), severità MEDIUM come indizio da confermare.

Nuova rotta `GET /api/mods/runtime`, sottocomando CLI
`runtime [--mods <dir|auto>] [--pid <pid>] [--out file.json]`, card GUI che
parte in automatico dopo il controllo integrità. Il JSON di `scan` resta
invariato.

### Memory-dump: match contro firme di cheat noti

Le classi del dump (incluse quelle "bypassed", senza origine su disco) vengono
confrontate con gli indicatori di cheat client già usati per la cartella
(`QUICK_FLAG_PREFIXES`), con matching **per segmento di package** (più stretto
del quick-flag sui nomi delle voci: `refill` non matcha `PotionRefilling`).
Esiti aggregati per famiglia nel nuovo campo `memoryScope.cheatMatches` e un
finding HIGH `mem-cheat-signature`. Scope dump invariato (v1.2.0): solo gioco
+ mod non verificate, retransform a blocchi.

### Anti-spoofing dei metadati

- **Id dichiarato contro quick-flag**: l'id in `fabric.mod.json` /
  `mods.toml` / `mcmod.info` ora viene controllato contro gli indicatori di
  cheat noti (prima solo i nomi delle voci del jar: un jar minimale con un
  solo id sfuggiva). Finding SUSPICIOUS con motivo esplicito.
- **Build non ufficiale di una mod nota**: se una mod dichiara il nome di una
  mod molto diffusa (Sodium, JEI, Create, …) ma l'hash non risulta su
  Modrinth/Megabase, viene marcata `spoofSuspect` con nota esplicita
  ("possibile build alterata o rename"); lo stato resta UNVERIFIED, mai
  verdict inventati. Match esatto sul nome, mai per sottostringa.

### Motore

- **JiJ più profondi**: scansione ricorsiva dei jar annidati da profondità 2 /
  64 MB a **3 / 128 MB** (le librerie dentro Fabric API annidano a loro
  volta); il tetto anti zip-bomb resta.
- **4 regole IOC dati per script engine a runtime** (Nashorn, GraalVM
  Polyglot, Jython, LuaJ; severità LOW, ambito constant pool): esecuzione di
  script dentro la mod come indizio. Rhino escluso di proposito (KubeJS e
  affini sono legittimi); SpEL/Groovy/BeanShell erano già coperti
  dall'InjectionAnalyzer.
- **Meno falsi positivi**: le stringhe di versione nel `META-INF/MANIFEST.MF`
  (es. `21.0.12.1` del JDK) non matchano più come "IP hardcodati" — il
  manifest è metadato, stesso principio delle regole IOC (trovato nello smoke
  test di questa release).
- Self-test eseguibili: `scripts/run-selftests.bat` — in più il nuovo
  `RuntimeSelfTest` copre log-vs-disco (ghost, builtin, JiJ, log vecchio),
  riga di comando (javaagent, tweakClass, classpath) e artefatti cheat.

## Rilevamento (v1.2.0)

Questa release raggruppa tutto il lavoro successivo alla v1.1.0: dump mirato e
automatico, integrità delle mod, scoping del dump e antifalsi-positivi.

### Dump mirato e avvio automatico

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

### Integrità mod e scoping del dump

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

### Antifalsi-positivi CRITICAL e process picker

- 4 falsi positivi CRITICAL eliminati alla fonte (verificati sul dump IntelliJ,
  8→3): package ransomware solo su segmenti (`Decrypter` Maven non matcha più
  `crypter`); `javax.net.ssl.*` escluso dai wallet path; trasformazioni Cipher
  (`AES/CBC/...`) escluse dalle chiavi; TrustManager delegati esclusi dall'SSL bypass.
- Process picker: `GET /api/mem/processes` + select nella card Memoria (niente
  più auto cieco sul primo java).

### Meno falsi positivi e attribuzione delle origini

- Meno falsi positivi sui dump: classi JDK scartate al pack (bootstrap/jrt +
  package `java/javax/jdk/sun/com.sun`); sulla vittima demo da 218 a 11 finding.
- Attribuzione origine: l'agent scrive `origins.txt` (CodeSource per classe),
  ogni finding ha campo `origin` e suffisso in location col jar di provenienza.

### Memory-dump nella sezione Mods

- Memory-dump spostato nella sezione Mods (niente terza tab): card dedicata
  con PID/auto, steps, verdetto, priorità, rilevamenti e mappa classi.
- Fix causa radice mappa assente: `J.fmtUptime` mancava e faceva fallire il
  render del verdetto processo (`report.js:122`).

### Memory-dump in GUI

- Memory-dump anche in GUI: terza modalità "Memoria" (PID o auto, endpoint
  `POST /api/mem/dump`, vista processo con `processInfo`), riuso del renderer
  report e della mappa classi.
- Fix bug reale: NPE in `InjectionAnalyzer` su `superName` null
  (`java/lang/Object` e interfacce) — falliva su ogni dump e su molti jar reali.

### Memory-dump opt-in (memagent)

- Memory-dump opt-in (`scan --mem <pid|auto>`): nuovo modulo `memagent`
  (`MemAgent.jar`, osservatore puro con `premain`/`agentmain`, ritorna sempre
  `null`) agganciato via Attach API; il dump viene impacchettato e analizzato
  dal motore esistente. Mai esecuzione di codice del bersaglio. Nota: su JDK
  futuri il target potrebbe richiedere `-XX:+EnableDynamicAgentLoading`.
- Packaging: `MemAgent.jar` incluso nello stage + modulo `jdk.attach` nel runtime.

### Segnala bug e badge versione

- Pulsante "Segnala bug" nell'header: copia un template diagnostico e apre
  le issue GitHub nel browser (`MsBridge.openIssues`, la WebView non naviga).
- Badge versione agganciato a `J.version` (era fermo a v1.0.0).
- Nota di attribuzione su `QUICK_FLAG_PREFIXES` (sovrapposizione con lo
  script Meow: da verificare prima di estenderla).

### Motore a regole IOC e integrità archivio

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
