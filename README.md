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
