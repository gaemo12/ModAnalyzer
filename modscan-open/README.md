# ModScanOpen — scansione mod open source

ModScanOpen è il programma **open source (MIT, senza licenza)** derivato da
JarAnalyzer: scansiona **un file `.jar`** oppure **tutta la cartella `mods`**
di Minecraft, in locale e **completamente offline** (nessuna rete, nessun
backend, nessuna licenza, nessun consenso remoto).

Mantiene SOLO due modalità, identiche a quelle della vecchia app:

- **File JAR** — analisi completa di un file (verdetto, punteggio, mappa delle classi, esplorazione dei rilevamenti, export del report HTML);
- **Cartella mods** — trova la cartella dal processo `javaw` attivo o a mano, elenca le mod con hash e flag di cheat noti, verifica l'hash sui database delle mod e approfondisce le singole mod con l'analisi completa.

Niente Staff, niente giocatore, niente scansioni di sistema, niente PIN/remoto.

L'interfaccia grafica è la **stessa UI web della vecchia JarAnalyzer** (WebView JavaFX, nessun server): doppio clic su `ModScanOpen.exe` e si apre direttamente la home con le due modalità. Senza argomenti da riga di comando parte la GUI; con argomenti parte la CLI qui sotto.

## Uso

```
ModScanOpen.bat scan --jar UnFile.jar
ModScanOpen.bat scan --mods auto
ModScanOpen.bat scan --jar a.jar --mods C:\...\mods --out results.json
ModScanOpen.bat runtime --mods auto
```

- `--jar <file>` analizza un singolo JAR con le regole operative (bytecode, rete, offuscamento, API sospette, entropy, struttura). Le stringhe di firma note di malware riservate allo Staff NON sono incluse in questa edizione open.
- `--mods <cartella|auto>` con `auto` trova la cartella mods dal processo
  `javaw.exe` attivo, altrimenti usa `%APPDATA%\.minecraft\mods`.
- `runtime [--mods <dir|auto>] [--pid <pid>]` (v1.3.0) confronto runtime:
  riga di comando del processo di gioco (javaagent/tweakClass/classpath),
  mod caricate secondo `logs/latest.log` vs jar su disco (JiJ inclusi),
  artefatti noti di cheat client nella .minecraft (solo nomi, mai contenuto).
- L'esito è **JSON su stdout** (o `--out nomefile.json`), leggibile da
  qualsiasi tool o script; exit code 0 = scansione eseguita.

## Requisiti

Java 17+ (per il runtime). Windows/Linux/macOS (l'auto-loc della cartella è
ottimizzata per Windows).

## Verifica online delle mod

Oltre ai controlli locali, l'app consulta due database pubblici per classificare le mod:

- **Modrinth** (principale): `https://api.modrinth.com/v2/version_file/{sha1}` per il singolo file e batch per la cartella;
- **Megabase** (riserva): `https://megabase.vercel.app/api/query?hash={sha1}` quando Modrinth non trova corrispondenze.

Una mod trovata in uno dei due è marcata **VERIFIED** (con nome, versione e URL del progetto).
Le uniche connessioni che l'app fa sono verso questi due endpoint: nessun dato del tuo PC
viene inviato, solo l'hash SHA-1 del file già calcolato localmente.

- lettura dei file **solamente locale**: verso i database delle mod va inviato solo l'hash
  SHA-1 del file (mai il file, mai percorsi, mai dati dell'utente); il motore di analisi è
  lo stesso di JarAnalyzer (modulo `scanners/`), senza le firme riservate allo Staff.
- Gli stati delle mod: **VERIFIED** (rilascio ufficiale su Modrinth/Megabase),
  **SUSPICIOUS** (cheat noto nell'archivio) o **UNVERIFIED** (nessuna corrispondenza:
  possibile build custom).
- Un errore di rete non inventa mai esiti: la nota dice esplicitamente che la verifica
  non era disponibile.
- Output deterministico: stesso file → stesso esito.
- Codice sorgente nel repo: `modscan-open/`. **Licenza: MIT** (LICENSE).

## Build dalla sorgente

```
mvn -q -DskipTests package -pl modscan-open
java -jar modscan-open/target/ModScanOpen.jar scan --mods auto
```
