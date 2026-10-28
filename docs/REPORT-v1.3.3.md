# Report v1.3.3 — ModAnalyzer / ModScanOpen

**Stato complessivo: PARZIALE / BLOCCATO — modifica sorgente applicata e verificata in build; release v1.3.3 non creata né pubblicata.**

Repository: <https://github.com/gaemo12/ModAnalyzer>

Branch locale: `feat/mods-sezione-unica`

HEAD base del branch prima del commit di questa attività: `14348462d9bfe54c9a08d05f635a654434e9e1dc`

La patch dello ZIP è stata applicata esattamente ai suoi otto file sorgente. In seguito è stata corretta la regola CSS dell’icona circolare: la rotazione si applica al solo SVG dell’anello, lasciando il triangolo di avviso verticale con punta in alto. La build e i self-test passano. Il gate del passo 3, tuttavia, non è completo: non ho provato il ripiego con Minecraft chiuso né potuto concludere le operazioni USN con privilegi elevati; inoltre non ho potuto ispezionare direttamente la console JavaScript della WebView. Il test elevato è stato effettivamente avviato e ha trovato il journal disponibile, ma la lettura ha restituito zero eventi dopo la creazione del file temporaneo; il test si è quindi fermato prima di rinomina/eliminazione e ha rimosso il file di prova. Per la condizione esplicita «Release solo se i passi 1–3 sono ok», non ho cambiato i numeri di versione né creato tag, eseguito merge o pubblicato artefatti. Il commit/push del branch sorgente è stato richiesto separatamente e non costituisce pubblicazione della release.

## Passi

| Passo | Stato | Risultato |
|---|---|---|
| 1 — Preparazione e patch | **OK** | Branch creato da `main` aggiornato; contenuto dello ZIP confrontato col repo e risultano solo gli otto file previsti; copiati i byte originali CRLF. Le modifiche preesistenti non tracciate nella working tree sono state lasciate intatte. |
| 2 — Build e test | **OK** | `mvn -q clean verify` passato; nove self-test eseguiti manualmente passano; `node --check` passa per tutti i nove JavaScript della UI. |
| 3 — Prova app | **PARZIALE** | GUI Windows avviata e verificata visivamente con Minecraft aperto; si veda l’esito dettagliato a–e sotto. |
| 4 — Release | **BLOCCATO / NON ESEGUITO** | Il passo 3 non è tutto OK. Inoltre `gh` non è installato. Nessuna release v1.3.3, tag, merge o pubblicazione. Il commit e push del branch sorgente sono stati richiesti separatamente in seguito e non costituiscono una release. |
| 5 — Report | **OK** | Questo report registra esiti, artefatti e limiti senza dichiarare verificate prove non eseguite. |

## Comandi eseguiti e risultati

- `git status --short --branch` — inizialmente mostrava elementi locali non tracciati già presenti (`RELEASE-NOTES-v1.3.0.md`, `RELEASE-NOTES-v1.3.1.md`, `REPORT-v1.3.0.md`, `dist231/`, `localagent/`). Sono stati conservati e non inclusi nella patch.
- `git checkout main && git pull --ff-only && git checkout -b feat/mods-sezione-unica` — riuscito; `main` era aggiornato e il branch è partito da `14348462d9bfe54c9a08d05f635a654434e9e1dc`.
- ZIP `C:\Users\Gabriele\Downloads\modAnalyzer-src_2.zip` — integrità verificata; confronto ricorsivo in directory temporanee con normalizzazione dei terminatori: **8 differenze di contenuto**, nessun file aggiunto o mancante. Le differenze di terminatore presenti in altri file dell’archivio non sono state copiate.
- `git diff --stat` prima della correzione mirata dell’icona — otto file, 218 inserimenti e 182 rimozioni; la correzione CSS successiva restringe `.ring svg` a `.ring>svg`. `git diff --check` — exit 0.
- `mvn -q clean verify` (Maven 3.9.9 installato localmente) — **PASS**, exit 0. I tentativi tramite `mvnw.cmd`/`cmd.exe` non hanno terminato entro il timeout; per la build è stato usato direttamente l’eseguibile Maven disponibile.
- Self-test: `RuleEngineSelfTest`, `ArchiveIntegritySelfTest`, `ModsTimelineSelfTest`, `RuntimeSelfTest`, `ModsAuditSelfTest`, `CrashLogsSelfTest`, `UsnJournalSelfTest`, `MemSkipSelfTest`, `MemAgentSelfTest` — **9/9 PASS**. Sono stati compilati ed eseguiti in una directory temporanea univoca, senza eseguire il `.bat` del progetto che pulisce `%TEMP%\selftests`.
- `node --check` sui nove file `modscan-open/src/main/resources/ui/js/*.js` — **9/9 PASS**.
- Avvio GUI su Windows, scansione della cartella mods del profilo Minecraft attivo e controllo dei log Java — la GUI è rimasta responsiva; nessun messaggio `[JS]`, `[WebView]` o errore JavaScript è apparso nei log osservati. Sono apparsi un warning di configurazione JavaFX e warning SLF4J senza provider; non sono stati soppressi.
- Test elevated USN eseguito con script temporaneo dedicato in `target/`: la prima esecuzione si è fermata prima di creare file per `JAVA_HOME` non impostata; il test corretto è stato approvato ed eseguito. Il journal risultava disponibile ma ha restituito `eventCount=0` dopo la creazione del probe; script terminato prima di rinomina/eliminazione e cleanup `finally`. Non viene dichiarato PASS.
- Packaging di prova Windows con `jlink`/`jpackage`, in cartelle nuove sotto `output/` (non pubblicate): EXE in `output/ModScanOpen-mods-patch-vertical-triangle/ModScanOpen/ModScanOpen.exe`, 453.632 byte, SHA-256 `844b7b899d55d83682b5c746df48e37a8ee40d12ffc737299c10135f81ecc0ac`; bundle 95.018.364 byte (204 file), runtime Java e JavaFX WebView inclusi. Il JAR incluso è stato ispezionato: contiene `.ring>svg` e non il vecchio selettore discendente. La prova `ModScanOpen.exe help` — **PASS**. Non è un rilascio v1.3.3; metadati ancora 1.3.2.
- JAR di prova Fabric metadata-only creato in `output/ModScanOpen-mods-patch/ModScanTestMod.jar`, 343 byte, SHA-256 `e212a9befbb69afd574aa890e79ad8aa6961dde4675382c9f9682c55e81889a6`; soltanto `fabric.mod.json`, nessuna classe/codice.
- `command -v gh` — `gh` **NOT INSTALLED**. Il tag remoto `v1.3.3` non esiste.

## Esito prova app a–e

| Controllo | Esito | Evidenza / limite |
|---|---|---|
| a) Una card Mods, pulsanti e Interrompi | **OK** | La vista GUI mostrava una sola card contenente Cambia cartella e Ricontrolla; Interrompi era nascosto quando non era in corso il controllo approfondito. |
| b) Minecraft aperto e sequenza automatica | **OK** | Rilevato il profilo di Minecraft in esecuzione con 30 JAR; scansione completata e riga di stato finale visibile (`29 ufficiali, 0 non riconosciute, 1 da controllare`, più stato runtime). Il risultato runtime è apparso nella lista. L’avanzamento è stato osservato durante il controllo; non ho registrato ogni fase intermedia separatamente. |
| c) Minecraft chiuso, ultima cartella o fallback `%APPDATA%\.minecraft\mods` | **NON ESEGUITO** | Minecraft era già in esecuzione e la cartella predefinita `.minecraft\mods` non era presente. Non ho chiuso un processo di gioco dell’utente per simulare questo scenario. |
| d) Journal senza admin e test elevato add/rinomina/elimina | **NON OK / PARZIALE** | L’avviso per journal non leggibile senza privilegi era visibile e la GUI ha continuato senza interrompersi. L’elevazione è stata approvata e il test controllato è partito; `journal.available=true`, ma dopo la creazione del JAR casuale la lettura ha restituito zero eventi. Test interrotto prima di rinomina/eliminazione; il `finally` ha rimosso il file temporaneo. Quindi non sono confermati add/rinomina/elimina. |
| e) Console WebView senza errori JS e scheda File JAR invariata | **NON ESEGUITO** | Il codice della modalità File JAR non è tra gli otto file modificati e la vista è stata avviata; i log Java non hanno segnalato errori WebView/JS durante la prova. Non è stato possibile leggere direttamente la console JS della WebView né verificare ogni interazione della scheda File JAR, quindi il controllo combinato non viene dichiarato superato. |

## File toccati

**File sorgente modificati, tutti appartenenti allo ZIP (CRLF conservati):**

- `modscan-open/src/main/java/modscan/OpenMods.java`
- `modscan-open/src/main/resources/ui/index.html`
- `modscan-open/src/main/resources/ui/css/style.css`
- `modscan-open/src/main/resources/ui/js/mods.js`
- `modscan-open/src/main/resources/ui/js/journal.js`
- `modscan-open/src/main/resources/ui/js/runtime.js`
- `modscan-open/src/main/resources/ui/js/mem.js`
- `modscan-open/src/main/resources/ui/js/core.js`

**Report aggiunto su richiesta:** `docs/REPORT-v1.3.3.md`.

**Correzione UI successiva:** `modscan-open/src/main/resources/ui/css/style.css` ruota solo l’anello, non il triangolo interno.

Nessun file di versione, README o release notes v1.3.3 è stato modificato/creato: tali cambi erano subordinati al superamento del passo 3. I file locali non tracciati già presenti sono rimasti intatti.

## Artefatti locali e SHA-256

Build corrente (patch sorgente applicata, identificatori di versione ancora 1.3.2 perché il passo release è bloccato):

| Artefatto | Dimensione | SHA-256 |
|---|---:|---|
| `modscan-open/target/ModScanOpen.jar` (build aggiornata dopo la correzione CSS) | 165.813 byte | `e0805ccc135be3c70c6a2b0d641cf97d84cca0c49935d0dbb9a29859af8d1150` |
| `memagent/target/MemAgent.jar` | 9.909 byte | `3703aee25ea6cd024b117bb731b02cc3585e882903bb2578faefc0a7950fabcf` |

Non sono stati generati asset di release v1.3.3 né aggiornati gli artefatti già presenti in `dist/`. È stata invece creata una app-image locale di prova (non un asset di release) in `output/ModScanOpen-mods-patch-vertical-triangle/ModScanOpen/`: 95.018.364 byte totali; EXE 453.632 byte, SHA-256 `844b7b899d55d83682b5c746df48e37a8ee40d12ffc737299c10135f81ecc0ac`. È stato creato anche il JAR metadata-only di prova descritto sopra.

## Commit, tag e release

- HEAD base del branch: `14348462d9bfe54c9a08d05f635a654434e9e1dc`.
- La patch sorgente non era committata né pushata alla stesura iniziale del report; un commit/push del branch è stato richiesto separatamente in seguito e non equivale al rilascio v1.3.3.
- Branch: `feat/mods-sezione-unica`.
- Tag `v1.3.3`: **non creato**.
- URL prevista, ma release **non esistente/non pubblicata**: <https://github.com/gaemo12/ModAnalyzer/releases/tag/v1.3.3>.
- `gh` non è disponibile; non è stato tentato alcun upload GitHub.

## Problemi e rischi residui

1. Prima della release occorre ripetere/diagnosticare il test USN elevato: il journal era accessibile, ma la lettura dopo la creazione del probe ha prodotto zero eventi; rinomina ed eliminazione non sono state provate. Il file di prova è stato rimosso.
2. Occorre testare il fallback con Minecraft chiuso senza terminare il processo di gioco già aperto dall’utente, e ispezionare direttamente la console JavaScript/WebView e la modalità File JAR.
3. Dopo che tutti i controlli a–e sono OK, resta da aggiornare a 1.3.3 versioni Maven/README/UI/JSON/help e script packaging, aggiungere le note release, ricostruire e verificare gli asset Windows, e poi eseguire commit/push/merge/tag/release secondo le regole del repository.
4. Per pubblicare occorre disporre di `gh` autenticato o di un flusso GitHub equivalente autorizzato.
