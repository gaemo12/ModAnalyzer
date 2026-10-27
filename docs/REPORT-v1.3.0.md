# REPORT v1.3.0 — ModAnalyzer / ModScanOpen

**Data:** 27 ottobre 2026
**Repository:** <https://github.com/gaemo12/ModAnalyzer>
**Release consegnata:** **v1.3.2** — <https://github.com/gaemo12/ModAnalyzer/releases/tag/v1.3.2>

> Il titolo del file è quello richiesto (`docs/REPORT-v1.3.0.md`), ma la release
> pubblica è la **v1.3.2**. I tag e le release **v1.3.0** e **v1.3.1** esistevano
> già: non sono stati riscritti, spostati o cancellati. La v1.3.2 è la release
> che integra il lavoro richiesto per la v1.3.0 senza compiere azioni
> distruttive sul repository.

## 1. Esito

La v1.3.2 integra e consolida i metodi di screening della cartella mods e del
runtime, correggendo anche alcuni difetti che rendevano poco affidabili i
controlli già presenti. Build, self-test, corpus, CLI e pacchetto Windows sono
stati verificati. La release è pubblicata con i quattro allegati richiesti:

- `ModScanOpen.zip` — pacchetto portable (app-image jpackage + runtime Java);
- `ModScanOpen.jar` — jar eseguibile;
- `ModScanOpen.exe` — **installer per-utente** (jpackage/WiX), non portable;
- `SHA256SUMS.txt` — hash SHA-256 dei tre file.

La versione portable consigliata è lo **zip**. L'installer è firmato solo dal
punto di vista del pacchetto MSI, **non dispone di una firma Authenticode**:
Windows SmartScreen può mostrare un avviso. Gli hash permettono di verificare
il download.

## 2. Cosa è stato integrato

### 2.1 Controllo strutturale della cartella mods

Nuovo motore `scanners/.../engine/ModsFolderAudit.java`, usato sia dalla GUI
(`OpenMods`) sia dalla CLI (`ModsFolderModule`). Restituisce:

- **id duplicati** tra jar abilitati (confronto case-insensitive);
- **jar camuffati**: estensione `.jar` ma firma iniziale non-ZIP (MZ/PE, ELF,
  shebang, RAR, 7z, GZIP, BZIP2, file vuoto, firma sconosciuta in esadecimale);
- **mod disabilitate** (`.jar.disabled`, `.off`, `.old`, `.bak`, `.backup`):
  elencate sempre, con controllo della firma; se sono disponibili indicatori
  noti vengono aperte in sola lettura per cercare un indicatore nel nome delle
  entry o nell'id (massimo 200 file, 50.000 entry per archivio);
- **nome file vs metadati**: un file che richiama una mod diffusa (Sodium,
  Iris, Xaero, …) ma dichiara un id/nome diverso viene segnalato a bassa
  severità, perché un rename legittimo è possibile.

Il matching degli indicatori sugli id (`flagInId`) è conservativo: id esatto,
match ai bordi o prefisso/suffisso per indicatori lunghi, senza `contains` su
stringhe corte. Gli esiti sono indizi, non prove.

### 2.2 Tracce dai crash log

Nuovo `CrashLogs.java`: legge gli 8 file più recenti tra `hs_err_pid*.log` e
`crash-reports/*.txt|*.log`, al massimo 256 KB ciascuno, e cerca solo nelle
righe di intestazione JVM (`Command Line:`, `java_command:`, `JVM Flags:`).
Restituisce **esclusivamente i nomi dei flag** sospetti (`-javaagent`,
`-Xbootclasspath`, `-Djava.system.class.loader`, `--tweakClass`,
`-XX:+DisableAttachMechanism`, JDWP). Percorsi, username e valori non vengono
esposti. `-cp` e `--mixin` sono esclusi perché troppo rumorosi e restano al
controllo del processo vivo. Il parser ignora un eventuale BOM iniziale.

### 2.3 Correzioni

- **Parser USN**: `File name length` sovrascriveva `File name`, quindi gli
  eventi del journal non venivano trattenuti. Il parser ora tiene nome, motivo,
  timestamp e troncamento; è coperto da self-test.
- **Cartella di gioco**: se l'utente seleziona la game dir, la GUI, la CLI e il
  journal usano `<gioco>/mods`; da `mods/<profilo>` si risale all'istanza.
  Runtime e journal condividono la stessa risoluzione.
- **Runtime Forge**: `loadedFilesNotOnDisk` viene contato e mostrato; gli errori
  non gonfiano il conteggio degli artefatti; i sospetti includono file fantasma
  e flag dei crash log.
- **UI**: corrispondenze di `explain.js` più precise (parole intere per
  `port`, niente `lambda`, termini cheat/download aggiunti); fallback CSS per
  `color-mix`. La card della cartella mostra l'audit (`mods-audit`), la card
  runtime mostra file fantasma e tracce dai crash log.

### 2.4 Versioni e packaging

- Parent Maven e quattro moduli: **1.3.2**.
- `J.version` e badge UI: **1.3.2**.
- JSON CLI, help e README: **1.3.2**.
- `scripts/run-selftests.bat` registra i nuovi self-test.
- `scripts/package-modscan-open.bat` accetta `--app-version 1.3.2`, produce
  zip/jar e, se WiX 3 è disponibile (o `WIX_BIN` è impostato), l'installer
  `.exe` per-utente.

## 3. Privacy e sicurezza

- Tutte le letture sono locali; nessuna telemetria, nessun upload, nessuna
  esecuzione dei file analizzati.
- Le mod disabilitate sono aperte solo in lettura e solo per gli indicatori;
  i crash log sono letti solo in testa e non espongono la riga di comando.
- Le uniche connessioni previste dall'app restano quelle già esistenti verso
  Modrinth e Megabase, e solo con l'hash SHA-1 del file. In questa release non
  sono stati aggiunti endpoint, token o raccolte di dati.
- Non sono stati inseriti segreti, percorsi utente o dati personali nel codice,
  nei test o negli artefatti.

## 4. Verifiche eseguite

| Verifica | Comando | Esito |
|---|---|---|
| Build completa | `.\mvnw.cmd -q clean verify` | **PASS** (exit 0) |
| Self-test progetto | `scripts\run-selftests.bat` | **PASS** — 9 suite |
| Corpus di regressione | `verify-corpus.ps1` con `ModScanOpen.jar` | **PASS 17/17** |
| CLI help/version | `java -jar ModScanOpen.jar help` | **PASS**, riporta 1.3.2 |
| CLI scan singolo JAR | `scan --jar 01-clean-mod.jar` / `05-zipslip.jar` | **PASS**, JSON 1.3.2 |
| CLI cartella + audit | `scan --mods <game>` | **PASS**: gioco→`mods`, 1 id duplicato, 1 jar camuffato |
| CLI runtime | `runtime --mods <game>` | **PASS**: ghost dal log, crash flag `-javaagent` |
| CLI journal | `journal --mods <game>` e `--usn` non elevato | **PASS** con degrado esplicito |
| Zip portable | estrazione + `ModScanOpen.exe help` + scan | **PASS**, 1.3.2 |
| GUI da zip | avvio processo | **PASS** (processo GUI attivo) |
| Installer `.exe` | installazione silenziosa `/quiet` | **PASS** (exit 0) |
| App installata | `help` + `scan --jar` + avvio GUI | **PASS**, 1.3.2 |
| Disinstallazione | `msiexec /x {GUID} /qn` | **PASS** (exit 0) |

Self-test eseguiti: `RuleEngineSelfTest`, `ArchiveIntegritySelfTest`,
`ModsTimelineSelfTest`, `RuntimeSelfTest`, `ModsAuditSelfTest`,
`CrashLogsSelfTest`, `UsnJournalSelfTest`, `MemSkipSelfTest`,
`MemAgentSelfTest`.

### Verifiche NON ESEGUITE

| Verifica | Motivo |
|---|---|
| Lettura reale del journal USN con privilegi di amministratore | La shell di build non è elevata (`fsutil usn readjournal` → accesso negato). È stato verificato il degrado controllato senza admin; il percorso elevato resta da provare manualmente. |
| Verifica online Modrinth/Megabase | Non fa parte del gate di questa release e non è stata forzata; gli endpoint e il flusso esistente non sono stati modificati. |
| Firma Authenticode dell'installer | Non è disponibile un certificato di code signing. Gli hash SHA-256 sono pubblicati. |

## 5. Hash degli allegati

```
8e9b9c877535322a3a7646daea67b4b012f54de8fdef06a5dad024956109907d  ModScanOpen.zip
6d29e1bfc070f89be0610c35dcd44973ab563616b68eb32eaa8abadcffdb6f9f  ModScanOpen.jar
bedb95679505a2f1b76e331aa0d4c23a298d3bd647423762023a3e49ce811a11  ModScanOpen.exe
```

Dimensioni: zip 77.479.924 byte; jar 164.745 byte; installer 79.419.904 byte.

## 6. Limiti noti

- L'installer è per-utente e non portable: per l'uso senza installazione usare
  `ModScanOpen.zip`.
- L'installer non è firmato Authenticode: SmartScreen può avvisare.
- Nella CLI open il set firme è vuoto per scelta (le firme riservate non sono
  incluse): l'audit delle mod disabilitate può sempre controllare la firma del
  file, ma l'apertura per indicatori noti richiede un set di indicatori
  disponibile. La GUI open usa la propria lista di indicatori.
- L'audit strutturale è euristico: id duplicati, rename e mod disabilitate sono
  indizi da verificare, non prove di cheat.
- I crash log possono essere incompleti o appartenere a sessioni precedenti:
  le tracce sono contestuali e non sostituiscono l'analisi del processo vivo.

## 7. Riproducibilità

```
.\mvnw.cmd -q clean verify
scripts\run-selftests.bat
powershell -ExecutionPolicy Bypass -File scripts\verify-corpus.ps1 `
  -Corpus <cartella-corpus> -Jar modscan-open\target\ModScanOpen.jar
set WIX_BIN=<cartella con candle.exe>
scripts\package-modscan-open.bat
```

Il pacchetto è stato prodotto con JDK 21.0.12.101-hotspot e WiX Toolset 3.14.1
(binari portatili, usati solo in build). Il runtime Java è incluso via jlink.
