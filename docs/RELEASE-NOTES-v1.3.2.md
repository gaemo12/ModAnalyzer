# ModScanOpen v1.3.2

Release di consolidamento dello screening SS. Integra il lavoro richiesto per
la v1.3.0 (già occupata da una release precedente) senza riscrivere tag o
release esistenti.

## Novità

- **Controllo strutturale della cartella mods**: id duplicati, `.jar` camuffati
  (firma non-ZIP), mod disabilitate con indicatori noti, nome file in contrasto
  con i metadati. Gli esiti sono indizi da verificare, non prove.
- **Tracce dai crash log**: analisi di `hs_err_pid*.log` e `crash-reports/` con
  restituzione dei soli **nomi dei flag JVM** sospetti (`-javaagent`,
  `-Xbootclasspath`, class loader sostituito, tweaker non standard, anti-attach,
  JDWP). Nessun percorso, username o valore viene esposto.
- **Runtime**: i file aperti dal loader ma assenti dalla cartella mods vengono
  contati e mostrati; i flag dei crash report entrano nei sospetti.
- **UI**: nuova riga di audit nella card della cartella; file fantasma e tracce
  crash nella card runtime; suggerimenti più precisi.

## Correzioni

- Parser USN: `File name length` non sovrascrive più `File name`.
- Risoluzione della cartella di gioco: se scegli la game dir viene usata
  `<gioco>/mods`; da `mods/<profilo>` si risale all'istanza.
- Journal e runtime usano la stessa risoluzione della cartella.
- Fallback CSS per browser senza `color-mix`.

## Download

- **`ModScanOpen.zip`** — portable consigliato: scompatta e avvia
  `ModScanOpen.exe` (runtime Java incluso).
- **`ModScanOpen.exe`** — installer per-utente (jpackage/WiX). Non portable e
  **non firmato Authenticode**: SmartScreen può mostrare un avviso. Usa lo zip
  se preferisci non installare.
- **`ModScanOpen.jar`** — richiede Java 17+.
- **`SHA256SUMS.txt`** — verifica i download.

## Verifiche

Build `mvn clean verify`, 9 suite di self-test, corpus **17/17**, CLI, zip
portable, installer e GUI verificati. La lettura USN con privilegi di
amministratore non è stata eseguita (shell non elevata); il degrado senza admin
è verificato. Dettagli e limiti nel report:
<https://github.com/gaemo12/ModAnalyzer/blob/main/docs/REPORT-v1.3.0.md>

## Hash SHA-256

```
8e9b9c877535322a3a7646daea67b4b012f54de8fdef06a5dad024956109907d  ModScanOpen.zip
6d29e1bfc070f89be0610c35dcd44973ab563616b68eb32eaa8abadcffdb6f9f  ModScanOpen.jar
bedb95679505a2f1b76e331aa0d4c23a298d3bd647423762023a3e49ce811a11  ModScanOpen.exe
```
