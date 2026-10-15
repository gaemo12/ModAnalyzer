package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Lettura di singole entry con limite PRIMA dell'allocazione.
 *
 * <p>Motivo: quasi tutti gli analyzer leggevano {@code is.readAllBytes()} per entry,
 * con controllo assente o postumo: una entry degenere (dichiarata piccola o {@code -1},
 * reale enorme) mandava in OOM il worker, aggravato dai ~16 analyzer in parallelo.
 * Qui il limite è applicato sui byte <i>effettivamente letti</i> (non sul dichiarato).
 *
 * <p>Le entry saltate NON sono silenziose: il chiamante registra i nomi in
 * {@link SkipLog} ed emette un finding riepilogativo INFO (non sposta il risk score).
 */
public final class EntryBytes {
    /**
     * Cap di default dove l'analyzer non ne ha uno proprio: ~10x le classi grandi
     * legittime (1-2 MB); con ~16 worker paralleli il picco resta sotto ~512 MB
     * transitori anche nel caso peggiore (ogni worker su un'entry diversa al cap).
     */
    public static final long DEFAULT_MAX_ENTRY_BYTES = 16L * 1024 * 1024;
    /** Nomi conservati nel riepilogo (il conteggio è sempre esatto). */
    public static final int MAX_SKIPPED_NAMES = 20;

    private EntryBytes() {
    }

    /** Registro delle entry saltate per limite, con riepilogo esplicito. */
    public static final class SkipLog {
        private int skipped;
        private final List<String> sample = new ArrayList<>();
        /** Entry oversize di cui è stato analizzato il campione iniziale (Fase 2). */
        private int sampled;
        private final List<String> sampledNames = new ArrayList<>();

        public void skip(String entryName) {
            skipped++;
            if (sample.size() < MAX_SKIPPED_NAMES) {
                sample.add(entryName);
            }
        }

        /** Registra un'entry oversize coperta da analisi parziale del campione. */
        public void sampled(String entryName) {
            sampled++;
            if (sampledNames.size() < MAX_SKIPPED_NAMES) {
                sampledNames.add(entryName);
            }
        }

        public boolean isEmpty() {
            return skipped == 0;
        }

        public int count() {
            return skipped;
        }

        public boolean hasSampled() {
            return sampled > 0;
        }

        /** Finding LOW: esito parziale ma non cieco sulle voci campionate. */
        public Finding toSampledFinding(String location, long sampleBytes) {
            return toSampledFinding(location, sampleBytes, null);
        }

        /** Variante con nome analyzer, per distinguere le coperture parziali. */
        public Finding toSampledFinding(String location, long sampleBytes, String analyzer) {
            StringBuilder ev = new StringBuilder();
            if (analyzer != null) {
                ev.append("Analyzer: ").append(analyzer).append("\n");
            }
            ev.append("Voci oltre il limite analizzate solo sul campione iniziale di ")
              .append(sampleBytes / 1024).append(" KB: ").append(sampled).append("\n");
            for (String n : sampledNames) {
                ev.append("- ").append(n).append("\n");
            }
            if (sampled > sampledNames.size()) {
                ev.append("(+ altre ").append(sampled - sampledNames.size()).append(")");
            }
            return new Finding.Builder().title("Voci oversize campionate (" + sampled + ")")
                    .ruleName("oversize-sampled")
                    .description("Alcune voci superano il limite per singola entry: ne è stato "
                            + "analizzato solo il campione iniziale. Un payload nascosto in coda "
                            + "a queste voci non sarebbe rilevato.")
                    .severity(Severity.LOW).category(Category.STRUCTURE).location(location)
                    .evidence(ev.toString()).family("EntrySampledOversize").build();
        }

        /** Finding riepilogativo INFO (non sposta il risk score, ma è visibile). */
        public Finding toFinding(String location, long capBytes) {
            StringBuilder ev = new StringBuilder();
            ev.append("Voci non analizzate perché oltre il limite di ")
              .append(capBytes / (1024 * 1024)).append(" MB per entry: ").append(skipped).append("\n");
            for (String n : sample) {
                ev.append("- ").append(n).append("\n");
            }
            if (skipped > sample.size()) {
                ev.append("(+ altre ").append(skipped - sample.size()).append(")");
            }
            return new Finding.Builder().title("Voci saltate per limite dimensione (" + skipped + ")")
                    .description("Alcune voci dell'archivio superano il limite di lettura per singola entry "
                            + "e non sono state analizzate: l'esito è parziale per queste voci.")
                    .severity(Severity.INFO).category(Category.STRUCTURE).location(location)
                    .evidence(ev.toString()).family("EntrySkippedOversize").build();
        }
    }

    /**
     * Legge un'entry fino a {@code capBytes} effettivi.
     *
     * @return contenuto, oppure {@code null} se oltre il cap (nome registrato in {@code skips})
     * @throws IOException solo per veri errori I/O (il chiamante li gestisce come prima)
     */
    public static byte[] read(JarFile jar, JarEntry entry, long capBytes, SkipLog skips) throws IOException {        long declared = entry.getSize();
        if (declared > capBytes) {
            skips.skip(entry.getName());
            return null;
        }
        try (InputStream in = jar.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    (int) Math.min(Math.max(declared, 0), 1 << 20));
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > capBytes) {
                    skips.skip(entry.getName());
                    return null;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    /**
     * Legge al massimo {@code headBytes} iniziali di un'entry, SENZA registrarla
     * come saltata (Fase 2: campionamento oversize). La registrazione spetta al
     * chiamante via {@link SkipLog#sampled(String)} dopo averlo analizzato.
     *
     * @return prefisso (mai null se la lettura riesce; vuoto se entry vuota)
     */
    public static byte[] readHead(JarFile jar, JarEntry entry, long headBytes) throws IOException {
        try (InputStream in = jar.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(headBytes, 1 << 20));
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while (total < headBytes && (n = in.read(buf, 0, (int) Math.min(buf.length, headBytes - total))) != -1) {
                out.write(buf, 0, n);
                total += n;
            }
            return out.toByteArray();
        }
    }

    /**
     * Legge uno stream sequenziale (es. entry di {@code JarInputStream} annidato)
     * fino a {@code capBytes} effettivi.
     *
     * @return contenuto, oppure {@code null} se oltre il cap
     */
    public static byte[] readCappedStream(InputStream in, long capBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 << 16);
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > capBytes) {
                return null;
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
