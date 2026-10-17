package com.jaranalyzer.scanners.engine;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Timeline delle mod rispetto all'avvio del gioco (reimplementazione clean-room del
 * controllo "Modified after Minecraft Launch" visto in RedLotus Mod Analyzer 2.0):
 * confronta la data di creazione e di ultima modifica dei file della cartella mods
 * con l'istante di avvio del processo javaw di Minecraft.
 *
 * <p>Solo attributi del filesystem: funziona sempre, anche senza privilegi elevati.
 * Il journal USN (che serve per i file eliminati/rinominati durante il runtime) sta
 * in {@link UsnJournal} e resta best-effort.</p>
 */
public final class ModsTimeline {

    /** File comparso sul disco dopo l'avvio del gioco. */
    public static final String ADDED = "added";
    /** File modificato dopo l'avvio del gioco. */
    public static final String MODIFIED = "modified";
    /** Nessuna modifica rispetto all'avvio. */
    public static final String OK = "ok";

    /** Un file della cartella mods con i suoi orari rispetto all'avvio del gioco. */
    public record Entry(String fileName, String path, long createdMillis, long modifiedMillis,
            long size, String state) {
        public boolean jar() {
            return fileName.toLowerCase(Locale.ROOT).endsWith(".jar");
        }
    }

    /** Esito del controllo: tutti i file (ordinati) e i conteggi. */
    public record Result(String modsDir, long sinceMillis, List<Entry> entries, int files,
            int added, int modified) {
        /** Solo i file sospetti: aggiunti o modificati dopo l'avvio, più recenti prima. */
        public List<Entry> suspects() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (!OK.equals(e.state())) {
                    out.add(e);
                }
            }
            out.sort(Comparator.comparingLong((Entry e) -> Math.max(e.createdMillis(), e.modifiedMillis())).reversed());
            return out;
        }
    }

    private ModsTimeline() {
    }

    /**
     * Stato di un file rispetto all'avvio: creato dopo = {@link #ADDED},
     * altrimenti modificato dopo = {@link #MODIFIED}, altrimenti {@link #OK}.
     */
    public static String state(long createdMillis, long modifiedMillis, long sinceMillis) {
        if (createdMillis > sinceMillis) {
            return ADDED;
        }
        if (modifiedMillis > sinceMillis) {
            return MODIFIED;
        }
        return OK;
    }

    /**
     * Controlla i file al primo livello della cartella mods. I file nascosti
     * (es. marker di launcher) vengono ignorati; su errori di lettura del singolo
     * file si continua, mai eccezioni per voce.
     */
    public static Result check(Path modsDir, long sinceMillis) throws IOException {
        List<Entry> entries = new ArrayList<>();
        int added = 0;
        int modified = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(modsDir)) {
            for (Path p : stream) {
                String name = p.getFileName() == null ? p.toString() : p.getFileName().toString();
                if (name.startsWith(".")) {
                    continue;
                }
                BasicFileAttributes attrs;
                try {
                    attrs = Files.readAttributes(p, BasicFileAttributes.class);
                } catch (Exception e) {
                    continue; // file sparito durante la lettura: si salta
                }
                if (!attrs.isRegularFile()) {
                    continue;
                }
                long created = attrs.creationTime().toMillis();
                long modMillis = attrs.lastModifiedTime().toMillis();
                String state = state(created, modMillis, sinceMillis);
                if (ADDED.equals(state)) {
                    added++;
                } else if (MODIFIED.equals(state)) {
                    modified++;
                }
                entries.add(new Entry(name, p.toAbsolutePath().toString().replace("\\", "/"),
                        created, modMillis, attrs.size(), state));
            }
        }
        entries.sort(Comparator.comparing(Entry::fileName, String.CASE_INSENSITIVE_ORDER));
        return new Result(modsDir.toAbsolutePath().toString().replace("\\", "/"), sinceMillis,
                List.copyOf(entries), entries.size(), added, modified);
    }
}
