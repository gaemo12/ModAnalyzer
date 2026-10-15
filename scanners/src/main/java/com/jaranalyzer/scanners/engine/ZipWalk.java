package com.jaranalyzer.scanners.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Lettura sicura di archivi ZIP/JAR: limiti su entry, dimensioni e totale
 * decompresso (zip-bomb), skip oltre soglia invece di OOM, path traversal
 * neutro (qui non si estrae nulla: i nomi servono solo per matching/report).
 */
public final class ZipWalk {
    /** Limiti documentati (vedere docs/SCANNERS.md). */
    public static final int MAX_ENTRIES = 100_000;
    public static final long MAX_ENTRY_BYTES = 100L * 1024 * 1024;
    public static final long MAX_TOTAL_BYTES = 2L * 1024 * 1024 * 1024;
    /** Letture di metadati/testo troncate a questa soglia (come il codice originale). */
    public static final int METADATA_CAP = 512_000;

    private ZipWalk() {
    }

    /** Voce letta in memoria entro i limiti (contenuto nullo se skippata per dimensione). */
    public record Entry(String name, long size, byte[] content, boolean skipped) {
    }

    public interface Visitor {
        void visit(Entry e) throws IOException;
    }

    /**
     * Itera le entry non-directory applicando i limiti. Lancia IOException con
     * messaggio tipizzato se l'archivio supera i limiti strutturali.
     */
    public static void walk(ZipFile zip, Visitor visitor) throws IOException {
        walk(zip, visitor, e -> true);
    }

    public static void walk(ZipFile zip, Visitor visitor, Predicate<ZipEntry> filter) throws IOException {
        // Passata singola (Fase 6): niente snapshot nomi + getEntry (TOCTOU), il
        // conteggio scatta solo sulle entry visitate. Directory sempre ignorate.
        Enumeration<? extends ZipEntry> entries = zip.entries();
        long count = 0;
        long total = 0;
        while (entries.hasMoreElements()) {
            ZipEntry e = entries.nextElement();
            if (e.isDirectory()) {
                continue;
            }
            if (!filter.test(e)) {
                continue;
            }
            if (++count > MAX_ENTRIES) {
                throw new IOException("limite entry superato (" + MAX_ENTRIES + "): archivio anomalo");
            }
            long size = e.getSize();
            if (size < 0 || size > MAX_ENTRY_BYTES) {
                visitor.visit(new Entry(e.getName(), size, null, true));
                continue;
            }
            if (total + size > MAX_TOTAL_BYTES) {
                throw new IOException("limite totale decompresso superato: archivio anomalo");
            }
            byte[] content;
            try (InputStream in = zip.getInputStream(e)) {
                content = readCapped(in, size);
            }
            total += content.length;
            visitor.visit(new Entry(e.getName(), size, content, false));
        }
    }

    /** Legge al massimo l'intera entry dichiarata (le dimensioni reali non possono superarla di molto). */
    public static byte[] readCapped(InputStream in, long declared) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(declared < 0 ? 8192 : declared, 1 << 20));
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        // Tolleranza per directory/metadati con size dichiarata imprecisa (+1MB oltre il dichiarato).
        long cap = (declared < 0 ? 0 : declared) + (1 << 20);
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > cap || total > MAX_ENTRY_BYTES) {
                throw new IOException("entry oltre i limiti: possibile zip-bomb");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** Lettura troncata per metadati/testo (stessa soglia del codice originale). */
    public static byte[] readMetadata(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int total = 0;
            int n;
            while (total < METADATA_CAP && (n = in.read(buf, 0, Math.min(buf.length, METADATA_CAP - total))) != -1) {
                out.write(buf, 0, n);
                total += n;
            }
            return out.toByteArray();
        }
    }
}
