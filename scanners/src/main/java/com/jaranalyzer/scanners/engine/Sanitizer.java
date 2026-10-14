package com.jaranalyzer.scanners.engine;

import java.nio.file.Path;

/**
 * Minimizzazione dati: nei risultati viaggiano solo nomi file, mai percorsi
 * assoluti (che su Windows contengono il nome utente), mai directory home.
 */
public final class Sanitizer {
    private Sanitizer() {
    }

    /** Solo il nome file, senza directory ("" se non determinabile). */
    public static String fileName(Path path) {
        if (path == null) {
            return "";
        }
        Path name = path.getFileName();
        return name == null ? "" : name.toString();
    }

    /**
     * Oscura la home dell'utente in un testo libero (righe di comando, evidence):
     * {@code C:\Users\bob\...} -&gt; {@code ~\...}. Non garantisce completezza su
     * percorsi già relativizzati: i moduli non devono emetterli proprio.
     */
    public static String redactHome(String text, String home) {
        if (text == null || home == null || home.isBlank()) {
            return text;
        }
        String h = home.replace('\\', '/');
        while (h.endsWith("/")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.isEmpty()) {
            return text;
        }
        String normalized = text.replace('\\', '/');
        String redacted = normalized.replace(h, "~").replace(h.toLowerCase(java.util.Locale.ROOT), "~");
        return redacted;
    }

    /** Vero se il testo sembra contenere un percorso assoluto o una home utente. */
    public static boolean looksLikeAbsolutePath(String text) {
        if (text == null) {
            return false;
        }
        return text.matches("(?s).*([A-Za-z]:(?!//)[\\\\/]|\\\\Users\\\\|/Users/|/home/).*");
    }

    /**
     * Rimuove da un messaggio di errore ogni riferimento al file analizzato
     * (le eccezioni I/O includono spesso il percorso assoluto): lo sostituisce
     * col solo nome file. Mai path host nei risultati.
     */
    public static String scrub(String text, Path path) {
        if (text == null) {
            return "";
        }
        if (path == null) {
            return text;
        }
        String name = fileName(path);
        String abs = path.toAbsolutePath().toString();
        String out = text;
        if (!abs.isEmpty() && !abs.equals(name)) {
            out = out.replace(abs, name);
        }
        String given = path.toString();
        if (!given.isEmpty() && !given.equals(name) && !given.equals(abs)) {
            out = out.replace(given, name);
        }
        return out;
    }
}
