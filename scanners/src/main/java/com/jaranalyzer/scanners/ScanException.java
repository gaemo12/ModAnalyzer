package com.jaranalyzer.scanners;

/**
 * Errore di scansione tipizzato. Gli errori sui singoli elementi (un JAR
 * illeggibile, un processo inaccessibile) NON lanciano eccezioni: vengono
 * registrati in contatori/finding e la scansione continua. L'eccezione serve
 * solo per abortire l'intero modulo:
 * <ul>
 *   <li>{@link Kind#FATAL} — il modulo non può produrre un esito (input non valido,
 *       limiti superati, I/O sull'input principale): il chiamante emette un
 *       ModuleResult fallito.</li>
 *   <li>{@link Kind#CANCELLED} — annullato via {@link ProgressSink#isCancelled()}:
 *       il chiamante interrompe senza inviare risultati parziali come completi.</li>
 * </ul>
 */
public final class ScanException extends Exception {
    public enum Kind {
        FATAL,
        CANCELLED
    }

    private final Kind kind;
    private final String module;

    public ScanException(Kind kind, String module, String message) {
        super(message);
        this.kind = kind;
        this.module = module;
    }

    public ScanException(Kind kind, String module, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.module = module;
    }

    public static ScanException fatal(String module, String message) {
        return new ScanException(Kind.FATAL, module, message);
    }

    public static ScanException fatal(String module, String message, Throwable cause) {
        return new ScanException(Kind.FATAL, module, message, cause);
    }

    public static ScanException cancelled(String module) {
        return new ScanException(Kind.CANCELLED, module, "scansione annullata");
    }

    public Kind kind() {
        return kind;
    }

    public String module() {
        return module;
    }
}
