package com.jaranalyzer.common;

/**
 * Stato di una sessione remota. {@code EXPIRED} è derivato in lettura
 * (scaduta e non {@code done}); il server non lo memorizza.
 */
public enum SessionStatus {
    WAITING,
    CLAIMED,
    DONE,
    EXPIRED,
    /** Valore futuro/sconosciuto: tollerato per compatibilità, mai emesso. */
    UNKNOWN;

    /** Stringhe esatte del backend; valori ignoti -&gt; UNKNOWN (forward compat). */
    public static SessionStatus fromString(String s) {
        if ("waiting".equals(s)) {
            return WAITING;
        }
        if ("claimed".equals(s)) {
            return CLAIMED;
        }
        if ("done".equals(s)) {
            return DONE;
        }
        if ("expired".equals(s)) {
            return EXPIRED;
        }
        return UNKNOWN;
    }

    public String wire() {
        switch (this) {
            case WAITING: return "waiting";
            case CLAIMED: return "claimed";
            case DONE: return "done";
            case EXPIRED: return "expired";
            default: throw new IllegalStateException("stato non serializzabile: " + this);
        }
    }
}
