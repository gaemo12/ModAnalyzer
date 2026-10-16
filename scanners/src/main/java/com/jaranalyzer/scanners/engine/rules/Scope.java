package com.jaranalyzer.scanners.engine.rules;

/**
 * Ambito di ricerca di una regola (report revisione, sez. 1).
 *
 * <p>Le regex da sole producono falsi positivi quando girano su tutto il jar
 * (es. {@code raw.githubusercontent.com} nei README): ogni regola dichiara
 * dove può scattare. I metadati (README, licenze, {@code mods.toml},
 * {@code fabric.mod.json}) non hanno regole in v1 e quindi non generano
 * finding.
 */
public enum Scope {
    /** Stringhe {@code LDC} usate dal codice (ambito principale). */
    CLASS_CONST,
    /** Tutte le costanti Utf8 del pool (annotazioni, bootstrap indy, campi). */
    CLASS_POOL,
    /** Risorse di testo eseguibili o di configurazione (.bat, .json, ...). */
    RESOURCE_TEXT,
    /** Metadati (README, licenze, manifesti mod): nessuna regola v1. */
    METADATA
}
