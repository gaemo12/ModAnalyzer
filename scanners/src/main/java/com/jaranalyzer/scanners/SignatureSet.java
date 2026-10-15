package com.jaranalyzer.scanners;

import java.util.List;
import java.util.Map;

/**
 * Firme in sola lettura, già validate crittograficamente dal chiamante
 * (il Player verifica il blob JS1; lo Staff usa i builtin o il JS1).
 * Lo scanner non scarica firme, non tocca URL, non modifica il set.
 * Un set vuoto è valido: i moduli girano comunque (zero match, esito pulito).
 */
public interface SignatureSet {
    /** Record di una firma a stringa: inclusione di {@code pattern} nel testo. */
    record SigPattern(String pattern, String severity, String family, String description) {
        public SigPattern {
            if (pattern == null || pattern.isEmpty()) {
                throw new IllegalArgumentException("pattern assente");
            }
            if (severity == null || severity.isBlank()) {
                throw new IllegalArgumentException("severity assente");
            }
            family = family == null ? "" : family;
            description = description == null ? "" : description;
        }
    }

    /** Record di una API sospetta (owner/method in formato interno ASM: a/b/C). */
    record SuspApi(String owner, String method, String severity, String description) {
        public SuspApi {
            if (owner == null || owner.isBlank() || method == null || method.isBlank()) {
                throw new IllegalArgumentException("owner/method assenti");
            }
            if (severity == null || severity.isBlank()) {
                throw new IllegalArgumentException("severity assente");
            }
            description = description == null ? "" : description;
        }
    }

    /** Firme a stringa da cercare nei contenuti (sottoinsiemi inclusi). */
    List<SigPattern> stringSignatures();

    /** API sospette per il matching sul bytecode. */
    List<SuspApi> suspiciousApis();

    /** Sottostringhe di percorsi sospetti (es. directory di wallet/browser). */
    List<String> suspiciousPaths();

    /** Gruppi di firme cheat: nome cheat -&gt; pattern (match per soglia, vedi modulo). */
    Map<String, List<String>> cheatGroups();

    /** Sottostringhe per la scansione rapida della cartella mods. */
    List<String> quickFlags();

    /** Hash SHA-256 noti malevoli -&gt; etichetta (vuota ammessa). Chiavi minuscole. */
    Map<String, String> maliciousHashes();

    /** Hash SHA-256 noti puliti -&gt; etichetta. Chiavi minuscole. */
    Map<String, String> knownGoodHashes();

    /** Versione del set (formato JS1 interno); "builtin-*" per i dati inclusi. */
    String version();

    /** Cerca tutte le firme a stringa contenute nel testo (mai null). */
    default List<SigPattern> matchStrings(String content) {
        if (content == null || content.isEmpty()) {
            return List.of();
        }
        return stringSignatures().stream().filter(s -> content.contains(s.pattern())).toList();
    }

    /**
     * Come {@link #matchStrings(String)} ma case-insensitive (Fase 1
     * anti-evasione): confronta su vista lowercase sia del contenuto che dei
     * pattern. Restituisce gli stessi record (pattern originali) per evidenze
     * stabili; il chiamante unisce i due set senza duplicati.
     */
    default List<SigPattern> matchStringsNormalized(String content) {
        if (content == null || content.isEmpty()) {
            return List.of();
        }
        String lower = content.toLowerCase(java.util.Locale.ROOT);
        return stringSignatures().stream()
                .filter(s -> lower.contains(s.pattern().toLowerCase(java.util.Locale.ROOT)))
                .toList();
    }

    /** Ritorna la API sospetta per owner/method, o null. */
    default SuspApi suspiciousApi(String owner, String method) {
        if (owner == null || method == null) {
            return null;
        }
        for (SuspApi api : suspiciousApis()) {
            if (api.owner().equals(owner) && api.method().equals(method)) {
                return api;
            }
        }
        return null;
    }
}
