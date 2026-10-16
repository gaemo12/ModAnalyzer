package com.jaranalyzer.scanners.engine.rules;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Severity;
import java.util.EnumSet;
import java.util.regex.Pattern;

/**
 * Singola regola IOC come dato (report revisione, sez. 1): id stabile (usato
 * come {@code ruleName} dei finding e come chiave di deduplica del punteggio),
 * ambiti consentiti, regex, severità, categoria, classe di evidenza e
 * descrizione. Il campo {@code special} attiva una post-verifica in codice
 * (es. {@code executable-blob}: il match regex è solo un candidato, il finding
 * scatta solo se il blob decodifica in un eseguibile).
 */
public record Rule(String id, String title, EnumSet<Scope> scopes, Pattern pattern,
        Severity severity, Category category, String cap, String description,
        boolean redact, String special) {

    public Rule {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("rule id assente");
        }
        if (pattern == null) {
            throw new IllegalArgumentException("pattern assente per " + id);
        }
        if (scopes == null || scopes.isEmpty()) {
            throw new IllegalArgumentException("scopes assenti per " + id);
        }
        if (severity == null || category == null) {
            throw new IllegalArgumentException("severity/category assenti per " + id);
        }
    }

    /** Vera solo per le regole che richiedono verifica oltre la regex. */
    public boolean needsVerification() {
        return special != null && !special.isBlank();
    }
}
