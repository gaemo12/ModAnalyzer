package com.jaranalyzer.scanners;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Converte i finding ricchi del motore (descrizione, famiglia, raccomandazione:
 * utili allo Staff in locale) in finding di protocollo (solo i campi del
 * contratto /api/v2). Mapping senza perdita sui campi wire; deterministico
 * (ordinamento per rule+location) per esiti confrontabili.
 */
public final class FindingMapper {
    private FindingMapper() {
    }

    /**
     * Gli analyzer storici non impostano sempre ruleName (solo title): il wire
     * richiede rule/title non vuoti, quindi si applicano fallback deterministici
     * ({@code "unspecified"}). Mai null, mai eccezioni qui: gli errori di
     * mappatura non devono abortire un modulo.
     */
    public static com.jaranalyzer.common.Finding toProtocol(Finding f) {
        String rule = f.getRuleName();
        if (rule == null || rule.isBlank()) {
            rule = "unspecified";
        }
        String title = f.getTitle();
        if (title == null || title.isBlank()) {
            title = rule;
        }
        return new com.jaranalyzer.common.Finding(
                rule,
                title,
                f.getSeverity() != null ? f.getSeverity().name() : Severity.INFO.name(),
                f.getCategory() != null ? f.getCategory().name() : Category.STRUCTURE.name(),
                f.getLocation(),
                f.getEvidence());
    }

    public static List<com.jaranalyzer.common.Finding> toProtocol(List<Finding> findings) {
        List<com.jaranalyzer.common.Finding> out = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            if (f != null) {
                out.add(toProtocol(f));
            }
        }
        out.sort(Comparator.comparing(com.jaranalyzer.common.Finding::rule)
                .thenComparing(f -> f.location() == null ? "" : f.location())
                .thenComparing(com.jaranalyzer.common.Finding::title)
                .thenComparing(f -> f.evidence() == null ? "" : f.evidence())
                .thenComparing(com.jaranalyzer.common.Finding::severity)
                .thenComparing(com.jaranalyzer.common.Finding::category));
        return List.copyOf(out);
    }
}
