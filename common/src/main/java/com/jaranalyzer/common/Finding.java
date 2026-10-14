package com.jaranalyzer.common;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Singolo rilevamento di uno scanner. Severità e categoria restano stringhe
 * di protocollo (es. {@code HIGH}, {@code NETWORK}): non si impone un enum,
 * per tollerare valori futuri senza rompere i client.
 */
public final class Finding {
    private final String rule;
    private final String title;
    private final String severity;
    private final String category;
    private final String location;
    private final String evidence;

    public Finding(String rule, String title, String severity, String category,
            String location, String evidence) {
        if (rule == null || rule.isBlank()) {
            throw new IllegalArgumentException("rule assente");
        }
        if (title == null || title.isBlank()) {
            throw new IllegalArgumentException("title assente");
        }
        if (severity == null || severity.isBlank()) {
            throw new IllegalArgumentException("severity assente");
        }
        if (category == null || category.isBlank()) {
            throw new IllegalArgumentException("category assente");
        }
        this.rule = rule;
        this.title = title;
        this.severity = severity;
        this.category = category;
        this.location = location;
        this.evidence = evidence;
    }

    public static Finding fromMap(Map<String, Object> m) {
        return new Finding(
                JsonCodec.requiredString(m, "rule"),
                JsonCodec.requiredString(m, "title"),
                JsonCodec.requiredString(m, "severity"),
                JsonCodec.requiredString(m, "category"),
                JsonCodec.optionalString(m, "location"),
                JsonCodec.optionalString(m, "evidence"));
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rule", rule);
        m.put("title", title);
        m.put("severity", severity);
        m.put("category", category);
        if (location != null) {
            m.put("location", location);
        }
        if (evidence != null) {
            m.put("evidence", evidence);
        }
        return m;
    }

    public String rule() {
        return rule;
    }

    public String title() {
        return title;
    }

    public String severity() {
        return severity;
    }

    public String category() {
        return category;
    }

    public String location() {
        return location;
    }

    public String evidence() {
        return evidence;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Finding)) {
            return false;
        }
        Finding f = (Finding) o;
        return rule.equals(f.rule) && title.equals(f.title) && severity.equals(f.severity)
                && category.equals(f.category) && Objects.equals(location, f.location)
                && Objects.equals(evidence, f.evidence);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rule, title, severity, category, location, evidence);
    }

    @Override
    public String toString() {
        return "Finding{rule='" + rule + "', severity='" + severity + "', category='" + category + "'}";
    }
}
