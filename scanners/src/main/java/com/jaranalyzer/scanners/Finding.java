/*
 * Decompiled with CFR 0.152.
 */
package com.jaranalyzer.scanners;


public class Finding {
    private final String ruleName;
    private final String title;
    private final String description;
    private final Severity severity;
    private final Category category;
    private final String location;
    private final String evidence;
    private final String family;
    private final String decompiledCode;
    private final String recommendation;

    private Finding(Builder builder) {
        this.ruleName = builder.ruleName;
        this.title = builder.title != null ? builder.title : builder.ruleName;
        this.description = builder.description;
        this.severity = builder.severity;
        this.category = builder.category;
        this.location = builder.location;
        this.evidence = builder.evidence;
        this.family = builder.family;
        this.decompiledCode = builder.decompiledCode;
        this.recommendation = builder.recommendation;
    }

    public Finding(String ruleName, String description, Severity severity, Category category) {
        this.ruleName = ruleName;
        this.title = ruleName;
        this.description = description;
        this.severity = severity;
        this.category = category;
        this.location = null;
        this.evidence = null;
        this.family = null;
        this.decompiledCode = null;
        this.recommendation = null;
    }

    /**
     * Convenienza per gli scanner (Fase 3): rule + titolo + posizione + evidenza,
     * senza descrizione/famiglia. Il Builder resta la via completa.
     */
    public Finding(String ruleName, String title, Severity severity, Category category,
            String location, String evidence) {
        this.ruleName = ruleName;
        this.title = title != null ? title : ruleName;
        this.description = null;
        this.severity = severity;
        this.category = category;
        this.location = location;
        this.evidence = evidence;
        this.family = null;
        this.decompiledCode = null;
        this.recommendation = null;
    }

    public Finding withLocation(String location) {
        return this.toBuilder().location(location).build();
    }

    public Finding withEvidence(String evidence) {
        return this.toBuilder().evidence(evidence).build();
    }

    public Finding withRecommendation(String recommendation) {
        return this.toBuilder().recommendation(recommendation).build();
    }

    private Builder toBuilder() {
        return new Builder().ruleName(this.ruleName).title(this.title).description(this.description).severity(this.severity).category(this.category).location(this.location).evidence(this.evidence).family(this.family).decompiledCode(this.decompiledCode).recommendation(this.recommendation);
    }

    public String getRuleName() {
        return this.ruleName;
    }

    public String getTitle() {
        return this.title;
    }

    public String getDescription() {
        return this.description;
    }

    public Severity getSeverity() {
        return this.severity;
    }

    public Category getCategory() {
        return this.category;
    }

    public String getLocation() {
        return this.location;
    }

    public String getEvidence() {
        return this.evidence;
    }

    public String getFamily() {
        return this.family;
    }

    public String getDecompiledCode() {
        return this.decompiledCode;
    }

    public String getRecommendation() {
        return this.recommendation;
    }

    public String toString() {
        return "Finding{severity=" + this.severity + ", category=" + this.category + ", title='" + this.title + "'}";
    }

    public static class Builder {
        private String ruleName;
        private String title;
        private String description;
        private Severity severity;
        private Category category;
        private String location;
        private String evidence;
        private String family;
        private String decompiledCode;
        private String recommendation;

        public Builder ruleName(String ruleName) {
            this.ruleName = ruleName;
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder category(Category category) {
            this.category = category;
            return this;
        }

        public Builder location(String location) {
            this.location = location;
            return this;
        }

        public Builder evidence(String evidence) {
            this.evidence = evidence;
            return this;
        }

        public Builder family(String family) {
            this.family = family;
            return this;
        }

        public Builder decompiledCode(String decompiledCode) {
            this.decompiledCode = decompiledCode;
            return this;
        }

        public Builder recommendation(String recommendation) {
            this.recommendation = recommendation;
            return this;
        }

        public Finding build() {
            return new Finding(this);
        }
    }
}
