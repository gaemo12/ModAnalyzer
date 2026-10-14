/*
 * Decompiled with CFR 0.152.
 */
package com.jaranalyzer.scanners;

public enum Severity {
    CRITICAL("Critical", "#DC2626", 40),
    HIGH("High", "#EA580C", 20),
    MEDIUM("Medium", "#CA8A04", 10),
    LOW("Low", "#2563EB", 3),
    INFO("Info", "#6B7280", 0);

    private final String displayName;
    private final String colorCode;
    private final int weight;

    private Severity(String displayName, String colorCode, int weight) {
        this.displayName = displayName;
        this.colorCode = colorCode;
        this.weight = weight;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public String getColorCode() {
        return this.colorCode;
    }

    public int getWeight() {
        return this.weight;
    }
}
