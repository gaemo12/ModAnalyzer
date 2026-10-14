package com.jaranalyzer.common;

/** Configurazione immutabile del client HTTP condiviso. */
public final class ApiClientConfig {
    private final int connectTimeoutMs;
    private final int requestTimeoutMs;
    private final int maxResponseBytes;
    private final int maxRetries;
    private final String userAgent;

    public ApiClientConfig(int connectTimeoutMs, int requestTimeoutMs,
            int maxResponseBytes, int maxRetries, String userAgent) {
        if (connectTimeoutMs <= 0 || requestTimeoutMs <= 0) {
            throw new IllegalArgumentException("timeout non validi");
        }
        if (maxResponseBytes < 1024) {
            throw new IllegalArgumentException("maxResponseBytes troppo piccolo");
        }
        if (maxRetries < 0 || maxRetries > 5) {
            throw new IllegalArgumentException("maxRetries fuori 0..5");
        }
        if (userAgent == null || userAgent.isBlank()) {
            throw new IllegalArgumentException("userAgent assente");
        }
        this.connectTimeoutMs = connectTimeoutMs;
        this.requestTimeoutMs = requestTimeoutMs;
        this.maxResponseBytes = maxResponseBytes;
        this.maxRetries = maxRetries;
        this.userAgent = userAgent;
    }

    /** Default allineati al backend e al vecchio BackendClient (5 s / 15 s). */
    public static ApiClientConfig defaults() {
        return new ApiClientConfig(5000, 15000, 2 * 1024 * 1024, 2, "JarAnalyzer-Common/2.4.0");
    }

    public int connectTimeoutMs() {
        return connectTimeoutMs;
    }

    public int requestTimeoutMs() {
        return requestTimeoutMs;
    }

    public int maxResponseBytes() {
        return maxResponseBytes;
    }

    /** Retry solo per GET idempotenti; POST/PUT non ritentati mai. */
    public int maxRetries() {
        return maxRetries;
    }

    public String userAgent() {
        return userAgent;
    }

    @Override
    public String toString() {
        return "ApiClientConfig{connectTimeoutMs=" + connectTimeoutMs
                + ", requestTimeoutMs=" + requestTimeoutMs
                + ", maxResponseBytes=" + maxResponseBytes + ", maxRetries=" + maxRetries + "}";
    }
}
