package com.jaranalyzer.common;

/**
 * Costanti del contratto /api/v2. Rispecchiano esattamente BACKEND/index.js:
 * in caso di dubbio fa fede il Worker (vedere docs/PROTOCOL.md).
 */
public final class Protocol {
    /** Versione del protocollo parlato nell'URL (/api/v2). */
    public static final String VERSION = "2";
    /** Versione dell'allowlist dei moduli (ModuleId). */
    public static final int ALLOWLIST_VERSION = 2; // v2: + autoruns, scheduled_tasks, services, hosts_file, software_installed

    public static final String BASE_PATH = "/api/v2";
    public static final String HEALTH = "/health";
    public static final String SESSIONS = "/api/v2/sessions";
    public static final String PIN_VERIFY = "/api/v2/pin/verify";
    public static final String JOB = "/api/v2/job";
    public static final String SIGNATURES = "/api/v2/signatures";
    public static final String RESULTS = "/api/v2/results";
    public static final String REVOCATIONS = "/api/v2/revocations";
    public static final String VERSION_LATEST = "/api/v2/version/latest";
    public static final String PUBLISH_REVOCATIONS = "/api/v2/publish/revocations";
    public static final String PUBLISH_SIGNATURES = "/api/v2/publish/signatures";
    public static final String PUBLISH_VERSION = "/api/v2/publish/version";

    // Default del server (BACKEND/wrangler.toml): duplicati qui solo come fallback documentativo.
    public static final int SESSION_TTL_MIN_DEFAULT = 10;
    public static final int RESULT_TTL_HOURS_DEFAULT = 6;
    public static final int MAX_RESULT_BYTES_DEFAULT = 524288;
    public static final int MAX_ACTIVE_SESSIONS_DEFAULT = 5;

    private Protocol() {
    }
}
