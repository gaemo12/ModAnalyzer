package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Risposta {@code GET /api/v2/job}:
 * {@code {"modules": [...], "status": "claimed", "expiresAt": 123}}.
 * Solo i moduli autorizzati: il player non esegue mai altro.
 */
public final class JobInfo {
    private final List<String> modules;
    private final SessionStatus status;
    private final long expiresAt;

    public JobInfo(List<String> modules, SessionStatus status, long expiresAt) {
        this.modules = ModuleId.requireAllowedList(modules);
        this.status = Objects.requireNonNull(status, "status");
        if (expiresAt <= 0) {
            throw new IllegalArgumentException("expiresAt non valido");
        }
        this.expiresAt = expiresAt;
    }

    public static JobInfo fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        List<String> mods = new ArrayList<>();
        for (Object o : JsonCodec.requiredList(m, "modules")) {
            if (!(o instanceof String)) {
                throw new JsonException("modulo non stringa in modules");
            }
            mods.add((String) o);
        }
        String st = JsonCodec.optionalString(m, "status");
        return new JobInfo(mods, SessionStatus.fromString(st), JsonCodec.requiredLong(m, "expiresAt"));
    }

    public List<String> modules() {
        return modules;
    }

    public SessionStatus status() {
        return status;
    }

    public long expiresAt() {
        return expiresAt;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof JobInfo)) {
            return false;
        }
        JobInfo j = (JobInfo) o;
        return expiresAt == j.expiresAt && status == j.status && modules.equals(j.modules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(modules, status, expiresAt);
    }

    @Override
    public String toString() {
        return "JobInfo{modules=" + modules + ", status=" + status + ", expiresAt=" + expiresAt + "}";
    }
}
