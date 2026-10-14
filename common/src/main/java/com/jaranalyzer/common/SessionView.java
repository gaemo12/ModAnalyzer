package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Risposta staff {@code GET /api/v2/sessions/{id}}:
 * {@code {"sessionId": "...", "status": "...", "modules": [...], "expiresAt": 123, "result": {...|null}}}.
 * {@code result} resta opaco (JSON grezzo): solo lo staff proprietario lo riceve,
 * ed è lui a interpretarlo (vedere {@link ScanReport}).
 */
public final class SessionView {
    private final String sessionId;
    private final SessionStatus status;
    private final List<String> modules;
    private final long expiresAt;
    private final String resultJson;

    public SessionView(String sessionId, SessionStatus status, List<String> modules,
            long expiresAt, String resultJson) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId assente");
        }
        this.sessionId = sessionId;
        this.status = Objects.requireNonNull(status, "status");
        this.modules = ModuleId.requireAllowedList(modules);
        if (expiresAt <= 0) {
            throw new IllegalArgumentException("expiresAt non valido");
        }
        this.expiresAt = expiresAt;
        if (resultJson != null) {
            // Validazione leggera: deve essere un oggetto JSON, senza imporne lo schema.
            JsonCodec.parseObject(resultJson);
        }
        this.resultJson = resultJson;
    }

    public static SessionView fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        List<String> mods = new ArrayList<>();
        for (Object o : JsonCodec.requiredList(m, "modules")) {
            if (!(o instanceof String)) {
                throw new JsonException("modulo non stringa in modules");
            }
            mods.add((String) o);
        }
        Object raw = m.get("result");
        String result = raw == null ? null : JsonCodec.write(raw);
        return new SessionView(
                JsonCodec.requiredString(m, "sessionId"),
                SessionStatus.fromString(JsonCodec.optionalString(m, "status")),
                mods,
                JsonCodec.requiredLong(m, "expiresAt"),
                result);
    }

    public String sessionId() {
        return sessionId;
    }

    public SessionStatus status() {
        return status;
    }

    public List<String> modules() {
        return modules;
    }

    public long expiresAt() {
        return expiresAt;
    }

    /** JSON grezzo del risultato, o null se non {@code done}. */
    public String resultJson() {
        return resultJson;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SessionView)) {
            return false;
        }
        SessionView s = (SessionView) o;
        return expiresAt == s.expiresAt && status == s.status && sessionId.equals(s.sessionId)
                && modules.equals(s.modules) && Objects.equals(resultJson, s.resultJson);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, status, modules, expiresAt, resultJson);
    }

    @Override
    public String toString() {
        return "SessionView{sessionId='" + sessionId + "', status=" + status + ", modules=" + modules
                + ", expiresAt=" + expiresAt + ", hasResult=" + (resultJson != null) + "}";
    }
}
