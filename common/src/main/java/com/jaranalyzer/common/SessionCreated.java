package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Risposta {@code POST /api/v2/sessions}:
 * {@code {"sessionId": "...", "pin": "123456", "modules": [...], "expiresAt": 123}}.
 * Il PIN esiste solo qui: mai nei log (toString lo oscura).
 */
public final class SessionCreated {
    private final String sessionId;
    private final String pin;
    private final List<String> modules;
    private final long expiresAt;

    public SessionCreated(String sessionId, String pin, List<String> modules, long expiresAt) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId assente");
        }
        if (pin == null || !pin.matches("\\d{6}")) {
            throw new IllegalArgumentException("pin non valido (attese 6 cifre)");
        }
        if (expiresAt <= 0) {
            throw new IllegalArgumentException("expiresAt non valido");
        }
        this.sessionId = sessionId;
        this.pin = pin;
        this.modules = ModuleId.requireAllowedList(modules);
        this.expiresAt = expiresAt;
    }

    public static SessionCreated fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        return fromMap(m);
    }

    static SessionCreated fromMap(Map<String, Object> m) {
        List<String> mods = new ArrayList<>();
        for (Object o : JsonCodec.requiredList(m, "modules")) {
            if (!(o instanceof String)) {
                throw new JsonException("modulo non stringa in modules");
            }
            mods.add((String) o);
        }
        return new SessionCreated(
                JsonCodec.requiredString(m, "sessionId"),
                JsonCodec.requiredString(m, "pin"),
                mods,
                JsonCodec.requiredLong(m, "expiresAt"));
    }

    public String sessionId() {
        return sessionId;
    }

    /** Il PIN mostrato una sola volta allo staff. Maneggiare con cura. */
    public String pin() {
        return pin;
    }

    public List<String> modules() {
        return modules;
    }

    public long expiresAt() {
        return expiresAt;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SessionCreated)) {
            return false;
        }
        SessionCreated s = (SessionCreated) o;
        return expiresAt == s.expiresAt && sessionId.equals(s.sessionId)
                && pin.equals(s.pin) && modules.equals(s.modules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, pin, modules, expiresAt);
    }

    @Override
    public String toString() {
        return "SessionCreated{sessionId='" + sessionId + "', pin='******', modules=" + modules
                + ", expiresAt=" + expiresAt + "}";
    }
}
