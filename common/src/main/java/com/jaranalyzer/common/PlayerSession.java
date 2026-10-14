package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Risposta {@code POST /api/v2/pin/verify}:
 * {@code {"playerToken": "...", "modules": [...], "expiresAt": 123}}.
 * Il token è distinto dal PIN, con durata limitata. Mai nei log.
 */
public final class PlayerSession {
    private final String playerToken;
    private final List<String> modules;
    private final long expiresAt;

    public PlayerSession(String playerToken, List<String> modules, long expiresAt) {
        if (playerToken == null || playerToken.isBlank()) {
            throw new IllegalArgumentException("playerToken assente");
        }
        if (expiresAt <= 0) {
            throw new IllegalArgumentException("expiresAt non valido");
        }
        this.playerToken = playerToken;
        this.modules = ModuleId.requireAllowedList(modules);
        this.expiresAt = expiresAt;
    }

    public static PlayerSession fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        List<String> mods = new ArrayList<>();
        for (Object o : JsonCodec.requiredList(m, "modules")) {
            if (!(o instanceof String)) {
                throw new JsonException("modulo non stringa in modules");
            }
            mods.add((String) o);
        }
        return new PlayerSession(
                JsonCodec.requiredString(m, "playerToken"),
                mods,
                JsonCodec.requiredLong(m, "expiresAt"));
    }

    public String playerToken() {
        return playerToken;
    }

    public List<String> modules() {
        return modules;
    }

    public long expiresAt() {
        return expiresAt;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof PlayerSession)) {
            return false;
        }
        PlayerSession p = (PlayerSession) o;
        return expiresAt == p.expiresAt && playerToken.equals(p.playerToken)
                && modules.equals(p.modules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(playerToken, modules, expiresAt);
    }

    @Override
    public String toString() {
        return "PlayerSession{playerToken='******', modules=" + modules + ", expiresAt=" + expiresAt + "}";
    }
}
