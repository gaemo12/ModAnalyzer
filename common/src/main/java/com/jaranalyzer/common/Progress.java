package com.jaranalyzer.common;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Avanzamento di un modulo (solo locale, per la UI: non viaggia sul backend).
 * I client limitano gli aggiornamenti visivi (~10/s); questo DTO resta puro.
 */
public final class Progress {
    private final String module;
    private final String phase;
    private final int percent;
    private final String message;

    public Progress(String module, String phase, int percent, String message) {
        if (!ModuleId.isAllowed(module)) {
            throw new IllegalArgumentException("modulo non consentito: " + module);
        }
        if (phase == null || phase.isBlank()) {
            throw new IllegalArgumentException("phase assente");
        }
        if (percent < 0 || percent > 100) {
            throw new IllegalArgumentException("percent fuori 0..100: " + percent);
        }
        this.module = module;
        this.phase = phase;
        this.percent = percent;
        this.message = message;
    }

    public static Progress fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        Object rawP = m.get("percent");
        if (!(rawP instanceof Long)) {
            throw new JsonException("percent mancante");
        }
        return new Progress(
                JsonCodec.requiredString(m, "module"),
                JsonCodec.requiredString(m, "phase"),
                ((Long) rawP).intValue(),
                JsonCodec.optionalString(m, "message"));
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("module", module);
        m.put("phase", phase);
        m.put("percent", (long) percent);
        if (message != null) {
            m.put("message", message);
        }
        return m;
    }

    public String toJson() {
        return JsonCodec.write(toMap());
    }

    public String module() {
        return module;
    }

    public String phase() {
        return phase;
    }

    public int percent() {
        return percent;
    }

    public String message() {
        return message;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Progress)) {
            return false;
        }
        Progress p = (Progress) o;
        return percent == p.percent && module.equals(p.module) && phase.equals(p.phase)
                && Objects.equals(message, p.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(module, phase, percent, message);
    }

    @Override
    public String toString() {
        return "Progress{module='" + module + "', phase='" + phase + "', percent=" + percent + "}";
    }
}
