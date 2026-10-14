package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Rappresentazione standard dell'esito di un modulo: esito, durata, conteggi,
 * rilevamenti e, in caso di fallimento, l'errore (obbligatorio se non ok).
 * Gli errori di un modulo non coinvolgono gli altri: ogni modulo ha il suo.
 */
public final class ModuleResult {
    private final String module;
    private final boolean success;
    private final long durationMillis;
    private final List<Finding> findings;
    private final Map<String, Long> counters;
    private final String error;

    public ModuleResult(String module, boolean success, long durationMillis,
            List<Finding> findings, Map<String, Long> counters, String error) {
        if (!ModuleId.isAllowed(module)) {
            throw new IllegalArgumentException("modulo non consentito: " + module);
        }
        if (durationMillis < 0) {
            throw new IllegalArgumentException("durationMillis negativa");
        }
        if (!success && (error == null || error.isBlank())) {
            throw new IllegalArgumentException("error obbligatorio quando success=false");
        }
        this.module = module;
        this.success = success;
        this.durationMillis = durationMillis;
        this.findings = findings == null ? List.of() : List.copyOf(findings);
        if (counters == null) {
            this.counters = Map.of();
        } else {
            Map<String, Long> c = new LinkedHashMap<>();
            for (Map.Entry<String, Long> e : counters.entrySet()) {
                if (e.getKey() == null || e.getValue() == null || e.getValue() < 0) {
                    throw new IllegalArgumentException("contatore non valido: " + e.getKey());
                }
                c.put(e.getKey(), e.getValue());
            }
            this.counters = Map.copyOf(c);
        }
        this.error = error;
    }

    /** Scorciatoia per un modulo riuscito senza rilevamenti. */
    public static ModuleResult ok(String module, long durationMillis) {
        return new ModuleResult(module, true, durationMillis, List.of(), Map.of(), null);
    }

    /** Scorciatoia per un modulo fallito (isolato dagli altri). */
    public static ModuleResult failed(String module, long durationMillis, String error) {
        return new ModuleResult(module, false, durationMillis, List.of(), Map.of(), error);
    }

    @SuppressWarnings("unchecked")
    public static ModuleResult fromMap(String module, Map<String, Object> m) {
        List<Finding> fs = new ArrayList<>();
        Object rawF = m.get("findings");
        if (rawF instanceof List) {
            for (Object o : (List<Object>) rawF) {
                if (!(o instanceof Map)) {
                    throw new JsonException("finding non oggetto per " + module);
                }
                fs.add(Finding.fromMap((Map<String, Object>) o));
            }
        } else if (rawF != null) {
            throw new JsonException("findings non lista per " + module);
        }
        Map<String, Long> counters = new LinkedHashMap<>();
        Object rawC = m.get("counters");
        if (rawC instanceof Map) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) rawC).entrySet()) {
                Object v = e.getValue();
                if (v instanceof Long) {
                    counters.put(e.getKey(), (Long) v);
                } else {
                    throw new JsonException("contatore non intero per " + module + ": " + e.getKey());
                }
            }
        } else if (rawC != null) {
            throw new JsonException("counters non oggetto per " + module);
        }
        Object rawD = m.get("durationMillis");
        if (!(rawD instanceof Long)) {
            throw new JsonException("durationMillis mancante per " + module);
        }
        return new ModuleResult(
                module,
                JsonCodec.optionalBoolean(m, "success", true),
                (Long) rawD,
                fs,
                counters,
                JsonCodec.optionalString(m, "error"));
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("success", success);
        m.put("durationMillis", durationMillis);
        List<Object> fs = new ArrayList<>();
        for (Finding f : findings) {
            fs.add(f.toMap());
        }
        m.put("findings", fs);
        m.put("counters", new LinkedHashMap<>(counters));
        if (error != null) {
            m.put("error", error);
        }
        return m;
    }

    public String module() {
        return module;
    }

    public boolean success() {
        return success;
    }

    public long durationMillis() {
        return durationMillis;
    }

    public List<Finding> findings() {
        return findings;
    }

    public Map<String, Long> counters() {
        return counters;
    }

    public String error() {
        return error;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ModuleResult)) {
            return false;
        }
        ModuleResult r = (ModuleResult) o;
        return success == r.success && durationMillis == r.durationMillis
                && module.equals(r.module) && findings.equals(r.findings)
                && counters.equals(r.counters) && Objects.equals(error, r.error);
    }

    @Override
    public int hashCode() {
        return Objects.hash(module, success, durationMillis, findings, counters, error);
    }

    @Override
    public String toString() {
        return "ModuleResult{module='" + module + "', success=" + success
                + ", durationMillis=" + durationMillis + ", findings=" + findings.size() + "}";
    }
}
