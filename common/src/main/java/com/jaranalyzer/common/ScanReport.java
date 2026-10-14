package com.jaranalyzer.common;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Invio player {@code POST /api/v2/results} e lettura staff del campo
 * {@code result}. Formato di rete volutamente PIATTO, chiavi = moduli:
 * {@code {"processes": {...}, "javaw": {...}}}. Niente wrapper: il server
 * accetta solo le chiavi dei moduli richiesti e scarta il resto.
 */
public final class ScanReport {
    private final Map<String, ModuleResult> results;

    public ScanReport(Map<String, ModuleResult> results) {
        if (results == null || results.isEmpty()) {
            throw new IllegalArgumentException("results assente o vuoto");
        }
        Map<String, ModuleResult> c = new LinkedHashMap<>();
        for (Map.Entry<String, ModuleResult> e : results.entrySet()) {
            if (!ModuleId.isAllowed(e.getKey())) {
                throw new IllegalArgumentException("modulo non consentito: " + e.getKey());
            }
            if (e.getValue() == null || !e.getKey().equals(e.getValue().module())) {
                throw new IllegalArgumentException("risultato incoerente per: " + e.getKey());
            }
            c.put(e.getKey(), e.getValue());
        }
        this.results = Map.copyOf(c);
    }

    public Map<String, ModuleResult> results() {
        return results;
    }

    /** Mappa piatta pronta per il body di {@code POST /results}. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        for (Map.Entry<String, ModuleResult> e : results.entrySet()) {
            m.put(e.getKey(), e.getValue().toMap());
        }
        return m;
    }

    public String toJson() {
        return JsonCodec.write(toMap());
    }

    /** Accetta la mappa piatta del server; chiavi ignote vengono scartate. */
    @SuppressWarnings("unchecked")
    public static ScanReport fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        Map<String, ModuleResult> out = new LinkedHashMap<>();
        for (String key : ModuleId.knownModules(m.keySet())) {
            Object v = m.get(key);
            if (!(v instanceof Map)) {
                throw new JsonException("risultato non oggetto per " + key);
            }
            out.put(key, ModuleResult.fromMap(key, (Map<String, Object>) v));
        }
        return new ScanReport(out);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ScanReport && results.equals(((ScanReport) o).results);
    }

    @Override
    public int hashCode() {
        return results.hashCode();
    }

    @Override
    public String toString() {
        return "ScanReport{modules=" + results.keySet() + "}";
    }
}
