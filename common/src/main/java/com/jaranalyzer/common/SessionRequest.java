package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Richiesta staff {@code POST /api/v2/sessions}: {@code {"modules": [...]}}. */
public final class SessionRequest {
    private final List<String> modules;

    public SessionRequest(List<String> modules) {
        this.modules = ModuleId.requireAllowedList(modules);
    }

    public List<String> modules() {
        return modules;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("modules", new ArrayList<>(modules));
        return m;
    }

    public String toJson() {
        return JsonCodec.write(toMap());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SessionRequest && modules.equals(((SessionRequest) o).modules);
    }

    @Override
    public int hashCode() {
        return modules.hashCode();
    }

    @Override
    public String toString() {
        return "SessionRequest{modules=" + modules + "}";
    }
}
