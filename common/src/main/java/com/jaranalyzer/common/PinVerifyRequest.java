package com.jaranalyzer.common;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Richiesta player {@code POST /api/v2/pin/verify}: {@code {"pin": "123456"}}.
 * Il PIN viaggia solo nel body JSON, mai in URL.
 */
public final class PinVerifyRequest {
    private final String pin;

    public PinVerifyRequest(String pin) {
        if (pin == null || !pin.matches("\\d{6}")) {
            throw new IllegalArgumentException("pin non valido (attese 6 cifre)");
        }
        this.pin = pin;
    }

    public String pin() {
        return pin;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pin", pin);
        return m;
    }

    public String toJson() {
        return JsonCodec.write(toMap());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PinVerifyRequest && pin.equals(((PinVerifyRequest) o).pin);
    }

    @Override
    public int hashCode() {
        return pin.hashCode();
    }

    @Override
    public String toString() {
        return "PinVerifyRequest{pin='******'}";
    }
}
