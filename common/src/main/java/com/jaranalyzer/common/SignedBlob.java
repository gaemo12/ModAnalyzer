package com.jaranalyzer.common;

import java.util.Map;
import java.util.Objects;

/**
 * Contenuto firmato scaricato ({@code signatures}, {@code revocations}, {@code version}):
 * {@code {"token": "JS1....", "issuedAt": 123}}. La verifica della firma
 * spetta al chiamante (vedere {@link SignedToken}).
 */
public final class SignedBlob {
    private final String token;
    private final long issuedAt;

    public SignedBlob(String token, long issuedAt) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("token assente");
        }
        if (issuedAt <= 0) {
            throw new IllegalArgumentException("issuedAt non valido");
        }
        this.token = token.strip();
        this.issuedAt = issuedAt;
    }

    public static SignedBlob fromJson(String json) {
        Map<String, Object> m = JsonCodec.parseObject(json);
        return new SignedBlob(
                JsonCodec.requiredString(m, "token"),
                JsonCodec.requiredLong(m, "issuedAt"));
    }

    public String token() {
        return token;
    }

    public long issuedAt() {
        return issuedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SignedBlob)) {
            return false;
        }
        SignedBlob s = (SignedBlob) o;
        return issuedAt == s.issuedAt && token.equals(s.token);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token, issuedAt);
    }

    @Override
    public String toString() {
        String prefix = token.contains(".") ? token.substring(0, token.indexOf('.')) : "?";
        return "SignedBlob{prefix='" + prefix + "', issuedAt=" + issuedAt + "}";
    }
}
