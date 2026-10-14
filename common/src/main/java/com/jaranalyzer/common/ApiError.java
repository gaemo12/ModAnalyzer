package com.jaranalyzer.common;

import java.util.Map;
import java.util.Objects;

/**
 * Errore restituito dal backend: corpo {@code {"error": "..."}} più stato HTTP.
 * Il server non riecheggia mai segreti nei messaggi.
 */
public final class ApiError {
    private final int httpStatus;
    private final String message;

    public ApiError(int httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = Objects.requireNonNull(message, "message");
    }

    /** Corpo {@code {"error": ...}} di una risposta di errore. */
    public static ApiError fromJson(int httpStatus, String body) {
        try {
            Map<String, Object> m = JsonCodec.parseObject(body);
            String msg = JsonCodec.optionalString(m, "error");
            return new ApiError(httpStatus, msg != null ? msg : "HTTP " + httpStatus);
        } catch (JsonException e) {
            return new ApiError(httpStatus, "HTTP " + httpStatus);
        }
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String message() {
        return message;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ApiError)) {
            return false;
        }
        ApiError a = (ApiError) o;
        return httpStatus == a.httpStatus && message.equals(a.message);
    }

    @Override
    public int hashCode() {
        return 31 * httpStatus + message.hashCode();
    }

    @Override
    public String toString() {
        return "ApiError{httpStatus=" + httpStatus + ", message='" + message + "'}";
    }
}
