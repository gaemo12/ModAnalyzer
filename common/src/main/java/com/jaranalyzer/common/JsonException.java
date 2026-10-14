package com.jaranalyzer.common;

/** Errore di serializzazione/deserializzazione JSON (unchecked). */
public final class JsonException extends RuntimeException {
    public JsonException(String message) {
        super(message);
    }

    public JsonException(String message, Throwable cause) {
        super(message, cause);
    }
}
