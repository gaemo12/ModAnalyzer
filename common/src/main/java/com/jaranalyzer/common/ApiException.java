package com.jaranalyzer.common;

import java.util.Objects;

/**
 * Errore di una chiamata API. {@code httpStatus == -1} = errore di trasporto
 * (rete, timeout, risposta illeggibile); altrimenti stato HTTP del server.
 * {@code retryable} indica se la STESSA operazione può essere ritentata in
 * sicurezza (vero solo per letture GET idempotenti, mai per POST/PUT).
 * Non contiene mai credenziali o token.
 */
public final class ApiException extends RuntimeException {
    private final int httpStatus;
    private final boolean retryable;

    public ApiException(int httpStatus, String message, boolean retryable) {
        super(Objects.requireNonNull(message, "message"));
        this.httpStatus = httpStatus;
        this.retryable = retryable;
    }

    public ApiException(int httpStatus, String message, boolean retryable, Throwable cause) {
        super(Objects.requireNonNull(message, "message"), cause);
        this.httpStatus = httpStatus;
        this.retryable = retryable;
    }

    static ApiException http(int status, String body) {
        return new ApiException(status, ApiError.fromJson(status, body).message(), false);
    }

    static ApiException transport(String message, Throwable cause) {
        return new ApiException(-1, message, false, cause);
    }

    static ApiException protocol(String message) {
        return new ApiException(-1, message, false);
    }

    static ApiException timeout(String message, Throwable cause) {
        return new ApiException(-1, message, true, cause);
    }

    public int httpStatus() {
        return httpStatus;
    }

    public boolean retryable() {
        return retryable;
    }

    /** Stesso significato operativo di HTTP 429/503/504/502 per il chiamante. */
    public boolean serverBusy() {
        return httpStatus == 429 || httpStatus == 502 || httpStatus == 503 || httpStatus == 504;
    }
}
