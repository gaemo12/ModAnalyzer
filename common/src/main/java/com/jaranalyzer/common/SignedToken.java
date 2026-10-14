package com.jaranalyzer.common;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

/**
 * Verifica dei token firmati {@code PREFIX.&lt;payload base64url&gt;.&lt;firma Ed25519&gt;}
 * (stesso formato di license-core e BACKEND/crypto.js): la firma copre i byte
 * ASCII di {@code "PREFIX.<payload>"}. Solo JDK, nessuna dipendenza.
 * Il Player lo userà per verificare il pacchetto firme JS1 (Fase 4).
 */
public final class SignedToken {
    /** Stesso limite del backend: oltre è rifiutato senza verificare. */
    public static final int MAX_TOKEN_CHARS = 2_000_000;

    /** Motivo del rifiuto: mai dettagli che aiutino la contraffazione. */
    public enum Reason {
        MALFORMED,
        BAD_SIGNATURE
    }

    public static final class TokenException extends RuntimeException {
        private final Reason reason;

        public TokenException(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }

        public Reason reason() {
            return reason;
        }
    }

    private SignedToken() {
    }

    /**
     * Verifica firma e formato, ritorna il payload. Non controlla scadenze
     * o versioni: lo fa il chiamante sul contenuto.
     */
    public static Map<String, Object> verify(String prefix, String token, PublicKey key) {
        if (prefix == null || prefix.isBlank()) {
            throw new IllegalArgumentException("prefix assente");
        }
        if (key == null) {
            throw new IllegalArgumentException("chiave pubblica assente");
        }
        if (token == null || token.length() > MAX_TOKEN_CHARS) {
            throw new TokenException(Reason.MALFORMED, "formato non riconosciuto");
        }
        String t = token.strip().replaceAll("\\s+", "");
        String[] parts = t.split("\\.");
        if (parts.length != 3 || !prefix.equals(parts[0])) {
            throw new TokenException(Reason.MALFORMED, "formato non riconosciuto");
        }
        byte[] sig;
        byte[] payload;
        try {
            sig = Base64.getUrlDecoder().decode(parts[2]);
            payload = Base64.getUrlDecoder().decode(parts[1]);
        } catch (IllegalArgumentException e) {
            throw new TokenException(Reason.MALFORMED, "Base64 non valido");
        }
        boolean ok;
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            ok = s.verify(sig);
        } catch (GeneralSecurityException e) {
            ok = false;
        }
        if (!ok) {
            throw new TokenException(Reason.BAD_SIGNATURE, "firma non valida");
        }
        try {
            return JsonCodec.parseObject(new String(payload, StandardCharsets.UTF_8));
        } catch (JsonException e) {
            throw new TokenException(Reason.MALFORMED, "payload non valido");
        }
    }
}
