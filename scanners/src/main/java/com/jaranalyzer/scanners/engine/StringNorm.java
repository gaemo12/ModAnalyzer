package com.jaranalyzer.scanners.engine;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Normalizzazione anti-evasione per il matching su stringhe (Fase 1).
 *
 * <p>Le firme storiche usano {@code String.contains} case-sensitive su testo
 * decodificato: bastavano maiuscole, split su più {@code LDC} + concat o un
 * Base64 per sparire. Qui si centralizzano le tre contromisure:
 * lowercase canonico, decodifica prudente (Base64/hex con round-trip
 * plausibile, per non flaggare hash e rumore) e test di stampabilità.
 *
 * <p>Solo JDK ({@code java.util}), nessuna rete: resta usabile da tutti gli
 * analyzer (igiene sorgenti: niente {@code java.net.http}/UI negli scanner).
 */
public final class StringNorm {
    private static final Pattern BASE64_SHAPE =
            Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$");
    private static final Pattern HEX_SHAPE = Pattern.compile("^(?:[0-9a-fA-F]{2})+$");
    /** Sotto questa lunghezza la decodifica è quasi sempre rumore. */
    private static final int MIN_DECODE_LEN = 12;
    private static final int MIN_HEX_LEN = 16;

    private StringNorm() {
    }

    /** Lowercase canonico (ROOT) per matching case-insensitive. */
    public static String lower(String s) {
        return s == null ? null : s.toLowerCase(Locale.ROOT);
    }

    /**
     * Decodifica Base64 solo se plausibile: forma canonica, lunghezza multipla
     * di 4, decode valido, testo stampabile diverso dall'input.
     *
     * @return testo decodificato, oppure {@code null}
     */
    public static String tryBase64(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.length() < MIN_DECODE_LEN || (t.length() & 3) != 0 || !BASE64_SHAPE.matcher(t).matches()) {
            return null;
        }
        final byte[] raw;
        try {
            raw = Base64.getDecoder().decode(t);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return printableOrNull(raw, t);
    }

    /**
     * Decodifica hex (es. {@code 68747470...} per "http...") con gli stessi
     * criteri di plausibilità del Base64.
     *
     * @return testo decodificato, oppure {@code null}
     */
    public static String tryHex(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.length() < MIN_HEX_LEN || (t.length() & 1) != 0 || !HEX_SHAPE.matcher(t).matches()) {
            return null;
        }
        byte[] raw = new byte[t.length() / 2];
        try {
            for (int i = 0; i < raw.length; i++) {
                raw[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return printableOrNull(raw, t);
    }

    private static String printableOrNull(byte[] raw, String original) {
        String d;
        try {
            d = new String(raw, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
        if (d.length() <= 4 || d.equals(original) || !isPrintable(d)) {
            return null;
        }
        return d;
    }

    /** Solo ASCII stampabile + tab/newline/CR: scarta binario e mojibake. */
    public static boolean isPrintable(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\t' || c == '\n' || c == '\r') {
                continue;
            }
            if (c < ' ' || c > '~') {
                return false;
            }
        }
        return true;
    }
}
