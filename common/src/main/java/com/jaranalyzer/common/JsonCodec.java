package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON minimale e autonomo (oggetti, array, stringhe, numeri, booleani, null),
 * per tenere {@code common} senza dipendenze (niente Jackson nel Player).
 * Numeri: interi senza punto/esponente -&gt; {@link Long}, altrimenti {@link Double}.
 * Limite di annidamento {@link #MAX_DEPTH} contro payload ostili.
 */
public final class JsonCodec {
    /** Profondità massima di annidamento accettata in lettura. */
    public static final int MAX_DEPTH = 64;

    private JsonCodec() {
    }

    // ---------------------------------------------------------- scrittura
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString(sb, (String) v);
        } else if (v instanceof Long || v instanceof Integer || v instanceof Short || v instanceof Byte) {
            sb.append(((Number) v).longValue());
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (!Double.isFinite(d)) {
                throw new JsonException("numero non finito non rappresentabile in JSON");
            }
            sb.append(Double.toString(d));
        } else if (v instanceof Boolean) {
            sb.append(v);
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (e.getKey() == null) {
                    throw new JsonException("chiave oggetto nulla");
                }
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, e.getKey());
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof Iterable) {
            sb.append('[');
            boolean first = true;
            for (Object o : (Iterable<Object>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeValue(sb, o);
            }
            sb.append(']');
        } else {
            throw new JsonException("tipo non supportato: " + v.getClass());
        }
    }

    private static void writeString(StringBuilder sb, String str) {
        sb.append('"');
        for (int k = 0; k < str.length(); k++) {
            char c = str.charAt(k);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || Character.isSurrogate(c)) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // ----------------------------------------------------------- lettura
    public static Object parse(String text) {
        if (text == null) {
            throw new JsonException("JSON nullo");
        }
        try {
            Reader p = new Reader(text);
            Object v = p.value(0);
            p.ws();
            if (p.i != p.s.length()) {
                throw new IllegalArgumentException("testo dopo la fine del valore");
            }
            return v;
        } catch (RuntimeException e) {
            if (e instanceof JsonException) {
                throw (JsonException) e;
            }
            throw new JsonException("JSON non valido: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new JsonException("atteso oggetto JSON");
        }
        return (Map<String, Object>) v;
    }

    private static final class Reader {
        final String s;
        int i;

        Reader(String s) {
            this.s = s;
        }

        void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw new JsonException("annidamento oltre il limite (" + MAX_DEPTH + ")");
            }
            ws();
            if (i >= s.length()) {
                throw new IllegalArgumentException("fine inattesa");
            }
            char c = s.charAt(i);
            if (c == '{') {
                return object(depth);
            }
            if (c == '[') {
                return array(depth);
            }
            if (c == '"') {
                return string();
            }
            if (s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            if (s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            return number();
        }

        Object number() {
            int st = i;
            if (i < s.length() && s.charAt(i) == '-') {
                i++;
            }
            while (i < s.length() && Character.isDigit(s.charAt(i))) {
                i++;
            }
            boolean decimal = false;
            if (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                decimal = true;
                if (s.charAt(i) == '.') {
                    i++;
                    while (i < s.length() && Character.isDigit(s.charAt(i))) {
                        i++;
                    }
                }
                if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                    i++;
                    if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) {
                        i++;
                    }
                    while (i < s.length() && Character.isDigit(s.charAt(i))) {
                        i++;
                    }
                }
            }
            String raw = s.substring(st, i);
            try {
                if (decimal) {
                    double d = Double.parseDouble(raw);
                    if (!Double.isFinite(d)) {
                        throw new IllegalArgumentException("numero fuori intervallo: " + raw);
                    }
                    return d;
                }
                return Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("numero non valido: " + raw);
            }
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            ws();
            if (i < s.length() && s.charAt(i) == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                String k = string();
                ws();
                expect(':');
                m.put(k, value(depth + 1));
                ws();
                if (i < s.length() && s.charAt(i) == ',') {
                    i++;
                    continue;
                }
                expect('}');
                return m;
            }
        }

        List<Object> array(int depth) {
            List<Object> l = new ArrayList<>();
            i++; // [
            ws();
            if (i < s.length() && s.charAt(i) == ']') {
                i++;
                return l;
            }
            while (true) {
                l.add(value(depth + 1));
                ws();
                if (i < s.length() && s.charAt(i) == ',') {
                    i++;
                    continue;
                }
                expect(']');
                return l;
            }
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    throw new IllegalArgumentException("stringa non terminata");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("escape troncato");
                    }
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'u':
                            if (i + 4 > s.length()) {
                                throw new IllegalArgumentException("escape \\u troncato");
                            }
                            try {
                                sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            } catch (NumberFormatException ex) {
                                throw new IllegalArgumentException("escape \\u non valido");
                            }
                            i += 4;
                            break;
                        default: sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        void expect(char c) {
            if (i >= s.length() || s.charAt(i) != c) {
                throw new IllegalArgumentException("atteso '" + c + "' in posizione " + i);
            }
            i++;
        }
    }

    // ------------------------------------------- accessori tipizzati per i DTO
    public static String requiredString(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (!(v instanceof String)) {
            throw new JsonException("campo stringa mancante o non valido: " + key);
        }
        return (String) v;
    }

    public static String optionalString(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) {
            return null;
        }
        if (!(v instanceof String)) {
            throw new JsonException("campo stringa non valido: " + key);
        }
        return (String) v;
    }

    public static long requiredLong(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v instanceof Long) {
            return (Long) v;
        }
        if (v instanceof Double) {
            double d = (Double) v;
            if (d == Math.rint(d) && Double.isFinite(d)) {
                return (long) d;
            }
        }
        throw new JsonException("campo intero mancante o non valido: " + key);
    }

    public static boolean optionalBoolean(Map<String, Object> m, String key, boolean def) {
        Object v = m.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof Boolean)) {
            throw new JsonException("campo booleano non valido: " + key);
        }
        return (Boolean) v;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> requiredList(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (!(v instanceof List)) {
            throw new JsonException("campo lista mancante o non valido: " + key);
        }
        return (List<Object>) v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> optionalMap(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) {
            return null;
        }
        if (!(v instanceof Map)) {
            throw new JsonException("campo oggetto non valido: " + key);
        }
        return (Map<String, Object>) v;
    }
}
