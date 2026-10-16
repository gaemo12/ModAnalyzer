package com.jaranalyzer.scanners.engine.rules;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Matching con normalizzazione (report revisione, sez. 1): NFKC Unicode +
 * rimozione zero-width prima del match (profondità 1; niente
 * decodifica-a-cascata per non creare falsi positivi).
 */
public final class RuleEngine {
    /** Hit per singola scansione (il chiamante aggrega per regola). */
    public static final int MAX_HITS_PER_SCAN = 5;
    private static final int SAMPLE_LEN = 120;
    private static final int REDACT_KEEP = 6;

    private RuleEngine() {
    }

    /** Normalizza per il matching: NFKC + via zero-width/BOM. */
    public static String normalize(String s) {
        if (s == null) {
            return "";
        }
        String n = Normalizer.normalize(s, Normalizer.Form.NFKC);
        StringBuilder sb = new StringBuilder(n.length());
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            if (c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\u200E'
                    || c == '\u200F' || c == '\u2060' || c == '\uFEFF') {
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * Applica una regola a un testo già in ambito. Ritorna al massimo
     * {@link #MAX_HITS_PER_SCAN} hit; il campione è redatto se la regola lo
     * richiede (mai segreti in chiaro nei report).
     */
    public static List<Hit> scan(Rule rule, Scope scope, String where, String text) {
        List<Hit> out = new ArrayList<>();
        if (rule == null || !rule.scopes().contains(scope) || text == null || text.isEmpty()) {
            return out;
        }
        Matcher m = rule.pattern().matcher(normalize(text));
        while (m.find() && out.size() < MAX_HITS_PER_SCAN) {
            String raw = m.group();
            out.add(new Hit(rule, where, rule.redact() ? redact(raw) : truncate(raw)));
        }
        return out;
    }

    /** Mostra solo i primi caratteri + lunghezza: maschera sempre i token. */
    public static String redact(String match) {
        if (match == null) {
            return "";
        }
        String head = match.length() <= REDACT_KEEP ? match : match.substring(0, REDACT_KEEP);
        return head + "\u2026<redacted, len " + match.length() + ">";
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > SAMPLE_LEN ? s.substring(0, SAMPLE_LEN) + "\u2026" : s;
    }
}
