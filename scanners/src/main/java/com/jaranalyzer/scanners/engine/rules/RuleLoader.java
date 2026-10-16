package com.jaranalyzer.scanners.engine.rules;

import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Severity;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Carica le regole da {@code rules/ioc-rules.json} in classpath (regole come
 * dati, non come codice). Tollerante come {@code BuiltinSignatures}: righe
 * malformate scartate con warn e conteggio; se il file manca o non contiene
 * nessuna regola valida si ripiega su un set minimo hardcoded, mai cecità
 * silenziosa.
 */
public final class RuleLoader {
    private static final Logger log = LoggerFactory.getLogger(RuleLoader.class);
    private static final String RESOURCE = "rules/ioc-rules.json";

    private RuleLoader() {
    }

    public static List<Rule> load() {
        return load(RuleLoader.class.getClassLoader());
    }

    static List<Rule> load(ClassLoader loader) {
        List<Rule> out = new ArrayList<>();
        int dropped = 0;
        String json = readResource(loader);
        if (json != null) {
            for (Map<String, Object> row : rows(json)) {
                try {
                    out.add(parse(row));
                } catch (Exception e) {
                    dropped++;
                    log.warn("Regola IOC scartata: {}", e.getMessage());
                }
            }
        }
        if (out.isEmpty()) {
            log.warn("Nessuna regola IOC valida da {}, uso il fallback minimo (dropped={})", RESOURCE, dropped);
            out.addAll(fallback());
        } else if (dropped > 0) {
            log.warn("Regole IOC caricate: {}, scartate: {}", out.size(), dropped);
        } else {
            log.info("Regole IOC caricate: {}", out.size());
        }
        return List.copyOf(out);
    }

    private static String readResource(ClassLoader loader) {
        try (InputStream in = loader.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return null;
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("Lettura {} fallita: {}", RESOURCE, e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows(String json) {
        Object root = JsonCodec.parseObject(json).get("rules");
        if (!(root instanceof List)) {
            throw new IllegalArgumentException("radice senza array 'rules'");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : (List<Object>) root) {
            if (o instanceof Map) {
                out.add((Map<String, Object>) o);
            }
        }
        return out;
    }

    private static Rule parse(Map<String, Object> m) {
        String id = str(m, "id");
        String pattern = str(m, "pattern");
        EnumSet<Scope> scopes = EnumSet.noneOf(Scope.class);
        Object sc = m.get("scopes");
        if (sc instanceof List) {
            for (Object o : (List<?>) sc) {
                scopes.add(Scope.valueOf(String.valueOf(o).toUpperCase(Locale.ROOT)));
            }
        }
        return new Rule(
                id,
                opt(m, "title", id),
                scopes,
                Pattern.compile(pattern),
                Severity.valueOf(str(m, "severity").toUpperCase(Locale.ROOT)),
                Category.valueOf(str(m, "category").toUpperCase(Locale.ROOT)),
                opt(m, "cap", "WEAK"),
                opt(m, "description", ""),
                Boolean.parseBoolean(String.valueOf(m.getOrDefault("redact", "false"))),
                opt(m, "special", null));
    }

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null || String.valueOf(v).isBlank()) {
            throw new IllegalArgumentException("campo '" + key + "' assente");
        }
        return String.valueOf(v);
    }

    private static String opt(Map<String, Object> m, String key, String dflt) {
        Object v = m.get(key);
        return v == null ? dflt : String.valueOf(v);
    }

    /** Set minimo anti-cecità: webhook, token bot, powershell codificato. */
    private static List<Rule> fallback() {
        EnumSet<Scope> code = EnumSet.of(Scope.CLASS_CONST, Scope.CLASS_POOL);
        return List.of(
                new Rule("discord-webhook", "Webhook Discord con token",
                        EnumSet.of(Scope.CLASS_CONST, Scope.CLASS_POOL, Scope.RESOURCE_TEXT),
                        Pattern.compile("https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d{17,20}/[\\w-]{60,}"),
                        Severity.HIGH, Category.NETWORK, "STRONG",
                        "URL webhook Discord completo di token: endpoint di esfiltrazione pronto all'uso.", true, null),
                new Rule("telegram-bot-token", "Token bot Telegram",
                        code,
                        Pattern.compile("\\b\\d{8,10}:[A-Za-z0-9_-]{35}\\b"),
                        Severity.MEDIUM, Category.NETWORK, "MEDIUM",
                        "Token bot Telegram: da solo medio, forte con invio in rete.", true, null),
                new Rule("powershell-encoded", "PowerShell con comando codificato",
                        EnumSet.of(Scope.CLASS_CONST, Scope.CLASS_POOL, Scope.RESOURCE_TEXT),
                        Pattern.compile("(?i)powershell(?:\\.exe)?[^;\\n&|]{0,300}-(?:e(?:nc(?:odedcommand)?)?)\\b"),
                        Severity.HIGH, Category.EXECUTION, "STRONG",
                        "PowerShell con -EncodedCommand: esecuzione offuscata.", false, null));
    }
}
