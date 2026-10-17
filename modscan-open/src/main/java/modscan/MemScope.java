package modscan;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Scoping del memory-dump (lezione RedLotus 2.0, clean-room): ogni classe del
 * dump viene attribuita alla sua origine reale — mod, copia remappata Fabric,
 * gioco, librerie, JDK — e i rilevamenti vengono letti in quell'ottica:
 * <ul>
 *   <li>gli artefatti di offuscamento attesi (xor, SourceFile assente, flag
 *       sintetici, chiavi esadecimali…) su classi del <b>gioco</b> o delle
 *       <b>librerie</b> vengono riassunti in un singolo finding INFO invece di
 *       inondare il report: Minecraft è offuscato per natura e le librerie non
 *       sono sospette;</li>
 *   <li>le classi di <b>mod</b> restano analizzate alla lettera (è lì che un
 *       cheat deve nascondersi);</li>
 *   <li>classi senza file su disco (generate a runtime con defineClass) o
 *       caricate da jar esterni/non più presenti diventano evidenze esplicite
 *       ("bypassed"), come il <i>Bypassed_Mods</i> di RedLotus;</li>
 *   <li>la tabella di attribuzione (origine → classi/finding) risponde alla
 *       domanda "quale mod ha prodotto questo rilevamento?".</li>
 * </ul>
 */
final class MemScope {

    /** Origine del bytecode di una classe. */
    enum Kind {
        MOD, PROC, GAME, LIB, JDK, OTHER, MISSING, NONE
    }

    /**
     * Regole che descrivono offuscamento generico: su gioco/librerie/copie
     * remappate sono rumore atteso (Minecraft è offuscato, Fabric rimappa e
     * toglie il SourceFile), sulle mod restano segnali utili.
     */
    private static final Set<String> DEMOTE_RULES = Set.of(
            "sourcefile-absent", "access-flag-anomaly", "xor-operation", "xor-encryption",
            "constant-pool-crypto-key", "crypto-string-hint", "high-cyclomatic-complexity",
            "nested-try-catch", "large-method", "opaque-predicate", "lambda-abuse",
            "class-injection-risk");

    private MemScope() {
    }

    /** True se la regola è un artefatto di offuscamento generico. */
    static boolean demote(String rule) {
        return rule != null && (DEMOTE_RULES.contains(rule) || rule.startsWith("obfuscator-"));
    }

    /** True se per l'origine indicata gli artefatti vanno soppressi. */
    static boolean demoteFor(Kind kind) {
        return kind == Kind.GAME || kind == Kind.LIB || kind == Kind.PROC || kind == Kind.JDK;
    }

    /**
     * Classifica una stringa di origine (CodeSource del dump): la copia
     * remappata Minecraft è GAME, i remapped/processed mods sono PROC, la
     * cartella mods è MOD, meta/libraries è LIB, il resto si decide sul file.
     */
    static Kind classify(String origin) {
        if (origin == null || origin.isBlank()) {
            return Kind.NONE;
        }
        String o = origin.toLowerCase(Locale.ROOT).replace("%20", " ");
        if (o.equals("bootstrap") || o.startsWith("jrt:") || o.startsWith("jdk.")) {
            return Kind.JDK;
        }
        if (o.contains("client-intermediary") || o.contains("remappedjars") || o.contains("/versions/")) {
            return Kind.GAME;
        }
        if (o.contains("/processedmods/") || o.contains("/remappedmods/")) {
            return Kind.PROC;
        }
        if (o.contains("/mods/")) {
            return Kind.MOD;
        }
        if (o.contains("/libraries/") || o.contains("/meta/") || o.contains("/.gradle/") || o.contains("/cache/")) {
            return Kind.LIB;
        }
        String p = toPath(origin);
        if (p != null) {
            if (p.toLowerCase(Locale.ROOT).contains("/libraries/")) {
                return Kind.LIB;
            }
            try {
                return Files.exists(Path.of(p)) ? Kind.OTHER : Kind.MISSING;
            } catch (Exception ignored) {
                return Kind.OTHER;
            }
        }
        return Kind.OTHER;
    }

    /** "file:/C:/…%20…/x.jar" → "C:\\… \\x.jar" (best-effort, null se non è un file). */
    static String toPath(String origin) {
        if (origin == null) {
            return null;
        }
        String o = origin;
        if (o.startsWith("file:")) {
            o = o.substring(5);
        } else {
            return null;
        }
        try {
            o = URLDecoder.decode(o, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // percent-encoding non valido: si tiene com'è
        }
        if (o.length() > 2 && o.charAt(0) == '/' && o.charAt(2) == ':') {
            o = o.substring(1);
        }
        return o;
    }

    /** Classe interna da una location "a/b/C.class::metodo" (null-safe). */
    static String classOf(String location) {
        if (location == null) {
            return "";
        }
        String s = location.split("::")[0];
        return s.endsWith(".class") ? s.substring(0, s.length() - 6) : s;
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    /**
     * Applica lo scoping a {@code findings} (mutata: rimuove i soppressi e
     * aggiunge i finding riassuntivi) e ritorna il riepilogo per la risposta
     * ({@code memoryScope}).
     */
    static Map<String, Object> apply(Path packedJar, List<Map<String, Object>> findings, Map<String, String> origins) {
        // Classi presenti nel dump impacchettato, con origine e categoria.
        Map<String, Kind> kinds = new LinkedHashMap<>();
        Map<String, String> originOf = new LinkedHashMap<>();
        Map<String, Integer> classesByOrigin = new LinkedHashMap<>();
        Map<Kind, Integer> kindCount = new LinkedHashMap<>();
        List<String> noOrigin = new ArrayList<>();
        try (JarFile jf = new JarFile(packedJar.toFile())) {
            Enumeration<JarEntry> en = jf.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (e.isDirectory() || !e.getName().endsWith(".class")) {
                    continue;
                }
                String cls = e.getName().substring(0, e.getName().length() - 6);
                String origin = origins.get(cls);
                Kind k = classify(origin);
                kinds.put(cls, k);
                originOf.put(cls, origin == null ? "" : origin);
                kindCount.merge(k, 1, Integer::sum);
                classesByOrigin.merge(origin == null ? "(senza origine)" : origin, 1, Integer::sum);
                if (k == Kind.NONE) {
                    noOrigin.add(cls);
                }
            }
        } catch (Exception ignored) {
            // jar non rileggibile: si prosegue col solo scoping dei finding
        }

        // Declassamento degli artefatti attesi su gioco/librerie/copie remappate.
        List<Map<String, Object>> kept = new ArrayList<>(findings.size());
        Map<String, Integer> suppressedByRule = new LinkedHashMap<>();
        int suppressed = 0;
        for (Map<String, Object> f : findings) {
            String rule = str(f.get("rule"));
            String cls = classOf(str(f.get("location")));
            Kind k = kinds.getOrDefault(cls, classify(originOf.get(cls)));
            if (demote(rule) && demoteFor(k)) {
                suppressed++;
                suppressedByRule.merge(rule, 1, Integer::sum);
                continue;
            }
            kept.add(f);
        }
        findings.clear();
        findings.addAll(kept);
        if (suppressed > 0) {
            StringBuilder detail = new StringBuilder();
            for (Map.Entry<String, Integer> e : suppressedByRule.entrySet()) {
                if (detail.length() > 0) {
                    detail.append(", ");
                }
                detail.append(e.getKey()).append('=').append(e.getValue());
            }
            findings.add(finding("mem-noise-suppressed",
                    "Offuscamento atteso su classi di gioco/librerie: " + suppressed
                            + " rilevamenti riassunti (non sono sospetti)",
                    "INFO", "OTHER", "(classi di gioco/librerie/copie remappate)",
                    "per regola: " + detail));
        }

        // Attribuzione finding → origine.
        Map<String, Integer> findingsByOrigin = new LinkedHashMap<>();
        for (Map<String, Object> f : findings) {
            String cls = classOf(str(f.get("location")));
            String origin = originOf.getOrDefault(cls, origins.getOrDefault(cls, ""));
            findingsByOrigin.merge(origin.isBlank() ? "(senza origine)" : origin, 1, Integer::sum);
        }
        List<Map<String, Object>> attribution = new ArrayList<>();
        List<String> originKeys = new ArrayList<>(classesByOrigin.keySet());
        originKeys.sort((a, b) -> Integer.compare(
                findingsByOrigin.getOrDefault(b, 0), findingsByOrigin.getOrDefault(a, 0)));
        for (String origin : originKeys) {
            if (attribution.size() >= 40) {
                break;
            }
            Kind k = classify(origin.equals("(senza origine)") ? null : origin);
            if (k == Kind.JDK) {
                continue;
            }
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("origin", origin);
            a.put("kind", k.name());
            a.put("classes", classesByOrigin.getOrDefault(origin, 0));
            a.put("findings", findingsByOrigin.getOrDefault(origin, 0));
            attribution.add(a);
        }

        // Bypassed: classi senza file, senza origine o da jar esterni.
        List<String> missingSamples = new ArrayList<>();
        int missingCount = 0;
        Map<String, Integer> external = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : originOf.entrySet()) {
            Kind k = kinds.get(e.getKey());
            if (k == Kind.MISSING) {
                missingCount++;
                if (missingSamples.size() < 8) {
                    missingSamples.add(e.getKey() + " ← " + e.getValue());
                }
            } else if (k == Kind.OTHER) {
                if (!e.getValue().toLowerCase(Locale.ROOT).contains("memagent")) {
                    external.merge(e.getValue(), 1, Integer::sum);
                }
            }
        }
        if (missingCount > 0) {
            findings.add(finding("mem-origin-missing",
                    missingCount + " classi caricate da jar non più presenti su disco",
                    "MEDIUM", "STRUCTURE", "(dump)",
                    "Esempi: " + String.join("; ", missingSamples)));
        }
        if (!noOrigin.isEmpty()) {
            List<String> samples = noOrigin.subList(0, Math.min(8, noOrigin.size()));
            findings.add(finding("mem-origin-unknown",
                    noOrigin.size() + " classi senza origine su file (possibile generazione a runtime)",
                    "MEDIUM", "CODE_INJECTION", "(dump)",
                    "Esempi: " + String.join("; ", samples)));
        }
        List<Map<String, Object>> externalList = new ArrayList<>();
        external.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(12)
                .forEach(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("origin", e.getKey());
                    m.put("classes", e.getValue());
                    externalList.add(m);
                });
        if (!externalList.isEmpty()) {
            StringBuilder detail = new StringBuilder();
            for (Map<String, Object> m : externalList) {
                if (detail.length() > 0) {
                    detail.append("; ");
                }
                detail.append(m.get("origin")).append(" (").append(m.get("classes")).append(" classi)");
            }
            findings.add(finding("mem-origin-external",
                    "Classi caricate da percorsi esterni alla cartella mods",
                    "INFO", "OTHER", "(dump)", detail.toString()));
        }

        Map<String, Object> bypassed = new LinkedHashMap<>();
        bypassed.put("missingOriginCount", missingCount);
        bypassed.put("missingOrigin", missingSamples);
        bypassed.put("noOriginCount", noOrigin.size());
        bypassed.put("noOrigin", noOrigin.subList(0, Math.min(8, noOrigin.size())));
        bypassed.put("externalCount", externalList.size());
        bypassed.put("external", externalList);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("suppressed", suppressed);
        out.put("suppressedByRule", suppressedByRule);
        Map<String, Object> kindOut = new LinkedHashMap<>();
        for (Map.Entry<Kind, Integer> e : kindCount.entrySet()) {
            kindOut.put(e.getKey().name(), e.getValue());
        }
        out.put("originKinds", kindOut);
        out.put("attribution", attribution);
        out.put("bypassed", bypassed);
        return out;
    }

    private static Map<String, Object> finding(String rule, String title, String severity,
            String category, String location, String evidence) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rule", rule);
        m.put("title", title);
        m.put("severity", severity);
        m.put("category", category);
        m.put("location", location);
        m.put("evidence", evidence);
        return m;
    }
}
