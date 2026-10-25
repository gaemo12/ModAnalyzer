package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.scanners.Severity;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Artefatti noti di cheat client nella cartella del gioco (screening SS):
 * cartelle e file di configurazione lasciai dai client più comuni
 * (Meteor, Future, Vape, RusherHack, …). I pattern vivono in
 * {@code rules/cheat-artifacts.json} (dati, non codice), nello stesso stile
 * delle regole IOC.
 *
 * <p>Privacy e anti-FP: si leggono SOLO i nomi (mai il contenuto dei file di
 * configurazione, che possono avere dati personali) e si matchano solo nomi
 * specifici di client (mai "config", "logs" o nomi generici). Ogni esito è
 * un indizio da confermare, non una prova.
 */
public final class CheatArtifacts {
    private static final Logger log = LoggerFactory.getLogger(CheatArtifacts.class);
    private static final String RESOURCE = "rules/cheat-artifacts.json";
    /** Profondità di scansione nella .minecraft (config/<nome> è a profondità 2). */
    private static final int MAX_DEPTH = 2;
    /** Tetto voci visitate e finding: cartelle di gioco sane non sono enormi. */
    private static final int MAX_VISITED = 20_000;
    private static final int MAX_FINDINGS = 40;

    /** Artefatto trovato su disco. */
    public record Artifact(String path, String name, String family, String severity) {
    }

    /** Pattern caricato dal file dati. */
    record Rule(String name, String match, String family, Severity severity) {
    }

    private static volatile List<Rule> rules;

    private CheatArtifacts() {
    }

    static List<Rule> rules() {
        List<Rule> r = rules;
        if (r == null) {
            synchronized (CheatArtifacts.class) {
                r = rules;
                if (r == null) {
                    r = load();
                    rules = r;
                }
            }
        }
        return r;
    }

    /** Carica i pattern da classpath (tollerante: file assente = lista vuota). */
    static List<Rule> load() {
        List<Rule> out = new ArrayList<>();
        try (InputStream in = CheatArtifacts.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            if (in == null) {
                log.warn("{} assente: controllo artefatti cheat disattivato", RESOURCE);
                return List.of();
            }
            Object root = JsonCodec.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8))
                    .get("artifacts");
            if (!(root instanceof List<?> list)) {
                log.warn("{}: radice senza array 'artifacts'", RESOURCE);
                return List.of();
            }
            int dropped = 0;
            for (Object o : list) {
                if (!(o instanceof Map<?, ?> m)) {
                    continue;
                }
                try {
                    String name = String.valueOf(m.get("name")).trim().toLowerCase(Locale.ROOT);
                    if (name.isBlank()) {
                        throw new IllegalArgumentException("nome vuoto");
                    }
                    Object matchObj = m.get("match");
                    String match = matchObj == null ? "exact" : String.valueOf(matchObj).trim();
                    if (!match.equals("exact") && !match.equals("prefix") && !match.equals("contains")) {
                        throw new IllegalArgumentException("match non valido: " + match);
                    }
                    Object familyObj = m.get("family");
                    Object sevObj = m.get("severity");
                    out.add(new Rule(name, match,
                            familyObj == null ? name : String.valueOf(familyObj),
                            Severity.valueOf((sevObj == null ? "MEDIUM" : String.valueOf(sevObj))
                                    .toUpperCase(Locale.ROOT))));
                } catch (Exception e) {
                    dropped++;
                    log.warn("{}: pattern scartato: {}", RESOURCE, e.getMessage());
                }
            }
            if (dropped > 0) {
                log.warn("{}: {} pattern scartati", RESOURCE, dropped);
            }
            log.info("Pattern artefatti cheat caricati: {}", out.size());
        } catch (Exception e) {
            log.warn("Lettura {} fallita: {}", RESOURCE, e.getMessage());
            return List.of();
        }
        return List.copyOf(out);
    }

    /**
     * Cerca gli artefatti noti dentro la cartella del gioco (di solito la
     * padre della cartella mods). Solo nomi, profondità {@link #MAX_DEPTH},
     * mai contenuto dei file.
     */
    public static List<Artifact> scan(Path gameDir) throws IOException {
        List<Artifact> out = new ArrayList<>();
        if (gameDir == null || !Files.isDirectory(gameDir)) {
            return out;
        }
        List<Rule> patterns = rules();
        if (patterns.isEmpty()) {
            return out;
        }
        long[] visited = {0};
        try (Stream<Path> walk = Files.walk(gameDir, MAX_DEPTH)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (visited[0]++ > MAX_VISITED || out.size() >= MAX_FINDINGS) {
                    break;
                }
                String name = p.getFileName() == null ? "" : p.getFileName().toString();
                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.isEmpty() || lower.startsWith("latest") || lower.endsWith(".log")) {
                    continue;
                }
                for (Rule r : patterns) {
                    boolean hit = switch (r.match()) {
                        case "prefix" -> lower.startsWith(r.name());
                        case "contains" -> lower.contains(r.name());
                        default -> lower.equals(r.name());
                    };
                    if (hit) {
                        String shown = gameDir.relativize(p).toString().replace('\\', '/');
                        out.add(new Artifact(shown.isEmpty() ? name : shown,
                                name, r.family(), r.severity().name()));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            // best-effort: si restituisce quanto trovato fin qui
            log.debug("Scansione artefatti interrotta: {}", e.getMessage());
        }
        return out;
    }
}
