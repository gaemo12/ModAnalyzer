package modscan;

import com.jaranalyzer.common.JsonCodec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifica delle mod sui database online (funzione richiesta esplicitamente per questa edizione):
 * <ul>
 *   <li><b>Modrinth</b> — database principale delle mod verificate:
 *       {@code GET /v2/version_file/{sha1}} per il singolo file e
 *       {@code POST /v2/version_files} (massimo 100 hash per blocco) per la scansione della cartella.
 *       Se trovata, restituisce nome, version_number e project_id del rilascio ufficiale.</li>
 *   <li><b>Megabase</b> — database alternativo di mod note, di riserva quando Modrinth non trova
 *       corrispondenze: {@code GET https://megabase.vercel.app/api/query?hash={sha1}}; se trovata
 *       restituisce nome e slug del progetto.</li>
 * </ul>
 * Una mod trovata in uno dei due viene classificata <b>VERIFIED</b>. Non c'è alcun retry in
 * silenzio: un servizio non raggiungibile produce la nota esplicita "verifica non disponibile",
 * mai esiti inventati. Cache in memoria per non interrogare di nuovo lo stesso hash nella sessione.
 */
final class OpenModVerify {

    /** Esito positivo di una ricerca per hash. */
    record ModHit(String source, String name, String slug, String projectId, String version) {
    }

    private static final String MODRINTH_FILE_URL = "https://api.modrinth.com/v2/version_file/";
    private static final String MODRINTH_BATCH_URL = "https://api.modrinth.com/v2/version_files";
    private static final String MEGABASE_URL = "https://megabase.vercel.app/api/query";
    private static final String USER_AGENT = "ModScanOpen/1.0 (mod verification)";
    /** Modrinth consigliano identificazione via User-Agent: aggiungo un contatto generico. */
    private static final String UA = USER_AGENT + " (desktop; +https://github.com/jar-analyzer)";

    static final int BATCH_CHUNK = 100;

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(8))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    /** Cache sessione: hash (SHA-1) → hit o assenza. Costa pochi MB al massimo ragionevole. */
    private static final Map<String, Optional<ModHit>> CACHE = new ConcurrentHashMap<>();
    private static final int CACHE_MAX = 4_000;

    private OpenModVerify() {
    }

    /* ------------------------------------------------------------ singolo file */

    /** Ricerca Modrinth → (fallback) Megabase per un solo hash. null = nessuna corrispondenza. */
    static ModHit verify(String sha1) {
        if (sha1 == null || sha1.isBlank()) {
            return null;
        }
        String key = sha1.toLowerCase(Locale.ROOT);
        Optional<ModHit> cached = CACHE.get(key);
        if (cached != null) {
            return cached.orElse(null);
        }
        ModHit hit = modrinthSingle(key);
        if (hit == null) {
            hit = megabase(key);
        }
        remember(key, hit);
        return hit;
    }

    private static void remember(String key, ModHit hit) {
        if (CACHE.size() >= CACHE_MAX) {
            CACHE.clear();
        }
        CACHE.put(key, Optional.ofNullable(hit));
    }

    /* ------------------------------------------------------------ Modrinth */

    private static ModHit modrinthSingle(String sha1) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(MODRINTH_FILE_URL + sha1))
                    .timeout(Duration.ofSeconds(20))
                    .header("User-Agent", UA)
                    .GET().build();
            HttpResponse<String> resp = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 404) {
                return null;
            }
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("Modrinth ha risposto HTTP " + resp.statusCode());
            }
            Object parsed = JsonCodec.parse(resp.body());
            if (!(parsed instanceof Map)) {
                return null;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> v = (Map<String, Object>) parsed;
            String pid = str(v, "project_id");
            return new ModHit("Modrinth",
                    str(v, "name"),
                    null,
                    pid,
                    str(v, "version_number"));
        } catch (Exception e) {
            // Rete o API non disponibili: il chiamante produce la nota esplicita.
            throw new IllegalStateException("Modrinth non raggiungibile: " + e.getMessage(), e);
        }
    }

    /**
     * Ricerca batch su Modrinth: POST {hashes:[...], algorithm:"sha1"} → mappa hash→versione.
     * Blocchi di {@link #BATCH_CHUNK}; un blocco fallito fa fallire l'intera verifica
     * (nota esplicita, mai esiti parziali presentati come completi).
     */
    static Map<String, ModHit> modrinthBatch(List<String> sha1s) {
        Map<String, ModHit> out = new LinkedHashMap<>();
        List<String> todo = new ArrayList<>();
        for (String h : sha1s) {
            String key = h == null ? null : h.toLowerCase(Locale.ROOT);
            if (key == null || out.containsKey(key)) {
                continue;
            }
            if (CACHE.containsKey(key)) {
                ModHit c = CACHE.get(key).orElse(null);
                if (c != null) {
                    out.put(key, c);
                }
            } else {
                todo.add(key);
            }
        }
        for (int i = 0; i < todo.size(); i += BATCH_CHUNK) {
            List<String> chunk = todo.subList(i, Math.min(todo.size(), i + BATCH_CHUNK));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("hashes", chunk);
            body.put("algorithm", "sha1");
            HttpResponse<String> resp;
            try {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(MODRINTH_BATCH_URL))
                        .timeout(Duration.ofSeconds(20))
                        .header("User-Agent", UA)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JsonCodec.write(body)))
                        .build();
                resp = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                throw new IllegalStateException("Modrinth non raggiungibile: " + e.getMessage(), e);
            }
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("Modrinth ha risposto HTTP " + resp.statusCode());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> root = (Map<String, Object>) JsonCodec.parse(resp.body());
            if (root == null) {
                continue;
            }
            for (String key : chunk) {
                @SuppressWarnings("unchecked")
                Map<String, Object> v = (Map<String, Object>) root.get(key);
                if (v != null) {
                    ModHit hit = new ModHit("Modrinth", str(v, "name"), null, str(v, "project_id"), str(v, "version_number"));
                    out.put(key, hit);
                    remember(key, hit);
                }
            }
            for (String key : chunk) {
                if (!out.containsKey(key)) {
                    remember(key, null); // 404 implicito nel batch
                }
            }
        }
        return out;
    }

    /* ------------------------------------------------------------ Megabase */

    private static ModHit megabase(String sha1) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(MEGABASE_URL + "?hash=" + sha1))
                    .timeout(Duration.ofSeconds(15))
                    .header("User-Agent", UA)
                    .GET().build();
            HttpResponse<String> resp = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                return null;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> v = (Map<String, Object>) JsonCodec.parse(resp.body());
            if (v == null || Boolean.TRUE.equals(v.get("error"))) {
                return null;
            }
            String name = str(v, "name");
            String slug = str(v, "slug");
            if (name == null && slug == null) {
                return null;
            }
            return new ModHit("Megabase", name, slug, null, null);
        } catch (Exception e) {
            // Megabase non raggiungibile: non è fatale, la mod resta non verificata.
            return null;
        }
    }

    /* ------------------------------------------------------------ utilità */

    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : String.valueOf(v);
    }
}
