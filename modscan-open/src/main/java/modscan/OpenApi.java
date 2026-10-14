package modscan;

import com.jaranalyzer.common.JsonCodec;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Router delle chiamate API della UI, versione open source: sostituisce il server web della
 * vecchia app ma espone SOLO le rotte servibili in locale e in offline:
 * <ul>
 *   <li>{@code POST /api/analyze-local} — analisi completa (motore locale) di un file .jar per percorso</li>
 *   <li>{@code GET /api/mods/folder?path=…} — elenco e stato delle mod di una cartella (nessun servizio esterno)</li>
 *   <li>{@code GET /api/mods/locate} — ricerca della cartella mods tra i processi javaw attivi</li>
 *   <li>{@code GET /api/health} — controllo che il bridge risponda</li>
 * </ul>
 * Nessuna rotta di licenza, nessun backend: la risposta JSON ha la stessa forma della vecchia
 * interfaccia perché la UI sia identica.
 */
public final class OpenApi {

    /** Limite fisico sulla dimensione dei .jar accettati (come la vecchia app: 512 MB). */
    public static final long MAX_LOCAL_JAR_BYTES = 512L * 1024 * 1024;

    /** Risposta: stato (200, 400, ...) e corpo JSON. */
    public static final class Response {
        public final int status;
        public final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    public Response handle(String method, String url, String body) {
        try {
            String path = url;
            String query = "";
            int q = url == null ? -1 : url.indexOf('?');
            if (q >= 0) {
                path = url.substring(0, q);
                query = url.substring(q + 1);
            }
            Map<String, String> params = new LinkedHashMap<>();
            parseForm(query, params);
            if (body != null && !body.isBlank()) {
                parseForm(body, params);
            }
            String route = (method == null ? "GET" : method.toUpperCase(Locale.ROOT)) + " " + path;
            switch (route) {
                case "GET /api/health":
                    return ok(Map.of("status", "ok", "app", "ModScanOpen", "openSource", true));
                case "POST /api/analyze-local":
                    return OpenAnalysis.analyzeLocal(params.get("path"));
                case "GET /api/mods/folder":
                    return OpenMods.folder(params.get("path"));
                case "GET /api/mods/locate":
                    return OpenMods.locate();
                default:
                    return new Response(404, JsonCodec.write(Map.of(
                            "error", "Not Found",
                            "message", "Funzione non disponibile in ModScanOpen (solo JAR e Mods): " + route)));
            }
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new Response(500, JsonCodec.write(Map.of("error", "Internal Server Error", "message", m)));
        }
    }

    private static Response ok(Object payload) {
        return new Response(200, JsonCodec.write(payload));
    }

    static void parseForm(String s, Map<String, String> into) {
        if (s == null || s.isEmpty()) {
            return;
        }
        for (String pair : s.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            into.put(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
    }
}
