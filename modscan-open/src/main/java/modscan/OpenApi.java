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
 *   <li>{@code POST /api/mem/dump} — memory-dump opt-in (pid=…|auto): dump del
 *   bytecode via agent, analisi col motore locale</li>
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
                case "GET /api/mem/processes":
                    return memProcesses();
                case "POST /api/mem/dump":
                    return memDump(params.get("pid"));
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

    /** Processi Java tra cui scegliere il bersaglio del dump (niente auto cieco). */
    static Response memProcesses() {
        try {
            java.util.List<Map<String, Object>> out = new java.util.ArrayList<>();
            for (com.jaranalyzer.scanners.engine.ProcessInventory.ProcInfo p
                    : com.jaranalyzer.scanners.engine.ProcessInventory.snapshot()) {
                if (!p.java()) {
                    continue;
                }
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("pid", p.pid());
                String exe = p.executable() == null ? "" : p.executable();
                int s = Math.max(exe.lastIndexOf('/'), exe.lastIndexOf('\\'));
                m.put("exe", s >= 0 ? exe.substring(s + 1) : exe);
                String cmd = p.commandLine() == null ? "" : p.commandLine();
                try {
                    cmd = com.jaranalyzer.scanners.engine.Sanitizer.redactHome(
                            cmd, System.getProperty("user.home", ""));
                } catch (Exception ignored) {
                    // riga comando al grezzo
                }
                m.put("cmd", cmd.length() > 160 ? cmd.substring(0, 160) + "…" : cmd);
                m.put("minecraftLike", p.minecraftLike());
                out.add(m);
            }
            return ok(Map.of("processes", out));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new Response(500, JsonCodec.write(Map.of("error", "Elenco processi fallito", "message", m)));
        }
    }

    /**
     * Memory-dump opt-in via GUI: attach al pid, dump impacchettato e analisi
     * con la stessa forma di {@code analyzeLocal} (kind {@code mem} +
     * processInfo per la vista processo della UI).
     */
    static Response memDump(String pidSpec) {
        try {
            String pid = MemDump.resolvePid(pidSpec == null || pidSpec.isBlank() ? "auto" : pidSpec);
            java.nio.file.Path workDir = java.nio.file.Path.of(
                    System.getProperty("java.io.tmpdir", "."), "modscan-mem");
            java.nio.file.Path packed = MemDump.capture(pid, ModScanOpen.Cli.agentJar(), workDir);
            Response base = OpenAnalysis.analyzeLocal(packed.toString());
            if (base.status != 200) {
                return base;
            }
            Map<String, Object> body = new LinkedHashMap<>(JsonCodec.parseObject(base.body));
            Object fo = body.get("findings");
            if (fo instanceof java.util.List) {
                Map<String, String> origins = MemDump.readOrigins(workDir.resolve("classes-" + pid));
                for (Object o : (java.util.List<?>) fo) {
                    if (o instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> fm = (Map<String, Object>) o;
                        MemDump.attachOrigin(fm, origins);
                    }
                }
            }
            body.put("kind", "mem");
            body.put("module", "mem_dump");
            body.put("source", "memory");
            body.put("pid", pid);
            body.put("file", packed.getFileName().toString());
            String procName = "";
            try {
                procName = ProcessHandle.of(Long.parseLong(pid)).map(h -> h.info())
                        .map(i -> i.command().orElse("")).orElse("");
            } catch (Exception ignored) {
                // nome processo facoltativo
            }
            Object classes = 0;
            try {
                Object meta = body.get("metadata");
                if (meta instanceof Map) {
                    Object cc = ((Map<?, ?>) meta).get("classCount");
                    if (cc instanceof Number) {
                        classes = ((Number) cc).intValue();
                    }
                }
            } catch (Exception ignored) {
                // conteggio facoltativo
            }
            Map<String, Object> proc = new LinkedHashMap<>();
            proc.put("processName", procName);
            proc.put("pid", pid);
            proc.put("loadedClassCount", classes);
            body.put("processInfo", proc);
            return new Response(200, JsonCodec.write(body));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new Response(500, JsonCodec.write(Map.of("error", "Memory dump fallito", "message", m)));
        }
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
