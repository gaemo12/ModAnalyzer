package modscan;

import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.engine.CheatArtifacts;
import com.jaranalyzer.scanners.engine.GameCommandLine;
import com.jaranalyzer.scanners.engine.LoadedModsLog;
import com.jaranalyzer.scanners.engine.MinecraftPathResolver;
import com.jaranalyzer.scanners.engine.Sanitizer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Controllo "runtime" (v1.3.0, screening SS): cosa è effettivamente in
 * esecuzione rispetto a cosa c'è su disco.
 * <ol>
 *   <li><b>Riga di comando del processo di gioco</b> ({@link GameCommandLine}):
 *       -javaagent, -Xbootclasspath, --tweakClass non standard, classpath fuori
 *       dai launcher noti, anti-attach;</li>
 *   <li><b>Mod caricate vs mod su disco</b> ({@link LoadedModsLog}): parsing di
 *       {@code logs/latest.log} (Fabric/Quilt per id, Forge per nome file) e
 *       confronto con gli id dichiarati dai jar della cartella mods, JiJ annidati
 *       inclusi. La differenza "caricata ma non su disco" è il segnale classico
 *       del client ghost iniettato;</li>
 *   <li><b>Artefatti noti di cheat client</b> ({@link CheatArtifacts}) nella
 *       cartella del gioco: solo nomi, mai contenuto.</li>
 * </ol>
 * Tutto locale e best-effort: ogni sezione dichiara cosa non ha potuto leggere
 * invece di inventare esiti. {@code GET /api/mods/runtime?path=…&pid=…}.
 */
final class OpenRuntime {

    private OpenRuntime() {
    }

    static OpenApi.Response check(String pathParam, String pidParam) {
        try {
            Path modsDir;
            if (pathParam != null && !pathParam.isBlank()) {
                modsDir = MinecraftPathResolver.resolveModsDir(Path.of(pathParam.trim()));
            } else {
                modsDir = MinecraftPathResolver.resolveModsDir(OpenJournal.autoLocate());
            }
            if (modsDir == null || !Files.isDirectory(modsDir)) {
                return bad("Cartella mods non valida",
                        "Indica path=… oppure avvia Minecraft per il rilevamento automatico.");
            }
            Path gameDir = MinecraftPathResolver.gameDirOfMods(modsDir);

            Map<String, Object> game = OpenJournal.findGame(pidParam);
            long gameStart = game == null ? 0L : ((Number) game.get("start")).longValue();
            List<Map<String, Object>> cmdFindings = cmdFindings(game);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("modsDir", modsDir.toAbsolutePath().toString().replace('\\', '/'));
            out.put("gameDir", gameDir == null ? null : gameDir.toAbsolutePath().toString().replace('\\', '/'));
            out.put("game", game);
            out.put("cmdFindings", cmdFindings);
            out.put("logDiff", logDiff(gameDir, modsDir, gameStart));
            out.put("artifacts", artifacts(gameDir));
            out.put("crashLogs", crashLogs(gameDir));
            out.put("counts", counts(out));
            return new OpenApi.Response(200, JsonCodec.write(out));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new OpenApi.Response(500, JsonCodec.write(Map.of(
                    "error", "Controllo runtime fallito", "message", m)));
        }
    }

    /* ------------------------------------------------------------ riga di comando */

    private static List<Map<String, Object>> cmdFindings(Map<String, Object> game) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (game == null) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("note", "Nessun processo di gioco attivo: riga di comando non controllabile.");
            out.add(m);
            return out;
        }
        String cmd = fullCommandLine(game);
        if (cmd.isBlank() || "null".equals(cmd)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("note", "Riga di comando non leggibile per il processo " + game.get("pid") + ".");
            out.add(m);
            return out;
        }
        for (GameCommandLine.Flag f : GameCommandLine.check(cmd)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("flag", f.flag());
            m.put("severity", f.severity().name());
            m.put("title", f.title());
            m.put("detail", f.detail());
            out.add(m);
        }
        return out;
    }

    /* ------------------------------------------------------------ log vs disco */

    private static Map<String, Object> logDiff(Path gameDir, Path modsDir, long gameStart) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            LoadedModsLog.Result r = LoadedModsLog.diff(gameDir, modsDir, gameStart);
            out.put("logFound", r.logFound());
            out.put("logFile", r.logFile());
            out.put("logModified", r.logModifiedMillis());
            out.put("stale", r.stale());
            out.put("format", r.format());
            out.put("loadedCount", r.loadedCount());
            out.put("diskCount", r.diskCount());
            out.put("loadedNotOnDisk", ghosts(r));
            out.put("onDiskNotLoaded", r.onDiskNotLoaded());
            out.put("loadedFilesNotOnDisk", r.loadedFilesNotOnDisk());
            out.put("notes", r.notes());
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            out.put("error", m);
        }
        return out;
    }

    /** Id caricati senza jar: severità piena o declassata se il log è vecchio. */
    private static List<Map<String, Object>> ghosts(LoadedModsLog.Result r) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String id : r.loadedNotOnDisk()) {
            String flag = cheatFlagOf(id);
            Severity sev = flag != null ? Severity.HIGH : Severity.MEDIUM;
            if (r.stale()) {
                sev = sev == Severity.HIGH ? Severity.MEDIUM : Severity.LOW;
            }
            String detail;
            if (flag != null) {
                detail = "Id caricato a runtime senza jar su disco, e combacia con l'indicatore di cheat «"
                        + flag + "».";
            } else {
                detail = "Caricata dal loader ma nessun jar nella cartella mods dichiara questo id"
                        + " (niente builtin del loader, niente JiJ annidati).";
            }
            if (r.stale()) {
                detail += " Nota: il log si riferisce alla sessione precedente.";
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("severity", sev.name());
            if (flag != null) {
                m.put("cheatFlag", flag);
            }
            m.put("detail", detail);
            out.add(m);
        }
        return out;
    }

    /** Primo quick-flag contenuto nell'id (stessa lista del controllo cartella). */
    static String cheatFlagOf(String id) {
        return com.jaranalyzer.scanners.engine.ModsFolderAudit.flagInId(id,
                java.util.List.of(OpenMods.quickFlagPrefixes()));
    }

    /* ------------------------------------------------------------ artefatti */

    private static List<Map<String, Object>> artifacts(Path gameDir) {
        List<Map<String, Object>> out = new ArrayList<>();
        try {
            for (CheatArtifacts.Artifact a : CheatArtifacts.scan(gameDir)) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("path", a.path());
                m.put("name", a.name());
                m.put("family", a.family());
                m.put("severity", a.severity());
                out.add(m);
            }
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("error", m);
            out.add(err);
        }
        return out;
    }

    /* ------------------------------------------------------------ crash report */

    private static List<Map<String, Object>> crashLogs(Path gameDir) {
        List<Map<String, Object>> out = new ArrayList<>();
        try {
            for (com.jaranalyzer.scanners.engine.CrashLogs.Trace t
                    : com.jaranalyzer.scanners.engine.CrashLogs.scan(gameDir)) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("file", t.file());
                m.put("kind", t.kind());
                m.put("modified", t.modifiedMillis());
                m.put("flags", t.flags());
                out.add(m);
            }
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("error", m);
            out.add(err);
        }
        return out;
    }

    /* ------------------------------------------------------------ riepilogo */

    private static Map<String, Object> counts(Map<String, Object> body) {
        /* Solo i finding veri (hanno "flag"): le voci "note" informative non contano. */
        int cmd = 0;
        for (Object o : (List<?>) body.getOrDefault("cmdFindings", List.of())) {
            if (o instanceof Map<?, ?> m && m.get("flag") != null) {
                cmd++;
            }
        }
        Object ld = body.get("logDiff");
        int ghosts = 0;
        int fileGhosts = 0;
        if (ld instanceof Map<?, ?> m) {
            if (m.get("loadedNotOnDisk") instanceof List<?> l) {
                ghosts = l.size();
            }
            if (m.get("loadedFilesNotOnDisk") instanceof List<?> l) {
                fileGhosts = l.size();
            }
        }
        int arts = 0;
        for (Object o : (List<?>) body.getOrDefault("artifacts", List.of())) {
            if (o instanceof Map<?, ?> m && m.get("name") != null) {
                arts++;
            }
        }
        int crash = 0;
        for (Object o : (List<?>) body.getOrDefault("crashLogs", List.of())) {
            if (o instanceof Map<?, ?> m && m.get("flags") instanceof List<?> l && !l.isEmpty()) {
                crash += l.size();
            }
        }
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("cmdFindings", cmd);
        c.put("loadedNotOnDisk", ghosts);
        c.put("loadedFilesNotOnDisk", fileGhosts);
        c.put("artifacts", arts);
        c.put("crashFlags", crash);
        c.put("suspects", cmd + ghosts + fileGhosts + arts + crash);
        return c;
    }

    /* Il confronto col processo usa la riga di comando completa (redatta qui):
       la versione corta esposta da findGame tronca a 200 caratteri. */
    static String fullCommandLine(Map<String, Object> game) {
        if (game == null) {
            return "";
        }
        Object pid = game.get("pid");
        try {
            for (com.jaranalyzer.scanners.engine.ProcessInventory.ProcInfo p
                    : com.jaranalyzer.scanners.engine.ProcessInventory.snapshot()) {
                if (String.valueOf(p.pid()).equals(String.valueOf(pid))) {
                    return Sanitizer.redactHome(p.commandLine() == null ? "" : p.commandLine(),
                            System.getProperty("user.home", ""));
                }
            }
        } catch (Exception ignored) {
            // snapshot non disponibile: si usa la versione corta
        }
        return String.valueOf(game.getOrDefault("cmd", ""));
    }

    private static OpenApi.Response bad(String error, String message) {
        return new OpenApi.Response(400, JsonCodec.write(Map.of("error", error, "message", message)));
    }
}
