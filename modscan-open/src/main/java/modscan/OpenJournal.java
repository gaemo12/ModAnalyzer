package modscan;

import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.scanners.engine.ModsTimeline;
import com.jaranalyzer.scanners.engine.ProcessInventory;
import com.jaranalyzer.scanners.engine.Sanitizer;
import com.jaranalyzer.scanners.engine.UsnJournal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Controllo "mod modificate dopo l'avvio di Minecraft" (reimplementazione
 * clean-room del flusso omonimo di RedLotus Mod Analyzer 2.0):
 * <ol>
 *   <li>trova la cartella mods (parametro {@code path} oppure rilevamento
 *       automatico dal processo javaw attivo, come la sezione Mods);</li>
 *   <li>trova l'istante di avvio del processo Minecraft (il javaw più recente
 *       con indicatori Minecraft, oppure {@code pid} esplicito);</li>
 *   <li>confronta creazione/modifica di ogni file con quell'istante
 *       ({@link ModsTimeline}: niente privilegi richiesti);</li>
 *   <li>se richiesto, incrocia il journal USN di NTFS per vedere anche
 *       eliminazioni e rinomine avvenute durante il gioco
 *       ({@link UsnJournal}: best-effort, nota chiara se serve admin).</li>
 * </ol>
 */
final class OpenJournal {

    private OpenJournal() {
    }

    /**
     * {@code GET /api/mods/journal?path=…&pid=…&after=…&usn=1}.
     * {@code after} (epoch millis o ISO) serve per prove e scenari senza gioco attivo.
     */
    static OpenApi.Response check(String pathParam, String pidParam, String afterParam, String usnParam) {
        try {
            Path dir;
            if (pathParam != null && !pathParam.isBlank()) {
                dir = Path.of(pathParam.trim());
            } else {
                dir = autoLocate();
            }
            if (dir == null || !Files.isDirectory(dir)) {
                return bad("Cartella mods non valida", "Indica path=… oppure avvia Minecraft per il rilevamento automatico.");
            }

            long since;
            Map<String, Object> game = null;
            if (afterParam != null && !afterParam.isBlank()) {
                since = parseAfter(afterParam.trim());
                if (since <= 0) {
                    return bad("Parametro after non valido", "Usa epoch millis oppure una data ISO (es. 2026-10-16T22:46:00).");
                }
            } else {
                game = findGame(pidParam);
                if (game == null) {
                    return bad("Nessun processo Minecraft attivo",
                            "Avvia il gioco (javaw) oppure indica pid=… o after=<data>.");
                }
                since = ((Number) game.get("start")).longValue();
            }

            ModsTimeline.Result tl = ModsTimeline.check(dir, since);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("modsDir", tl.modsDir());
            body.put("since", since);
            body.put("game", game);
            Map<String, Object> counts = new LinkedHashMap<>();
            counts.put("checked", tl.files());
            counts.put("added", tl.added());
            counts.put("modified", tl.modified());
            body.put("counts", counts);
            List<Map<String, Object>> suspects = new ArrayList<>();
            for (ModsTimeline.Entry e : tl.suspects()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fileName", e.fileName());
                m.put("path", e.path());
                m.put("size", e.size());
                m.put("created", e.createdMillis());
                m.put("modified", e.modifiedMillis());
                m.put("state", e.state());
                suspects.add(m);
            }
            body.put("suspects", suspects);
            Set<String> present = new HashSet<>();
            for (ModsTimeline.Entry e : tl.entries()) {
                present.add(e.fileName().toLowerCase(Locale.ROOT));
            }
            Map<String, Object> journal = journalSection(dir, since, usnParam, present);
            body.put("journal", journal);
            Object gone = journal.get("gone");
            counts.put("gone", gone instanceof List ? ((List<?>) gone).size() : 0);
            return new OpenApi.Response(200, JsonCodec.write(body));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new OpenApi.Response(500, JsonCodec.write(Map.of("error", "Controllo journal fallito", "message", m)));
        }
    }

    /* ------------------------------------------------------------ processo di gioco */

    /**
     * Cartella mods automatica: prima il rilevamento della sezione Mods
     * (processi javaw attivi, user.dir/--gameDir via jcmd), poi il fallback
     * {@code ~/.minecraft/mods}.
     */
    static Path autoLocate() {
        try {
            OpenApi.Response r = OpenMods.locate();
            if (r.status == 200) {
                Object best = JsonCodec.parseObject(r.body).get("best");
                if (best instanceof Map) {
                    Object p = ((Map<?, ?>) best).get("path");
                    Object exists = ((Map<?, ?>) best).get("exists");
                    if (p != null && !Boolean.FALSE.equals(exists)) {
                        return Path.of(String.valueOf(p));
                    }
                }
            }
        } catch (Exception ignored) {
            // si passa al fallback
        }
        return ModScanOpen.Cli.locate();
    }

    /**
     * Processo Minecraft di riferimento: {@code pid} esplicito, altrimenti il
     * javaw/java con indicatori Minecraft avviato più di recente (l'istanza
     * attualmente in gioco). Null se non esiste.
     */
    static Map<String, Object> findGame(String pidParam) {
        List<ProcessInventory.ProcInfo> procs = ProcessInventory.snapshot();
        ProcessInventory.ProcInfo pick = null;
        if (pidParam != null && !pidParam.isBlank() && !"auto".equalsIgnoreCase(pidParam)) {
            long pid;
            try {
                pid = Long.parseLong(pidParam.trim());
            } catch (NumberFormatException e) {
                return null;
            }
            for (ProcessInventory.ProcInfo p : procs) {
                if (p.pid() == pid) {
                    pick = p;
                    break;
                }
            }
            if (pick == null || pick.startEpochMillis() <= 0) {
                return null;
            }
        } else {
            for (ProcessInventory.ProcInfo p : procs) {
                if (!p.java() || !p.minecraftLike() || p.startEpochMillis() <= 0) {
                    continue;
                }
                if (pick == null || p.startEpochMillis() > pick.startEpochMillis()) {
                    pick = p;
                }
            }
        }
        if (pick == null) {
            return null;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pid", pick.pid());
        m.put("exe", pick.executable());
        m.put("start", pick.startEpochMillis());
        String cmd = pick.commandLine() == null ? "" : pick.commandLine();
        try {
            cmd = Sanitizer.redactHome(cmd, System.getProperty("user.home", ""));
        } catch (Exception ignored) {
            // riga comando al grezzo
        }
        m.put("cmd", cmd.length() > 200 ? cmd.substring(0, 200) + "…" : cmd);
        m.put("minecraftLike", pick.minecraftLike());
        return m;
    }

    /* ------------------------------------------------------------ journal USN */

    private static Map<String, Object> journalSection(Path dir, long since, String usnParam, Set<String> present) {
        Map<String, Object> journal = new LinkedHashMap<>();
        journal.put("available", false);
        journal.put("truncated", false);
        journal.put("deleted", 0);
        List<Map<String, Object>> events = new ArrayList<>();
        journal.put("events", events);
        /* Storia per file (solo file ancora presenti) e file spariti dopo l'avvio. */
        journal.put("files", new LinkedHashMap<String, Object>());
        journal.put("gone", new ArrayList<Map<String, Object>>());

        boolean wantUsn = usnParam != null && !"0".equals(usnParam) && !"false".equalsIgnoreCase(usnParam);
        if (!wantUsn) {
            journal.put("note", "Journal USN non richiesto: controllati solo gli orari dei file.");
            return journal;
        }
        if (!UsnJournal.isWindows()) {
            journal.put("note", "Journal USN disponibile solo su Windows.");
            return journal;
        }
        try {
            String volume = volumeOf(dir);
            UsnJournal.Query q = UsnJournal.query(volume);
            if (q == null) {
                journal.put("note", "Journal USN non disponibile sul volume " + volume + ".");
                return journal;
            }
            long startUsn = UsnJournal.usnForTime(volume, since, q, 6_000);
            String base = dir.toAbsolutePath().toString().replace('/', '\\').toLowerCase(Locale.ROOT);
            while (base.endsWith("\\")) {
                base = base.substring(0, base.length() - 1);
            }
            final String baseLower = base;
            final String vol = volume;
            /* Se fsutil riporta solo il nome (senza percorso) si attribuiscono gli eventi ai file
               attualmente presenti nella cartella: così la storia di una mod non va persa. */
            UsnJournal.Read rr = UsnJournal.readEvents(volume, startUsn,
                    file -> underVolume(file, vol, baseLower)
                            || (!hasSeparator(file) && present.contains(file.toLowerCase(Locale.ROOT))),
                    20_000, 2000);
            List<UsnJournal.Event> evs = new ArrayList<>(rr.events());
            evs.sort(Comparator.comparingLong(UsnJournal.Event::usn));
            Map<String, List<Map<String, Object>>> perFile = new LinkedHashMap<>();
            Map<String, String> renamedTo = new LinkedHashMap<>();
            Map<String, Map<String, Object>> gone = new LinkedHashMap<>();
            String pendingOld = null;
            long pendingTime = 0;
            int deleted = 0;
            for (UsnJournal.Event e : evs) {
                String name = baseName(e.file());
                String lname = name.toLowerCase(Locale.ROOT);
                String kind = reasonKind(e.reason());
                Map<String, Object> em = new LinkedHashMap<>();
                em.put("usn", e.usn());
                em.put("file", e.file());
                em.put("reason", e.reason());
                em.put("kind", kind);
                em.put("time", e.timeMillis());
                if ("renamed_from".equals(kind)) {
                    pendingOld = name;
                    pendingTime = e.timeMillis();
                } else if ("renamed_to".equals(kind) && pendingOld != null
                        && Math.abs(e.timeMillis() - pendingTime) <= 2000) {
                    em.put("from", pendingOld);
                    renamedTo.put(pendingOld.toLowerCase(Locale.ROOT), name);
                    pendingOld = null;
                }
                events.add(em);
                if ("deleted".equals(kind) || "renamed".equals(kind) || "renamed_from".equals(kind)) {
                    deleted++;
                }
                if (present.contains(lname)) {
                    perFile.computeIfAbsent(lname, k -> new ArrayList<>()).add(em);
                }
            }
            for (UsnJournal.Event e : evs) {
                String kind = reasonKind(e.reason());
                if (!"deleted".equals(kind) && !"renamed_from".equals(kind) && !"renamed".equals(kind)) {
                    continue;
                }
                String name = baseName(e.file());
                String lname = name.toLowerCase(Locale.ROOT);
                if (present.contains(lname) || !interesting(name)) {
                    continue;
                }
                Map<String, Object> g = new LinkedHashMap<>();
                g.put("fileName", name);
                g.put("kind", "deleted".equals(kind) ? "deleted" : "renamed");
                g.put("time", e.timeMillis());
                String to = renamedTo.get(lname);
                if (to != null) {
                    g.put("renamedTo", to);
                }
                gone.put(lname, g);
            }
            Map<String, Object> files = new LinkedHashMap<>();
            for (Map.Entry<String, List<Map<String, Object>>> en : perFile.entrySet()) {
                List<Map<String, Object>> l = en.getValue();
                files.put(en.getKey(), l.size() > 40 ? new ArrayList<>(l.subList(l.size() - 40, l.size())) : l);
            }
            journal.put("files", files);
            journal.put("gone", new ArrayList<>(gone.values()));
            journal.put("available", true);
            journal.put("truncated", rr.truncated());
            journal.put("deleted", deleted);
            journal.put("note", "Eventi del journal USN dalla cartella mods dopo l'avvio del gioco"
                    + (rr.truncated() ? " (elenco troncato a 2000 eventi)" : "") + ".");
            return journal;
        } catch (UsnJournal.AccessDenied ad) {
            journal.put("note", "Il journal di Windows non è leggibile senza privilegi di amministratore:"
                    + " vedi solo i file aggiunti o modificati, non quelli spariti o rinominati."
                    + " Avvia ModScanOpen come amministratore per il controllo completo.");
            return journal;
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            journal.put("note", "Journal USN: " + m);
            return journal;
        }
    }

    static boolean underVolume(String file, String volume, String baseLower) {
        String f = file == null ? "" : file;
        if (f.startsWith("\\")) {
            f = volume + f;
        }
        String norm = f.replace('/', '\\').toLowerCase(Locale.ROOT);
        return norm.equals(baseLower) || norm.startsWith(baseLower + "\\");
    }

    private static String volumeOf(Path dir) {
        Path root = dir.toAbsolutePath().getRoot();
        String r = root == null ? "C:\\" : root.toString();
        return r.length() >= 2 ? r.substring(0, 2) : "C:";
    }

    private static boolean hasSeparator(String file) {
        return file != null && (file.indexOf('\\') >= 0 || file.indexOf('/') >= 0);
    }

    /** Ultimo componente del percorso (il journal può riportare percorso completo o solo il nome). */
    static String baseName(String file) {
        if (file == null) {
            return "";
        }
        int i = Math.max(file.lastIndexOf('\\'), file.lastIndexOf('/'));
        return i >= 0 ? file.substring(i + 1) : file;
    }

    /** Esclude temporanei e file senza estensione (cartelle, lock, download parziali). */
    static boolean interesting(String name) {
        String n = name == null ? "" : name.toLowerCase(Locale.ROOT);
        if (n.isEmpty() || n.indexOf('.') < 0 || n.startsWith("~$") || n.endsWith("~")) {
            return false;
        }
        for (String ext : new String[] { ".tmp", ".temp", ".part", ".crdownload", ".lock", ".bak~" }) {
            if (n.endsWith(ext)) {
                return false;
            }
        }
        return true;
    }

    static String reasonKind(String reason) {
        String r = reason == null ? "" : reason.toLowerCase(Locale.ROOT);
        if (r.contains("delete")) {
            return "deleted";
        }
        if (r.contains("rename: old") || r.contains("old name")) {
            return "renamed_from";
        }
        if (r.contains("rename: new") || r.contains("new name")) {
            return "renamed_to";
        }
        if (r.contains("rename")) {
            return "renamed";
        }
        if (r.contains("basic info") || r.contains("security change")) {
            return "attrs";
        }
        if (r.contains("file create") || r.contains("data extend") || r.contains("data overwrite")
                || r.contains("data truncation")) {
            return "written";
        }
        if (r.contains("close")) {
            return "closed";
        }
        return "other";
    }

    /* ------------------------------------------------------------ utilità */

    /** Epoch millis, ISO-8601 oppure "2026-10-16 22:46" (ora locale). */
    static long parseAfter(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException ignored) {
            // altri formati
        }
        try {
            return java.time.Instant.parse(s).toEpochMilli();
        } catch (Exception ignored) {
            // altri formati
        }
        try {
            return java.time.OffsetDateTime.parse(s).toInstant().toEpochMilli();
        } catch (Exception ignored) {
            // altri formati
        }
        try {
            java.time.LocalDateTime ldt = java.time.LocalDateTime.parse(s.replace(' ', 'T'));
            return ldt.atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        } catch (Exception ignored) {
            return 0L;
        }
    }

    private static OpenApi.Response bad(String error, String message) {
        return new OpenApi.Response(400, JsonCodec.write(Map.of("error", error, "message", message)));
    }
}
