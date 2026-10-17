package modscan;

import com.jaranalyzer.scanners.engine.ProcessInventory;
import com.sun.tools.attach.VirtualMachine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

/**
 * Memory-dump opt-in (punto 1 del RE RedLotus, reimplementazione clean-room):
 * aggancia l'agent {@code MemAgent} a una JVM in esecuzione, raccoglie il
 * bytecode delle classi caricate e lo impacchetta in un jar analizzabile dal
 * motore esistente. Mai esecuzione di codice del bersaglio: solo attach,
 * dump e scansione statica del dump.
 */
final class MemDump {
    /** Attesa massima del marker di fine dump (retransform a blocchi: resta ampia per macchine lente). */
    static final long DUMP_TIMEOUT_MS = 900_000;
    static final long POLL_MS = 500;
    /** Package sempre JDK: mai interessanti per le mod, solo rumore. */
    static final java.util.Set<String> JDK_PREFIXES = java.util.Set.of(
            "java/", "javax/", "jdk/", "sun/", "com/sun/");

    /** Stato del dump in corso, letto dall'endpoint /api/mem/progress e dalla GUI. */
    private static volatile java.util.Map<String, Object> progressState = idleState();

    private MemDump() {
    }

    private static java.util.Map<String, Object> idleState() {
        java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("state", "idle");
        m.put("phase", "");
        m.put("pct", 0);
        m.put("note", "nessun dump in corso");
        m.put("done", 0);
        m.put("total", 0);
        m.put("skippedJdk", 0);
        m.put("skippedTrusted", 0);
        m.put("updatedAt", 0L);
        return java.util.Collections.unmodifiableMap(m);
    }

    static synchronized void setState(String state, String phase, int pct, String note,
            int done, int total, int skippedJdk, int skippedTrusted) {
        java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("state", state);
        m.put("phase", phase);
        m.put("pct", Math.max(0, Math.min(100, pct)));
        m.put("note", note);
        m.put("done", done);
        m.put("total", total);
        m.put("skippedJdk", skippedJdk);
        m.put("skippedTrusted", skippedTrusted);
        m.put("updatedAt", System.currentTimeMillis());
        progressState = java.util.Collections.unmodifiableMap(m);
    }

    /** Fase lato app (pack, analisi) con percentuale indicativa per la barra della GUI. */
    static void phase(String phase, String note, int pct) {
        setState("running", phase, pct, note, 0, 0, 0, 0);
    }

    static void done(String note) {
        setState("done", "done", 100, note, 0, 0, 0, 0);
    }

    static void fail(String note) {
        setState("error", "error", 0, note, 0, 0, 0, 0);
    }

    static void idle() {
        setState("idle", "", 0, "nessun dump in corso", 0, 0, 0, 0);
    }

    static java.util.Map<String, Object> progress() {
        return progressState;
    }

    /** Risolve "auto" (primo javaw/java con riga di comando) o un PID numerico. */
    static String resolvePid(String spec) {
        if (spec != null && spec.matches("\\d+")) {
            return spec;
        }
        try {
            for (ProcessInventory.ProcInfo p : ProcessInventory.snapshot()) {
                if (!p.java() || !p.detailsAvailable()) {
                    continue;
                }
                String exe = p.executable() == null ? "" : p.executable().toLowerCase(java.util.Locale.ROOT);
                if (exe.endsWith("javaw.exe") || exe.endsWith("java.exe")) {
                    return String.valueOf(p.pid());
                }
            }
        } catch (Exception ignored) {
            // nessun processo leggibile: errore sotto
        }
        throw new IllegalArgumentException("nessun processo javaw/java trovato (usa --mem <pid>)");
    }

    /**
     * Aggancia l'agent al pid, attende il dump e impacchetta le classi in
     * {@code workDir/mem-<pid>.jar}. Ritorna il jar impacchettato.
     *
     * @param skipEntries righe {@code path:…}/{@code prefix:…} scritte in
     *        {@code skip.txt} dentro la dir di dump: l'agent non ri-trasforma e
     *        non dumpa quelle origini (mod verificate, librerie note). Vuoto o
     *        null = dump completo.
     */
    static Path capture(String pid, Path agentJar, Path workDir, java.util.List<String> skipEntries) throws IOException {
        if (!Files.isRegularFile(agentJar)) {
            throw new IOException("agent non trovato: " + agentJar.toAbsolutePath());
        }
        Files.createDirectories(workDir);
        Path dumpDir = workDir.resolve("classes-" + pid);
        deleteTree(dumpDir);
        Files.createDirectories(dumpDir);
        if (skipEntries != null && !skipEntries.isEmpty()) {
            Files.writeString(dumpDir.resolve("skip.txt"),
                    "# ModScanOpen: origini da non ri-trasformare e non dumpare\n"
                            + String.join("\n", skipEntries) + "\n",
                    java.nio.charset.StandardCharsets.UTF_8);
        }
        setState("running", "attach", 2, "attach alla JVM (pid " + pid + ")…", 0, 0, 0, 0);
        /* Il thread che chiama loadAgent resta bloccato fino alla fine di agentmain:
           un watcher separato legge progress.txt del target e tiene viva la GUI. */
        Thread watcher = new Thread(() -> watchProgress(dumpDir), "memdump-progress");
        watcher.setDaemon(true);
        watcher.start();
        VirtualMachine vm = null;
        try {
            try {
                vm = VirtualMachine.attach(pid);
                vm.loadAgent(agentJar.toAbsolutePath().toString(), "out=" + dumpDir.toAbsolutePath());
            } catch (Exception e) {
                throw new IOException("attach al pid " + pid + " fallito: " + e.getMessage(), e);
            } finally {
                if (vm != null) {
                    try {
                        vm.detach();
                    } catch (Exception ignored) {
                        // detach best-effort
                    }
                }
            }
        } finally {
            watcher.interrupt();
        }
        waitMarker(dumpDir);
        phase("pack", "impacchettamento in mem-" + pid + ".jar…", 80);
        Map<String, String> origins = readOrigins(dumpDir);
        Path jar = pack(pid, dumpDir, workDir, origins);
        writeOriginsJson(workDir, pid, origins);
        phase("pack", "jar pronto: " + jar.getFileName(), 84);
        return jar;
    }

    static Path originsPath(Path workDir, String pid) {
        return workDir.resolve("origins-" + pid + ".json");
    }

    /** origins.txt dell'agent (nome interno TAB origine) -> mappa. */
    static Map<String, String> readOrigins(Path dumpDir) {
        Map<String, String> m = new java.util.LinkedHashMap<>();
        Path f = dumpDir.resolve("origins.txt");
        if (!Files.isRegularFile(f)) {
            return m;
        }
        try {
            for (String line : Files.readAllLines(f, java.nio.charset.StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab > 0) {
                    m.put(line.substring(0, tab), line.substring(tab + 1));
                }
            }
        } catch (Exception ignored) {
            // origins facoltative: si analizza senza attribuzione
        }
        return m;
    }

    /** Vero se la classe viene dal runtime JDK (bootstrap/jrt o package noto). */
    static boolean isJdk(String internalName, String origin) {
        if (origin != null && (origin.equals("bootstrap") || origin.startsWith("jrt:/"))) {
            return true;
        }
        if (internalName != null) {
            for (String p : JDK_PREFIXES) {
                if (internalName.startsWith(p)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Nome corto dell'origine per i report (basename del jar/URL). */
    static String shortOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            return "sconosciuta";
        }
        String o = origin.trim();
        int cut = Math.max(o.lastIndexOf('/'), o.lastIndexOf('\\'));
        String base = cut >= 0 && cut + 1 < o.length() ? o.substring(cut + 1) : o;
        return base.length() > 80 ? base.substring(0, 80) + "…" : base;
    }

    /** Aggiunge "origin" e suffisso alla location di un finding (mappa location tabellare). */
    static void attachOrigin(Map<String, Object> finding, Map<String, String> origins) {
        if (finding == null || origins == null || origins.isEmpty()) {
            return;
        }
        Object loc = finding.get("location");
        if (!(loc instanceof String)) {
            return;
        }
        String entry = (String) loc;
        int method = entry.indexOf("::");
        if (method >= 0) {
            entry = entry.substring(0, method);
        }
        entry = entry.replaceFirst(" \\(\\+\\d+\\)$", "");
        if (!entry.endsWith(".class")) {
            return;
        }
        String internal = entry.substring(0, entry.length() - 6);
        String origin = origins.get(internal);
        if (origin == null) {
            return;
        }
        finding.put("origin", origin);
        finding.put("location", loc + " ← " + shortOrigin(origin));
    }

    private static void waitMarker(Path dumpDir) throws IOException {
        Path marker = dumpDir.resolve("done.marker");
        long waited = 0;
        while (!Files.isRegularFile(marker)) {
            if (waited >= DUMP_TIMEOUT_MS) {
                throw new IOException("timeout dump (" + (DUMP_TIMEOUT_MS / 1000) + "s): marker assente in " + dumpDir);
            }
            try {
                Thread.sleep(POLL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("dump interrotto", e);
            }
            waited += POLL_MS;
        }
    }

    /** Legge in continuo progress.txt dell'agent (thread dedicato, fermato col marker). */
    private static void watchProgress(Path dumpDir) {
        long t0 = System.currentTimeMillis();
        boolean seen = false;
        while (!Thread.currentThread().isInterrupted()) {
            boolean ok = readAgentProgress(dumpDir);
            if (ok) {
                seen = true;
            } else if (!seen && System.currentTimeMillis() - t0 > 40_000) {
                // Nessun progresso: nella JVM può essere già caricato l'agent di una
                // versione precedente (stessa classe: questa nuova non entra in scena).
                setState("running", "attach", 4,
                        "agent di una versione precedente già presente in questa JVM: riavvia il gioco per il dump rapido — dump in corso…",
                        0, 0, 0, 0);
            }
            try {
                Thread.sleep(POLL_MS);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    /** Legge progress.txt dell'agent e aggiorna lo stato esposto alla GUI; true se letto. */
    private static boolean readAgentProgress(Path dumpDir) {
        Path f = dumpDir.resolve("progress.txt");
        if (!Files.isRegularFile(f)) {
            return false;
        }
        try {
            String line = Files.readString(f, java.nio.charset.StandardCharsets.UTF_8).trim();
            Map<String, String> kv = new java.util.LinkedHashMap<>();
            for (String part : line.split(";")) {
                int eq = part.indexOf('=');
                if (eq > 0) {
                    kv.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
                }
            }
            String ph = kv.getOrDefault("phase", "");
            int done = intOf(kv.get("done"));
            int total = intOf(kv.get("total"));
            int skJdk = intOf(kv.get("skipped_jdk"));
            int skTrusted = intOf(kv.get("skipped_trusted"));
            switch (ph) {
                case "retransform" -> setState("running", "retransform",
                        total > 0 ? 3 + (int) (60.0 * done / total) : 3,
                        "retransform " + done + " di " + total + " classi in scope"
                                + ((skJdk + skTrusted) > 0
                                        ? " — fuori scope: " + (skJdk + skTrusted) + " (JDK/mod verificate/librerie)" : ""),
                        done, total, skJdk, skTrusted);
                case "dump" -> setState("running", "dump", 67,
                        "scrittura delle classi del dump su disco…", done, total, skJdk, skTrusted);
                case "origins" -> setState("running", "origins", 70,
                        "scrittura delle origini delle classi…", 0, 0, skJdk, skTrusted);
                default -> {
                    // fase agent non riconosciuta (done pronta per il pack): si tiene lo stato corrente
                }
            }
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static int intOf(String s) {
        try {
            return s == null ? 0 : Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Path pack(String pid, Path dumpDir, Path workDir, Map<String, String> origins) throws IOException {
        Path jar = workDir.resolve("mem-" + pid + ".jar");
        Files.deleteIfExists(jar);
        int skippedJdk = 0;
        try (JarOutputStream j = new JarOutputStream(Files.newOutputStream(jar));
                Stream<Path> walk = Files.walk(dumpDir)) {
            for (Path f : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
                String name = dumpDir.relativize(f).toString().replace('\\', '/');
                if (!name.endsWith(".class") || name.contains("..")) {
                    continue;
                }
                String internal = name.substring(0, name.length() - 6);
                if (isJdk(internal, origins.get(internal))) {
                    skippedJdk++;
                    continue;
                }
                j.putNextEntry(new JarEntry(name));
                Files.copy(f, j);
                j.closeEntry();
            }
        }
        if (Files.size(jar) < 100) {
            throw new IOException("dump vuoto: nessuna classe catturata dal pid " + pid);
        }
        System.err.println("mem-dump: classi JDK scartate: " + skippedJdk);
        return jar;
    }

    private static void writeOriginsJson(Path workDir, String pid, Map<String, String> origins) {
        Map<String, String> perEntry = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, String> e : origins.entrySet()) {
            perEntry.put(e.getKey() + ".class", e.getValue());
        }
        try {
            StringBuilder sb = new StringBuilder("{\n");
            boolean first = true;
            for (Map.Entry<String, String> e : perEntry.entrySet()) {
                if (!first) {
                    sb.append(",\n");
                }
                first = false;
                sb.append('"').append(escape(e.getKey())).append("\":\"").append(escape(e.getValue())).append('"');
            }
            sb.append("\n}\n");
            Files.writeString(originsPath(workDir, pid), sb.toString(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // origins best-effort
        }
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            for (Path p : (Iterable<Path>) walk.sorted(Comparator.reverseOrder())::iterator) {
                Files.deleteIfExists(p);
            }
        }
    }
}
