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
    /** Attesa massima del marker di fine dump (retransform di migliaia di classi). */
    static final long DUMP_TIMEOUT_MS = 120_000;
    static final long POLL_MS = 500;
    /** Package sempre JDK: mai interessanti per le mod, solo rumore. */
    static final java.util.Set<String> JDK_PREFIXES = java.util.Set.of(
            "java/", "javax/", "jdk/", "sun/", "com/sun/");

    private MemDump() {
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
     */
    static Path capture(String pid, Path agentJar, Path workDir) throws IOException {
        if (!Files.isRegularFile(agentJar)) {
            throw new IOException("agent non trovato: " + agentJar.toAbsolutePath());
        }
        Files.createDirectories(workDir);
        Path dumpDir = workDir.resolve("classes-" + pid);
        deleteTree(dumpDir);
        Files.createDirectories(dumpDir);
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
            // l'agent resta caricato nel bersaglio ma inerte (solo transformer-osservatore)
        }
        waitMarker(dumpDir);
        Map<String, String> origins = readOrigins(dumpDir);
        Path jar = pack(pid, dumpDir, workDir, origins);
        writeOriginsJson(workDir, pid, origins);
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
