package modscan;

import com.jaranalyzer.scanners.engine.ProcessInventory;
import com.sun.tools.attach.VirtualMachine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
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
        return pack(pid, dumpDir, workDir);
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

    private static Path pack(String pid, Path dumpDir, Path workDir) throws IOException {
        Path jar = workDir.resolve("mem-" + pid + ".jar");
        Files.deleteIfExists(jar);
        try (JarOutputStream j = new JarOutputStream(Files.newOutputStream(jar));
                Stream<Path> walk = Files.walk(dumpDir)) {
            for (Path f : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
                String name = dumpDir.relativize(f).toString().replace('\\', '/');
                if (!name.endsWith(".class") || name.contains("..")) {
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
        return jar;
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
