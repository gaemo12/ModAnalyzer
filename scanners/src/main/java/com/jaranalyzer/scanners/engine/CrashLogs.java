package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Severity;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Tracce JVM rimaste nei crash report e nei file {@code hs_err_pid*.log}
 * della cartella di gioco. Sono utili quando il gioco è chiuso o l'agente è
 * stato rimosso: il crash log conserva la riga di comando o i JVM flags della
 * sessione e può quindi mostrare un {@code -javaagent}, un bootclasspath
 * manomesso o un {@code --tweakClass} non standard.
 *
 * <p>Privacy: si legge solo l'inizio del file (tetto), si cercano solo le righe
 * di intestazione JVM e si restituiscono esclusivamente i <b>nomi</b> dei flag.
 * Il contenuto della riga di comando (username, percorsi, token) non viene
 * esposto né salvato.
 */
public final class CrashLogs {

    /** Crash report esaminati al massimo (i più recenti). */
    private static final int MAX_FILES = 8;
    /** Byte letti dall'inizio di ogni file. */
    private static final int MAX_BYTES = 256 * 1024;

    /** Una traccia trovata: solo flag, mai la riga di comando completa. */
    public record Trace(String file, String kind, long modifiedMillis, List<String> flags) {
    }

    private CrashLogs() {
    }

    public static List<Trace> scan(Path gameDir) throws IOException {
        List<Candidate> candidates = new ArrayList<>();
        if (gameDir == null || !Files.isDirectory(gameDir)) {
            return List.of();
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(gameDir, "hs_err_pid*.log")) {
            for (Path p : stream) {
                if (Files.isRegularFile(p)) {
                    candidates.add(new Candidate(p, "hs_err"));
                }
            }
        } catch (Exception ignored) {
            // nessun hs_err o cartella non leggibile: si passa ai crash report
        }
        Path reports = gameDir.resolve("crash-reports");
        if (Files.isDirectory(reports)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(reports)) {
                for (Path p : stream) {
                    String name = p.getFileName() == null ? "" : p.getFileName().toString().toLowerCase(Locale.ROOT);
                    if ((name.endsWith(".txt") || name.endsWith(".log")) && Files.isRegularFile(p)) {
                        candidates.add(new Candidate(p, "crash-report"));
                    }
                }
            } catch (Exception ignored) {
                // cartella presente ma non leggibile: nessun crash report
            }
        }
        candidates.sort(Comparator.comparingLong((Candidate c) -> modified(c.path)).reversed());
        List<Trace> out = new ArrayList<>();
        for (int i = 0; i < candidates.size() && i < MAX_FILES; i++) {
            Candidate c = candidates.get(i);
            String text;
            try {
                text = readHead(c.path, MAX_BYTES);
            } catch (Exception e) {
                continue;
            }
            List<String> flags = flagsIn(text);
            if (flags.isEmpty()) {
                continue;
            }
            out.add(new Trace(relative(gameDir, c.path), c.kind, modified(c.path), flags));
        }
        return List.copyOf(out);
    }

    /**
     * Estrae i flag JVM sospetti dalle righe di intestazione del crash log
     * ({@code Command Line:}, {@code java_command:}, {@code JVM Flags:}).
     * Restituisce solo i nomi, senza valori o percorsi.
     */
    public static List<String> flagsIn(String text) {
        Set<String> out = new LinkedHashSet<>();
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        for (String raw : text.split("\\R")) {
            String line = raw.trim();
            if (!line.isEmpty() && line.charAt(0) == '\uFEFF') {
                line = line.substring(1).trim(); // alcuni editor salvano i crash report con BOM
            }
            String lower = line.toLowerCase(Locale.ROOT);
            String command = null;
            for (String prefix : new String[] {"command line:", "java_command:", "java command:", "jvm flags:"}) {
                if (lower.startsWith(prefix)) {
                    command = line.substring(prefix.length()).trim();
                    break;
                }
            }
            if (command == null || command.isEmpty()) {
                continue;
            }
            for (GameCommandLine.Flag f : GameCommandLine.check(command)) {
                if (f.severity() == Severity.INFO) {
                    continue;
                }
                // Il classpath può variare molto tra launcher: resta al controllo del processo vivo.
                if ("-cp".equals(f.flag()) || "--mixin".equals(f.flag())) {
                    continue;
                }
                out.add(f.flag());
            }
        }
        return List.copyOf(out);
    }

    private record Candidate(Path path, String kind) {
    }

    private static long modified(Path p) {
        try {
            return Files.getLastModifiedTime(p).toMillis();
        } catch (Exception e) {
            return 0L;
        }
    }

    private static String relative(Path base, Path file) {
        try {
            return base.relativize(file).toString().replace('\\', '/');
        } catch (Exception e) {
            return file.getFileName() == null ? "" : file.getFileName().toString();
        }
    }

    private static String readHead(Path file, int max) throws IOException {
        byte[] buf = new byte[max];
        int n = 0;
        try (InputStream in = Files.newInputStream(file)) {
            int r;
            while (n < max && (r = in.read(buf, n, max - n)) != -1) {
                n += r;
            }
        }
        return new String(buf, 0, n, StandardCharsets.UTF_8);
    }
}
