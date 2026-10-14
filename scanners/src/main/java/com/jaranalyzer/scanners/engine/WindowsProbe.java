package com.jaranalyzer.scanners.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Primitive di lettura per i moduli «scan completa»: reg query read-only,
 * schtasks /query, elenchi di cartelle. SOLO-LETTURA: nessuna chiave viene
 * scritta, nessun processo viene terminato, nessun input utente.
 * Su sistemi non-Windows i metodi restano no-op tolleranti (lista vuota).
 */
public final class WindowsProbe {
    private static final Charset CONSOLE = Charset.forName("IBM850"); // console cp850 di default su Windows italiano

    private WindowsProbe() {
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("windows");
    }

    /** Esegue un comando read-only e restituisce stdout riga per riga. */
    public static List<String> exec(String[] cmd) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process p = pb.start();
        List<String> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), CONSOLE))) {
            String line;
            while ((line = r.readLine()) != null) {
                out.add(line);
            }
        } catch (Exception e) {
            p.destroyForcibly();
            IOException io = e instanceof IOException ? (IOException) e : new IOException(e);
            throw io;
        }
        try {
            if (!p.waitFor(60, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new IOException("timeout comando: " + cmd[0]);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            throw new IOException("comando interrotto");
        }
        return out;
    }

    /**
     * reg query chiave: restituisce solo valori (nome -> dato), riga per riga.
     * Output tipico: "    Nome    REG_SZ    dato" (tre+ spazi bianchi separano).
     */
    public static Map<String, String> regValues(String registryKey) throws IOException {
        Map<String, String> values = new LinkedHashMap<>();
        List<String> lines = exec(new String[]{"reg", "query", registryKey, "/reg:64"}).isEmpty()
                ? exec(new String[]{"reg", "query", registryKey, "/reg:64"})
                : exec(new String[]{"reg", "query", registryKey, "/reg:64"});
        parseRegValues(lines, values);
        // Re-inserisce con la vista 32 bit per le chiavi preesistenti lì (fusione best-effort).
        try {
            Map<String, String> w = new LinkedHashMap<>();
            parseRegValues(exec(new String[]{"reg", "query", registryKey, "/reg:32"}), w);
            w.forEach(values::putIfAbsent);
        } catch (Exception ignored) {
            // chiave assente sulla vista 32: va bene
        }
        return values;
    }

    public static List<String> regKeyLines(String key) throws IOException {
        return exec(new String[]{"reg", "query", key, "/s", "/v", "ImagePath"});
    }

    private static void parseRegValues(List<String> lines, Map<String, String> into) {
        for (String line : lines) {
            String t = line == null ? "" : line.strip();
            if (t.isEmpty() || t.startsWith("HKEY_")) {
                continue;
            }
            int type = t.indexOf("REG_");
            if (type <= 0) {
                continue;
            }
            String name = t.substring(0, type).strip();
            int after = t.indexOf(type + 3);
            int space = t.indexOf(' ', type + 3);
            if (space < 0) {
                continue;
            }
            String data = t.substring(space).strip();
            if (t.contains("REG_SZ") || t.contains("REG_EXPAND") || t.contains("REG_BINARY")) {
                into.put(name.isEmpty() ? "(Predefinito)" : name, data);
            }
        }
    }

    /** Lista file della cartella (no ricorsione, read-only). */
    public static List<String> listFiles(java.nio.file.Path dir) {
        List<String> names = new ArrayList<>();
        if (dir != null && java.nio.file.Files.isDirectory(dir)) {
            try (var s = java.nio.file.Files.list(dir)) {
                s.map(p -> p.getFileName().toString()).sorted().forEach(names::add);
            } catch (IOException ignored) {
                // permessi negati: counter, non fatale
            }
        }
        return names;
    }
}
