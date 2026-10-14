package com.jaranalyzer.scanners.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Ricava la cartella di gioco di Minecraft (e quindi la cartella "mods") dalla command line
 * di un processo java/javaw in esecuzione. Classe pura (nessuna dipendenza da Spring) e quindi
 * facile da testare.
 *
 * Fonti, dalla più alla meno affidabile:
 *  - argomento del gioco  --gameDir <path>            (launcher ufficiale, Prism, MultiMC, Lunar, ...)
 *  - -Dminecraft.applet.TargetDirectory=<path>        (launcher legacy / MultiMC)
 *  - user.dir letto dalla JVM (jcmd VM.system_properties), se fornito
 *  - --assetsDir / -Djava.library.path / classpath    (si risale alla cartella .minecraft)
 */
public final class MinecraftPathResolver {

    /** Un possibile percorso della game dir con la sua provenienza. */
    public static final class Hint {
        public final String gameDir;
        public final String source;
        public final int confidence;

        public Hint(String gameDir, String source, int confidence) {
            this.gameDir = gameDir;
            this.source = source;
            this.confidence = confidence;
        }

        @Override
        public String toString() {
            return gameDir + " [" + source + ", " + confidence + "]";
        }
    }

    private MinecraftPathResolver() {
    }

    /** true se la command line sembra quella di un client Minecraft (non di un altro programma Java). */
    public static boolean looksLikeMinecraft(String commandLine) {
        if (commandLine == null) {
            return false;
        }
        String c = commandLine.toLowerCase(Locale.ROOT);
        return c.contains("net.minecraft") || c.contains("--gamedir") || c.contains("net.fabricmc")
                || c.contains("cpw.mods") || c.contains("net.minecraftforge") || c.contains("net.neoforged")
                || c.contains("org.quiltmc") || c.contains("knotclient") || c.contains("launchwrapper")
                || c.contains("minecraft.applet") || c.contains(".minecraft") || c.contains("lunarclient")
                || c.contains("badlion") || c.contains("modrinthapp");
    }

    /** Divide una command line rispettando le virgolette ("C:\Program Files\...\javaw.exe" -Xmx2G ...). */
    public static List<String> tokenize(String cmd) {
        List<String> out = new ArrayList<>();
        if (cmd == null) {
            return out;
        }
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        boolean has = false;
        for (int i = 0; i < cmd.length(); i++) {
            char ch = cmd.charAt(i);
            if (ch == '"') {
                inQuotes = !inQuotes;
                has = true;
            } else if (Character.isWhitespace(ch) && !inQuotes) {
                if (has) {
                    out.add(cur.toString());
                    cur.setLength(0);
                    has = false;
                }
            } else {
                cur.append(ch);
                has = true;
            }
        }
        if (has) {
            out.add(cur.toString());
        }
        return out;
    }

    /**
     * @param commandLine command line completa del processo
     * @param userDir     valore di user.dir della JVM, se noto (può essere null)
     * @return hint ordinati per confidenza decrescente, senza duplicati (a parità di cartella vince la fonte migliore)
     */
    public static List<Hint> resolve(String commandLine, String userDir) {
        Map<String, Hint> best = new LinkedHashMap<>();
        List<String> t = tokenize(commandLine);

        for (int i = 0; i < t.size(); i++) {
            String a = t.get(i);
            String lower = a.toLowerCase(Locale.ROOT);

            if (lower.equals("--gamedir") && i + 1 < t.size()) {
                add(best, t.get(i + 1), "argomento --gameDir", 95);
            } else if (lower.startsWith("--gamedir=")) {
                add(best, a.substring(10), "argomento --gameDir", 95);
            } else if (lower.startsWith("-dminecraft.applet.targetdirectory=")) {
                add(best, a.substring(a.indexOf('=') + 1), "-Dminecraft.applet.TargetDirectory", 90);
            } else if (lower.equals("--assetsdir") && i + 1 < t.size()) {
                addFromAssets(best, t.get(i + 1));
            } else if (lower.startsWith("--assetsdir=")) {
                addFromAssets(best, a.substring(12));
            } else if (lower.startsWith("-djava.library.path=")) {
                for (String p : splitPathList(a.substring(a.indexOf('=') + 1))) {
                    addFromRootMarker(best, p, "java.library.path", 65);
                }
            } else if ((lower.equals("-cp") || lower.equals("-classpath") || lower.equals("--class-path")) && i + 1 < t.size()) {
                for (String p : splitPathList(t.get(i + 1))) {
                    addFromRootMarker(best, p, "classpath", 60);
                }
            } else if (lower.startsWith("-djava.class.path=")) {
                for (String p : splitPathList(a.substring(a.indexOf('=') + 1))) {
                    addFromRootMarker(best, p, "classpath", 60);
                }
            }
        }
        if (userDir != null && !userDir.isBlank()) {
            add(best, userDir, "cartella di lavoro della JVM (user.dir)", 85);
        }

        List<Hint> list = new ArrayList<>(best.values());
        list.sort((x, y) -> Integer.compare(y.confidence, x.confidence));
        return list;
    }

    /** Percorso della cartella mods dentro una game dir (separatore coerente con la game dir). */
    public static String modsDirOf(String gameDir) {
        String g = trimSeparators(gameDir);
        String sep = g.contains("\\") && !g.contains("/") ? "\\" : "/";
        return g + sep + "mods";
    }

    // ---------------------------------------------------------------- interni

    private static void add(Map<String, Hint> map, String dir, String source, int confidence) {
        if (dir == null) {
            return;
        }
        String d = trimSeparators(dir.trim());
        if (d.isEmpty() || d.equals(".") || d.length() < 3) {
            return;
        }
        String key = d.replace('\\', '/').toLowerCase(Locale.ROOT);
        Hint old = map.get(key);
        if (old == null || old.confidence < confidence) {
            map.put(key, new Hint(d, source, confidence));
        }
    }

    private static void addFromAssets(Map<String, Hint> map, String assetsDir) {
        String a = trimSeparators(assetsDir.trim());
        String norm = a.replace('\\', '/');
        if (norm.toLowerCase(Locale.ROOT).endsWith("/assets")) {
            // Solo il launcher "classico" mette assets dentro .minecraft; Prism/MultiMC li condividono fuori dall'istanza.
            String parent = a.substring(0, a.length() - "/assets".length());
            if (parent.replace('\\', '/').toLowerCase(Locale.ROOT).endsWith(".minecraft")) {
                add(map, parent, "--assetsDir (cartella .minecraft)", 70);
            }
        }
    }

    private static void addFromRootMarker(Map<String, Hint> map, String path, String source, int confidence) {
        String norm = path.replace('\\', '/');
        String low = norm.toLowerCase(Locale.ROOT);
        for (String marker : new String[]{"/libraries/", "/versions/", "/bin/natives"}) {
            int idx = low.indexOf(marker);
            if (idx > 0) {
                String root = path.substring(0, idx);
                if (root.replace('\\', '/').toLowerCase(Locale.ROOT).endsWith(".minecraft")) {
                    add(map, root, source + " (" + marker.replace("/", "") + ")", confidence);
                }
                return;
            }
        }
    }

    private static List<String> splitPathList(String s) {
        List<String> out = new ArrayList<>();
        // separatore di classpath: ';' su Windows, ':' altrove (ma ':' compare in "C:\")
        String[] parts = s.contains(";") ? s.split(";") : s.split("(?<!\\b[A-Za-z]):");
        for (String p : parts) {
            String q = p.trim();
            if (!q.isEmpty()) {
                out.add(q);
            }
        }
        return out;
    }

    private static String trimSeparators(String p) {
        String r = p;
        while (r.length() > 1 && (r.endsWith("/") || r.endsWith("\\"))) {
            r = r.substring(0, r.length() - 1);
        }
        return r;
    }
}
