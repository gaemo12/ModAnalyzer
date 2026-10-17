package com.jaranalyzer.memagent;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Agent di memory-dump opt-in per ModScanOpen (implementazione clean-room del
 * meccanismo osservato: attach + transformer + dump, senza riuso di codice).
 *
 * <p>Osservatore puro: il transformer copia i byte delle classi caricate e
 * ritorna sempre {@code null} (nessuna modifica al bytecode del processo
 * bersaglio). Uso: {@code -javaagent:MemAgent.jar=out=&lt;dir&gt;} oppure
 * attach dinamico con gli stessi argomenti.
 *
 * <p>Argomenti ({@code k=v;k=v}): {@code out} (dir di dump, obbligatorio),
 * {@code retransform} (default {@code true}: ri-trasforma le classi già
 * caricate per catturarle subito).
 *
 * <p>Nella dir di dump l'app scrive, prima dell'attach, un file opzionale
 * {@code skip.txt} con le origini da NON ritrasformare e da NON dumpare
 * (mod verificate, librerie note del launcher):
 * <pre>
 *   path:c:\...\mods\sodium.jar     (confronto esatto del percorso)
 *   prefix:c:\...\meta\libraries    (confronto per prefisso di cartella)
 * </pre>
 * Le classi JDK sono sempre saltate. La retransform procede a blocchi
 * (una chiamata ogni {@link #BATCH} classi) e scrive {@code progress.txt}
 * nella dir di dump per mostrare l'avanzamento nella GUI.
 */
public final class MemAgent {
    private static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();
    /** Origine per classe (CodeSource o "bootstrap"): attribuzione nei report. */
    private static final Map<String, String> ORIGINS = new ConcurrentHashMap<>();
    /** Percorsi (normalizzati) da non ritrasformare né dumpare. */
    private static final Set<String> SKIP_PATHS = ConcurrentHashMap.newKeySet();
    private static final List<String> SKIP_PREFIXES = new CopyOnWriteArrayList<>();
    /** Conteggi dei salti (ultima retransform): riportati nel progresso fino alla fine. */
    private static volatile int skippedJdkCount;
    private static volatile int skippedTrustedCount;
    /** Il transformer si registra una volta sola anche con attach ripetuti. */
    private static volatile boolean registered;
    /** Package JDK: mai interessanti per le mod, saltati prima della retransform. */
    private static final String[] JDK_PREFIXES = {"java/", "javax/", "jdk/", "sun/", "com/sun/"};
    /** Classi per chiamata a retransformClasses: un blocco invece di N chiamate native. */
    private static final int BATCH = 256;

    private MemAgent() {
    }

    public static void premain(String args, Instrumentation inst) {
        start(args, inst, "premain");
    }

    public static void agentmain(String args, Instrumentation inst) {
        start(args, inst, "agentmain");
    }

    private static synchronized void start(String args, Instrumentation inst, String mode) {
        Map<String, String> opt = parse(args);
        String out = opt.get("out");
        if (out == null || out.isBlank()) {
            System.err.println("[MemAgent] argomento out= mancante, dump saltato");
            return;
        }
        File dir = new File(out);
        dir.mkdirs();
        // Un secondo attach nella stessa JVM riusa questa stessa classe (stesso
        // loader per nome): senza azzerare, vettori e skip-list dell'attach
        // precedente rimarrebbero attivi. Ogni start è un dump nuovo e pulito.
        CACHE.clear();
        ORIGINS.clear();
        SKIP_PATHS.clear();
        SKIP_PREFIXES.clear();
        skippedJdkCount = 0;
        skippedTrustedCount = 0;
        loadSkip(dir);
        if (!registered) {
            inst.addTransformer(new Snapshot(), true);
            registered = true;
        }
        System.out.println("[MemAgent] attivo (" + mode + ") -> " + dir
                + " (skip: " + SKIP_PATHS.size() + " percorsi, " + SKIP_PREFIXES.size() + " prefissi)");
        if (!"false".equalsIgnoreCase(opt.getOrDefault("retransform", "true"))) {
            retransformAll(inst, dir);
        }
        progress(dir, "dump", 0, 0);
        int n = dump(dir);
        progress(dir, "origins", 0, 0);
        int o = dumpOrigins(dir);
        try {
            Files.writeString(new File(dir, "done.marker").toPath(),
                    "classes=" + n + " origins=" + o + "\n", StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[MemAgent] marker fallito: " + e.getMessage());
        }
        progress(dir, "done", 0, 0);
        System.out.println("[MemAgent] dump: " + n + " classi in " + dir);
    }

    /**
     * Ri-trasforma le classi già caricate a blocchi (best-effort). Le classi
     * JDK e quelle con origine nella skip-list non vengono nemmeno toccate:
     * non finirebbero comunque nel dump, quindi la loro retransform era solo
     * tempo sprecato (era il costo dominante: ~17 minuti su un gioco avviato).
     */
    private static void retransformAll(Instrumentation inst, File dir) {
        if (!inst.isRetransformClassesSupported()) {
            System.err.println("[MemAgent] retransform non supportato dalla JVM");
            return;
        }
        List<Class<?>> todo = new ArrayList<>();
        int skJdk = 0, skTrusted = 0;
        for (Class<?> c : inst.getAllLoadedClasses()) {
            try {
                if (!inst.isModifiableClass(c)) {
                    continue;
                }
                String internal = c.getName().replace('.', '/');
                String origin = originOf(c.getProtectionDomain());
                if (isJdk(internal, origin)) {
                    skJdk++;
                    continue;
                }
                if (isSkipped(origin)) {
                    skTrusted++;
                    continue;
                }
                todo.add(c);
            } catch (Throwable t) {
                // singola classe non ispezionabile: si prosegue
            }
        }
        int ok = 0, ko = 0;
        int total = todo.size();
        skippedJdkCount = skJdk;
        skippedTrustedCount = skTrusted;
        progress(dir, "retransform", 0, total);
        for (int i = 0; i < total; i += BATCH) {
            List<Class<?>> chunk = todo.subList(i, Math.min(i + BATCH, total));
            try {
                inst.retransformClasses(chunk.toArray(new Class<?>[0]));
                ok += chunk.size();
            } catch (Throwable batchError) {
                // un blocco fallisce in blocco: si riprova una classe per volta
                for (Class<?> c : chunk) {
                    try {
                        inst.retransformClasses(c);
                        ok++;
                    } catch (Throwable t) {
                        ko++;
                    }
                }
            }
            progress(dir, "retransform", Math.min(i + BATCH, total), total);
        }
        System.out.println("[MemAgent] ri-trasformate: " + ok + " (saltate: " + ko
                + ", fuori scope: jdk=" + skJdk + " trusted=" + skTrusted + ")");
    }

    /** Scrive la cache su disco preservando i package; ritorna il conteggio. */
    private static int dump(File dir) {
        int n = 0;
        for (Map.Entry<String, byte[]> e : CACHE.entrySet()) {
            String internal = e.getKey();
            byte[] bytes = e.getValue();
            if (internal == null || bytes == null || bytes.length < 8) {
                continue;
            }
            try {
                File f = new File(dir, internal + ".class");
                File parent = f.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                try (FileOutputStream fos = new FileOutputStream(f)) {
                    fos.write(bytes);
                }
                n++;
            } catch (Exception ex) {
                // singola classe non scrivibile: si continua con le altre
            }
        }
        return n;
    }

    /** Scrive origins.txt (nome interno TAB origine); ritorna le righe scritte. */
    private static int dumpOrigins(File dir) {
        int n = 0;
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : ORIGINS.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) {
                continue;
            }
            sb.append(e.getKey()).append('\t')
                    .append(e.getValue().replace('\t', '?').replace('\n', '?').replace('\r', '?'))
                    .append('\n');
            n++;
        }
        try {
            Files.writeString(new File(dir, "origins.txt").toPath(), sb.toString(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[MemAgent] origins fallito: " + e.getMessage());
        }
        return n;
    }

    /* ---------- skip list e normalizzazione percorsi ---------- */

    /** Legge skip.txt dalla dir di dump (righe {@code path:…} / {@code prefix:…}, # = commento). */
    private static void loadSkip(File dir) {
        File f = new File(dir, "skip.txt");
        if (!f.isFile()) {
            return;
        }
        try {
            for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) {
                    continue;
                }
                if (s.regionMatches(true, 0, "path:", 0, 5)) {
                    String p = toPath(s.substring(5));
                    if (!p.isEmpty()) {
                        SKIP_PATHS.add(p);
                    }
                } else if (s.regionMatches(true, 0, "prefix:", 0, 7)) {
                    String p = toPath(s.substring(7));
                    if (!p.isEmpty()) {
                        SKIP_PREFIXES.add(p);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[MemAgent] skip.txt non leggibile: " + e.getMessage());
        }
    }

    /** True se l'origine (URL/percorso) è nella skip-list (percorso esatto o prefisso di cartella). */
    private static boolean isSkipped(String origin) {
        String p = toPath(origin);
        if (p.isEmpty()) {
            return false;
        }
        if (SKIP_PATHS.contains(p)) {
            return true;
        }
        for (String prefix : SKIP_PREFIXES) {
            if (p.equals(prefix) || p.startsWith(prefix + "\\")) {
                return true;
            }
        }
        return false;
    }

    /** True per le classi del runtime JDK (nome noto o origine jrt:/bootstrap). */
    private static boolean isJdk(String internalName, String origin) {
        if (origin == null || origin.equals("bootstrap") || origin.startsWith("jrt:")) {
            return true;
        }
        if (internalName != null) {
            for (String prefix : JDK_PREFIXES) {
                if (internalName.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Normalizza un'origine in percorso confrontabile su Windows:
     * "file:/C:/x%20y/z.jar" -> "c:\x y\z.jar" (minuscolo, separatori '\').
     * Stringa vuota se non è un file.
     */
    private static String toPath(String origin) {
        if (origin == null) {
            return "";
        }
        String s = origin.trim();
        if (s.isEmpty() || s.equals("bootstrap") || s.startsWith("jrt:")) {
            return "";
        }
        if (s.startsWith("file:")) {
            s = s.substring(5);
        }
        try {
            s = URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // percent-encoding non valido: si tiene com'è
        }
        if (s.length() >= 3 && s.charAt(0) == '/' && s.charAt(2) == ':') {
            s = s.substring(1);
        } else if (s.startsWith("//") && s.length() >= 4 && s.charAt(3) == ':') {
            s = s.substring(2);
        }
        s = s.replace('/', '\\').toLowerCase(Locale.ROOT);
        while (s.endsWith("\\")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    /* ---------- progresso su file (letto dall'app durante l'attesa) ---------- */

    /** Scrive progress.txt: una riga {@code k=v;…} sovrascritta a ogni blocco. */
    private static void progress(File dir, String phase, int done, int total) {
        try {
            String line = "phase=" + phase + ";done=" + done + ";total=" + total
                    + ";skipped_jdk=" + skippedJdkCount + ";skipped_trusted=" + skippedTrustedCount + "\n";
            Files.writeString(new File(dir, "progress.txt").toPath(), line, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // avanzamento best-effort: il dump vale comunque
        }
    }

    private static Map<String, String> parse(String args) {
        Map<String, String> m = new java.util.LinkedHashMap<>();
        if (args == null) {
            return m;
        }
        for (String kv : args.split(";")) {
            int eq = kv.indexOf('=');
            if (eq > 0) {
                m.put(kv.substring(0, eq).trim(), kv.substring(eq + 1).trim());
            }
        }
        return m;
    }

    /** Transformer-osservatore: fotografa i byte, non trasforma nulla. */
    private static final class Snapshot implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if (className == null || classfileBuffer == null || classfileBuffer.length < 8) {
                return null;
            }
            String origin = originOf(protectionDomain);
            if (isJdk(className, origin) || isSkipped(origin)) {
                return null;
            }
            CACHE.putIfAbsent(className, classfileBuffer.clone());
            ORIGINS.putIfAbsent(className, origin);
            return null;
        }

        private static String originOf(ProtectionDomain pd) {
            try {
                if (pd != null && pd.getCodeSource() != null && pd.getCodeSource().getLocation() != null) {
                    return pd.getCodeSource().getLocation().toString();
                }
            } catch (Exception ignored) {
                // origine non leggibile: bootstrap
            }
            return "bootstrap";
        }
    }

    /** Origine (URL) di una classe caricata, con le stesse regole del transformer. */
    private static String originOf(ProtectionDomain pd) {
        try {
            if (pd != null && pd.getCodeSource() != null && pd.getCodeSource().getLocation() != null) {
                return pd.getCodeSource().getLocation().toString();
            }
        } catch (Exception ignored) {
            // origine non leggibile: bootstrap
        }
        return "bootstrap";
    }
}
