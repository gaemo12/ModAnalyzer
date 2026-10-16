package com.jaranalyzer.memagent;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.ProtectionDomain;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
 */
public final class MemAgent {
    private static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();

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
        inst.addTransformer(new Snapshot(), true);
        System.out.println("[MemAgent] attivo (" + mode + ") -> " + dir);
        if (!"false".equalsIgnoreCase(opt.getOrDefault("retransform", "true"))) {
            retransformAll(inst);
        }
        int n = dump(dir);
        try {
            Files.writeString(new File(dir, "done.marker").toPath(),
                    "classes=" + n + "\n", StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[MemAgent] marker fallito: " + e.getMessage());
        }
        System.out.println("[MemAgent] dump: " + n + " classi in " + dir);
    }

    /** Ri-trasforma le classi già caricate (best-effort, una per volta). */
    private static void retransformAll(Instrumentation inst) {
        if (!inst.isRetransformClassesSupported()) {
            System.err.println("[MemAgent] retransform non supportato dalla JVM");
            return;
        }
        int ok = 0, ko = 0;
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (!inst.isModifiableClass(c)) {
                continue;
            }
            try {
                inst.retransformClasses(c);
                ok++;
            } catch (Throwable t) {
                ko++;
            }
        }
        System.out.println("[MemAgent] ri-trasformate: " + ok + " (saltate: " + ko + ")");
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
            if (className != null && classfileBuffer != null && classfileBuffer.length >= 8) {
                CACHE.putIfAbsent(className, classfileBuffer.clone());
            }
            return null;
        }
    }
}
