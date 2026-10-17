package modscan;

import com.jaranalyzer.common.ModuleId;
import com.jaranalyzer.common.ModuleResult;
import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.scanners.ProgressSink;
import com.jaranalyzer.scanners.ScanContext;
import com.jaranalyzer.scanners.ScanModule;
import com.jaranalyzer.scanners.engine.MinecraftPathResolver;
import com.jaranalyzer.scanners.engine.ProcessInventory;
import com.jaranalyzer.scanners.engine.Sanitizer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ModScanOpen — scansione open source (MIT) delle mod di Minecraft:
 * un file .jar o un'intera cartella mods. Nessuna licenza, nessuna rete, nessun backend.
 * CLI quando arrivano argomenti, GUI (WebView, stessa UI della vecchia app con le due
 * modalità Jar e Mods) quando si avvia senza argomenti.
 */
public final class ModScanOpen {

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            try {
                Class.forName("javafx.application.Application");
                javafx.application.Application.launch(WebUi.class);
                return;
            } catch (Throwable t) {
                System.err.println("GUI non disponibile (" + t.getMessage() + "): uso la CLI.\n");
                try {
                    System.exit(Cli.run(new String[]{"help"}));
                } catch (Exception e) {
                    System.err.println("Errore: " + e.getMessage());
                    System.exit(3);
                }
            }
            return;
        }
        try {
            System.exit(Cli.run(args));
        } catch (Exception e) {
            System.err.println("Errore: " + (e.getMessage() == null ? e.toString() : e.getMessage()));
            System.exit(3);
        }
    }

    private ModScanOpen() {
    }

    /** Accesso al motore condiviso per la UI/CLI (conover SignatureSet e ProgressSink espliciti). */
    static ModuleResult scanModule(String id, ScanContext ctx, com.jaranalyzer.scanners.SignatureSet signatures, ProgressSink sink)
            throws IOException, com.jaranalyzer.scanners.ScanException {
        return Cli.scanModule(id, ctx, signatures, sink);
    }

    static final class Cli {
        static int run(String[] args) throws IOException {
            if (args.length == 0 || args[0].equals("help") || args[0].equals("--help")) {
                usage();
                return 0;
            }
            String cmd = args[0];
            Map<String, String> opt = options(args);
            if (cmd.equals("journal")) {
                return runJournal(opt);
            }
            if (!cmd.equals("scan")) {
                System.err.println("Comando sconosciuto: " + cmd);
                usage();
                return 1;
            }
            Path jar = opt.containsKey("jar") ? Path.of(opt.get("jar")) : null;
            Path mods = null;
            if (opt.containsKey("mods")) {
                String v = opt.get("mods");
                mods = "auto".equalsIgnoreCase(v) ? locate() : Path.of(v);
            } else if (jar == null && !opt.containsKey("mem")) {
                mods = locate();
            }
            if (jar == null && mods == null && !opt.containsKey("mem")) {
                System.err.println("Nessun bersaglio: specificare --jar <file>, --mods <dir|auto> o --mem <pid|auto>.");
                return 1;
            }
            boolean modsFirst = opt.containsKey("mods-first");
            List<Map<String, Object>> results = new ArrayList<>();
            if (opt.containsKey("mem")) {
                runMem(opt.get("mem"), opt.get("mem-out"), opt.get("mods"), results);
            }
            if (modsFirst) {
                runMods(mods, results);
                runJar(jar, results);
            } else {
                runJar(jar, results);
                runMods(mods, results);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("tool", "ModScanOpen");
            out.put("version", "1.2.0");
            out.put("openSource", true);
            out.put("results", results);
            String json = JsonCodec.write(out);
            String outFile = opt.get("out");
            if (outFile != null) {
                Files.writeString(Path.of(outFile), json, StandardCharsets.UTF_8);
                System.err.println("Risultato salvato in " + outFile);
            }
            System.out.println(json);
            return 0;
        }

        static void runJar(Path jar, List<Map<String, Object>> results) {
            if (jar == null) {
                return;
            }
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("module", ModuleId.SINGLE_JAR);
            try {
                if (!Files.isRegularFile(jar)) {
                    r.put("success", false);
                    r.put("error", "file non trovato: " + jar.toAbsolutePath());
                } else {
                    ModuleResult mr = run("single_jar", new ScanContext.JarFileContext(jar));
                    r.put("success", mr.success());
                    r.put("durationMillis", mr.durationMillis());
                    r.put("counters", mr.counters());
                    r.put("findings", jsonFindings(mr));
                    r.put("file", Sanitizer.fileName(jar));
                    if (mr.error() != null) {
                        r.put("error", mr.error());
                    }
                }
            } catch (Exception e) {
                r.put("success", false);
                r.put("error", message(e));
            }
            System.err.println("scan single_jar …");
            results.add(r);
        }

        static void runMods(Path mods, List<Map<String, Object>> results) {
            if (mods == null) {
                return;
            }
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("module", ModuleId.MODS_FOLDER);
            try {
                ModuleResult mr = run("mods_folder", new ScanContext.DirectoryContext(mods));
                r.put("success", mr.success());
                r.put("durationMillis", mr.durationMillis());
                r.put("counters", mr.counters());
                r.put("findings", jsonFindings(mr));
                r.put("folder", Sanitizer.fileName(mods));
                if (mr.error() != null) {
                    r.put("error", mr.error());
                }
            } catch (Exception e) {
                r.put("success", false);
                r.put("error", message(e));
            }
            System.err.println("scan mods_folder …");
            results.add(r);
        }

        static void runMem(String spec, String memOut, String modsOpt, List<Map<String, Object>> results) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("module", "mem_dump");
            r.put("source", "memory");
            try {
                String pid = MemDump.resolvePid(spec == null || spec.isBlank() ? "auto" : spec);
                r.put("pid", pid);
                Path workDir = memOut == null || memOut.isBlank()
                        ? Path.of(System.getProperty("java.io.tmpdir", "."), "modscan-mem")
                        : Path.of(memOut);

                /* Con --mods si salta ciò che è già verificato (mod + annidati +
                   librerie note): meno classi da ri-trasformare e da analizzare. */
                List<String> skip = new ArrayList<>();
                Map<String, Object> skipInfo = new LinkedHashMap<>();
                try {
                    java.io.File mods = null;
                    if (modsOpt != null && !modsOpt.isBlank()) {
                        mods = ("auto".equalsIgnoreCase(modsOpt) ? locate() : Path.of(modsOpt)).toFile();
                    }
                    if (mods != null && mods.isDirectory()) {
                        MemSkip.Result sr = MemSkip.buildFor(mods);
                        skip = sr.lines;
                        skipInfo = sr.summary();
                        System.err.println("mem-dump: skip " + skip.size() + " origini (mod verificate e librerie)");
                    } else if (modsOpt != null) {
                        skipInfo.put("note", "cartella mods non valida: dump completo");
                    } else {
                        skipInfo.put("note", "nessuna cartella mods indicata (--mods): dump completo");
                    }
                } catch (Exception e) {
                    skipInfo.put("note", "skip non calcolabile: " + message(e));
                }

                Path packed = MemDump.capture(pid, agentJar(), workDir, skip);
                ModuleResult mr = run("single_jar", new ScanContext.JarFileContext(packed));
                r.put("success", mr.success());
                r.put("durationMillis", mr.durationMillis());
                r.put("counters", mr.counters());
                List<Map<String, Object>> fj = jsonFindings(mr);
                Map<String, String> origins = MemDump.readOrigins(workDir.resolve("classes-" + pid));
                Map<String, Object> scope = MemScope.apply(packed, fj, origins);
                scope.put("skip", skipInfo);
                r.put("memoryScope", scope);
                for (Map<String, Object> f : fj) {
                    MemDump.attachOrigin(f, origins);
                }
                r.put("findings", fj);
                r.put("riskScore", OpenAnalysis.riskScore(fj));
                r.put("riskLevel", OpenAnalysis.riskLevel(OpenAnalysis.riskScore(fj), fj));
                r.put("file", Sanitizer.fileName(packed));
                if (mr.error() != null) {
                    r.put("error", mr.error());
                }
            } catch (Exception e) {
                r.put("success", false);
                r.put("error", message(e));
            }
            System.err.println("scan mem_dump …");
            results.add(r);
        }

        /** Sotto-comando: journal --mods <dir|auto> [--pid <pid>] [--after <data|ms>] [--usn] [--out file]. */
        static int runJournal(Map<String, String> opt) throws IOException {
            String mods = opt.get("mods");
            if (mods != null && (mods.isBlank() || "auto".equalsIgnoreCase(mods))) {
                mods = null; // rilevamento automatico dal processo javaw
            }
            String usn = null;
            if (opt.containsKey("usn")) {
                String v = opt.get("usn");
                usn = v == null || v.isBlank() ? "1" : v;
            }
            OpenApi.Response r = OpenJournal.check(mods, opt.get("pid"), opt.get("after"), usn);
            String outFile = opt.get("out");
            if (outFile != null) {
                Files.writeString(Path.of(outFile), r.body, StandardCharsets.UTF_8);
                System.err.println("Risultato salvato in " + outFile);
            }
            System.out.println(r.body);
            return r.status == 200 ? 0 : 1;
        }

        /** Jar dell'agent: proprietà modscan.agent, poi a fianco del nostro jar, poi target di sviluppo. */
        static Path agentJar() {
            String prop = System.getProperty("modscan.agent");
            if (prop != null && !prop.isBlank()) {
                return Path.of(prop);
            }
            try {
                Path own = Path.of(ModScanOpen.class.getProtectionDomain().getCodeSource().getLocation().toURI());
                Path nextTo = (Files.isDirectory(own) ? own : own.getParent()).resolve("MemAgent.jar");
                if (Files.isRegularFile(nextTo)) {
                    return nextTo;
                }
            } catch (Exception ignored) {
                // si passa al fallback di sviluppo
            }
            return Path.of("memagent", "target", "MemAgent.jar");
        }

    /** Rappresentazione JSON dei finding (JsonCodec non serializza POI provider). */
    static List<Map<String, Object>> jsonFindings(ModuleResult mr) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (mr.findings() == null) {
            return out;
        }
        for (com.jaranalyzer.common.Finding f : mr.findings()) {
            if (f == null) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("rule", f.rule());
            m.put("title", f.title());
            m.put("severity", f.severity());
            m.put("category", f.category());
            if (f.location() != null) {
                m.put("location", f.location());
            }
            if (f.evidence() != null) {
                m.put("evidence", f.evidence());
            }
            out.add(m);
        }
        return out;
    }

    /** Esecuzione di un modulo col motore condiviso (usata da CLI e GUI). */
    static ModuleResult run(String id, ScanContext ctx, com.jaranalyzer.scanners.SignatureSet signatures, ProgressSink sink)
            throws IOException, com.jaranalyzer.scanners.ScanException {
        ScanModule m = null;
        for (ScanModule candidate : com.jaranalyzer.scanners.modules.ScanModules.all()) {
            if (candidate.id().equals(id)) {
                m = candidate;
                break;
            }
        }
        if (m == null) {
            throw new IOException("modulo non disponibile in ModScanOpen: " + id);
        }
        return m.run(ctx, sink, signatures == null ? com.jaranalyzer.scanners.SignatureSets.empty() : signatures);
    }

    /** Alias storico per la CLI. */
    static ModuleResult run(String id, ScanContext ctx) throws IOException, com.jaranalyzer.scanners.ScanException {
        return run(id, ctx, com.jaranalyzer.scanners.SignatureSets.empty(), ProgressSink.noop());
    }

    /** Alias per la GUI (firma con sink reale e SignatureSet pre-caricato). */
    static ModuleResult scanModule(String id, ScanContext ctx, com.jaranalyzer.scanners.SignatureSet set, ProgressSink sink)
            throws IOException, com.jaranalyzer.scanners.ScanException {
        return run(id, ctx, set, sink);
    }

    /** Dalla mod folder del minecraft in esecuzione (javaw), con fallback ~/.minecraft/mods. */
    static Path locate() {
        try {
            for (ProcessInventory.ProcInfo p : ProcessInventory.snapshot()) {
                if (!p.java() || !p.detailsAvailable()) {
                    continue;
                }
                try {
                    String cmd = Sanitizer.redactHome(p.commandLine(), p.commandLine() == null ? "" : "");
                    for (MinecraftPathResolver.Hint h : MinecraftPathResolver.resolve(cmd, null)) {
                        String variants = com.jaranalyzer.scanners.engine.MinecraftPathResolver.modsDirOf(h.gameDir);
                        java.nio.file.Path dir = Path.of(variants);
                        if (java.nio.file.Files.isDirectory(dir)) {
                            return dir;
                        }
                    }
                } catch (Exception ignored) {
                    // tentativo fallito: si passa al prossimo processo
                }
            }
        } catch (Exception ignored) {
        }
        return defaultMinecraftMods();
    }

        static Path defaultMinecraftMods() {
            String appData = System.getenv("APPDATA");
            if (appData == null) {
                appData = System.getProperty("user.home", "");
            }
            return Path.of(appData, ".minecraft", "mods");
        }

        static Map<String, String> options(String[] a) {
            Map<String, String> m = new LinkedHashMap<>();
            for (int i = 1; i < a.length; i++) {
                String s = a[i];
                if (s.startsWith("--")) {
                    m.put(s.substring(2), (i + 1 < a.length && !a[i + 1].startsWith("--")) ? a[++i] : "true");
                }
            }
            return m;
        }

        static void usage() {
            System.out.println("ModScanOpen 1.2.0 - scansioni mod, open source (MIT), offline\n"
                    + "\n"
                    + "  scan --jar <file.jar>              analizza un file .jar\n"
                    + "  scan --mods <cartella|auto>        analizza tutta la cartella delle mod (auto: dal processo javaw)\n"
                    + "  scan --jar <f> --mods <d> --mods-first   entrambe le scansioni\n"
                    + "  scan --mem <pid|auto> [--mem-out <dir>] [--mods <cartella|auto>]\n"
                    + "                                     dump bytecode da JVM e scansione (opt-in);\n"
                    + "                                     con --mods le mod verificate e le librerie note non vengono dumpate\n"
                    + "  journal [--mods <cartella|auto>] [--pid <pid>] [--after <data|ms>] [--usn]\n"
                    + "                                     mod aggiunte/modificate dopo l'avvio di Minecraft\n"
                    + "      [--out file.json]              salva l'esito JSON su file\n");
            System.out.println("Esempi:");
            System.out.println("  java -jar ModScanOpen.jar scan --jar UnSospetto.jar");
            System.out.println("  java -jar ModScanOpen.jar scan --mods auto --out results.json");
            System.out.println("  java -jar ModScanOpen.jar journal --mods auto --usn --out journal.json");
        }

        static String message(Exception e) {
            String m = e.getMessage();
            return m == null ? e.getClass().getSimpleName() : m;
        }
    }
}
