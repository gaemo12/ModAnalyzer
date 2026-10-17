package com.jaranalyzer.scanners.modules;

import com.jaranalyzer.common.ModuleId;
import com.jaranalyzer.common.ModuleResult;
import com.jaranalyzer.scanners.FindingMapper;
import com.jaranalyzer.scanners.ProgressSink;
import com.jaranalyzer.scanners.ScanContext;
import com.jaranalyzer.scanners.ScanException;
import com.jaranalyzer.scanners.ScanModule;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.SignatureSet;
import com.jaranalyzer.scanners.engine.ArchiveIntegrityAnalyzer;
import com.jaranalyzer.scanners.engine.BytecodeAnalyzer;
import com.jaranalyzer.scanners.engine.CheatAnalyzer;
import com.jaranalyzer.scanners.engine.CheatSignatureAnalyzer;
import com.jaranalyzer.scanners.engine.CryptoAnalyzer;
import com.jaranalyzer.scanners.engine.EntropyAnalyzer;
import com.jaranalyzer.scanners.engine.ExfiltrationAnalyzer;
import com.jaranalyzer.scanners.engine.Hashing;
import com.jaranalyzer.scanners.engine.InjectionAnalyzer;
import com.jaranalyzer.scanners.engine.IocRuleAnalyzer;
import com.jaranalyzer.scanners.engine.JarAnalyzer;
import com.jaranalyzer.scanners.engine.JavawAnalyzer;
import com.jaranalyzer.scanners.engine.ManifestAnalyzer;
import com.jaranalyzer.scanners.engine.MinerAnalyzer;
import com.jaranalyzer.scanners.engine.ModMetadata;
import com.jaranalyzer.scanners.engine.NetworkAnalyzer;
import com.jaranalyzer.scanners.engine.ObfuscationAnalyzer;
import com.jaranalyzer.scanners.engine.ProcessInjectionAnalyzer;
import com.jaranalyzer.scanners.engine.RATAnalyzer;
import com.jaranalyzer.scanners.engine.RansomwareAnalyzer;
import com.jaranalyzer.scanners.engine.Sanitizer;
import com.jaranalyzer.scanners.engine.SignatureAnalyzer;
import com.jaranalyzer.scanners.engine.StealerAnalyzer;
import com.jaranalyzer.scanners.engine.StringDecryptorAnalyzer;
import com.jaranalyzer.scanners.engine.StructureAnalyzer;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@code single_jar}: analisi locale di un file JAR esplicito col motore condiviso.
 * Offline (niente Modrinth/VirusTotal/rete), niente drag&amp;drop/controller: solo un percorso.
 * Errori dei singoli analyzer non abortiscono il modulo (contatore {@code analyzerErrors}).
 */
public final class SingleJarModule implements ScanModule {
    private static final Logger log = LoggerFactory.getLogger(SingleJarModule.class);
    /** Limite input documentato (vedere docs/SCANNERS.md). */
    public static final long MAX_JAR_BYTES = 512L * 1024 * 1024;
    private static final long ANALYZER_TIMEOUT_SECONDS = 30L;

    @Override
    public String id() {
        return ModuleId.SINGLE_JAR;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.JarFileContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve JarFileContext");
        }
        Path jar = ((ScanContext.JarFileContext) ctx).jar();
        String fileName = Sanitizer.fileName(jar);
        checkCancelled(progress);
        progress.report(id(), "hash", 5);
        String sha256 = hash(jar, fileName);
        checkCancelled(progress);
        progress.report(id(), "open", 10);
        JarStats stats = open(jar, fileName);
        List<Finding> findings = new ArrayList<>();
        findings.add(hashFinding(fileName, stats.bytes, sha256));
        String malicious = signatures.maliciousHashes().get(sha256.toLowerCase(java.util.Locale.ROOT));
        if (malicious != null) {
            findings.add(new Finding("known-malicious-hash",
                    "Hash noto malevolo" + (malicious.isBlank() ? "" : ": " + malicious),
                    Severity.CRITICAL, Category.MALWARE_SIGNATURE, fileName, "SHA-256: " + sha256));
        } else {
            String good = signatures.knownGoodHashes().get(sha256.toLowerCase(java.util.Locale.ROOT));
            if (good != null) {
                findings.add(new Finding("known-good-hash",
                        "Hash di release nota e pulita" + (good.isBlank() ? "" : ": " + good),
                        Severity.INFO, Category.MALWARE_SIGNATURE, fileName, "SHA-256: " + sha256));
            }
        }
        checkCancelled(progress);
        progress.report(id(), "analyze", 20);
        int analyzerErrors = runAnalyzers(jar.toFile(), signatures, findings, progress);
        checkCancelled(progress);
        progress.report(id(), "certificate", 85);
        findings.addAll(certificatePresence(jar, fileName));
        progress.report(id(), "modinfo", 90);
        findings.addAll(modInfo(jar, fileName));
        checkCancelled(progress);
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new java.util.LinkedHashMap<>(); // ordine stabile nel JSON (determinismo)
        counters.put("files", 1L);
        counters.put("classes", stats.classes);
        counters.put("entries", stats.entries);
        counters.put("bytes", stats.bytes);
        counters.put("analyzerErrors", (long) analyzerErrors);
        long duration = System.currentTimeMillis() - start;
        log.info("single_jar {}: {} finding(s), {} classi", fileName, findings.size(), stats.classes);
        return new ModuleResult(id(), true, duration, FindingMapper.toProtocol(findings), counters, null);
    }

    private String hash(Path jar, String fileName) throws ScanException {
        if (!Files.isRegularFile(jar) || !Files.isReadable(jar)) {
            throw ScanException.fatal(id(), "file non leggibile: " + fileName);
        }
        try {
            long size = Files.size(jar);
            if (size <= 0) {
                throw ScanException.fatal(id(), "file vuoto: " + fileName);
            }
            if (size > MAX_JAR_BYTES) {
                throw ScanException.fatal(id(), "file oltre il limite (" + MAX_JAR_BYTES + " byte): " + fileName);
            }
            if (!fileName.toLowerCase(java.util.Locale.ROOT).endsWith(".jar")) {
                throw ScanException.fatal(id(), "formato non valido (atteso .jar): " + fileName);
            }
            return Hashing.sha256(jar);
        } catch (ScanException e) {
            throw e;
        } catch (Exception e) {
            throw ScanException.fatal(id(), "hash fallito per " + fileName + ": "
                    + Sanitizer.scrub(message(e), jar));
        }
    }

    private record JarStats(long bytes, long entries, long classes) {
    }

    private JarStats open(Path jar, String fileName) throws ScanException {
        try {
            long bytes = Files.size(jar);
            long entries = 0;
            long classes = 0;
            try (JarFile zf = new JarFile(jar.toFile())) {
                Enumeration<JarEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    JarEntry e = en.nextElement();
                    if (e.isDirectory()) {
                        continue;
                    }
                    entries++;
                    if (e.getName().endsWith(".class")) {
                        classes++;
                    }
                }
            } catch (Exception e) {
                throw ScanException.fatal(id(), "non è un archivio JAR valido (" + fileName + "): "
                        + Sanitizer.scrub(message(e), jar));
            }
            return new JarStats(bytes, entries, classes);
        } catch (ScanException e) {
            throw e;
        } catch (Exception e) {
            throw ScanException.fatal(id(), "apertura fallita per " + fileName + ": "
                    + Sanitizer.scrub(message(e), jar));
        }
    }

    private Finding hashFinding(String fileName, long bytes, String sha256) {
        return new Finding("file-hash", "SHA-256 del file analizzato", Severity.INFO,
                Category.STRUCTURE, fileName, "SHA-256: " + sha256 + "\nSize: " + bytes);
    }

    private List<JarAnalyzer> analyzers(SignatureSet signatures) {
        List<JarAnalyzer> out = new ArrayList<>();
        out.add(new SignatureAnalyzer(signatures));
        out.add(new EntropyAnalyzer());
        out.add(new ManifestAnalyzer());
        out.add(new StructureAnalyzer());
        out.add(new ObfuscationAnalyzer());
        out.add(new JavawAnalyzer());
        out.add(new NetworkAnalyzer());
        out.add(new CryptoAnalyzer());
        out.add(new CheatAnalyzer());
        out.add(new InjectionAnalyzer());
        out.add(new RATAnalyzer());
        out.add(new RansomwareAnalyzer());
        out.add(new StealerAnalyzer());
        out.add(new MinerAnalyzer());
        out.add(new StringDecryptorAnalyzer());
        out.add(new ExfiltrationAnalyzer());
        out.add(new ProcessInjectionAnalyzer());
        out.add(new CheatSignatureAnalyzer(signatures));
        out.add(new IocRuleAnalyzer());
        out.add(new ArchiveIntegrityAnalyzer());
        return out;
    }

    private int runAnalyzers(File file, SignatureSet signatures, List<Finding> findings, ProgressSink progress) throws ScanException {
        List<JarAnalyzer> list = analyzers(signatures);
        int pool = Math.max(2, Math.min(list.size(), Runtime.getRuntime().availableProcessors()));
        ExecutorService pool2 = Executors.newFixedThreadPool(pool, r -> {
            Thread t = new Thread(r, "scanners-single-jar");
            t.setDaemon(true);
            // Priorità sotto il normale: la GUI (stessa JVM) resta reattiva
            // durante la scansione dei dump grandi.
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.NORM_PRIORITY - 1));
            return t;
        });
        int errors = 0;
        Map<Future<List<Finding>>, String> futures = new HashMap<>();
        try {
            for (JarAnalyzer a : list) {
                Callable<List<Finding>> task = () -> a.analyze(file);
                futures.put(pool2.submit(task), a.getClass().getSimpleName());
            }
            int done = 0;
            for (Map.Entry<Future<List<Finding>>, String> e : futures.entrySet()) {
                checkCancelled(progress);
                try {
                    List<Finding> part = e.getKey().get(ANALYZER_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    if (part != null) {
                        synchronized (findings) {
                            findings.addAll(part);
                        }
                    }
                } catch (java.util.concurrent.TimeoutException te) {
                    e.getKey().cancel(true);
                    errors++;
                    log.warn("Analyzer {} oltre il timeout, saltato", e.getValue());
                } catch (Exception ex) {
                    errors++;
                    log.warn("Analyzer {} fallito, saltato: {}", e.getValue(), message(ex));
                }
                done++;
                progress.report(id(), "analyze", 20 + (60 * done) / futures.size());
            }
            checkCancelled(progress);
            try (JarFile zf = new JarFile(file)) {
                new BytecodeAnalyzer(signatures).analyze(zf, findings);
            } catch (Exception ex) {
                errors++;
                log.warn("BytecodeAnalyzer fallito, saltato: {}", message(ex));
            }
        } finally {
            pool2.shutdownNow();
        }
        return errors;
    }

    private List<Finding> certificatePresence(Path jar, String fileName) {
        List<Finding> out = new ArrayList<>();
        try (JarFile zf = new JarFile(jar.toFile())) {
            Enumeration<JarEntry> en = zf.entries();
            boolean signed = false;
            while (en.hasMoreElements()) {
                String name = en.nextElement().getName().toUpperCase(java.util.Locale.ROOT);
                if (name.startsWith("META-INF/") && (name.endsWith(".SF") || name.endsWith(".RSA")
                        || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    signed = true;
                    break;
                }
            }
            if (!signed) {
                out.add(new Finding("unsigned-jar", "JAR senza file di firma: impossibile verificare un editore.",
                        Severity.LOW, Category.CERTIFICATE, fileName,
                        "Nessun META-INF/*.SF|RSA|DSA|EC. La verifica completa resta allo Staff."));
            } else {
                out.add(new Finding("signed-jar", "JAR con file di firma presenti (verifica completa allo Staff).",
                        Severity.INFO, Category.CERTIFICATE, fileName, null));
            }
        } catch (Exception e) {
            log.debug("certificatePresence fallito per {}: {}", fileName, message(e));
        }
        return out;
    }

    private List<Finding> modInfo(Path jar, String fileName) {
        List<Finding> out = new ArrayList<>();
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(jar.toFile())) {
            ModMetadata.Info info = ModMetadata.read(zf);
            if (info.modName() != null || info.knownAuthor()) {
                out.add(new Finding("minecraft-mod",
                        "Mod Minecraft" + (info.modName() != null ? ": " + info.modName() : "")
                                + (info.knownAuthor() ? " di " + info.author() : ""),
                        Severity.INFO, Category.MANIFEST, fileName,
                        "Source: " + info.source()));
            }
        } catch (Exception e) {
            log.debug("modInfo fallito per {}: {}", fileName, message(e));
        }
        return out;
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }

    private static String message(Exception e) {
        String m = e.getMessage();
        return m == null ? e.getClass().getSimpleName() : m;
    }
}
