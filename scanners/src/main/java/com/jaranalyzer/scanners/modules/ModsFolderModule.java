package com.jaranalyzer.scanners.modules;

import com.jaranalyzer.common.ModuleId;
import com.jaranalyzer.common.ModuleResult;
import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.FindingMapper;
import com.jaranalyzer.scanners.ProgressSink;
import com.jaranalyzer.scanners.ScanContext;
import com.jaranalyzer.scanners.ScanException;
import com.jaranalyzer.scanners.ScanModule;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.SignatureSet;
import com.jaranalyzer.scanners.engine.Hashing;
import com.jaranalyzer.scanners.engine.ModMetadata;
import com.jaranalyzer.scanners.engine.Sanitizer;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@code mods_folder}: inventario locale della cartella mod autorizzata.
 * Solo analisi locale (hash streaming, metadati offline, quick-flag, reputation):
 * niente upload di JAR, niente Modrinth (resta allo Staff), niente percorsi
 * assoluti nei risultati. Errori sui singoli file non abortiscono il modulo.
 */
public final class ModsFolderModule implements ScanModule {
    private static final Logger log = LoggerFactory.getLogger(ModsFolderModule.class);
    /** Limite file *.jar per cartella (oltre: FATAL, cartella anomala). */
    public static final int MAX_FILES = 5_000;
    private static final Pattern OBFUSCATED_CLASS =
            Pattern.compile("[\\u3040-\\u309F\\u30A0-\\u30FF\\u4e00-\\u9fff\\u0400-\\u04ff\\uac00-\\ud7af]\\.class");

    @Override
    public String id() {
        return ModuleId.MODS_FOLDER;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.DirectoryContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve DirectoryContext");
        }
        Path dir = ((ScanContext.DirectoryContext) ctx).directory();
        List<Finding> findings = new ArrayList<>();
        if (dir == null || !Files.exists(dir)) {
            findings.add(new Finding("mods-dir-missing", "Cartella mods assente: nessuna mod installata.",
                    Severity.INFO, Category.STRUCTURE, "", null));
            return result(start, findings, 0, 0, 0, 0);
        }
        if (!Files.isDirectory(dir) || !Files.isReadable(dir)) {
            throw ScanException.fatal(id(), "cartella non leggibile: " + Sanitizer.fileName(dir));
        }
        File[] jars = dir.toFile().listFiles((d, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (jars == null) {
            throw ScanException.fatal(id(), "elenco file fallito: " + Sanitizer.fileName(dir));
        }
        if (jars.length > MAX_FILES) {
            throw ScanException.fatal(id(), "troppi file (" + jars.length + ", limite " + MAX_FILES + ")");
        }
        java.util.Arrays.sort(jars, Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));
        long suspicious = 0;
        long failed = 0;
        long bytes = 0;
        for (int i = 0; i < jars.length; i++) {
            checkCancelled(progress);
            progress.report(id(), "scan", jars.length == 0 ? 100 : (100 * i) / jars.length);
            FileResult r = scanOne(jars[i].toPath(), signatures);
            findings.add(r.finding);
            if (r.suspicious) {
                suspicious++;
            }
            if (r.failed) {
                failed++;
            }
            bytes += r.bytes;
        }
        progress.report(id(), "done", 100);
        log.info("mods_folder {}: {} file, {} sospetti, {} illeggibili",
                Sanitizer.fileName(dir), jars.length, suspicious, failed);
        return result(start, findings, jars.length, suspicious, failed, bytes);
    }

    private record FileResult(Finding finding, boolean suspicious, boolean failed, long bytes) {
    }

    private FileResult scanOne(Path jar, SignatureSet signatures) {
        String name = Sanitizer.fileName(jar);
        long size = 0;
        try {
            size = Files.size(jar);
        } catch (Exception e) {
            return unreadable(name, 0, "dimensione illeggibile: " + Sanitizer.scrub(message(e), jar));
        }
        String[] hashes;
        try {
            hashes = Hashing.sha256AndSha1(jar);
        } catch (Exception e) {
            return unreadable(name, size, "hash fallito: " + Sanitizer.scrub(message(e), jar));
        }
        String sha256 = hashes[0];
        ModMetadata.Info meta;
        String quickReason = null;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            meta = ModMetadata.read(zip);
            quickReason = quickFlagScan(zip, signatures);
        } catch (Exception e) {
            return unreadable(name, size, "non è un archivio JAR valido: " + Sanitizer.scrub(message(e), jar));
        }
        String malicious = signatures.maliciousHashes().get(sha256.toLowerCase(Locale.ROOT));
        if (malicious != null) {
            return new FileResult(suspicious(name, size, sha256, hashes[1], meta,
                    "Hash noto malevolo" + (malicious.isBlank() ? "" : ": " + malicious),
                    Severity.CRITICAL, com.jaranalyzer.scanners.Category.MALWARE_SIGNATURE),
                    true, false, size);
        }
        if (quickReason != null) {
            return new FileResult(suspicious(name, size, sha256, hashes[1], meta,
                    quickReason, Severity.HIGH, com.jaranalyzer.scanners.Category.CHEAT),
                    true, false, size);
        }
        String good = signatures.knownGoodHashes().get(sha256.toLowerCase(Locale.ROOT));
        StringBuilder ev = evidence(name, size, sha256, hashes[1], meta);
        if (good != null) {
            ev.append("\nReputation: pulito").append(good.isBlank() ? "" : " (" + good + ")");
        }
        return new FileResult(new Finding("mod-file", "Mod analizzata: " + name + statusSuffix(meta, good != null),
                Severity.INFO, Category.STRUCTURE, name, ev.toString()), false, false, size);
    }

    private FileResult unreadable(String name, long size, String reason) {
        return new FileResult(new Finding("mod-unreadable", "File non analizzabile: " + name,
                Severity.LOW, Category.STRUCTURE, name, "Motivo: " + reason), false, true, size);
    }

    private Finding suspicious(String name, long size, String sha256, String sha1,
            ModMetadata.Info meta, String reason, Severity severity, Category category) {
        StringBuilder ev = evidence(name, size, sha256, sha1, meta);
        ev.append("\nSegnalazione: ").append(reason);
        return new Finding("mod-suspicious", "Mod sospetta: " + name, severity, category, name, ev.toString());
    }

    private StringBuilder evidence(String name, long size, String sha256, String sha1, ModMetadata.Info meta) {
        StringBuilder ev = new StringBuilder();
        ev.append("File: ").append(name).append("\nSHA-256: ").append(sha256)
                .append("\nSHA-1: ").append(sha1).append("\nSize: ").append(size);
        if (meta.modName() != null) {
            ev.append("\nMod: ").append(meta.modName());
        }
        if (meta.knownAuthor()) {
            ev.append("\nAutore: ").append(meta.author()).append(" (").append(meta.source()).append(")");
        }
        return ev;
    }

    private String statusSuffix(ModMetadata.Info meta, boolean knownGood) {
        if (knownGood) {
            return " (reputation pulita)";
        }
        if (meta.modName() != null) {
            return " (verifica Modrinth allo Staff)";
        }
        return "";
    }

    private String quickFlagScan(ZipFile zip, SignatureSet signatures) {
        var entries = zip.entries();
        while (entries.hasMoreElements()) {
            String orig = entries.nextElement().getName();
            String lower = orig.toLowerCase(Locale.ROOT);
            for (String flag : signatures.quickFlags()) {
                if (!flag.isEmpty() && lower.contains(flag)) {
                    return "Percorso o signature sospetta rilevata: " + flag;
                }
            }
            if (OBFUSCATED_CLASS.matcher(orig).find()) {
                return "Nome classe offuscata (caratteri non-standard): " + orig;
            }
        }
        return null;
    }

    private ModuleResult result(long start, List<Finding> findings, long files,
            long suspicious, long failed, long bytes) {
        Map<String, Long> counters = new HashMap<>();
        counters.put("files", files);
        counters.put("suspicious", suspicious);
        counters.put("failed", failed);
        counters.put("bytes", bytes);
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
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
