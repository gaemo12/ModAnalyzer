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
import com.jaranalyzer.scanners.engine.ModsFolderAudit;
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
            return result(start, findings, 0, 0, 0, 0, ModsFolderAudit.Report.empty());
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
        List<ModsFolderAudit.Entry> auditEntries = new ArrayList<>();
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
            if (r.fileName != null) {
                auditEntries.add(new ModsFolderAudit.Entry(r.fileName, r.modId, r.modName, r.nonJarKind));
            }
        }
        ModsFolderAudit.Report audit = ModsFolderAudit.audit(dir, auditEntries, signatures.quickFlags());
        findings.addAll(auditFindings(audit));
        suspicious += audit.suspiciousDisabled().size();
        progress.report(id(), "done", 100);
        log.info("mods_folder {}: {} file, {} sospetti, {} illeggibili, {} problemi di struttura",
                Sanitizer.fileName(dir), jars.length, suspicious, failed, audit.issues());
        return result(start, findings, jars.length, suspicious, failed, bytes, audit);
    }

    private record FileResult(Finding finding, boolean suspicious, boolean failed, long bytes,
            String fileName, String modId, String modName, String nonJarKind) {
    }

    /** Finding aggiuntivi dell'audit strutturale (id duplicati, rename, mod disabilitate). */
    private List<Finding> auditFindings(ModsFolderAudit.Report audit) {
        List<Finding> out = new ArrayList<>();
        for (ModsFolderAudit.DuplicateId d : audit.duplicateIds()) {
            out.add(new Finding("mods-duplicate-id", "Id duplicato nella cartella mods: " + d.id(),
                    Severity.MEDIUM, Category.STRUCTURE, null,
                    "Lo stesso id è dichiarato da più JAR abilitati:\n" + String.join("\n", d.files())
                            + "\nUno può sovrascrivere o mascherare l'altro: verifica quale versione vuoi tenere."));
        }
        for (ModsFolderAudit.Mismatch m : audit.mismatches()) {
            out.add(new Finding("mods-name-mismatch", "Nome file diverso dai metadati: " + m.fileName(),
                    Severity.LOW, Category.STRUCTURE, m.fileName(), m.note()));
        }
        for (ModsFolderAudit.DisabledFinding d : audit.suspiciousDisabled()) {
            out.add(new Finding("mods-disabled-suspicious", "Mod disabilitata sospetta: " + d.fileName(),
                    Severity.HIGH, Category.CHEAT, d.fileName(),
                    "File disabilitato con un indicatore noto: " + d.reason()
                            + ". Un cheat può essere nascosto rinominando il jar; controlla da dove arriva."));
        }
        if (!audit.disabled().isEmpty()) {
            List<String> shown = audit.disabled().size() > 20
                    ? audit.disabled().subList(0, 20) : audit.disabled();
            out.add(new Finding("mods-disabled", "Mod disabilitate nella cartella (" + audit.disabled().size() + ")",
                    Severity.INFO, Category.STRUCTURE, null,
                    "File non attivi (rinominati da launcher o dall'utente):\n" + String.join("\n", shown)
                            + (audit.disabled().size() > shown.size() ? "\n…" : "")));
        }
        if (!audit.notes().isEmpty()) {
            out.add(new Finding("mods-audit-note", "Nota del controllo struttura cartella",
                    Severity.INFO, Category.STRUCTURE, null, String.join("\n", audit.notes())));
        }
        return out;
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
        String nonJar = ModsFolderAudit.nonJarMagic(jar);
        ModMetadata.Info meta;
        String quickReason = null;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            meta = ModMetadata.read(zip);
            quickReason = quickFlagScan(zip, signatures);
        } catch (Exception e) {
            if (nonJar != null) {
                return disguised(name, size, sha256, hashes[1], nonJar);
            }
            return unreadable(name, size, "non è un archivio JAR valido: " + Sanitizer.scrub(message(e), jar));
        }
        String malicious = signatures.maliciousHashes().get(sha256.toLowerCase(Locale.ROOT));
        if (malicious != null) {
            return new FileResult(suspicious(name, size, sha256, hashes[1], meta,
                    "Hash noto malevolo" + (malicious.isBlank() ? "" : ": " + malicious),
                    Severity.CRITICAL, com.jaranalyzer.scanners.Category.MALWARE_SIGNATURE, null),
                    true, false, size, name, meta.id(), meta.modName(), null);
        }
        if (nonJar != null) {
            return new FileResult(suspicious(name, size, sha256, hashes[1], meta,
                    "Il file ha estensione .jar ma è " + nonJar + ": possibile file rinominato.",
                    Severity.HIGH, Category.STRUCTURE, nonJar),
                    true, false, size, name, meta.id(), meta.modName(), nonJar);
        }
        if (quickReason != null) {
            return new FileResult(suspicious(name, size, sha256, hashes[1], meta,
                    quickReason, Severity.HIGH, com.jaranalyzer.scanners.Category.CHEAT, null),
                    true, false, size, name, meta.id(), meta.modName(), null);
        }
        String good = signatures.knownGoodHashes().get(sha256.toLowerCase(Locale.ROOT));
        StringBuilder ev = evidence(name, size, sha256, hashes[1], meta);
        if (good != null) {
            ev.append("\nReputation: pulito").append(good.isBlank() ? "" : " (" + good + ")");
        }
        return new FileResult(new Finding("mod-file", "Mod analizzata: " + name + statusSuffix(meta, good != null),
                Severity.INFO, Category.STRUCTURE, name, ev.toString()), false, false, size,
                name, meta.id(), meta.modName(), null);
    }

    private FileResult disguised(String name, long size, String sha256, String sha1, String nonJar) {
        StringBuilder ev = new StringBuilder();
        ev.append("File: ").append(name).append("\nSHA-256: ").append(sha256)
                .append("\nSHA-1: ").append(sha1).append("\nSize: ").append(size)
                .append("\nFirma rilevata: ").append(nonJar)
                .append("\nIl file non è un archivio JAR valido: possibile eseguibile o archivio rinominato.");
        return new FileResult(new Finding("mod-disguised", "File .jar camuffato: " + name,
                Severity.HIGH, Category.STRUCTURE, name, ev.toString()), true, false, size,
                name, null, null, nonJar);
    }

    private FileResult unreadable(String name, long size, String reason) {
        return new FileResult(new Finding("mod-unreadable", "File non analizzabile: " + name,
                Severity.LOW, Category.STRUCTURE, name, "Motivo: " + reason), false, true, size,
                name, null, null, null);
    }

    private Finding suspicious(String name, long size, String sha256, String sha1,
            ModMetadata.Info meta, String reason, Severity severity, Category category, String nonJar) {
        StringBuilder ev = evidence(name, size, sha256, sha1, meta);
        if (nonJar != null) {
            ev.append("\nFirma rilevata: ").append(nonJar);
        }
        ev.append("\nSegnalazione: ").append(reason);
        return new Finding("mod-suspicious", "Mod sospetta: " + name, severity, category, name, ev.toString());
    }

    private StringBuilder evidence(String name, long size, String sha256, String sha1, ModMetadata.Info meta) {
        StringBuilder ev = new StringBuilder();
        ev.append("File: ").append(name).append("\nSHA-256: ").append(sha256)
                .append("\nSHA-1: ").append(sha1).append("\nSize: ").append(size);
        if (meta.id() != null && !meta.id().isBlank()) {
            ev.append("\nId: ").append(meta.id());
        }
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
            long suspicious, long failed, long bytes, ModsFolderAudit.Report audit) {
        Map<String, Long> counters = new java.util.LinkedHashMap<>(); // ordine stabile nel JSON (determinismo)
        counters.put("files", files);
        counters.put("suspicious", suspicious);
        counters.put("failed", failed);
        counters.put("bytes", bytes);
        counters.put("auditIssues", (long) audit.issues());
        counters.put("duplicateIds", (long) audit.duplicateIds().size());
        counters.put("disabled", (long) audit.disabled().size());
        counters.put("disguised", (long) audit.disguised().size());
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
