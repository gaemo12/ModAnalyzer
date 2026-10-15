/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 */
package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.SignatureSet;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(SignatureAnalyzer.class);
    private static final long MAX_ENTRY_SIZE = 0x500000L;
    /** Campione iniziale letto dalle entry oversize invece di saltarle in silenzio (Fase 2). */
    private static final long SAMPLE_HEAD_BYTES = 1L * 1024 * 1024;
    /** Profondità massima di ricorsione nei JAR annidati (Fase 3). */
    private static final int MAX_NESTED_DEPTH = 2;
    /** Tetto totale ai byte annidati scompattati per archivio (anti zip-bomb). */
    private static final long MAX_NESTED_TOTAL_BYTES = 64L * 1024 * 1024;
    private static final Set<String> SUSPICIOUS_EXTENSIONS = Set.of(".exe", ".dll", ".bat", ".sh", ".ps1",
            ".so", ".dylib", ".cmd", ".vbs", ".scr", ".msi");
    private final SignatureSet signatures;

    public SignatureAnalyzer(SignatureSet signatures) {
        if (signatures == null) {
            throw new IllegalArgumentException("signatures assente");
        }
        this.signatures = signatures;
    }

    @Override
    public String getName() {
        return "Signature Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting signature analysis on {}", (Object)jarFile.getName());
        NestedBudget budget = new NestedBudget();
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                this.checkEntryName(entry.getName(), findings);
                if (entry.getSize() > 0x500000L) {
                    log.debug("Oversized entry, sampling head: {} ({} bytes)", (Object)entry.getName(), (Object)entry.getSize());
                    this.scanSample(jar, entry, findings, skips);
                    continue;
                }
                byte[] bytes;
                try {
                    bytes = EntryBytes.read(jar, entry, 0x500000L, skips);
                    if (bytes == null) {
                        log.debug("Oversized entry (actual bytes), sampling head: {}", (Object)entry.getName());
                        this.scanSample(jar, entry, findings, skips);
                        continue;
                    }
                }
                catch (Exception e) {
                    log.debug("Could not read entry {} as text: {}", (Object)entry.getName(), (Object)e.getMessage());
                    continue;
                }
                this.matchContent(entry.getName(), new String(bytes, StandardCharsets.UTF_8), findings);
                this.scanNested(entry.getName(), bytes, 0, budget, findings);
            }
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), 0x500000L));
        }
        if (skips.hasSampled()) {
            findings.add(skips.toSampledFinding(jarFile.getName(), SAMPLE_HEAD_BYTES, "SignatureAnalyzer"));
        }
        log.info("Signature analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    /** Legge il campione iniziale di un'entry oversize e lo scansiona come testo (Fase 2). */
    private void scanSample(JarFile jar, JarEntry entry, List<Finding> findings, EntryBytes.SkipLog skips) {
        try {
            byte[] head = EntryBytes.readHead(jar, entry, SAMPLE_HEAD_BYTES);
            if (head == null || head.length == 0) {
                return;
            }
            skips.sampled(entry.getName());
            this.matchContent(entry.getName() + " [campione]", new String(head, StandardCharsets.UTF_8), findings);
        } catch (Exception e) {
            log.debug("Could not sample entry {}: {}", (Object)entry.getName(), (Object)e.getMessage());
        }
    }

    /** Match esatto + normalizzato (case-insensitive), senza duplicati (Fase 1). */
    private void matchContent(String location, String content, List<Finding> findings) {
        List<SignatureSet.SigPattern> matches = new ArrayList<>(this.signatures.matchStrings(content));
        for (SignatureSet.SigPattern m : this.signatures.matchStringsNormalized(content)) {
            boolean dup = false;
            for (SignatureSet.SigPattern e : matches) {
                if (e.pattern().equals(m.pattern())) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                matches.add(m);
            }
        }
        for (SignatureSet.SigPattern match : matches) {
            String evidence = this.extractSnippet(content, match.pattern());
            findings.add(new Finding.Builder().title("Malware signature match: " + match.pattern()).description(match.description()).severity(Severity.valueOf(match.severity())).category(Category.MALWARE_SIGNATURE).location(location).evidence(evidence).family(match.family()).build());
            log.warn("Signature match in {}: pattern='{}', family='{}'", new Object[]{location, match.pattern(), match.family()});
        }
    }

    /** Ricorsione nei JAR/ZIP annidati fino a {@link #MAX_NESTED_DEPTH} (Fase 3). */
    private void scanNested(String outerName, byte[] bytes, int depth, NestedBudget budget, List<Finding> findings) {
        String lower = outerName.toLowerCase(Locale.ROOT);
        if (depth >= MAX_NESTED_DEPTH || !(lower.endsWith(".jar") || lower.endsWith(".zip"))) {
            return;
        }
        try (JarInputStream jin = new JarInputStream(new ByteArrayInputStream(bytes))) {
            java.util.jar.JarEntry e;
            while ((e = jin.getNextJarEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                String innerName = outerName + "!/" + e.getName();
                this.checkEntryName(innerName, findings);
                byte[] data = EntryBytes.readCappedStream(jin, MAX_ENTRY_SIZE);
                if (data == null) {
                    continue;
                }
                if (!budget.consume(data.length)) {
                    log.debug("Budget annidati esaurito in {}", (Object)outerName);
                    return;
                }
                this.matchContent(innerName, new String(data, StandardCharsets.UTF_8), findings);
                this.scanNested(innerName, data, depth + 1, budget, findings);
            }
        } catch (Exception ex) {
            log.debug("Nested scan fallita per {}: {}", (Object)outerName, (Object)ex.getMessage());
        }
    }

    /** Tetto anti zip-bomb condiviso da tutte le ricorsioni di un archivio. */
    private static final class NestedBudget {
        private long used;
        boolean consume(long n) {
            if (used + n > MAX_NESTED_TOTAL_BYTES) {
                return false;
            }
            used += n;
            return true;
        }
    }

    private void checkEntryName(String entryName, List<Finding> findings) {
        String lower = entryName.toLowerCase();
        for (String ext : SUSPICIOUS_EXTENSIONS) {
            if (!lower.endsWith(ext)) continue;
            findings.add(new Finding.Builder().title("Suspicious file extension: " + ext).description("JAR entry '" + entryName + "' has an executable/script extension that is uncommon in legitimate Java archives.").severity(Severity.HIGH).category(Category.MALWARE_SIGNATURE).location(entryName).evidence("Entry name: " + entryName).family("Embedded Executable").build());
            log.warn("Suspicious file extension detected: {}", (Object)entryName);
            break;
        }
    }

    private String extractSnippet(String content, String pattern) {
        int end;
        int idx = content.indexOf(pattern);
        if (idx < 0) {
            // Match case-insensitive (Fase 1): localizza sulla vista lowercase, ritaglia sull'originale.
            idx = content.toLowerCase(Locale.ROOT).indexOf(pattern.toLowerCase(Locale.ROOT));
            if (idx < 0) {
                return pattern;
            }
        }
        int snippetRadius = 100;
        int start = Math.max(0, idx - snippetRadius);
        String snippet = content.substring(start, end = Math.min(content.length(), idx + pattern.length() + snippetRadius)).replace("\n", "\\n").replace("\r", "\\r");
        if (snippet.length() > 200) {
            snippet = snippet.substring(0, 200);
        }
        return (start > 0 ? "..." : "") + snippet + (end < content.length() ? "..." : "");
    }
}
