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
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(SignatureAnalyzer.class);
    private static final long MAX_ENTRY_SIZE = 0x500000L;
    private static final Set<String> SUSPICIOUS_EXTENSIONS = Set.of(".exe", ".dll", ".bat", ".sh", ".ps1");
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
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                String content;
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                this.checkEntryName(entry.getName(), findings);
                if (entry.getSize() > 0x500000L) {
                    log.debug("Skipping oversized entry: {} ({} bytes)", (Object)entry.getName(), (Object)entry.getSize());
                    continue;
                }
                try {
                    byte[] bytes = EntryBytes.read(jar, entry, 0x500000L, skips);
                    if (bytes == null) {
                        log.debug("Skipping oversized entry (actual bytes): {}", (Object)entry.getName());
                        continue;
                    }
                    content = new String(bytes, StandardCharsets.UTF_8);
                }
                catch (Exception e) {
                    log.debug("Could not read entry {} as text: {}", (Object)entry.getName(), (Object)e.getMessage());
                    continue;
                }
                List<SignatureSet.SigPattern> matches = this.signatures.matchStrings(content);
                for (SignatureSet.SigPattern match : matches) {
                    String evidence = this.extractSnippet(content, match.pattern());
                    findings.add(new Finding.Builder().title("Malware signature match: " + match.pattern()).description(match.description()).severity(Severity.valueOf(match.severity())).category(Category.MALWARE_SIGNATURE).location(entry.getName()).evidence(evidence).family(match.family()).build());
                    log.warn("Signature match in {}: pattern='{}', family='{}'", new Object[]{entry.getName(), match.pattern(), match.family()});
                }
            }
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), 0x500000L));
        }
        log.info("Signature analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
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
            return pattern;
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
