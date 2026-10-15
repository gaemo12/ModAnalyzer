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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CheatSignatureAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(CheatSignatureAnalyzer.class);
    private static final int MIN_MATCH_THRESHOLD = 5;
    private static final long MAX_ENTRY_SIZE = 0x1400000L;
    /** Campione iniziale per le entry oltre il cap (Fase 2). */
    private static final long SAMPLE_HEAD_BYTES = 1L * 1024 * 1024;
    private static final int MAX_SAMPLE_STRINGS = 15;
    private final SignatureSet signatures;

    public CheatSignatureAnalyzer(SignatureSet signatures) {
        if (signatures == null) {
            throw new IllegalArgumentException("signatures assente");
        }
        this.signatures = signatures;
    }

    @Override
    public String getName() {
        return "Cheat Client Signature Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting cheat-signature analysis on {}", (Object)jarFile.getName());
        Map<String, List<String>> database = this.signatures.cheatGroups();
        LinkedHashMap<String, Set<String>> matchesByCheat = new LinkedHashMap<String, Set<String>>();
        for (String string : database.keySet()) {
            matchesByCheat.put(string, new LinkedHashSet());
        }
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> enumeration = jar.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (entry.isDirectory() || entry.getSize() <= 0L) continue;
                if (entry.getSize() > 0x1400000L) {
                    // Oversize: campione iniziale invece di punto cieco (Fase 2).
                    try {
                        byte[] head = EntryBytes.readHead(jar, entry, SAMPLE_HEAD_BYTES);
                        if (head != null && head.length > 0) {
                            skips.sampled(entry.getName());
                            this.scanEntryAgainstDatabase(new String(head, StandardCharsets.ISO_8859_1),
                                    database, matchesByCheat);
                        }
                    } catch (Exception e) {
                        log.debug("Could not sample entry {}: {}", (Object)entry.getName(), (Object)e.getMessage());
                    }
                    continue;
                }
                String content = this.readEntryAsLatin1(jar, entry, skips);
                if (content == null) continue;
                this.scanEntryAgainstDatabase(content, database, matchesByCheat);
            }
        }
        for (Map.Entry entry : database.entrySet()) {
            String cheatName = (String)entry.getKey();
            int total = ((List)entry.getValue()).size();
            Set found = (Set)matchesByCheat.get(cheatName);
            int matchCount = found.size();
            if (matchCount < 5) continue;
            double confidence = total > 0 ? (double)matchCount * 100.0 / (double)total : 0.0;
            Severity severity = this.severityFor(confidence);
            List sample = found.stream().limit(15L).toList();
            String evidence = "Stringhe corrispondenti (" + matchCount + " totali, esempio max 15):\n" + String.join((CharSequence)"\n", sample);
            findings.add(new Finding.Builder().title("Possibile match firma cheat: " + cheatName).description(String.format("Il JAR contiene %d/%d stringhe firma associate al cheat client conosciuto '%s' (confidenza %.1f%%). Il match \u00e8 basato sul numero di stringhe univoche del campione di riferimento ritrovate nel JAR analizzato.", matchCount, total, cheatName, confidence)).severity(severity).category(Category.EXECUTION).location(jarFile.getName()).evidence(evidence).family("CheatSignature:" + cheatName).build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), 0x1400000L));
        }
        if (skips.hasSampled()) {
            findings.add(skips.toSampledFinding(jarFile.getName(), SAMPLE_HEAD_BYTES, "CheatSignatureAnalyzer"));
        }
        log.info("Cheat-signature analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private void scanEntryAgainstDatabase(String content, Map<String, List<String>> database, Map<String, Set<String>> matchesByCheat) {
        // Vista normalizzata per l'anti-evasione case-insensitive (Fase 1).
        String lower = content.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, List<String>> cheatEntry : database.entrySet()) {
            String cheatName = cheatEntry.getKey();
            Set<String> alreadyFound = matchesByCheat.get(cheatName);
            for (String signature : cheatEntry.getValue()) {
                if (alreadyFound.contains(signature)) {
                    continue;
                }
                if (content.contains(signature)
                        || lower.contains(signature.toLowerCase(Locale.ROOT))) {
                    alreadyFound.add(signature);
                }
            }
        }
    }

    private String readEntryAsLatin1(JarFile jar, JarEntry entry, EntryBytes.SkipLog skips) throws Exception {
        byte[] bytes = EntryBytes.read(jar, entry, 0x1400000L, skips);
        if (bytes == null) {
            return null;
        }
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private Severity severityFor(double confidencePercent) {
        if (confidencePercent >= 25.0) {
            return Severity.CRITICAL;
        }
        if (confidencePercent >= 10.0) {
            return Severity.HIGH;
        }
        return Severity.MEDIUM;
    }
}
