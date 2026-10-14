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
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EntropyAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(EntropyAnalyzer.class);
    private static final int MIN_ENTRY_SIZE = 100;
    private static final double HIGH_ENTROPY_THRESHOLD = 7.9;
    private static final double MEDIUM_ENTROPY_THRESHOLD = 7.5;

    @Override
    public String getName() {
        return "Entropy Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        long[] overallHist = new long[256];
        long overallTotal = 0L;
        log.info("Starting entropy analysis on {}", (Object)jarFile.getName());
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                boolean isMultimedia;
                byte[] data;
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                try {
                    data = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (data == null) continue;
                }
                catch (Exception e) {
                    log.debug("Could not read entry {}: {}", (Object)entry.getName(), (Object)e.getMessage());
                    continue;
                }
                for (byte b : data) {
                    overallHist[b & 0xFF]++;
                }
                overallTotal += data.length;
                if (data.length < 100) {
                    log.debug("Skipping small entry: {} ({} bytes)", (Object)entry.getName(), (Object)data.length);
                    continue;
                }
                double entropy = this.calculateShannonEntropy(data);
                log.debug("Entropy for {}: {}", (Object)entry.getName(), (Object)String.format("%.4f", entropy));
                String nameLower = entry.getName().toLowerCase();
                boolean bl = isMultimedia = nameLower.endsWith(".png") || nameLower.endsWith(".jpg") || nameLower.endsWith(".jpeg") || nameLower.endsWith(".ogg") || nameLower.endsWith(".wav") || nameLower.endsWith(".mp3") || nameLower.endsWith(".gif");
                if (isMultimedia && entropy > 7.95) {
                    findings.add(this.buildEntropyFinding(entry.getName(), entropy, Severity.CRITICAL, "Possibile STEGANOGRAFIA rilevata. Un file multimediale ha un'entropia innaturalmente alta (~8.0), il che indica quasi certamente che nasconde un payload eseguibile crittografato al suo interno invece di dati audio/video reali."));
                    continue;
                }
                if (entropy > 7.9) {
                    findings.add(this.buildEntropyFinding(entry.getName(), entropy, Severity.HIGH, "Very high entropy detected \u2013 content is likely encrypted, compressed with a secondary layer, or packed."));
                    continue;
                }
                if (!(entropy > 7.5)) continue;
                findings.add(this.buildEntropyFinding(entry.getName(), entropy, Severity.MEDIUM, "Elevated entropy detected \u2013 content may be obfuscated or contain embedded encrypted payloads."));
            }
        }
        if (overallTotal >= 100) {
            double overallEntropy = this.calculateShannonEntropy(overallHist, overallTotal);
            log.info("Overall JAR entropy: {}", (Object)String.format("%.4f", overallEntropy));
            if (overallEntropy > 7.9) {
                findings.add(this.buildEntropyFinding(jarFile.getName() + " (overall)", overallEntropy, Severity.HIGH, "The overall entropy of the entire JAR is very high, suggesting the archive may be packed or encrypted as a whole."));
            } else if (overallEntropy > 7.5) {
                findings.add(this.buildEntropyFinding(jarFile.getName() + " (overall)", overallEntropy, Severity.MEDIUM, "The overall entropy of the entire JAR is elevated, which may indicate significant obfuscation or embedded encrypted data."));
            }
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Entropy analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private double calculateShannonEntropy(byte[] data) {
        if (data.length == 0) {
            return 0.0;
        }
        int[] frequency = new int[256];
        for (byte b : data) {
            int n = b & 0xFF;
            frequency[n] = frequency[n] + 1;
        }
        double entropy = 0.0;
        double length = data.length;
        for (int count : frequency) {
            if (count == 0) continue;
            double p = (double)count / length;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    /**
     * Stesso calcolo di {@link #calculateShannonEntropy(byte[])}, ma su un
     * istogramma cumulativo: evita di tenere l'intero archivio in memoria.
     * L'ordine di somma è identico, quindi il risultato è bit-identico.
     */
    private double calculateShannonEntropy(long[] frequency, long total) {
        if (total == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        double length = total;
        for (long count : frequency) {
            if (count == 0) continue;
            double p = (double)count / length;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    private Finding buildEntropyFinding(String location, double entropy, Severity severity, String description) {
        return new Finding.Builder().title("High entropy detected").description(description).severity(severity).category(Category.ENTROPY).location(location).evidence(String.format("Shannon entropy: %.2f/8.0", entropy)).family("Entropy Anomaly").build();
    }
}
