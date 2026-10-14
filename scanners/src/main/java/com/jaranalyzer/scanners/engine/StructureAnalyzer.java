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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StructureAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(StructureAnalyzer.class);
    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".sh", ".bash", ".vbs", ".ps1", ".py", ".pl");

    @Override
    public String getName() {
        return "Structure Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        log.info("Starting structure analysis on {}", (Object)jarFile.getName());
        HashSet<String> classNames = new HashSet<String>();
        ArrayList<String> nestedJars = new ArrayList<String>();
        ArrayList<String> embeddedExecutables = new ArrayList<String>();
        ArrayList<String> hiddenFiles = new ArrayList<String>();
        ArrayList<String> duplicateClasses = new ArrayList<String>();
        ArrayList<String> configFiles = new ArrayList<String>();
        int classCount = 0;
        int resourceCount = 0;
        int totalEntries = 0;
        int zeroTimeEntries = 0;
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                ++totalEntries;
                long time = entry.getTime();
                if (time != -1L && time <= 347155200000L) {
                    ++zeroTimeEntries;
                }
                String name = entry.getName();
                String nameLower = name.toLowerCase();
                if (name.endsWith(".class")) {
                    ++classCount;
                    if (!classNames.add(name)) {
                        duplicateClasses.add(name);
                    }
                } else {
                    ++resourceCount;
                }
                if ((nameLower.endsWith(".jar") || nameLower.endsWith(".zip")) && !name.startsWith("META-INF/")) {
                    nestedJars.add(name);
                }
                for (String ext : EXECUTABLE_EXTENSIONS) {
                    if (!nameLower.endsWith(ext)) continue;
                    embeddedExecutables.add(name);
                    break;
                }
                String fileName = name;
                int lastSlash = name.lastIndexOf(47);
                if (lastSlash >= 0 && lastSlash < name.length() - 1) {
                    fileName = name.substring(lastSlash + 1);
                }
                if (fileName.startsWith(".") && !fileName.equals(".") && !fileName.equals("..")) {
                    hiddenFiles.add(name);
                }
                if (!nameLower.endsWith(".yml") && !nameLower.endsWith(".yaml") && !nameLower.endsWith(".json") && !nameLower.endsWith(".properties") && !nameLower.endsWith(".xml") || nameLower.contains("/") && !nameLower.startsWith("config/")) continue;
                configFiles.add(name);
            }
        }
        if (!nestedJars.isEmpty()) {
            findings.add(new Finding.Builder().title("Archivio JAR/ZIP annidato").description("Il JAR contiene altri archivi compressi annidati. Questa tecnica \u00e8 spesso utilizzata dai malware per nascondere carichi utili (payload stage-2) o librerie non dichiarate.").severity(Severity.MEDIUM).category(Category.STRUCTURE).location((String)nestedJars.get(0)).evidence("Archivi annidati trovati:\n" + String.join((CharSequence)"\n", nestedJars)).build());
        }
        if (!embeddedExecutables.isEmpty()) {
            findings.add(new Finding.Builder().title("Eseguibile o Script incorporato").description("Sono stati rilevati file di script o eseguibili nativi del sistema operativo all'interno del JAR. Questo comportamento \u00e8 sospetto perch\u00e9 i programmi Java standard raramente includono binari di sistema nativi.").severity(Severity.HIGH).category(Category.STRUCTURE).location((String)embeddedExecutables.get(0)).evidence("File esecutivi rilevati:\n" + String.join((CharSequence)"\n", embeddedExecutables)).build());
        }
        if (!hiddenFiles.isEmpty()) {
            findings.add(new Finding.Builder().title("File nascosto rilevato").description("Trovati file che iniziano con il punto ('.'). Questo potrebbe essere un tentativo di nascondere file di configurazione, carichi utili o exploit all'interno del JAR.").severity(Severity.MEDIUM).category(Category.STRUCTURE).location((String)hiddenFiles.get(0)).evidence("File nascosti rilevati:\n" + String.join((CharSequence)"\n", hiddenFiles)).build());
        }
        if (!duplicateClasses.isEmpty()) {
            findings.add(new Finding.Builder().title("Classi duplicate (Classpath Hijacking)").description("Sono state trovate classi duplicate all'interno del file JAR. Questo potrebbe indicare un tentativo di sovrascrivere o fare 'hijack' di classi di sistema o di librerie legittime.").severity(Severity.HIGH).category(Category.STRUCTURE).location((String)duplicateClasses.get(0)).evidence("Classi duplicate:\n" + String.join((CharSequence)"\n", duplicateClasses)).build());
        }
        if (totalEntries > 0 && (double)zeroTimeEntries >= (double)totalEntries * 0.9) {
            findings.add(new Finding.Builder().title("Archive Entries All Carry 1980 Epoch Mtime").description("Every entry in the archive reports a DOS timestamp of ~1980-01-01. This is the canonical zeroed value produced by reproducible-build tools and by hand-rolled ZIP writers. On its own this is dual-use; combined with other findings it removes false positives.").severity(Severity.MEDIUM).category(Category.STRUCTURE).location("File system entries").evidence("Entries with 1980 mtime: " + zeroTimeEntries + " / " + totalEntries).family("Archive-Zeroed-Mtimes").build());
        }
        if (!configFiles.isEmpty()) {
            findings.add(new Finding.Builder().title("Configuration Files").description("Configuration files that may contain sensitive data or affect application behavior.").severity(Severity.INFO).category(Category.STRUCTURE).location((String)configFiles.get(0)).evidence("Files:\n" + String.join((CharSequence)"\n", configFiles)).family("config-files").build());
        }
        if (classCount == 0 && resourceCount > 0) {
            findings.add(new Finding.Builder().title("JAR privo di codice Java").description("Questo file JAR contiene risorse ma non contiene file di classe compilati (.class).").severity(Severity.INFO).category(Category.STRUCTURE).location("Nessuna classe trovata").evidence("Numero risorse: " + resourceCount).build());
        }
        log.info("Structure analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }
}
