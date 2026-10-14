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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ManifestAnalyzer
implements JarAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(ManifestAnalyzer.class);
    private static final String LOCATION = "META-INF/MANIFEST.MF";
    private static final Pattern SUSPICIOUS_MAIN_CLASS_PATTERN = Pattern.compile("^[a-zA-Z]$|^[a-zA-Z]{1,2}\\.[a-zA-Z]{1,2}$|\\$\\$|^[a-z]{1,3}(\\.[a-z]{1,3})+\\.[A-Z]$");
    private static final Set<String> STANDARD_ATTRIBUTES = Set.of("manifest-version", "created-by", "signature-version", "class-path", "main-class", "extension-list", "extension-name", "implementation-title", "implementation-version", "implementation-vendor", "implementation-vendor-id", "implementation-url", "specification-title", "specification-version", "specification-vendor", "sealed", "premain-class", "agent-class", "can-redefine-classes", "can-retransform-classes", "can-set-native-method-prefix", "boot-class-path", "launcher-agent-class", "multi-release", "automatic-module-name", "bundle-name", "bundle-symbolicname", "bundle-version", "bundle-vendor", "bundle-manifestversion", "bundle-description", "bundle-license", "export-package", "import-package", "require-bundle", "bundle-activator", "bundle-classpath", "built-by", "build-jdk", "build-jdk-spec", "archiver-version", "ant-version", "x-compile-source-jdk", "x-compile-target-jdk");

    @Override
    public String getName() {
        return "Manifest Analyzer";
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    @Override
    public List<Finding> analyze(File jarFile) {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        logger.info("Starting manifest analysis for: {}", (Object)jarFile.getName());
        try (JarFile jar = new JarFile(jarFile);){
            Manifest manifest = jar.getManifest();
            if (manifest == null) {
                logger.debug("No manifest found in JAR: {}", (Object)jarFile.getName());
                findings.add(new Finding.Builder().title("Missing Manifest").description("The JAR file does not contain a META-INF/MANIFEST.MF file. While not inherently malicious, legitimate libraries typically include a manifest.").severity(Severity.INFO).category(Category.MANIFEST).location(LOCATION).evidence("No MANIFEST.MF present").family("manifest-missing").build());
                ArrayList<Finding> arrayList = findings;
                return arrayList;
            }
            Attributes mainAttributes = manifest.getMainAttributes();
            this.checkMainClass(mainAttributes, findings);
            this.checkPremainClass(mainAttributes, findings);
            this.checkAgentClass(mainAttributes, findings);
            this.checkClassPath(mainAttributes, findings);
            this.checkUnusualAttributes(mainAttributes, findings);
            this.checkRedefineClasses(mainAttributes, findings);
            logger.info("Manifest analysis complete for {}. Found {} issue(s).", (Object)jarFile.getName(), (Object)findings.size());
            return findings;
        }
        catch (IOException e) {
            logger.error("Failed to read JAR file for manifest analysis: {}", (Object)jarFile.getName(), (Object)e);
            findings.add(new Finding.Builder().title("Manifest Analysis Error").description("An error occurred while attempting to read the manifest: " + e.getMessage()).severity(Severity.INFO).category(Category.MANIFEST).location(LOCATION).evidence(e.getClass().getSimpleName() + ": " + e.getMessage()).family("manifest-error").build());
        }
        return findings;
    }

    private void checkMainClass(Attributes attributes, List<Finding> findings) {
        String mainClass = attributes.getValue("Main-Class");
        if (mainClass == null) {
            return;
        }
        logger.debug("Main-Class found: {}", (Object)mainClass);
        findings.add(new Finding.Builder().title("Main-Class in Manifest").description("JAR contains a Main-Class entry - has a standalone entry point (public static void main)").severity(Severity.INFO).category(Category.MANIFEST).location(LOCATION).evidence("Main-Class: " + mainClass).family("manifest-main").build());
        if (SUSPICIOUS_MAIN_CLASS_PATTERN.matcher(mainClass).find()) {
            findings.add(new Finding.Builder().title("Suspicious Main-Class Name").description("The Main-Class attribute contains a name that appears obfuscated or suspiciously short. Malware often uses obfuscated class names to avoid detection and reverse engineering.").severity(Severity.HIGH).category(Category.MANIFEST).location(LOCATION).evidence("Main-Class: " + mainClass).family("manifest-suspicious-main-class").build());
        }
    }

    private void checkRedefineClasses(Attributes attributes, List<Finding> findings) {
        String retransform;
        String redefine = attributes.getValue("Can-Redefine-Classes");
        if ("true".equalsIgnoreCase(redefine)) {
            findings.add(new Finding.Builder().title("Can-Redefine-Classes Manifest").description("JAR manifest allows runtime class redefinition - hot code patching capability").severity(Severity.MEDIUM).category(Category.MANIFEST).location(LOCATION).evidence("Can-Redefine-Classes: true").family("manifest-redefine").build());
        }
        if ("true".equalsIgnoreCase(retransform = attributes.getValue("Can-Retransform-Classes"))) {
            findings.add(new Finding.Builder().title("Can-Retransform-Classes Manifest").description("JAR manifest allows runtime class retransformation - live code modification").severity(Severity.MEDIUM).category(Category.MANIFEST).location(LOCATION).evidence("Can-Retransform-Classes: true").family("manifest-retransform").build());
        }
    }

    private void checkPremainClass(Attributes attributes, List<Finding> findings) {
        String premainClass = attributes.getValue("Premain-Class");
        if (premainClass != null) {
            logger.debug("Premain-Class found: {}", (Object)premainClass);
            findings.add(new Finding.Builder().title("Java Agent Premain-Class Detected").description("The manifest declares a Premain-Class attribute, indicating this JAR is designed to be loaded as a Java agent via the -javaagent flag. Java agents can intercept and modify class loading, which can be used for instrumentation but also for malicious bytecode manipulation.").severity(Severity.MEDIUM).category(Category.MANIFEST).location(LOCATION).evidence("Premain-Class: " + premainClass).family("manifest-premain-class").build());
        }
    }

    private void checkAgentClass(Attributes attributes, List<Finding> findings) {
        String agentClass = attributes.getValue("Agent-Class");
        if (agentClass != null) {
            logger.debug("Agent-Class found: {}", (Object)agentClass);
            findings.add(new Finding.Builder().title("Java Agent Agent-Class Detected").description("The manifest declares an Agent-Class attribute, indicating this JAR can be attached to a running JVM as an agent. Runtime-attachable agents can modify application behavior after startup, a technique sometimes used by malware for code injection.").severity(Severity.MEDIUM).category(Category.MANIFEST).location(LOCATION).evidence("Agent-Class: " + agentClass).family("manifest-agent-class").build());
        }
    }

    private void checkClassPath(Attributes attributes, List<Finding> findings) {
        String classPath = attributes.getValue("Class-Path");
        if (classPath == null) {
            return;
        }
        logger.debug("Class-Path found: {}", (Object)classPath);
        String[] entries = classPath.split("\\s+");
        ArrayList<String> urlEntries = new ArrayList<String>();
        for (String entry : entries) {
            String lower = entry.toLowerCase();
            if (!lower.startsWith("http://") && !lower.startsWith("https://") && !lower.startsWith("ftp://")) continue;
            urlEntries.add(entry);
        }
        if (!urlEntries.isEmpty()) {
            findings.add(new Finding.Builder().title("Class-Path Contains URLs").description("The Class-Path manifest attribute contains URL entries, which could cause the JVM to download and load remote code at runtime. This is a significant security risk as it enables remote code execution.").severity(Severity.HIGH).category(Category.MANIFEST).location(LOCATION).evidence("URL entries in Class-Path: " + String.join((CharSequence)", ", urlEntries)).family("manifest-classpath-url").build());
        }
    }

    private void checkUnusualAttributes(Attributes attributes, List<Finding> findings) {
        ArrayList<String> unusualAttrs = new ArrayList<String>();
        for (Map.Entry<Object, Object> entry : attributes.entrySet()) {
            String attrName = entry.getKey().toString();
            if (STANDARD_ATTRIBUTES.contains(attrName.toLowerCase())) continue;
            unusualAttrs.add((attrName + ": " + entry.getValue()));
        }
        if (!unusualAttrs.isEmpty()) {
            logger.debug("Found {} unusual manifest attribute(s)", (Object)unusualAttrs.size());
            findings.add(new Finding.Builder().title("Unusual Manifest Attributes").description("The manifest contains non-standard attributes that are not commonly found in legitimate JAR files. While custom attributes are allowed by the specification, they may be used to store metadata for malicious purposes.").severity(Severity.LOW).category(Category.MANIFEST).location(LOCATION).evidence("Unusual attributes:\n" + String.join((CharSequence)"\n", unusualAttrs)).family("manifest-unusual-attributes").build());
        }
    }
}
