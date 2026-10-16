package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.engine.rules.ConstantPool;
import com.jaranalyzer.scanners.engine.rules.Hit;
import com.jaranalyzer.scanners.engine.rules.Rule;
import com.jaranalyzer.scanners.engine.rules.RuleEngine;
import com.jaranalyzer.scanners.engine.rules.RuleLoader;
import com.jaranalyzer.scanners.engine.rules.Scope;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Motore a regole IOC sul constant pool (report revisione, sez. 1).
 *
 * <p>Le regole vivono in {@code rules/ioc-rules.json} (dati, non codice) e
 * scattano solo nel loro {@link Scope}: costanti di codice e risorse
 * eseguibili/config, MAI nei metadati (README, licenze, mods.toml,
 * fabric.mod.json). Un finding per regola (id stabile = ruleName), campioni
 * redatti, tetto alle evidenze.
 */
public class IocRuleAnalyzer implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(IocRuleAnalyzer.class);
    private static final long MAX_CLASS_BYTES = 5L * 1024 * 1024;
    private static final long MAX_RESOURCE_BYTES = 1L * 1024 * 1024;
    private static final int MAX_EVIDENCE_PER_RULE = 5;
    private static final Set<String> TEXT_EXTS = Set.of(".bat", ".ps1", ".sh", ".cmd",
            ".json", ".js", ".toml", ".properties", ".xml", ".yml", ".yaml",
            ".cfg", ".ini", ".conf", ".config", ".gradle");

    private static volatile List<Rule> rules;

    private static List<Rule> rules() {
        List<Rule> r = rules;
        if (r == null) {
            synchronized (IocRuleAnalyzer.class) {
                r = rules;
                if (r == null) {
                    r = RuleLoader.load();
                    rules = r;
                }
            }
        }
        return r;
    }

    @Override
    public String getName() {
        return "IOC Rule Engine";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        List<Finding> findings = new ArrayList<>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        Map<String, RuleAgg> agg = new LinkedHashMap<>();
        log.info("Starting IOC rule analysis on {}", jarFile.getName());
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (name.toLowerCase(Locale.ROOT).endsWith(".class")) {
                    byte[] bytes = EntryBytes.read(jar, entry, MAX_CLASS_BYTES, skips);
                    if (bytes == null) {
                        continue;
                    }
                    scanClass(name, bytes, agg);
                } else if (isScannedResource(name)) {
                    byte[] bytes = EntryBytes.read(jar, entry, MAX_RESOURCE_BYTES, skips);
                    if (bytes == null || bytes.length == 0) {
                        continue;
                    }
                    scanText(Scope.RESOURCE_TEXT, name, decode(bytes), agg);
                }
            }
        }
        for (RuleAgg a : agg.values()) {
            findings.add(a.toFinding());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), MAX_CLASS_BYTES));
        }
        log.info("IOC rule analysis complete - {} finding(s)", findings.size());
        return findings;
    }

    private void scanClass(String name, byte[] bytes, Map<String, RuleAgg> agg) {
        for (String s : ConstantPool.ldcStrings(bytes)) {
            scanText(Scope.CLASS_CONST, name, s, agg);
        }
        for (String s : ConstantPool.utf8Constants(bytes)) {
            scanText(Scope.CLASS_POOL, name, s, agg);
        }
    }

    private void scanText(Scope scope, String where, String text, Map<String, RuleAgg> agg) {
        if (text == null || text.isEmpty()) {
            return;
        }
        for (Rule rule : rules()) {
            if (!rule.scopes().contains(scope)) {
                continue;
            }
            if ("executable-blob".equals(rule.special())) {
                scanBlob(rule, where, text, agg);
                continue;
            }
            for (Hit h : RuleEngine.scan(rule, scope, where, text)) {
                agg.computeIfAbsent(rule.id(), k -> new RuleAgg(rule)).add(h);
            }
        }
    }

    /**
     * La regex è solo il candidato: il finding scatta solo se il blob
     * decodifica in magia nota (MZ/ELF/PK/CAFEBABE). Il campione resta redatto.
     */
    private void scanBlob(Rule rule, String where, String text, Map<String, RuleAgg> agg) {
        java.util.regex.Matcher m = rule.pattern().matcher(RuleEngine.normalize(text));
        int verified = 0;
        while (m.find() && verified < RuleEngine.MAX_HITS_PER_SCAN) {
            String cand = m.group();
            if (blobIsExecutable(cand)) {
                agg.computeIfAbsent(rule.id(), k -> new RuleAgg(rule))
                        .add(new Hit(rule, where, RuleEngine.redact(cand)));
                verified++;
            }
        }
    }

    /** Accetta solo se il PRIMO candidato lungo decodifica in magia nota. */
    static boolean blobIsExecutable(String candidate) {
        String t = candidate.trim();
        if (t.length() < 200 || (t.length() & 3) != 0) {
            return false;
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(t);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (raw.length < 4) {
            return false;
        }
        return (raw[0] == 0x4D && raw[1] == 0x5A) // MZ
                || (raw[0] == 0x7F && raw[1] == 0x45 && raw[2] == 0x4C && raw[3] == 0x46) // ELF
                || (raw[0] == 0x50 && raw[1] == 0x4B) // PK (zip/jar)
                || (raw[0] == (byte) 0xCA && raw[1] == (byte) 0xFE
                        && raw[2] == (byte) 0xBA && raw[3] == (byte) 0xBE); // class
    }

    static boolean isScannedResource(String entryName) {
        String lower = entryName.toLowerCase(Locale.ROOT);
        if (lower.startsWith("meta-inf/")) {
            return false;
        }
        int slash = lower.lastIndexOf('/');
        String file = slash >= 0 ? lower.substring(slash + 1) : lower;
        if (file.startsWith("readme") || file.startsWith("license") || file.startsWith("licence")
                || file.startsWith("notice") || file.startsWith("authors") || file.startsWith("changelog")
                || file.startsWith("copying") || file.endsWith(".md") || file.endsWith(".txt")
                || file.equals("mods.toml") || file.endsWith("mods.toml")
                || file.equals("fabric.mod.json") || file.equals("quilt.mod.json")
                || file.equals("pack.mcmeta")) {
            return false;
        }
        for (String ext : TEXT_EXTS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static String decode(byte[] bytes) {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        try {
            return dec.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return "";
        }
    }

    /** Aggregatore per regola: conteggio totale + prime evidenze. */
    private static final class RuleAgg {
        private final Rule rule;
        private int count;
        private final List<Hit> first = new ArrayList<>();

        RuleAgg(Rule rule) {
            this.rule = rule;
        }

        void add(Hit h) {
            count++;
            if (first.size() < MAX_EVIDENCE_PER_RULE) {
                first.add(h);
            }
        }

        Finding toFinding() {
            String loc = first.isEmpty() ? "" : first.get(0).where()
                    + (count > 1 ? " (+" + (count - 1) + ")" : "");
            StringBuilder ev = new StringBuilder("Evidenza: ").append(rule.cap())
                    .append(", occorrenze: ").append(count).append('\n');
            for (Hit h : first) {
                ev.append(h.where()).append(" -> ").append(h.sample()).append('\n');
            }
            Severity sev = rule.severity();
            Category cat = rule.category();
            return new Finding.Builder().ruleName(rule.id())
                    .title(rule.title() + " (" + count + ")")
                    .description(rule.description()).severity(sev).category(cat)
                    .location(loc).evidence(ev.toString().trim()).family("ioc-rule").build();
        }
    }
}
