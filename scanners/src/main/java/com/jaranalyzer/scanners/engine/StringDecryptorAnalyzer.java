/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.objectweb.asm.ClassReader
 *  org.objectweb.asm.ClassVisitor
 *  org.objectweb.asm.MethodVisitor
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 */
package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StringDecryptorAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(StringDecryptorAnalyzer.class);

    @Override
    public String getName() {
        return "String Decryptor Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting String Decryptor analysis on {}", (Object)jarFile.getName());
        final ArrayList suspiciousStrings = new ArrayList();
        final ArrayList decryptedBase64 = new ArrayList();
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                final JarEntry entry = en.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                try {
                    InputStream is = jar.getInputStream(entry);
                    try {
                        byte[] bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                        if (bytes == null) continue;
                        ClassReader cr = new ClassReader(bytes);
                        cr.accept(new ClassVisitor(589824){

                            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                                return new MethodVisitor(589824){

                                    public void visitLdcInsn(Object value) {
                                        if (value instanceof String) {
                                            String s = (String)value;
                                            StringDecryptorAnalyzer.this.checkString(s, entry.getName(), suspiciousStrings, decryptedBase64);
                                        }
                                        super.visitLdcInsn(value);
                                    }
                                };
                            }
                        }, 6);
                    }
                    finally {
                        if (is == null) continue;
                        is.close();
                    }
                }
                catch (Exception exception) {}
            }
        }
        if (!decryptedBase64.isEmpty()) {
            findings.add(new Finding.Builder().title("Base64 Encoded Strings Detected").description("Trovate stringhe crittografate in Base64 (Spesso usate per nascondere URL o Webhook).").severity(Severity.HIGH).category(Category.OBFUSCATION).location("Constant Pool (LDC)").evidence("Decrypted strings:\n" + String.join((CharSequence)"\n", decryptedBase64)).build());
        }
        if (suspiciousStrings.size() > 50) {
            findings.add(new Finding.Builder().title("High Entropy Strings (Possible Custom Obfuscation)").description("Rilevate numerose stringhe ad alta entropia. Potrebbero essere crittografate con algoritmi custom (es. XOR/AES).").severity(Severity.MEDIUM).category(Category.OBFUSCATION).location("Constant Pool (LDC)").evidence("Count: " + suspiciousStrings.size() + "\nSample:\n" + String.join((CharSequence)"\n", suspiciousStrings.subList(0, Math.min(10, suspiciousStrings.size())))).build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        return findings;
    }

    private void checkString(String s, String className, List<String> suspiciousStrings, List<String> decryptedBase64) {
        double entropy;
        if (s.length() < 10) {
            return;
        }
        if (s.matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")) {
            try {
                byte[] decoded = Base64.getDecoder().decode(s);
                String decodedStr = new String(decoded, StandardCharsets.UTF_8);
                if (decodedStr.length() > 5 && decodedStr.matches("^[\\x20-\\x7E]+$") && !decodedStr.equals(s)) {
                    if (decodedStr.contains("http") || decodedStr.contains("webhook") || decodedStr.contains("discord")) {
                        decryptedBase64.add(s + " -> " + decodedStr + " (in " + className + ")");
                    } else if (this.shannonEntropy(decodedStr) < 4.0) {
                        decryptedBase64.add(s + " -> " + decodedStr + " (in " + className + ")");
                    }
                }
            }
            catch (Exception decoded) {
                // empty catch block
            }
        }
        if ((entropy = this.shannonEntropy(s)) > 5.5 && s.length() > 20) {
            suspiciousStrings.add(s);
        }
    }

    private double shannonEntropy(String s) {
        HashMap<Character, Integer> freq = new HashMap<Character, Integer>();
        for (char c : s.toCharArray()) {
            freq.put(Character.valueOf(c), freq.getOrDefault(Character.valueOf(c), 0) + 1);
        }
        double entropy = 0.0;
        int len = s.length();
        Iterator iterator = freq.values().iterator();
        while (iterator.hasNext()) {
            int count = (Integer)iterator.next();
            double p = (double)count / (double)len;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }
}
