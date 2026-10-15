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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StringDecryptorAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(StringDecryptorAnalyzer.class);
    /** Coda IP:porta o IPv4 che nel decodificato indica C2 anche senza keyword. */
    private static final Pattern DECODED_IP = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b");
    private static final Pattern DECODED_C2_HINT = Pattern.compile("https?://|\\.onion|ngrok|no-ip|duckdns|pastebin|webhook|discord\\.", Pattern.CASE_INSENSITIVE);
    /** Finestra concat: quante LDC consecutive unire (split banale su 2-3 pezzi). */
    private static final int CONCAT_WINDOW = 3;
    private static final int MAX_CONCAT_LEN = 4096;

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
        final ArrayList decodedC2 = new ArrayList();
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                final JarEntry entry = en.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                try {
                    byte[] bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
                    ClassReader cr = new ClassReader(bytes);
                    cr.accept(new ClassVisitor(589824){

                        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                            return new MethodVisitor(589824){
                                /** Ultime LDC del metodo: ricompone gli split su più costanti (Fase 1). */
                                private final ArrayList<String> recent = new ArrayList<>();

                                public void visitLdcInsn(Object value) {
                                    if (value instanceof String) {
                                        String s = (String)value;
                                        StringDecryptorAnalyzer.this.checkString(s, entry.getName(), suspiciousStrings, decryptedBase64, decodedC2);
                                        // Finestre di concat su LDC adiacenti (split "ht"+"tp", XOR a pezzi, ...).
                                        StringBuilder sb = new StringBuilder(s.length() + 64);
                                        sb.append(s);
                                        for (int i = recent.size() - 1; i >= 0 && sb.length() <= MAX_CONCAT_LEN; i--) {
                                            sb.insert(0, recent.get(i));
                                            String joined = sb.toString();
                                            if (joined.length() >= 10) {
                                                StringDecryptorAnalyzer.this.checkString(joined,
                                                        entry.getName() + " [concat]", suspiciousStrings, decryptedBase64, decodedC2);
                                            }
                                        }
                                        recent.add(s.length() > 2048 ? s.substring(0, 2048) : s);
                                        if (recent.size() > CONCAT_WINDOW - 1) {
                                            recent.remove(0);
                                        }
                                    }
                                    super.visitLdcInsn(value);
                                }
                            };
                        }
                    }, 6);
                }
                catch (Exception e) {
                    log.debug("StringDecryptor: entry {} illeggibile: {}", (Object)entry.getName(), (Object)e.getMessage());
                }
            }
        }
        if (!decryptedBase64.isEmpty()) {
            findings.add(new Finding.Builder().title("Base64 Encoded Strings Detected").description("Trovate stringhe crittografate in Base64 (Spesso usate per nascondere URL o Webhook).").severity(Severity.HIGH).category(Category.OBFUSCATION).location("Constant Pool (LDC)").evidence("Decrypted strings:\n" + String.join((CharSequence)"\n", decryptedBase64)).build());
        }
        if (!decodedC2.isEmpty()) {
            findings.add(new Finding.Builder().title("Stringa decodificata con indicatore di rete (possibile C2 nascosto)").description("Una stringa Base64/hex decodificata contiene URL, IP o dominio da infrastruttura C2: offuscamento mirato a nascondere la rete.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Constant Pool (LDC, decoded)").evidence(String.join((CharSequence)"\n", decodedC2.subList(0, Math.min(10, decodedC2.size())))).family("HiddenC2").build());
        }
        if (suspiciousStrings.size() > 50) {
            findings.add(new Finding.Builder().title("High Entropy Strings (Possible Custom Obfuscation)").description("Rilevate numerose stringhe ad alta entropia. Potrebbero essere crittografate con algoritmi custom (es. XOR/AES).").severity(Severity.MEDIUM).category(Category.OBFUSCATION).location("Constant Pool (LDC)").evidence("Count: " + suspiciousStrings.size() + "\nSample:\n" + String.join((CharSequence)"\n", suspiciousStrings.subList(0, Math.min(10, suspiciousStrings.size())))).build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        return findings;
    }

    private void checkString(String s, String className, List<String> suspiciousStrings, List<String> decryptedBase64, List<String> decodedC2) {
        double entropy;
        if (s.length() < 10) {
            return;
        }
        String decoded = StringNorm.tryBase64(s);
        if (decoded == null) {
            decoded = StringNorm.tryHex(s);
        }
        if (decoded != null) {
            if (decoded.contains("http") || decoded.contains("webhook") || decoded.contains("discord")) {
                decryptedBase64.add(s + " -> " + decoded + " (in " + className + ")");
            } else if (this.shannonEntropy(decoded) < 4.0) {
                decryptedBase64.add(s + " -> " + decoded + " (in " + className + ")");
            }
            // Re-scan del decodificato per indicatori di rete (Fase 1): C2 nascosto anche
            // senza keyword, via IP o pattern di domini/porta da infrastruttura anonima.
            if (DECODED_IP.matcher(decoded).find() || DECODED_C2_HINT.matcher(decoded).find()) {
                decodedC2.add(s + " -> " + decoded + " (in " + className + ")");
            }
        } else if (s.matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")) {
            try {
                byte[] legacy = Base64.getDecoder().decode(s);
                String decodedStr = new String(legacy, StandardCharsets.UTF_8);
                if (decodedStr.length() > 5 && StringNorm.isPrintable(decodedStr) && !decodedStr.equals(s)) {
                    if (decodedStr.contains("http") || decodedStr.contains("webhook") || decodedStr.contains("discord")) {
                        decryptedBase64.add(s + " -> " + decodedStr + " (in " + className + ")");
                    } else if (this.shannonEntropy(decodedStr) < 4.0) {
                        decryptedBase64.add(s + " -> " + decodedStr + " (in " + className + ")");
                    }
                    if (DECODED_IP.matcher(decodedStr).find() || DECODED_C2_HINT.matcher(decodedStr).find()) {
                        decodedC2.add(s + " -> " + decodedStr + " (in " + className + ")");
                    }
                }
            }
            catch (Exception e) {
                log.debug("Base64 legacy non decodificabile in {}: {}", (Object)className, (Object)e.getMessage());
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
