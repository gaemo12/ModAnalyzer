/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.objectweb.asm.ClassReader
 *  org.objectweb.asm.ClassVisitor
 *  org.objectweb.asm.Handle
 *  org.objectweb.asm.Label
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
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ObfuscationAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(ObfuscationAnalyzer.class);
    private static final Set<String> OBFUSCATOR_STRINGS = Set.of("ProGuard", "proguard", "allatori", "Allatori", "zelix", "Zelix", "Skidfuscator", "skidfuscator", "DashO", "dasho", "Stringer", "stringer", "yGuard", "yguard", "retroguard", "RetroGuard", "BisGuard", "JShrink", "Smoke", "ParGuard", "JBCO", "SandMark");
    private static final int MAX_IDENTIFIER_COLLISION_DEPTH = 3;

    @Override
    public String getName() {
        return "Obfuscation Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        int collisions;
        int ltc;
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting obfuscation analysis on {}", (Object)jarFile.getName());
        int totalClasses = 0;
        int obfuscatedClasses = 0;
        int nonAsciiNames = 0;
        int shortNames = 0;
        ArrayList<String> sampleObfuscated = new ArrayList<String>();
        final List stringEncryptMethods = Collections.synchronizedList(new ArrayList());
        final List cfgFlattenMethods = Collections.synchronizedList(new ArrayList());
        List<String> proxyClasses = Collections.synchronizedList(new ArrayList());
        final List reflectionChains = Collections.synchronizedList(new ArrayList());
        final List<String> obfuscatorFound = Collections.synchronizedList(new ArrayList());
        final AtomicInteger totalInvokedynamic = new AtomicInteger();
        final AtomicInteger totalMethods = new AtomicInteger();
        final AtomicInteger largeTryCatch = new AtomicInteger();
        HashMap<String, List<String>> packageClasses = new HashMap<String, List<String>>();
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            block21: while (en.hasMoreElements()) {
                ClassReader cr;
                byte[] bytes;
                boolean isShort;
                String simpleName;
                JarEntry entry = en.nextElement();
                final String name = entry.getName();
                if (!entry.isDirectory() && !name.endsWith(".class")) {
                    if (!name.endsWith(".txt") && !name.endsWith(".properties") && !name.endsWith(".xml") && !name.endsWith(".json")) continue;
                    try {
                        byte[] b = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                        if (b == null) continue;
                        if (b.length <= 0 || b.length > 100000) continue;
                        String text = new String(b, StandardCharsets.UTF_8);
                        for (String string : OBFUSCATOR_STRINGS) {
                            if (!text.contains(string) || obfuscatorFound.size() >= 10) continue;
                            obfuscatorFound.add((string + " in " + name));
                            continue block21;
                        }
                    }
                    catch (Exception is22) {}
                    continue;
                }
                if (entry.isDirectory()) continue;
                ++totalClasses;
                int slash = name.lastIndexOf(47);
                String string = simpleName = slash >= 0 ? name.substring(slash + 1) : name;
                if (simpleName.endsWith(".class")) {
                    simpleName = simpleName.substring(0, simpleName.length() - 6);
                }
                String pkg = slash > 0 ? name.substring(0, slash).replace('/', '.') : "default";
                packageClasses.computeIfAbsent(pkg, k -> new ArrayList()).add(simpleName);
                boolean hasNonAscii = false;
                for (char c : simpleName.toCharArray()) {
                    if (c >= ' ' && c <= '~') continue;
                    hasNonAscii = true;
                    break;
                }
                boolean bl = simpleName.length() >= 3 && simpleName.matches("^[Il10O]+$");
                boolean bl2 = isShort = simpleName.length() <= 2;
                if (hasNonAscii) {
                    ++nonAsciiNames;
                    if (sampleObfuscated.size() < 10) {
                        sampleObfuscated.add((name + " (Non-ASCII)"));
                    }
                } else if (bl) {
                    ++obfuscatedClasses;
                    ++shortNames;
                    if (sampleObfuscated.size() < 10) {
                        sampleObfuscated.add((name + " (Barcode)"));
                    }
                } else if (isShort) {
                    ++obfuscatedClasses;
                    ++shortNames;
                    if (sampleObfuscated.size() < 10) {
                        sampleObfuscated.add((name + " (Short: '" + simpleName + "')"));
                    }
                }
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
                }
                catch (Exception e) {
                    continue;
                }
                try {
                    cr = new ClassReader(bytes);
                }
                catch (Exception e) {
                    continue;
                }
                for (String s : OBFUSCATOR_STRINGS) {
                    if (!name.contains(s) || obfuscatorFound.size() >= 10) continue;
                    obfuscatorFound.add((s + " in " + name));
                }
                cr.accept(new ClassVisitor(589824){

                    public MethodVisitor visitMethod(int access, String mName, String desc, String sig, String[] exc) {
                        totalMethods.incrementAndGet();
                        final String methodRef = name + "::" + mName;
                        return new MethodVisitor(589824){
                            boolean hasCipherInit;
                            boolean hasSecretKeySpec;
                            boolean hasXor;
                            boolean hasByteArray;
                            boolean hasSwitchState;
                            boolean hasStateVar;
                            int delegations;
                            int reflDepth;
                            int tryCatchCount;
                            {
                                this.hasCipherInit = false;
                                this.hasSecretKeySpec = false;
                                this.hasXor = false;
                                this.hasByteArray = false;
                                this.hasSwitchState = false;
                                this.hasStateVar = false;
                                this.delegations = 0;
                                this.reflDepth = 0;
                                this.tryCatchCount = 0;
                            }

                            public void visitMethodInsn(int opc, String owner, String n, String d, boolean itf) {
                                if ("javax/crypto/Cipher".equals(owner) && "init".equals(n)) {
                                    this.hasCipherInit = true;
                                }
                                if ("javax/crypto/spec/SecretKeySpec".equals(owner) && "<init>".equals(n)) {
                                    this.hasSecretKeySpec = true;
                                }
                                if ("java/lang/reflect/Method".equals(owner) && "invoke".equals(n) || "java/lang/Class".equals(owner) && "forName".equals(n)) {
                                    ++this.reflDepth;
                                }
                                if (!(owner.startsWith("java/") || owner.startsWith("javax/") || owner.replace('/', '.').startsWith(name.replace('/', '.').replaceAll("(/[^/]+)$", "")))) {
                                    ++this.delegations;
                                }
                                for (String s : OBFUSCATOR_STRINGS) {
                                    if (!owner.contains(s) || obfuscatorFound.size() >= 10) continue;
                                    obfuscatorFound.add(s + " call in " + methodRef);
                                    break;
                                }
                                super.visitMethodInsn(opc, owner, n, d, itf);
                            }

                            public void visitFieldInsn(int opc, String owner, String n, String d) {
                                String nl = n.toLowerCase(Locale.ROOT);
                                if (nl.contains("state") || nl.contains("stage") || nl.contains("case") || nl.contains("phase")) {
                                    this.hasStateVar = true;
                                }
                                super.visitFieldInsn(opc, owner, n, d);
                            }

                            public void visitInsn(int opcode) {
                                if (opcode == 130 || opcode == 131) {
                                    this.hasXor = true;
                                }
                                if (opcode == 51 || opcode == 84 || opcode == 188) {
                                    this.hasByteArray = true;
                                }
                                super.visitInsn(opcode);
                            }

                            public void visitTableSwitchInsn(int min, int max, Label dflt, Label ... labels) {
                                this.hasSwitchState = true;
                                super.visitTableSwitchInsn(min, max, dflt, labels);
                            }

                            public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
                                this.hasSwitchState = true;
                                super.visitLookupSwitchInsn(dflt, keys, labels);
                            }

                            public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
                                ++this.tryCatchCount;
                                super.visitTryCatchBlock(start, end, handler, type);
                            }

                            public void visitInvokeDynamicInsn(String n, String d, Handle bsm, Object ... args) {
                                totalInvokedynamic.incrementAndGet();
                                super.visitInvokeDynamicInsn(n, d, bsm, args);
                            }

                            public void visitLdcInsn(Object value) {
                                if (value instanceof String) {
                                    String s = (String)value;
                                    for (String ob : OBFUSCATOR_STRINGS) {
                                        if (!s.contains(ob) || obfuscatorFound.size() >= 10) continue;
                                        obfuscatorFound.add(ob + " LDC in " + methodRef);
                                        break;
                                    }
                                }
                                super.visitLdcInsn(value);
                            }

                            public void visitEnd() {
                                if (this.hasCipherInit && (this.hasSecretKeySpec || this.hasXor && this.hasByteArray) && stringEncryptMethods.size() < 20) {
                                    stringEncryptMethods.add(methodRef);
                                }
                                if (this.hasStateVar && this.hasSwitchState && cfgFlattenMethods.size() < 20) {
                                    cfgFlattenMethods.add(methodRef + " (state+switch)");
                                }
                                if (this.reflDepth > 3 && reflectionChains.size() < 20) {
                                    reflectionChains.add(methodRef + " (depth: " + this.reflDepth + ")");
                                }
                                if (this.tryCatchCount > 10) {
                                    largeTryCatch.incrementAndGet();
                                }
                            }
                        };
                    }
                }, 4);
                final int[] ownM = new int[]{0};
                final int[] delM = new int[]{0};
                cr.accept(new ClassVisitor(589824){

                    public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                        if (!"<init>".equals(n) && !"<clinit>".equals(n)) {
                            ownM[0] = ownM[0] + 1;
                        }
                        return new MethodVisitor(589824){

                            public void visitMethodInsn(int op, String owner, String mn, String desc, boolean itf) {
                                if (!owner.startsWith("java/") && !owner.startsWith("javax/")) {
                                    delM[0] = delM[0] + 1;
                                }
                                super.visitMethodInsn(op, owner, mn, desc, itf);
                            }
                        };
                    }
                }, 4);
                if (ownM[0] <= 0 || ownM[0] >= 5 || delM[0] <= ownM[0] * 2 || proxyClasses.size() >= 20) continue;
                proxyClasses.add((name + " (methods:" + ownM[0] + " delegations:" + delM[0] + ")"));
            }
        }
        if (nonAsciiNames > 0) {
            findings.add(new Finding.Builder().title("Nomi classe non-ASCII (" + nonAsciiNames + ")").description("Classi con caratteri non stampabili nel nome. Tecnica avanzata per impedire decompilazione e analisi manuale.").severity(Severity.HIGH).category(Category.OBFUSCATION).location("Multipli .class").evidence("Esempi:\n" + String.join((CharSequence)"\n", sampleObfuscated.subList(0, Math.min(5, sampleObfuscated.size())))).family("NonAsciiNames").build());
        }
        if (totalClasses > 0) {
            double ratio = (double)(obfuscatedClasses + nonAsciiNames) / (double)totalClasses;
            if (ratio > 0.3 && totalClasses > 5) {
                findings.add(new Finding.Builder().title(String.format("Offuscamento codice \u2014 %.0f%% classi rinominate", ratio * 100.0)).description(String.format("%.1f%% delle classi (%d su %d) ha nomi offuscati (singola/doppia lettera, barcode). Indica ProGuard, Allatori o simile.", ratio * 100.0, obfuscatedClasses + nonAsciiNames, totalClasses)).severity(ratio > 0.6 ? Severity.HIGH : Severity.MEDIUM).category(Category.OBFUSCATION).evidence("Ratio: " + String.format("%.2f", ratio) + "\nEsempi:\n" + String.join((CharSequence)"\n", sampleObfuscated)).family("NameObfuscation").build());
            } else if (obfuscatedClasses > 0) {
                findings.add(new Finding.Builder().title("Classi con nomi offuscati (" + obfuscatedClasses + ")").description("Alcune classi con nomi molto corti in un JAR prevalentemente leggibile. Possibile modulo nascosto o malware iniettato.").severity(Severity.LOW).category(Category.OBFUSCATION).evidence("Esempi:\n" + String.join((CharSequence)"\n", sampleObfuscated)).family("NameObfuscation").build());
            }
        }
        if (!stringEncryptMethods.isEmpty()) {
            findings.add(new Finding.Builder().title("String encryption \u2014 " + stringEncryptMethods.size() + " metodi").description("Metodi che decifrano stringhe a runtime (Cipher + SecretKeySpec o XOR su byte[]). Tecnica per nascondere URL C2, payload, chiavi API.").severity(Severity.HIGH).category(Category.OBFUSCATION).location("Multipli .class").evidence("Metodi:\n" + String.join((CharSequence)"\n", stringEncryptMethods)).family("StringEncryption").recommendation("Decompila questi metodi per estrarre le stringhe cifrate.").build());
        }
        if (!cfgFlattenMethods.isEmpty()) {
            findings.add(new Finding.Builder().title("Control Flow Flattening \u2014 " + cfgFlattenMethods.size() + " metodi").description("Variabile di stato con switch centrale: pattern di CFG flattening usato da Allatori, DashO, Skidfuscator per rendere illeggibile il flusso.").severity(Severity.HIGH).category(Category.OBFUSCATION).location("Multipli .class").evidence("Metodi:\n" + String.join((CharSequence)"\n", cfgFlattenMethods)).family("ControlFlowFlattening").build());
        }
        if (!proxyClasses.isEmpty()) {
            findings.add(new Finding.Builder().title("Proxy classes \u2014 " + proxyClasses.size() + " classi").description("Classi con pochi metodi che delegano tutto ad altri. Pattern di dispatch indiretto per nascondere le relazioni reali.").severity(Severity.MEDIUM).category(Category.OBFUSCATION).location("Multipli .class").evidence("Classi:\n" + String.join((CharSequence)"\n", proxyClasses)).family("ProxyClass").build());
        }
        if (!reflectionChains.isEmpty()) {
            findings.add(new Finding.Builder().title("Reflection chains \u2014 " + reflectionChains.size() + " catene").description("Catene di reflection con >3 livelli di invoke() annidato. Usate per nascondere il flusso delle chiamate e bypassare l'analisi statica.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location("Multipli .class").evidence("Chains:\n" + String.join((CharSequence)"\n", reflectionChains)).family("ReflectionChain").build());
        }
        if (!obfuscatorFound.isEmpty()) {
            findings.add(new Finding.Builder().title("Firma offuscatore identificata \u2014 " + obfuscatorFound.size() + " riferimenti").description("Stringhe che identificano specifici offuscatori: ProGuard, Allatori, Zelix, DashO, Stringer, Skidfuscator.").severity(Severity.HIGH).category(Category.OBFUSCATION).location("Multipli file").evidence(String.join((CharSequence)"\n", obfuscatorFound)).family("ObfuscatorFingerprint").build());
        }
        int tm = totalMethods.get();
        int id = totalInvokedynamic.get();
        if (tm > 0 && id > tm * 2) {
            findings.add(new Finding.Builder().title(String.format("Lambda abuse \u2014 %.1f invokedynamic/metodo", (double)id / (double)tm)).description("Densit\u00e0 anomala di invokedynamic: " + id + " su " + tm + " metodi. Indica lambda abuse per offuscare chiamate (Skidfuscator).").severity(Severity.MEDIUM).category(Category.OBFUSCATION).evidence("invokedynamic: " + id + " / methods: " + tm).family("LambdaAbuse").build());
        }
        if ((ltc = largeTryCatch.get()) > 5) {
            findings.add(new Finding.Builder().title("Nested try/catch diffuso \u2014 " + ltc + " metodi").description(ltc + " metodi con >10 blocchi try/catch. Pattern di CFG obfuscation tramite exception handlers (Allatori, Zelix).").severity(Severity.MEDIUM).category(Category.OBFUSCATION).evidence("Metodi con try/catch >10: " + ltc).family("NestedTryCatch").build());
        }
        if ((collisions = this.detectIdentifierCollisions(packageClasses)) > 0) {
            findings.add(new Finding.Builder().title("Identifier collision \u2014 " + collisions + " gruppi").description("Package con classi che differiscono solo per maiuscole/minuscole. Tecnica di offuscamento per confondere decompiler e analisi.").severity(Severity.MEDIUM).category(Category.OBFUSCATION).evidence("Collision groups: " + collisions).family("IdentifierCollision").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Obfuscation analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private int detectIdentifierCollisions(Map<String, List<String>> packageClasses) {
        int count = 0;
        for (Map.Entry<String, List<String>> e : packageClasses.entrySet()) {
            boolean allShort;
            String pkg;
            String[] parts;
            HashSet<String> lower = new HashSet<String>();
            for (String c : e.getValue()) {
                if (lower.add(c.toLowerCase(Locale.ROOT))) continue;
                ++count;
                break;
            }
            if ((parts = (pkg = e.getKey()).split("\\.")).length < 3 || !(allShort = Arrays.stream(parts).allMatch(p -> p.length() <= 2))) continue;
            ++count;
        }
        return count;
    }
}
