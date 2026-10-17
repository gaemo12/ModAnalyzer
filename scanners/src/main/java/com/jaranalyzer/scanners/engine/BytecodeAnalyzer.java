/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.objectweb.asm.AnnotationVisitor
 *  org.objectweb.asm.ClassReader
 *  org.objectweb.asm.ClassVisitor
 *  org.objectweb.asm.Label
 *  org.objectweb.asm.MethodVisitor
 */
package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.SignatureSet;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

public class BytecodeAnalyzer {
    // Nota (anti-FP): java/net/URL NON è nella lista — usare una URL (getPath,
    // toURI, CodeSource.getLocation) non è traffico di rete. Si contano solo
    // openConnection/openStream/getContent (vedi visitMethodInsn). Senza questo,
    // LWJGL e classi del gioco finivano segnalate come "dropper".
    private static final Set<String> NETWORK_OWNERS = Set.of("java/net/HttpURLConnection", "java/net/Socket", "java/net/ServerSocket", "java/nio/channels/SocketChannel", "okhttp3/OkHttpClient", "okhttp3/Request$Builder");
    private static final Set<String> FILE_WRITE_OWNERS = Set.of("java/io/FileOutputStream", "java/io/FileWriter", "java/nio/file/Files");
    private static final Set<String> EXEC_METHODS = Set.of("java/lang/Runtime exec", "java/lang/ProcessBuilder start");
    private static final Set<String> VISITOR_TYPES = Set.of("org/objectweb/asm/ClassVisitor", "org/objectweb/asm/MethodVisitor", "org/objectweb/asm/ClassWriter", "org/objectweb/asm/ClassReader");
    private static final Set<String> JNI_LOAD_METHODS = Set.of("java/lang/System load", "java/lang/System loadLibrary", "java/lang/Runtime load", "java/lang/Runtime loadLibrary");
    private static final Set<String> REFLECTION_INVOKE = Set.of("java/lang/reflect/Method invoke", "java/lang/Class forName", "java/lang/ClassLoader defineClass", "java/lang/ClassLoader loadClass");
    private static final Set<String> XOR_STRING_HINTS = Set.of("xor", "xored", "decrypt", "decryptor", "deobfuscate", "decode", "cipher", "enckey", "encryptionkey", "xorkey");
    private static final String MIXIN_PACKAGE = "org/spongepowered/asm/mixin";
    private static final Set<String> WHITELIST_PACKAGES = Set.of("org/spongepowered/asm/", "net/fabricmc/", "cpw/mods/fml/", "net/minecraftforge/", "org/objectweb/asm/", "com/llamalad7/mixinextras/");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))\\b");
    private static final Set<String> PRIVATE_IP_PREFIXES = Set.of("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "0.0.0.0", "255.255.255.255");
    private static final int MAX_INSTRUCTIONS_PER_METHOD = 2000;
    private static final int MAX_CYCLOMATIC_COMPLEXITY = 50;
    private static final Map<String, String> OBFUSCATOR_SIGNATURES = new LinkedHashMap<String, String>();
    private final SignatureSet signatures;

    public BytecodeAnalyzer(SignatureSet signatures) {
        if (signatures == null) {
            throw new IllegalArgumentException("signatures assente");
        }
        this.signatures = signatures;
    }

    /** Analizza tutte le classi versando i finding nel sink (analisi single-thread qui). */
    public void analyze(JarFile jarFile, List<Finding> sink) {
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        Enumeration<JarEntry> entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            if (!entry.getName().endsWith(".class")) continue;
            try {
                byte[] bytecode = EntryBytes.read(jarFile, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                if (bytecode == null) continue;
                this.analyzeClass(bytecode, entry.getName(), sink);
            }
            catch (Exception e) {
                sink.add(new Finding("bytecode-read-error", "Could not read class: " + entry.getName() + " – " + e.getMessage(), Severity.LOW, Category.STRUCTURE));
            }
        }
        if (!skips.isEmpty()) {
            sink.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
    }

    private void analyzeClass(byte[] bytecode, String className, List<Finding> result) {
        ClassReader cr = new ClassReader(bytecode);
        SuspiciousClassVisitor visitor = new SuspiciousClassVisitor(className, result);
        cr.accept((ClassVisitor)visitor, 4);
    }

    private void checkAccessFlags(String className, int access, List<Finding> result) {
        boolean isInterface;
        ArrayList<String> anomalies = new ArrayList<String>();
        boolean bl = isInterface = (access & 0x200) != 0;
        if (isInterface) {
            return;
        }
        boolean isAbstract = (access & 0x400) != 0;
        boolean isFinal = (access & 0x10) != 0;
        // Nota (anti-FP): ACC_SYNTHETIC segnalato solo non è utile — javac lo
        // mette su bridge/record/lambda di qualsiasi progetto. Si tengono solo
        // le contraddizioni vere (es. FINAL+ABSTRACT).
        if (isFinal && isAbstract) {
            anomalies.add("ACC_FINAL + ACC_ABSTRACT insieme \u2014 access flag contraddittorie (possibile offuscamento)");
        }
        if (!anomalies.isEmpty()) {
            result.add(new Finding("access-flag-anomaly", "Access flags anomali: " + String.join((CharSequence)"; ", anomalies), Severity.MEDIUM, Category.OBFUSCATION).withLocation(className));
        }
    }

    private boolean isPrivateIP(String ip) {
        for (String prefix : PRIVATE_IP_PREFIXES) {
            if (!ip.startsWith(prefix)) continue;
            return true;
        }
        return false;
    }

    private boolean looksLikeCryptoKey(String s) {
        if (s.length() < 8) {
            return false;
        }
        if (s.length() != 16 && s.length() != 24 && s.length() != 32) {
            return false;
        }
        // Anti-FP: le chiavi reali non contengono spazi/controlli. Il backslash
        // esclude anche le regex ("\\s*", "\\\"") scambiate per chiavi.
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c) || c == '\\') {
                return false;
            }
        }
        // Anti-FP: identificatori camelCase/snake_case di 16/24/32 char
        // ("verificationNote", "handleLocalFileSelection") non sono chiavi.
        if (s.matches("^[a-z]+([A-Z][a-zA-Z0-9]*)+$") || s.matches("^[a-z]+(_[a-z0-9]+)+$")) {
            return false;
        }
        // Anti-FP: le chiavi vere sono quasi casuali (entropia alta); le parole
        // inglesi e gli identificatori stanno sotto ~3.7 bit/char.
        if (shannonEntropy(s) < 3.8) {
            return false;
        }
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        for (char c : s.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
                continue;
            }
            if (Character.isLowerCase(c)) {
                hasLower = true;
                continue;
            }
            if (!Character.isDigit(c)) continue;
            hasDigit = true;
        }
        return hasUpper && hasLower || hasUpper && hasDigit || hasLower && hasDigit;
    }

    private static double shannonEntropy(String s) {
        int[] freq = new int[256];
        for (int i = 0; i < s.length(); i++) {
            freq[s.charAt(i) & 0xFF]++;
        }
        double entropy = 0.0;
        double len = s.length();
        for (int count : freq) {
            if (count == 0) {
                continue;
            }
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    static {
        OBFUSCATOR_SIGNATURES.put("proguard", "ProGuard");
        OBFUSCATOR_SIGNATURES.put("ProGuard", "ProGuard");
        OBFUSCATOR_SIGNATURES.put("allatori", "Allatori");
        OBFUSCATOR_SIGNATURES.put("Allatori", "Allatori");
        OBFUSCATOR_SIGNATURES.put("zelix", "Zelix KlassMaster");
        OBFUSCATOR_SIGNATURES.put("Zelix", "Zelix KlassMaster");
        OBFUSCATOR_SIGNATURES.put("skidfuscator", "Skidfuscator");
        OBFUSCATOR_SIGNATURES.put("Skidfuscator", "Skidfuscator");
        OBFUSCATOR_SIGNATURES.put("dasho", "DashO");
        OBFUSCATOR_SIGNATURES.put("DashO", "DashO");
        OBFUSCATOR_SIGNATURES.put("Stringer", "Stringer");
        OBFUSCATOR_SIGNATURES.put("stringer", "Stringer");
        OBFUSCATOR_SIGNATURES.put("yGuard", "yGuard");
        OBFUSCATOR_SIGNATURES.put("yguard", "yGuard");
        OBFUSCATOR_SIGNATURES.put("branch2005", "Branch Obfuscator");
        OBFUSCATOR_SIGNATURES.put("CafeBabe", "CafeBabe Obfuscator");
        OBFUSCATOR_SIGNATURES.put("caelob", "Caelo Obfuscator");
        OBFUSCATOR_SIGNATURES.put("retroguard", "RetroGuard");
        OBFUSCATOR_SIGNATURES.put("RetroGuard", "RetroGuard");
    }

    private class SuspiciousClassVisitor
    extends ClassVisitor {
        private final String className;
        private final List<Finding> result;
        private boolean isWhitelisted;
        private int classVersion;
        private int classAccess;
        private String superName;
        private boolean sourceFilePresent;
        private List<String> classInterfaces;

        SuspiciousClassVisitor(String className, List<Finding> result) {
            super(589824);
            this.isWhitelisted = false;
            this.sourceFilePresent = false;
            this.classInterfaces = new ArrayList<String>();
            this.className = className;
            this.result = result;
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            for (String pkg : WHITELIST_PACKAGES) {
                if (!name.startsWith(pkg)) continue;
                this.isWhitelisted = true;
                break;
            }
            this.classVersion = version;
            this.classAccess = access;
            this.superName = superName;
            if (interfaces != null) {
                this.classInterfaces.addAll(Arrays.asList(interfaces));
            }
            super.visit(version, access, name, signature, superName, interfaces);
        }

        public void visitSource(String source, String debug) {
            this.sourceFilePresent = true;
            super.visitSource(source, debug);
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (this.isWhitelisted) {
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }
            return new SuspiciousMethodVisitor(this.className, name, this.result, access, super.visitMethod(access, name, descriptor, signature, exceptions));
        }

        public void visitEnd() {
            if (!this.sourceFilePresent && !this.isWhitelisted) {
                this.result.add(new Finding("sourcefile-absent", "Classe compilata senza SourceFile attribute (stripped debug info). Tecnica usata per ostacolare il debugging e l'analisi. Comune in malware e cheat offuscati.", Severity.MEDIUM, Category.OBFUSCATION).withLocation(this.className));
            }
            BytecodeAnalyzer.this.checkAccessFlags(this.className, this.classAccess, this.result);
            for (String iface : this.classInterfaces) {
                for (Map.Entry<String, String> obf : OBFUSCATOR_SIGNATURES.entrySet()) {
                    if (!iface.contains(obf.getKey())) continue;
                    this.result.add(new Finding("obfuscator-" + obf.getValue().toLowerCase().replace(' ', '-'), "Firma bytecode rilevata: " + obf.getValue() + " (interfaccia: " + iface + "). L'offuscatore " + obf.getValue() + " \u00e8 stato identificato nel bytecode.", Severity.HIGH, Category.OBFUSCATION).withLocation(this.className));
                }
            }
        }
    }

    private class SuspiciousMethodVisitor
    extends MethodVisitor {
        private final String className;
        private final String methodName;
        private final List<Finding> result;
        private final int methodAccess;
        private boolean usesNetwork;
        private boolean usesFileWrite;
        private boolean usesExec;
        private boolean usesVisitor;
        private boolean usesMixin;
        private boolean usesXor;
        private boolean usesByteArray;
        private boolean usesBase64Decode;
        private boolean usesJniLoad;
        private boolean usesReflectionInvoke;
        private final Set<String> reportedApis;
        private final List<String> xorStringHints;
        private int instructionCount;
        private int tryCatchCount;
        private int invokedynamicCount;
        private int cyclomaticComplexity;
        private boolean hasConstantPoolIP;
        private boolean hasCryptoKeyString;
        private final List<String> constantPoolFindings;
        private int prevOpcode;
        private int alwaysTruePredicates;
        private int alwaysFalsePredicates;

        SuspiciousMethodVisitor(String className, String methodName, List<Finding> result, int access, MethodVisitor mv) {
            super(589824, mv);
            this.usesNetwork = false;
            this.usesFileWrite = false;
            this.usesExec = false;
            this.usesVisitor = false;
            this.usesMixin = false;
            this.usesXor = false;
            this.usesByteArray = false;
            this.usesBase64Decode = false;
            this.usesJniLoad = false;
            this.usesReflectionInvoke = false;
            this.reportedApis = new HashSet<String>();
            this.xorStringHints = new ArrayList<String>();
            this.instructionCount = 0;
            this.tryCatchCount = 0;
            this.invokedynamicCount = 0;
            this.cyclomaticComplexity = 1;
            this.hasConstantPoolIP = false;
            this.hasCryptoKeyString = false;
            this.constantPoolFindings = new ArrayList<String>();
            this.prevOpcode = -1;
            this.alwaysTruePredicates = 0;
            this.alwaysFalsePredicates = 0;
            this.className = className;
            this.methodName = methodName;
            this.result = result;
            this.methodAccess = access;
        }

        public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
            ++this.tryCatchCount;
            super.visitTryCatchBlock(start, end, handler, type);
        }

        public void visitMaxs(int maxStack, int maxLocals) {
            ++this.instructionCount;
            super.visitMaxs(maxStack, maxLocals);
        }

        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            String apiKey;
            SignatureSet.SuspApi api;
            String key;
            ++this.instructionCount;
            this.prevOpcode = -1;
            if (NETWORK_OWNERS.contains(owner)) {
                this.usesNetwork = true;
            }
            if ("java/net/URL".equals(owner)
                    && ("openConnection".equals(name) || "openStream".equals(name) || "getContent".equals(name))) {
                this.usesNetwork = true;
            }
            if (FILE_WRITE_OWNERS.contains(owner)) {
                this.usesFileWrite = true;
            }
            if (EXEC_METHODS.contains(key = owner + " " + name)) {
                this.usesExec = true;
            }
            if (JNI_LOAD_METHODS.contains(key)) {
                this.usesJniLoad = true;
            }
            if (REFLECTION_INVOKE.contains(key)) {
                this.usesReflectionInvoke = true;
            }
            if ("java/util/Base64$Decoder".equals(owner) && "decode".equals(name)) {
                this.usesBase64Decode = true;
            }
            if (opcode == 186) {
                ++this.invokedynamicCount;
            }
            if ((api = BytecodeAnalyzer.this.signatures.suspiciousApi(owner, name)) != null && this.reportedApis.add(apiKey = owner + "#" + name)) {
                this.result.add(new Finding("suspicious-api-" + apiKey.replace('/', '-'), api.description(), Severity.valueOf(api.severity()), Category.SUSPICIOUS_API).withLocation(this.className + "::" + this.methodName).withRecommendation("Verifica manualmente l'uso di " + owner.replace('/', '.') + "." + name));
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }

        public void visitInsn(int opcode) {
            ++this.instructionCount;
            this.prevOpcode = opcode == 3 || opcode == 4 ? opcode : -1;
            if (opcode == 130 || opcode == 131) {
                this.usesXor = true;
            }
            if (opcode == 51 || opcode == 84 || opcode == 188) {
                this.usesByteArray = true;
            }
            super.visitInsn(opcode);
        }

        public void visitJumpInsn(int opcode, Label label) {
            ++this.instructionCount;
            if (opcode != 167 && opcode != 168) {
                ++this.cyclomaticComplexity;
            }
            if (this.prevOpcode == 4 && (opcode == 153 || opcode == 154)) {
                ++this.alwaysTruePredicates;
            } else if (this.prevOpcode == 3 && (opcode == 153 || opcode == 154)) {
                ++this.alwaysFalsePredicates;
            }
            this.prevOpcode = -1;
            super.visitJumpInsn(opcode, label);
        }

        public void visitTableSwitchInsn(int min, int max, Label dflt, Label ... labels) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            this.cyclomaticComplexity += labels != null ? labels.length : 0;
            super.visitTableSwitchInsn(min, max, dflt, labels);
        }

        public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            this.cyclomaticComplexity += labels != null ? labels.length : 0;
            super.visitLookupSwitchInsn(dflt, keys, labels);
        }

        public void visitLdcInsn(Object value) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            if (value instanceof String) {
                String str = (String)value;
                String lower = str.toLowerCase(Locale.ROOT);
                for (String hint : XOR_STRING_HINTS) {
                    if (!lower.contains(hint)) continue;
                    this.xorStringHints.add((String)(str.length() > 80 ? str.substring(0, 80) + "\u2026" : str));
                    break;
                }
                if (str.length() >= 8 && BytecodeAnalyzer.this.looksLikeCryptoKey(str)) {
                    this.hasCryptoKeyString = true;
                    this.constantPoolFindings.add("Possible crypto key: \"" + str.substring(0, Math.min(20, str.length())) + "...\"");
                }
                Matcher ipMatcher = IP_PATTERN.matcher(str);
                while (ipMatcher.find()) {
                    String ip = ipMatcher.group(1);
                    if (BytecodeAnalyzer.this.isPrivateIP(ip)) continue;
                    this.hasConstantPoolIP = true;
                    this.constantPoolFindings.add("Hardcoded public IP: " + ip);
                }
                for (Map.Entry<String, String> obf : OBFUSCATOR_SIGNATURES.entrySet()) {
                    if (!str.contains(obf.getKey())) continue;
                    this.result.add(new Finding("obfuscator-sig-" + obf.getValue().toLowerCase().replace(' ', '-'), "Firma offuscatore nel Constant Pool: " + obf.getValue() + " (stringa: \"" + str.substring(0, Math.min(40, str.length())) + "\"). Il JAR contiene tracce dell'offuscatore " + obf.getValue() + ".", Severity.HIGH, Category.OBFUSCATION).withLocation(this.className + "::" + this.methodName));
                }
            }
            super.visitLdcInsn(value);
        }

        public void visitTypeInsn(int opcode, String type) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            if (VISITOR_TYPES.contains(type)) {
                this.usesVisitor = true;
            }
            if (type.startsWith(BytecodeAnalyzer.MIXIN_PACKAGE)) {
                this.usesMixin = true;
            }
            super.visitTypeInsn(opcode, type);
        }

        public void visitVarInsn(int opcode, int var) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            super.visitVarInsn(opcode, var);
        }

        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            super.visitFieldInsn(opcode, owner, name, descriptor);
        }

        public void visitIntInsn(int opcode, int operand) {
            ++this.instructionCount;
            this.prevOpcode = -1;
            super.visitIntInsn(opcode, operand);
        }

        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            if (descriptor.contains("spongepowered/asm/mixin")) {
                this.usesMixin = true;
            }
            return super.visitAnnotation(descriptor, visible);
        }

        public void visitEnd() {
            String location = this.className + "::" + this.methodName;
            if (this.usesNetwork && (this.usesFileWrite || this.usesExec)) {
                StringBuilder detail = new StringBuilder("Method combines network access");
                if (this.usesFileWrite) {
                    detail.append(" + file write");
                }
                if (this.usesExec) {
                    detail.append(" + process execution");
                }
                detail.append(". ");
                if (this.usesExec) {
                    detail.append("Pattern dropper/stager: scarica ed esegue codice.");
                } else {
                    detail.append("Pattern downloader: scarica e salva file (verifica la provenienza).");
                }
                // Solo rete+scrittura = downloader (media, resource pack, aggiornamenti:
                // normali nelle mod) → MEDIUM. Rete+esecuzione di un processo = vero
                // dropper/stager → CRITICAL.
                Severity sev = this.usesExec ? Severity.CRITICAL : Severity.MEDIUM;
                this.result.add(new Finding("dropper-behavior", detail.toString(), sev, Category.MALWARE_BEHAVIOR).withLocation(location).withRecommendation(this.usesExec
                        ? "Review this method: legitimate mods rarely download and execute files at runtime."
                        : "Verify the download source: files should be data assets, not executables."));
            }
            // Solo ASM a runtime (ClassWriter/ClassVisitor?): è il pattern
            // Fractureiser. Il solo riferimento a Mixin NON è un segnale: nelle
            // mod Fabric le classi caricate in memoria sono già processate da
            // Mixin (firme con CallbackInfo) e il vecchio OR riempiva i dump
            // del gioco di falsi positivi HIGH. CheatAnalyzer copre i combo ASM+Mixin.
            if (this.usesVisitor) {
                this.result.add(new Finding("class-injection-risk", "Suspicious use of ClassVisitor/MethodVisitor (ASM) in non-framework code. Used by Fractureiser-style malware for runtime bytecode injection.", Severity.HIGH, Category.CODE_INJECTION).withLocation(location).withRecommendation("Verify this is a legitimate transformation pipeline, not runtime mod patching."));
            }
            if (this.usesXor && this.usesByteArray) {
                this.result.add(new Finding("xor-encryption", "Rilevato loop XOR su array di byte (istruzione ixor + baload/bastore). Tecnica comune per nascondere stringhe, URL C2 e payload nei JAR malevoli.", Severity.HIGH, Category.CRYPTO).withLocation(location).withRecommendation("Decompila e verifica cosa viene decifrato; spesso precede il caricamento di classi o l'esecuzione di comandi."));
            } else if (this.usesXor) {
                // Un solo XOR senza array = tipicamente hashCode o bit flag:
                // LOW, altrimenti ogni libreria produce una valanga di MEDIUM.
                this.result.add(new Finding("xor-operation", "Uso dell'istruzione XOR nel bytecode. Pu\u00f2 indicare offuscamento leggero o decifratura runtime.", Severity.LOW, Category.CRYPTO).withLocation(location));
            }
            if (!this.xorStringHints.isEmpty()) {
                this.result.add(new Finding("crypto-string-hint", "Stringhe nel constant pool suggeriscono decifratura/offuscamento: " + String.join((CharSequence)", ", this.xorStringHints), Severity.MEDIUM, Category.CRYPTO).withLocation(location));
            }
            if (this.usesBase64Decode && (this.usesXor || this.usesReflectionInvoke)) {
                this.result.add(new Finding("staged-payload-decode", "Base64 decode combinato con XOR o reflection: pattern tipico di stager multi-fase.", Severity.HIGH, Category.MALWARE_BEHAVIOR).withLocation(location));
            }
            if (this.usesJniLoad) {
                this.result.add(new Finding("jni-native-load", "Caricamento libreria nativa (System.load/loadLibrary). Usato da RAT e stealer per bypassare il sandbox Java.", Severity.HIGH, Category.MALWARE_BEHAVIOR).withLocation(location).withRecommendation("Controlla quali .dll/.so sono estratti o referenziati dal JAR."));
            }
            if (this.hasConstantPoolIP) {
                for (String cpFinding : this.constantPoolFindings) {
                    if (!cpFinding.startsWith("Hardcoded public IP")) continue;
                    this.result.add(new Finding("constant-pool-ip", cpFinding + " nel Constant Pool di " + location, Severity.MEDIUM, Category.NETWORK).withLocation(location));
                    break;
                }
            }
            if (this.hasCryptoKeyString) {
                List<String> keys = new ArrayList<>();
                for (String cpFinding : this.constantPoolFindings) {
                    if (!cpFinding.startsWith("Possible crypto key")) continue;
                    if (keys.size() < 3) {
                        keys.add(cpFinding);
                    }
                }
                this.result.add(new Finding("constant-pool-crypto-key", "Possibile chiave crypto hardcodata nel Constant Pool: " + location, Severity.MEDIUM, Category.CRYPTO).withLocation(location).withEvidence(keys.isEmpty() ? null : String.join((CharSequence)"\n", keys)));
            }
            if (this.instructionCount > 2000) {
                this.result.add(new Finding("large-method", "Metodo molto grande: " + this.instructionCount + " istruzioni (soglia: 2000). Metodi eccessivamente grandi sono tipici di codice offuscato, payload cifrati, o bytecode generato automaticamente.", Severity.MEDIUM, Category.OBFUSCATION).withLocation(location));
            }
            if (this.tryCatchCount > 10) {
                this.result.add(new Finding("nested-try-catch", "Nested try/catch blocks: " + this.tryCatchCount + " in " + location + ". Alto numero di blocchi try/catch nidificati \u00e8 una tecnica di offuscamento del control flow (opaque exception handlers). Usato da Allatori, Zelix e altri offuscatori per confondere i decompilatori.", Severity.MEDIUM, Category.OBFUSCATION).withLocation(location));
            }
            if (this.cyclomaticComplexity > 50) {
                this.result.add(new Finding("high-cyclomatic-complexity", "Cyclomatic complexity molto alta: " + this.cyclomaticComplexity + " (soglia: 50). Indica control flow altamente ramificato, tipico di offuscamento o codice generato automaticamente.", Severity.MEDIUM, Category.OBFUSCATION).withLocation(location));
            }
            if (this.alwaysTruePredicates > 5 || this.alwaysFalsePredicates > 5) {
                this.result.add(new Finding("opaque-predicate", "Opaque predicates rilevati in " + location + " \u2014 " + this.alwaysTruePredicates + " sempre-true, " + this.alwaysFalsePredicates + " sempre-false. Tecnica di offuscamento del control flow: condizioni boolean sempre vere/false che confondono il decompilatore ma non alterano il flusso reale.", Severity.MEDIUM, Category.OBFUSCATION).withLocation(location));
            }
            if (this.invokedynamicCount > 20) {
                this.result.add(new Finding("lambda-abuse", "High invokedynamic density: " + this.invokedynamicCount + " in " + location + ". Alta densit\u00e0 di invokedynamic pu\u00f2 indicare lambda abuse per offuscare il flusso del programma o eludere analisi statiche.", Severity.MEDIUM, Category.OBFUSCATION).withLocation(location));
            }
            super.visitEnd();
        }
    }
}
