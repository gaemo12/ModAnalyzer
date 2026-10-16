/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.objectweb.asm.ClassReader
 *  org.objectweb.asm.ClassVisitor
 *  org.objectweb.asm.FieldVisitor
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(CryptoAnalyzer.class);
    private static final Map<String, String> WEAK_ALGORITHMS = Map.ofEntries(Map.entry("DES", "DES \u2014 56-bit key, broken since 1997"), Map.entry("DESede", "3DES \u2014 deprecato, vulnerabile a meet-in-the-middle"), Map.entry("RC2", "RC2 \u2014 algoritmo debole, deprecato"), Map.entry("RC4", "RC4 \u2014 broken, vulnerabile a bias statistici"), Map.entry("Blowfish", "Blowfish \u2014 block size 64-bit, vulnerabile a SWEET32"), Map.entry("MD5", "MD5 \u2014 hash collisions noti, non usare per integrit\u00e0"), Map.entry("SHA1", "SHA-1 \u2014 collision attack dimostrato (SHAttered)"), Map.entry("SHA-1", "SHA-1 \u2014 collision attack dimostrato (SHAttered)"), Map.entry("MD2", "MD2 \u2014 completamente rotto"), Map.entry("MD4", "MD4 \u2014 completamente rotto"), Map.entry("ARCFOUR", "ARCFOUR = RC4 \u2014 broken"), Map.entry("ECB", "Modalit\u00e0 ECB \u2014 non sicura, rivela pattern nel plaintext"), Map.entry("AES/ECB", "AES in modalit\u00e0 ECB \u2014 non sicura per dati strutturati"), Map.entry("DES/ECB", "DES/ECB \u2014 doppiamente insicuro"), Map.entry("NoPadding", "NoPadding senza autenticazione \u2014 vulnerabile a padding oracle"));
    private static final Set<String> CIPHER_OWNERS = Set.of("javax/crypto/Cipher", "javax/crypto/KeyGenerator", "javax/crypto/SecretKeyFactory", "javax/crypto/Mac", "javax/crypto/spec/SecretKeySpec", "javax/crypto/spec/IvParameterSpec", "javax/crypto/spec/PBEKeySpec", "javax/crypto/spec/GCMParameterSpec");
    private static final Set<String> KEYSTORE_OWNERS = Set.of("java/security/KeyStore", "java/security/KeyPairGenerator", "java/security/Signature", "java/security/MessageDigest", "java/security/cert/X509Certificate", "javax/net/ssl/TrustManagerFactory", "javax/net/ssl/KeyManagerFactory");
    private static final int MIN_KEY_ENTROPY_LENGTH = 8;
    private static final Set<String> KEY_HINT_WORDS = Set.of("key", "KEY", "Key", "secret", "SECRET", "Secret", "password", "PASSWORD", "Password", "pass", "PASS", "aeskey", "deskey", "hmackey", "enckey", "iv", "IV", "salt", "SALT", "token", "TOKEN", "cipher", "CIPHER");
    private static final Map<String, String> SUSPICIOUS_CRYPTO_METHODS = Map.ofEntries(Map.entry("init", "Cipher.init() \u2014 inizializzazione cipher"), Map.entry("doFinal", "Cipher.doFinal() \u2014 cifratura/decifratura blocco"), Map.entry("update", "Cipher.update() \u2014 cifratura/decifratura stream"), Map.entry("generateKey", "KeyGenerator.generateKey()"), Map.entry("generateSecret", "SecretKeyFactory.generateSecret()"), Map.entry("getInstance", "Cipher/MD/KeyStore.getInstance()"), Map.entry("load", "KeyStore.load() \u2014 caricamento keystore"));

    @Override
    public String getName() {
        return "Crypto Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        final ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting crypto analysis on {}", (Object)jarFile.getName());
        LinkedHashMap<String, List<String>> weakAlgoByClass = new LinkedHashMap<String, List<String>>();
        LinkedHashMap<String, List<String>> hardcodedKeyByClass = new LinkedHashMap<String, List<String>>();
        LinkedHashMap<String, List<String>> keystorePassByClass = new LinkedHashMap<>();
        final AtomicInteger xorByteArrayCount = new AtomicInteger();
        final AtomicInteger cipherInitCount = new AtomicInteger();
        final AtomicInteger staticIVCount = new AtomicInteger();
        final AtomicInteger ecbCount = new AtomicInteger();
        final AtomicBoolean hasBase64PlusXor = new AtomicBoolean(false);
        final List xorLocations = Collections.synchronizedList(new ArrayList());
        final List staticIVLocs = Collections.synchronizedList(new ArrayList());
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                ClassReader cr;
                byte[] bytes;
                JarEntry entry = en.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
                }
                catch (Exception e2) {
                    continue;
                }
                final String className = entry.getName();
                try {
                    cr = new ClassReader(bytes);
                }
                catch (Exception e3) {
                    continue;
                }
                final ArrayList<String> classWeakAlgos = new ArrayList<String>();
                final ArrayList<String> classHardcodedKeys = new ArrayList<String>();
                final ArrayList classKeystorePass = new ArrayList();
                cr.accept(new ClassVisitor(589824){

                    public FieldVisitor visitField(int access, String name, String desc, String sig, Object value) {
                        String nameLower = name.toLowerCase(Locale.ROOT);
                        for (String hint : KEY_HINT_WORDS) {
                            String sv;
                            if (!nameLower.contains(hint.toLowerCase(Locale.ROOT))) continue;
                            if (!(value instanceof String) || (sv = (String)value).length() < 8) break;
                            classHardcodedKeys.add("field:" + name + " = \"" + sv.substring(0, Math.min(40, sv.length())) + "\"");
                            break;
                        }
                        return super.visitField(access, name, desc, sig, value);
                    }

                    public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                        return new MethodVisitor(589824){
                            boolean hasCipherInit;
                            boolean hasCipherFinal;
                            boolean hasXor;
                            boolean hasByteArray;
                            boolean hasBase64;
                            boolean hasStaticIV;
                            final List<String> methodStrings;
                            {
                                this.hasCipherInit = false;
                                this.hasCipherFinal = false;
                                this.hasXor = false;
                                this.hasByteArray = false;
                                this.hasBase64 = false;
                                this.hasStaticIV = false;
                                this.methodStrings = new ArrayList<String>();
                            }

                            public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                                String fullKey = owner + "." + name;
                                if (!"getInstance".equals(name) || CIPHER_OWNERS.contains(owner) || KEYSTORE_OWNERS.contains(owner)) {
                                    // empty if block
                                }
                                if (CIPHER_OWNERS.contains(owner)) {
                                    if ("init".equals(name)) {
                                        this.hasCipherInit = true;
                                        cipherInitCount.incrementAndGet();
                                    }
                                    if ("doFinal".equals(name)) {
                                        this.hasCipherFinal = true;
                                    }
                                }
                                if (!"java/security/KeyStore".equals(owner) || "load".equals(name)) {
                                    // empty if block
                                }
                                if ("java/util/Base64$Decoder".equals(owner) && "decode".equals(name)) {
                                    this.hasBase64 = true;
                                }
                                if ("javax/crypto/spec/IvParameterSpec".equals(owner) && "<init>".equals(name)) {
                                    this.hasStaticIV = true;
                                    staticIVCount.incrementAndGet();
                                    String loc = className + "::" + mName;
                                    if (staticIVLocs.size() < 5) {
                                        staticIVLocs.add(loc);
                                    }
                                }
                                super.visitMethodInsn(opc, owner, name, d, itf);
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

                            public void visitLdcInsn(Object value) {
                                if (value instanceof String) {
                                    String s = (String)value;
                                    this.methodStrings.add(s);
                                    for (Map.Entry<String, String> algo : WEAK_ALGORITHMS.entrySet()) {
                                        if (!s.contains(algo.getKey())) continue;
                                        String entry = mName + ": \"" + s + "\" \u2014 " + algo.getValue();
                                        if (!classWeakAlgos.contains(entry)) {
                                            classWeakAlgos.add(entry);
                                        }
                                        if (!s.contains("ECB")) continue;
                                        ecbCount.incrementAndGet();
                                    }
                                    if (s.length() >= 8) {
                                        String sLower = s.toLowerCase(Locale.ROOT);
                                        if ((s.length() == 16 || s.length() == 24 || s.length() == 32) && CryptoAnalyzer.this.looksLikeKey(s)) {
                                            classHardcodedKeys.add(mName + ": key candidate \"" + s.substring(0, Math.min(20, s.length())) + "...\"");
                                        }
                                        if (sLower.contains("keystore") || sLower.contains(".jks") || sLower.contains(".p12") || sLower.contains(".pfx")) {
                                            classKeystorePass.add(mName + ": \"" + s.substring(0, Math.min(60, s.length())) + "\"");
                                        }
                                    }
                                }
                                super.visitLdcInsn(value);
                            }

                            public void visitEnd() {
                                String loc = className + "::" + mName;
                                if (this.hasXor && this.hasByteArray) {
                                    xorByteArrayCount.incrementAndGet();
                                    if (xorLocations.size() < 5) {
                                        xorLocations.add(loc);
                                    }
                                    if (this.hasBase64) {
                                        hasBase64PlusXor.set(true);
                                        findings.add(new Finding.Builder().title("Base64 + XOR decode \u2014 staged payload").description("Metodo che combina decodifica Base64 con XOR su array di byte. Pattern classico di stager: decodifica Base64 poi applica XOR key per ottenere il payload reale.").severity(Severity.CRITICAL).category(Category.CRYPTO).location(loc).evidence("Base64.decode() + ixor + baload/bastore in " + loc).family("StagedPayload").build());
                                    }
                                }
                                if (this.hasCipherInit && !this.methodStrings.isEmpty()) {
                                    for (String s : this.methodStrings) {
                                        if (!CryptoAnalyzer.this.looksLikeKey(s) || s.length() < 8) continue;
                                        findings.add(new Finding.Builder().title("Chiave crittografica hardcodata").description("Metodo che inizializza un Cipher con una stringa costante come chiave. Le chiavi hardcodate nel bytecode sono facilmente estraibili con un decompiler.").severity(Severity.CRITICAL).category(Category.CRYPTO).location(loc).evidence("Cipher.init() con stringa costante: \"" + s.substring(0, Math.min(30, s.length())) + "\"").family("HardcodedKey").build());
                                        break;
                                    }
                                }
                            }
                        };
                    }
                }, 4);
                if (!classWeakAlgos.isEmpty()) {
                    weakAlgoByClass.put(className, classWeakAlgos);
                }
                if (!classHardcodedKeys.isEmpty()) {
                    hardcodedKeyByClass.put(className, classHardcodedKeys);
                }
                if (classKeystorePass.isEmpty()) continue;
                keystorePassByClass.put(className, classKeystorePass);
            }
        }
        if (!weakAlgoByClass.isEmpty()) {
            int total = weakAlgoByClass.values().stream().mapToInt(List::size).sum();
            final List<String> examples = new ArrayList<>();
            weakAlgoByClass.entrySet().stream().limit(5L).forEach(e -> ((List)e.getValue()).stream().limit(2L).forEach(v -> examples.add((String)e.getKey() + ": " + v)));
            findings.add(new Finding.Builder().title("Algoritmi crittografici deboli (" + total + " utilizzi)").description("Il JAR usa algoritmi crittografici insicuri o deprecati: DES, 3DES, RC4, MD5, SHA-1, ECB mode. Questi algoritmi sono vulnerabili ad attacchi noti e non dovrebbero essere usati per proteggere dati sensibili.").severity(Severity.HIGH).category(Category.CRYPTO).location("Multipli .class").evidence("Classi coinvolte: " + weakAlgoByClass.size() + "\nEsempi:\n" + String.join((CharSequence)"\n", examples)).family("WeakCrypto").recommendation("Sostituire con: AES-256-GCM, SHA-256/SHA-3, bcrypt/Argon2 per password.").build());
        }
        if (ecbCount.get() > 0) {
            findings.add(new Finding.Builder().title("Modalità ECB rilevata — cifratura non sicura").description("AES o DES in modalità ECB (Electronic Code Book): ogni blocco è cifrato indipendentemente, rivelando pattern nel plaintext. La 'ECB penguin' vulnerability rende visibile la struttura dei dati anche dopo la cifratura.").severity(Severity.HIGH).category(Category.CRYPTO).evidence("ECB mode usages: " + ecbCount.get()).family("WeakCrypto").build());
        }
        if (!hardcodedKeyByClass.isEmpty()) {
            int total = hardcodedKeyByClass.values().stream().mapToInt(List::size).sum();
            final List<String> examples = new ArrayList<>();
            hardcodedKeyByClass.entrySet().stream().limit(5L).forEach(e -> ((List)e.getValue()).stream().limit(2L).forEach(v -> examples.add((String)e.getKey() + ": " + v)));
            findings.add(new Finding.Builder().title("Chiavi crittografiche candidate hardcodate (" + total + ")").description("Il JAR contiene stringhe di lunghezza 16/24/32 byte con caratteristiche di chiave crittografica (alta entropia, charset alfanumerico/hex). Le chiavi hardcodate nel bytecode sono facilmente estraibili con javap o un decompiler.").severity(Severity.HIGH).category(Category.CRYPTO).location("Multipli .class").evidence("Candidate keys:\n" + String.join((CharSequence)"\n", examples)).family("HardcodedKey").recommendation("Le chiavi non devono mai essere nel bytecode. Usare KeyStore, variabili d'ambiente o KMS.").build());
        }
        if (staticIVCount.get() > 0) {
            findings.add(new Finding.Builder().title("IV statico rilevato (" + staticIVCount.get() + " istanze)").description("IvParameterSpec inizializzato con byte[] costante. Un IV statico (mai cambiante) neutralizza la sicurezza della cifratura in modalit\u00e0 CBC/CTR: testi identici producono ciphertext identici, rendendo il sistema vulnerabile ad analisi.").severity(Severity.HIGH).category(Category.CRYPTO).location("Multipli .class").evidence("Static IV locations:\n" + String.join((CharSequence)"\n", staticIVLocs)).family("StaticIV").build());
        }
        if (xorByteArrayCount.get() > 0) {
            findings.add(new Finding.Builder().title("Custom XOR su array di byte (" + xorByteArrayCount.get() + " metodi)").description("Rilevati " + xorByteArrayCount.get() + " metodi con loop XOR su array di byte (istruzione ixor + baload/bastore). Tecnica comune per nascondere stringhe C2, URL, payload e chiavi nei JAR malevoli.").severity(Severity.HIGH).category(Category.CRYPTO).location("Multipli .class").evidence("XOR+bytearray locations:\n" + String.join((CharSequence)"\n", xorLocations)).family("CustomXOR").recommendation("Decompila i metodi segnalati: quasi sempre decifrano URL C2 o payload da costanti nel Constant Pool.").build());
        }
        if (!keystorePassByClass.isEmpty()) {
            findings.add(new Finding.Builder().title("KeyStore / file .jks/.p12 referenziati").description("Il JAR referenzia file KeyStore (.jks, .p12, .pfx). Se la password del KeyStore \u00e8 hardcodata vicino al path, le chiavi private e i certificati sono completamente esposti.").severity(Severity.MEDIUM).category(Category.CRYPTO).location("Multipli .class").evidence("KeyStore references:\n" + keystorePassByClass.entrySet().stream().limit(5L).flatMap(e -> ((List)e.getValue()).stream().map(v -> (String)e.getKey() + ": " + v)).reduce("", (a, b) -> a + "\n" + b)).family("KeyStoreAccess").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Crypto analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private boolean looksLikeKey(String s) {
        if (s.length() < 8) {
            return false;
        }
        // Anti-FP: stringhe di trasformazione Cipher ("AES/CBC/PKCS5Padding",
        // "PBEWithMD5AndDES") non sono chiavi (FP su PBECipher/plexus).
        if (s.matches("(?i)[A-Za-z0-9._+-]+/[A-Za-z0-9._+-]+/[A-Za-z0-9._+-]+")) {
            return false;
        }
        // Anti-FP (come BytecodeAnalyzer.looksLikeCryptoKey): niente spazi/controlli/backslash.
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c) || c == '\\') {
                return false;
            }
        }
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        int hexCount = 0;
        for (char c : s.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') && (c < 'A' || c > 'F')) continue;
            ++hexCount;
        }
        if (hexCount == s.length() && s.length() >= 16) {
            return true;
        }
        int variety = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);
        return variety >= 3;
    }
}
