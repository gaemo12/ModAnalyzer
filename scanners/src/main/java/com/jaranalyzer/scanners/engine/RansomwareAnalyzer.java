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
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RansomwareAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(RansomwareAnalyzer.class);
    private static final Set<String> FILE_ENUM_METHODS = Set.of("listFiles", "listRoots", "list", "walkFileTree", "walk", "find", "newDirectoryStream", "visitFile");
    private static final Set<String> FILE_ENUM_OWNERS = Set.of("java/io/File", "java/nio/file/Files", "java/nio/file/FileVisitor", "java/nio/file/SimpleFileVisitor", "java/nio/file/FileTreeWalker");
    private static final Set<String> FILE_CRYPT_OWNERS = Set.of("javax/crypto/Cipher", "javax/crypto/KeyGenerator", "javax/crypto/SecretKey", "javax/crypto/spec/SecretKeySpec", "javax/crypto/spec/IvParameterSpec", "javax/crypto/spec/PBEKeySpec", "javax/crypto/SealedObject");
    private static final Set<String> FILE_CRYPT_METHODS = Set.of("doFinal", "init", "generateKey", "getInstance", "update", "wrap", "unwrap");
    private static final Set<String> FILE_WRITE_OWNERS = Set.of("java/io/FileOutputStream", "java/io/FileWriter", "java/nio/file/Files", "java/io/RandomAccessFile");
    private static final Set<String> FILE_RENAME_OWNERS = Set.of("java/io/File", "java/nio/file/Files");
    private static final Set<String> FILE_RENAME_METHODS = Set.of("renameTo", "move", "copy");
    private static final Set<String> SHADOW_COPY_STRINGS = Set.of("vssadmin", "VSSADMIN", "shadow copy", "Shadow Copy", "delete shadows", "Delete Shadows", "wmic shadowcopy", "WMIC SHADOWCOPY", "bcdedit", "bootrec", "wbadmin", "WbAdmin", "diskshadow", "DiskShadow", "vss", "VSS", "volume shadow", "Volume Shadow");
    private static final Set<String> RANSOM_EXTENSIONS = Set.of(".crypted", ".encrypted", ".locked", ".enc", ".ransom", ".cry", ".crypt", ".locky", ".wallet", ".onion", ".README", ".README.txt", ".howto", ".how_to", ".decrypt", ".encrypt");
    private static final Set<String> RANSOM_NOTE_STRINGS = Set.of("ransom", "Ransom", "RANSOM", "your files", "Your Files", "encrypted", "Encrypted", "decrypt", "Decrypt", "bitcoin", "Bitcoin", "BTC", "payment", "Payment", "deadline", "Deadline", "private key", "Private Key", "recover", "Recover", "readme", "README", "#ransom", "ransomware");
    private static final Set<String> RANSOM_PACKAGES = Set.of("ransomware", "Ransomware", "RANSOMWARE", "locker", "Locker", "crypter", "Crypter");
    private static final Set<String> DISK_ACCESS_OWNERS = Set.of("java/io/File", "java/nio/file/FileStore", "java/nio/file/FileSystem", "java/nio/file/FileSystems");

    @Override
    public String getName() {
        return "Ransomware Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        boolean comboFileEnumCrypt;
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting ransomware analysis on {}", (Object)jarFile.getName());
        final AtomicInteger fileEnumCount = new AtomicInteger();
        final AtomicInteger fileCryptCount = new AtomicInteger();
        final AtomicInteger fileWriteCount = new AtomicInteger();
        final AtomicInteger fileRenameCount = new AtomicInteger();
        AtomicInteger shadowCopyCount = new AtomicInteger();
        AtomicInteger ransomNoteCount = new AtomicInteger();
        AtomicInteger ransomExtCount = new AtomicInteger();
        final AtomicInteger diskEnumCount = new AtomicInteger();
        final List fileEnumLocs = Collections.synchronizedList(new ArrayList());
        final List fileCryptLocs = Collections.synchronizedList(new ArrayList());
        final List fileWriteLocs = Collections.synchronizedList(new ArrayList());
        final List fileRenameLocs = Collections.synchronizedList(new ArrayList());
        List shadowCopyLocs = Collections.synchronizedList(new ArrayList());
        List<String> ransomNoteLocs = Collections.synchronizedList(new ArrayList());
        List<String> ransomExtLocs = Collections.synchronizedList(new ArrayList());
        List suspectedPaths = Collections.synchronizedList(new ArrayList());
        HashSet<String> classesWithRansomPkg = new HashSet<String>();
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            block21: while (en.hasMoreElements()) {
                JarEntry entry = en.nextElement();
                String name = entry.getName();
                // Match sui SEGMENTI di package (non substring): "Decrypter" contiene
                // "crypter" ma org/apache/maven/settings/crypto e' legittimo (FP su
                // Maven/plexus). Il nome classe non conta, solo i segmenti di package.
                String pkgPath = name;
                int dot = name.lastIndexOf('.');
                int slash = name.lastIndexOf('/', dot < 0 ? name.length() : dot);
                if (slash > 0) {
                    pkgPath = name.substring(0, slash);
                } else if (dot >= 0) {
                    pkgPath = "";
                }
                for (String pkg : RANSOM_PACKAGES) {
                    if (!segmentContains(pkgPath, pkg)) continue;
                    classesWithRansomPkg.add(name);
                    break;
                }
                if (entry.isDirectory()) continue;
                if (name.endsWith(".class")) {
                    ClassReader cr;
                    byte[] bytes;
                    try {
                        bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                        if (bytes == null) continue;
                    }
                    catch (Exception e) {
                        continue;
                    }
                    final String classRef = name;
                    try {
                        cr = new ClassReader(bytes);
                    }
                    catch (Exception e) {
                        continue;
                    }
                    cr.accept(new ClassVisitor(589824){

                        public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                            return new MethodVisitor(589824){
                                boolean hasFileEnum;
                                boolean hasFileCrypt;
                                boolean hasFileWrite;
                                boolean hasFileRename;
                                boolean hasDiskEnum;
                                {
                                    this.hasFileEnum = false;
                                    this.hasFileCrypt = false;
                                    this.hasFileWrite = false;
                                    this.hasFileRename = false;
                                    this.hasDiskEnum = false;
                                }

                                public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                                    String loc = classRef + "::" + mName;
                                    if (FILE_ENUM_OWNERS.contains(owner) && FILE_ENUM_METHODS.contains(name)) {
                                        this.hasFileEnum = true;
                                        if (fileEnumLocs.size() < 5) {
                                            fileEnumLocs.add(loc + " -> " + name);
                                        }
                                    }
                                    if (FILE_CRYPT_OWNERS.contains(owner) && FILE_CRYPT_METHODS.contains(name)) {
                                        this.hasFileCrypt = true;
                                        if (fileCryptLocs.size() < 5) {
                                            fileCryptLocs.add(loc + " -> " + owner + "." + name);
                                        }
                                    }
                                    if (FILE_WRITE_OWNERS.contains(owner) && ("<init>".equals(name) || "write".equals(name))) {
                                        this.hasFileWrite = true;
                                        if (fileWriteLocs.size() < 5) {
                                            fileWriteLocs.add(loc + " -> " + owner + "." + name);
                                        }
                                    }
                                    if (FILE_RENAME_OWNERS.contains(owner) && FILE_RENAME_METHODS.contains(name)) {
                                        this.hasFileRename = true;
                                        if (fileRenameLocs.size() < 5) {
                                            fileRenameLocs.add(loc + " -> " + name);
                                        }
                                    }
                                    if (DISK_ACCESS_OWNERS.contains(owner) && ("listRoots".equals(name) || "getFileStores".equals(name) || "getRootDirectories".equals(name))) {
                                        this.hasDiskEnum = true;
                                        diskEnumCount.incrementAndGet();
                                    }
                                    super.visitMethodInsn(opc, owner, name, d, itf);
                                }

                                public void visitEnd() {
                                    if (this.hasFileEnum) {
                                        fileEnumCount.incrementAndGet();
                                    }
                                    if (this.hasFileCrypt) {
                                        fileCryptCount.incrementAndGet();
                                    }
                                    if (this.hasFileWrite) {
                                        fileWriteCount.incrementAndGet();
                                    }
                                    if (this.hasFileRename) {
                                        fileRenameCount.incrementAndGet();
                                    }
                                }
                            };
                        }
                    }, 4);
                    continue;
                }
                if (!name.endsWith(".txt") && !name.endsWith(".html") && !name.endsWith(".hta") && !name.endsWith(".ini")) continue;
                try {
                    InputStream is = jar.getInputStream(entry);
                    try {
                        byte[] bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                        if (bytes == null) continue;
                        if (bytes.length <= 0 || bytes.length > 102400) continue;
                        String text = new String(bytes, StandardCharsets.UTF_8);
                        String lower = text.toLowerCase(Locale.ROOT);
                        for (String note : RANSOM_NOTE_STRINGS) {
                            if (!lower.contains(note.toLowerCase(Locale.ROOT))) continue;
                            ransomNoteCount.incrementAndGet();
                            if (ransomNoteLocs.size() >= 5) break;
                            ransomNoteLocs.add((name + " contiene \"" + note + "\""));
                            break;
                        }
                        for (String ext : RANSOM_EXTENSIONS) {
                            if (!lower.contains(ext.toLowerCase(Locale.ROOT))) continue;
                            ransomExtCount.incrementAndGet();
                            if (ransomExtLocs.size() >= 5) continue block21;
                            ransomExtLocs.add((ext + " in " + name));
                            continue block21;
                        }
                    }
                    finally {
                        if (is == null) continue;
                        is.close();
                    }
                }
                catch (Exception exception) {}
            }
        }
        if (!classesWithRansomPkg.isEmpty()) {
            findings.add(new Finding.Builder().title("Package ransomware \u2014 " + classesWithRansomPkg.size() + " classi").description("Il JAR contiene classi in package con nome 'ransomware', 'locker' o 'crypter'. Nome altamente indicativo.").severity(Severity.CRITICAL).category(Category.MALWARE_SIGNATURE).location("Multipli .class").evidence("Classi:\n" + String.join((CharSequence)"\n", classesWithRansomPkg.stream().limit(10L).toList())).family("RansomwarePackage").build());
        }
        boolean bl = comboFileEnumCrypt = fileEnumCount.get() > 0 && fileCryptCount.get() > 0 && fileWriteCount.get() > 0;
        if (comboFileEnumCrypt) {
            findings.add(new Finding.Builder().title("COMBO: File enumeration + Cipher + FileWrite \u2014 RANSOMWARE PATTERN").description("Combinazione critica: enumera file del disco, inizializza Cipher, e scrive su disco. Pattern esatto del ransomware: percorre directory, cifra ogni file, riscrive il risultato.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli .class").evidence("FileEnum: " + fileEnumCount.get() + "\nFileCrypt: " + fileCryptCount.get() + "\nFileWrite: " + fileWriteCount.get() + "\nEnum locations:\n" + String.join((CharSequence)"\n", fileEnumLocs)).family("RansomwareBehavior").recommendation("Ransomware classico: elenca file, cifra con chiave generata, sovrascrive originale.").build());
        } else if (fileEnumCount.get() > 0 && fileCryptCount.get() > 0) {
            findings.add(new Finding.Builder().title("File enumeration + Cipher usage \u2014 ALTO RISCHIO RANSOMWARE").description("Enumera file E usa Cipher. Manca solo la scrittura per completare il pattern ransomware.").severity(Severity.HIGH).category(Category.MALWARE_BEHAVIOR).location("Multipli .class").evidence("FileEnum: " + fileEnumCount.get() + "\nFileCrypt: " + fileCryptCount.get()).family("RansomwareBehavior").build());
        }
        if (shadowCopyCount.get() > 0) {
            findings.add(new Finding.Builder().title("Shadow Copy deletion \u2014 " + shadowCopyCount.get() + " riferimenti").description("Riferimenti a vssadmin.exe o comandi per eliminare le shadow copy di Windows. Tecnica usata dal ransomware per impedire il ripristino dei file.").severity(Severity.CRITICAL).category(Category.EXECUTION).location("Multipli file").evidence("Shadow copy references:\n" + String.join((CharSequence)"\n", shadowCopyLocs)).family("ShadowCopyDeletion").recommendation("vssadmin delete shadows /all \u00e8 firma inequivocabile di ransomware.").build());
        }
        if (ransomNoteCount.get() > 0) {
            findings.add(new Finding.Builder().title("Ransom note \u2014 " + ransomNoteCount.get() + " file").description("File di testo con linguaggio da ransom note: 'your files encrypted', 'decrypt', 'bitcoin payment'. Contenuto tipico delle note di riscatto.").severity(Severity.CRITICAL).category(Category.MALWARE_SIGNATURE).location("Multipli file").evidence("Ransom notes:\n" + String.join((CharSequence)"\n", ransomNoteLocs)).family("RansomNote").build());
        }
        if (ransomExtCount.get() > 0) {
            findings.add(new Finding.Builder().title("Estensioni ransomware \u2014 " + ransomExtCount.get() + " riferimenti").description("Il JAR contiene riferimenti a estensioni di file cifrati tipiche del ransomware (.crypted, .encrypted, .locked, .onion).").severity(Severity.HIGH).category(Category.MALWARE_SIGNATURE).location("Multipli file").evidence("Extensions:\n" + String.join((CharSequence)"\n", ransomExtLocs)).family("RansomwareExtension").build());
        }
        if (fileRenameCount.get() > 5) {
            findings.add(new Finding.Builder().title("Mass file rename \u2014 " + fileRenameCount.get() + " operazioni").description("Elevato numero di operazioni di rename/move. Pattern di ransomware che rinomina i file dopo la cifratura.").severity(Severity.MEDIUM).category(Category.FILE_ACCESS).location("Multipli .class").evidence("Rename operations: " + fileRenameCount.get()).family("MassFileRename").build());
        }
        if (diskEnumCount.get() > 0) {
            findings.add(new Finding.Builder().title("Disk root enumeration \u2014 " + diskEnumCount.get() + " chiamate").description("Il JAR enumera le root directory del disco (C:\\, D:\\, etc.). Preliminare per cifratura ransomware di tutte le unit\u00e0.").severity(Severity.MEDIUM).category(Category.FILE_ACCESS).location("Multipli .class").evidence("Disk root enum count: " + diskEnumCount.get()).family("DiskEnumeration").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Ransomware analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    /** Vero se un SEGMENTO di package contiene il marker (mai a cavallo di '/'). */
    private static boolean segmentContains(String pkgPath, String marker) {
        if (pkgPath == null || pkgPath.isEmpty() || marker == null || marker.isEmpty()) {
            return false;
        }
        for (String seg : pkgPath.split("/", -1)) {
            if (seg.contains(marker)) {
                return true;
            }
        }
        return false;
    }
}
