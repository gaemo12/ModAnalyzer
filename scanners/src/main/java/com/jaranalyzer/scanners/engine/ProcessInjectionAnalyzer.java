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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProcessInjectionAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(ProcessInjectionAnalyzer.class);
    private static final Set<String> CLASSIC_INJECTION_APIS = Set.of("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread");
    private static final Set<String> HOLLOWING_APIS = Set.of("NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "GetThreadContext", "ResumeThread");
    private static final Set<String> APC_INJECTION_APIS = Set.of("QueueUserAPC", "NtQueueApcThread", "NtTestAlert");
    private static final Set<String> GLOBAL_HOOK_APIS = Set.of("SetWindowsHookExA", "SetWindowsHookExW", "SetWindowsHookEx");
    private static final Set<String> MEMORY_PROTECTION_APIS = Set.of("VirtualProtect", "VirtualProtectEx");
    private static final Set<String> ALL_TRACKED_APIS = new HashSet<String>();
    private static final String JNA_LIBRARY_INTERFACE = "com/sun/jna/Library";
    private static final String JNA_NATIVE_CLASS = "com/sun/jna/Native";

    @Override
    public String getName() {
        return "Process Injection Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        boolean corroborated;
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting process injection analysis on {}", (Object)jarFile.getName());
        boolean usesJna = false;
        LinkedHashMap<String, Set<String>> apisByClass = new LinkedHashMap<String, Set<String>>();
        ArrayList<String> nativeLibLoads = new ArrayList<String>();
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                byte[] bytes;
                JarEntry entry = en.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
                }
                catch (Exception e) {
                    continue;
                }
                ClassInspectionResult res = this.inspectClass(entry.getName(), bytes);
                if (res == null) continue;
                if (res.implementsJnaLibrary) {
                    usesJna = true;
                }
                if (!res.foundApis.isEmpty()) {
                    apisByClass.put(entry.getName(), res.foundApis);
                }
                nativeLibLoads.addAll(res.nativeLibLoads);
            }
        }
        if (apisByClass.isEmpty()) {
            if (!skips.isEmpty()) {
                findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
            }
            log.info("Process injection analysis complete \u2013 nessuna API sospetta trovata");
            return findings;
        }
        HashSet<String> allFound = new HashSet<String>();
        apisByClass.values().forEach(allFound::addAll);
        this.addChainFinding(findings, allFound, apisByClass, CLASSIC_INJECTION_APIS, "Possibile process injection classica (DLL/shellcode injection)", "Sono presenti chiamate a funzioni Win32 tipiche della injection classica (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread): la sequenza standard per allocare memoria in un processo remoto, scriverci codice ed eseguirlo tramite un thread creato in quel processo.", Severity.CRITICAL, "ProcessInjectionClassic", 3);
        this.addChainFinding(findings, allFound, apisByClass, HOLLOWING_APIS, "Possibile process hollowing", "Sono presenti chiamate a funzioni NT usate per il process hollowing (NtUnmapViewOfSection/ZwUnmapViewOfSection insieme a SetThreadContext/ResumeThread): tecnica che smonta l'immagine di un processo legittimo (spesso avviato sospeso) e la sostituisce con codice malevolo, per eseguire sotto le mentite spoglie di un processo fidato.", Severity.CRITICAL, "ProcessHollowing", 2);
        this.addChainFinding(findings, allFound, apisByClass, APC_INJECTION_APIS, "Possibile APC injection", "Sono presenti chiamate a QueueUserAPC/NtQueueApcThread: tecnica di injection che accoda una routine di esecuzione a un thread in stato alertable, spesso usata per evitare le euristiche degli antivirus/EDR basate sul monitoraggio di CreateRemoteThread.", Severity.CRITICAL, "ApcInjection", 1);
        this.addChainFinding(findings, allFound, apisByClass, GLOBAL_HOOK_APIS, "Hook di sistema globale (SetWindowsHookEx)", "SetWindowsHookEx con scope globale permette di intercettare messaggi/eventi in tutti i processi del sistema; \u00e8 una tecnica comune per keylogging o per forzare il caricamento di una DLL malevola in ogni processo che riceve l'hook.", Severity.HIGH, "GlobalWindowsHook", 1);
        if ((allFound.contains("VirtualProtect") || allFound.contains("VirtualProtectEx")) && (corroborated = allFound.stream().anyMatch(a -> CLASSIC_INJECTION_APIS.contains(a) || HOLLOWING_APIS.contains(a) || APC_INJECTION_APIS.contains(a)))) {
            findings.add(new Finding.Builder().title("VirtualProtect(Ex) usato insieme ad altre API di injection").description("VirtualProtect/VirtualProtectEx \u00e8 presente insieme ad altre funzioni di process injection: probabile uso per rendere eseguibile una regione di memoria dopo averci scritto shellcode (bypass di DEP/NX).").severity(Severity.HIGH).category(Category.MALWARE_BEHAVIOR).location(String.join((CharSequence)", ", this.classesContaining(apisByClass, MEMORY_PROTECTION_APIS))).family("MemoryProtectionBypass").build());
        }
        if (usesJna) {
            findings.add(new Finding.Builder().title("Uso di JNA per chiamare API native Windows").description("Il jar dichiara/implementa interfacce com.sun.jna.Library, cio\u00e8 chiama funzioni Win32 direttamente da Java tramite binding nativo. Non \u00e8 di per s\u00e9 malevolo (JNA \u00e8 usato anche legittimamente), ma \u00e8 il meccanismo con cui vengono realizzate tutte le tecniche di process injection sopra elencate: aumenta la confidenza sui finding precedenti se presenti.").severity(Severity.MEDIUM).category(Category.PROCESS).location("com.sun.jna.Library").family("JnaNativeAccess").build());
        }
        if (!nativeLibLoads.isEmpty()) {
            findings.add(new Finding.Builder().title("Caricamento esplicito di libreria nativa").description("Il codice carica esplicitamente una libreria nativa (System.load/loadLibrary o Native.loadLibrary di JNA) puntando a componenti di sistema come kernel32/ntdll/user32, oppure a un file .dll/.so incorporato nel jar. Verificare se la libreria caricata \u00e8 legittima o \u00e8 un payload nativo aggiuntivo nascosto nelle risorse.").severity(Severity.MEDIUM).category(Category.PROCESS).location(String.join((CharSequence)"; ", nativeLibLoads.subList(0, Math.min(10, nativeLibLoads.size())))).family("NativeLibraryLoad").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Process injection analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private void addChainFinding(List<Finding> findings, Set<String> allFound, Map<String, Set<String>> apisByClass, Set<String> chainApis, String title, String description, Severity severity, String family, int minApisRequired) {
        LinkedHashSet<String> matched = new LinkedHashSet<String>(chainApis);
        matched.retainAll(allFound);
        if (matched.size() < minApisRequired) {
            return;
        }
        List<String> classes = this.classesContaining(apisByClass, chainApis);
        findings.add(new Finding.Builder().title(title).description(description).severity(severity).category(Category.MALWARE_BEHAVIOR).location(String.join((CharSequence)", ", classes)).evidence("API individuate: " + String.join((CharSequence)", ", matched)).family(family).recommendation("Verificare manualmente il flusso: da dove vengono ottenuti l'handle di processo e i dati scritti in memoria, e se l'esecuzione \u00e8 condizionata (es. solo su determinati target).").build());
    }

    private List<String> classesContaining(Map<String, Set<String>> apisByClass, Set<String> apiSet) {
        ArrayList<String> out = new ArrayList<String>();
        for (Map.Entry<String, Set<String>> e : apisByClass.entrySet()) {
            boolean any = e.getValue().stream().anyMatch(apiSet::contains);
            if (!any) continue;
            out.add(e.getKey());
        }
        return out;
    }

    private ClassInspectionResult inspectClass(final String entryName, byte[] bytes) {
        ClassReader cr;
        try {
            cr = new ClassReader(bytes);
        }
        catch (Exception e) {
            return null;
        }
        final ClassInspectionResult result = new ClassInspectionResult();
        cr.accept(new ClassVisitor(589824){

            public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                if (interfaces != null) {
                    for (String iface : interfaces) {
                        if (!ProcessInjectionAnalyzer.JNA_LIBRARY_INTERFACE.equals(iface)) continue;
                        result.implementsJnaLibrary = true;
                    }
                }
                super.visit(version, access, name, signature, superName, interfaces);
            }

            public MethodVisitor visitMethod(int access, String mName, String desc, String sig, String[] exc) {
                return new MethodVisitor(589824){
                    String pendingStringConst;
                    {
                        this.pendingStringConst = null;
                    }

                    public void visitLdcInsn(Object value) {
                        if (value instanceof String) {
                            String s;
                            this.pendingStringConst = s = (String)value;
                        }
                        super.visitLdcInsn(value);
                    }

                    public void visitMethodInsn(int opcode, String owner, String calledName, String d, boolean itf) {
                        String lib;
                        boolean isLoadLibrary;
                        if (ALL_TRACKED_APIS.contains(calledName)) {
                            result.foundApis.add(calledName);
                        }
                        boolean bl = isLoadLibrary = "java/lang/System".equals(owner) && ("load".equals(calledName) || "loadLibrary".equals(calledName)) || ProcessInjectionAnalyzer.JNA_NATIVE_CLASS.equals(owner) && "loadLibrary".equals(calledName);
                        if (isLoadLibrary && this.pendingStringConst != null && ((lib = this.pendingStringConst.toLowerCase(Locale.ROOT)).contains("kernel32") || lib.contains("ntdll") || lib.contains("user32") || lib.contains("advapi32") || lib.endsWith(".dll") || lib.endsWith(".so"))) {
                            result.nativeLibLoads.add(entryName + " -> " + this.pendingStringConst);
                        }
                        this.pendingStringConst = null;
                        super.visitMethodInsn(opcode, owner, calledName, d, itf);
                    }
                };
            }
        }, 4);
        return result;
    }

    static {
        ALL_TRACKED_APIS.addAll(CLASSIC_INJECTION_APIS);
        ALL_TRACKED_APIS.addAll(HOLLOWING_APIS);
        ALL_TRACKED_APIS.addAll(APC_INJECTION_APIS);
        ALL_TRACKED_APIS.addAll(GLOBAL_HOOK_APIS);
        ALL_TRACKED_APIS.addAll(MEMORY_PROTECTION_APIS);
    }

    private static class ClassInspectionResult {
        boolean implementsJnaLibrary;
        Set<String> foundApis = new LinkedHashSet<String>();
        List<String> nativeLibLoads = new ArrayList<String>();

        private ClassInspectionResult() {
        }
    }
}
