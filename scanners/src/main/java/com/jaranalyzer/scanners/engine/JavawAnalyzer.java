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
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JavawAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(JavawAnalyzer.class);
    private static final List<PatternEntry> LAUNCHER_PATTERNS = List.of(JavawAnalyzer.p("javaw.exe", Severity.HIGH, "JavawLauncher", "Riferimento diretto a javaw.exe \u2014 avvio di processo Java nascosto"), JavawAnalyzer.p("javaw ", Severity.HIGH, "JavawLauncher", "Avvio javaw con argomenti"), JavawAnalyzer.p("java.exe", Severity.MEDIUM, "JavawLauncher", "Riferimento a java.exe \u2014 avvio processo Java"), JavawAnalyzer.p("java -jar", Severity.HIGH, "JavawLauncher", "Esecuzione di JAR secondario tramite java -jar"), JavawAnalyzer.p("java -cp", Severity.MEDIUM, "JavawLauncher", "Esecuzione con classpath personalizzato"), JavawAnalyzer.p("java -Xbootclasspath", Severity.CRITICAL, "JavawLauncher", "Override del bootstrap classloader \u2014 tecnica di injection avanzata"), JavawAnalyzer.p("java -javaagent", Severity.CRITICAL, "JavawLauncher", "Avvio con Java Agent \u2014 bytecode instrumentation"), JavawAnalyzer.p("-javaagent:", Severity.CRITICAL, "JavaAgent", "Flag -javaagent passato a processo figlio"), JavawAnalyzer.p("-Xbootclasspath/p:", Severity.CRITICAL, "ClasspathHijack", "Prepend al bootstrap classpath \u2014 classloader hijacking"), JavawAnalyzer.p("-Djava.system.class.loader", Severity.CRITICAL, "ClasspathHijack", "Override del system class loader tramite propriet\u00e0 JVM"), JavawAnalyzer.p("java -Dfile.encoding", Severity.LOW, "JavawLauncher", "Avvio Java con encoding customizzato"), JavawAnalyzer.p("Runtime.getRuntime().exec", Severity.HIGH, "Execution", "Esecuzione di processo tramite Runtime.exec"), JavawAnalyzer.p("new ProcessBuilder", Severity.HIGH, "Execution", "Creazione di processo tramite ProcessBuilder"));
    private static final List<PatternEntry> HIDDEN_WINDOW_PATTERNS = List.of(JavawAnalyzer.p("CREATE_NO_WINDOW", Severity.HIGH, "HiddenProcess", "Flag WIN32 per nascondere finestra del processo"), JavawAnalyzer.p("DETACHED_PROCESS", Severity.HIGH, "HiddenProcess", "Flag WIN32 per processo scollegato dal terminale"), JavawAnalyzer.p("SW_HIDE", Severity.HIGH, "HiddenProcess", "Flag ShowWindow HIDE"), JavawAnalyzer.p("-WindowStyle Hidden", Severity.HIGH, "HiddenProcess", "PowerShell senza finestra"), JavawAnalyzer.p("-windowstyle hidden", Severity.HIGH, "HiddenProcess", "PowerShell senza finestra (lowercase)"), JavawAnalyzer.p("start /b ", Severity.HIGH, "HiddenProcess", "Avvio processo in background con cmd start /b"), JavawAnalyzer.p("cmd /c start /min", Severity.HIGH, "HiddenProcess", "Avvio processo minimizzato"), JavawAnalyzer.p("ProcessBuilder.inheritIO", Severity.MEDIUM, "HiddenProcess", "Reindirizzamento I/O per processo figlio"), JavawAnalyzer.p("Redirect.DISCARD", Severity.HIGH, "HiddenProcess", "Output del processo discarded \u2014 nasconde attivit\u00e0"), JavawAnalyzer.p("Desktop.getDesktop().open", Severity.MEDIUM, "Execution", "Apertura file tramite OS handler"), JavawAnalyzer.p("NativeMethods.CreateProcess", Severity.CRITICAL, "HiddenProcess", "Creazione processo Win32 diretta via JNI"));
    private static final List<PatternEntry> SHELL_PATTERNS = List.of(JavawAnalyzer.p("cmd.exe", Severity.HIGH, "ShellExecution", "Avvio CMD di Windows"), JavawAnalyzer.p("cmd /c ", Severity.HIGH, "ShellExecution", "Esecuzione comando CMD"), JavawAnalyzer.p("cmd.exe /c", Severity.HIGH, "ShellExecution", "Esecuzione comando CMD"), JavawAnalyzer.p("/bin/sh", Severity.HIGH, "ShellExecution", "Shell Bash/POSIX Linux"), JavawAnalyzer.p("/bin/bash", Severity.HIGH, "ShellExecution", "Bash Linux"), JavawAnalyzer.p("/bin/sh -c", Severity.HIGH, "ShellExecution", "Shell con comando inline"), JavawAnalyzer.p("/bin/bash -c", Severity.HIGH, "ShellExecution", "Bash con comando inline"), JavawAnalyzer.p("powershell.exe", Severity.HIGH, "ShellExecution", "Avvio PowerShell"), JavawAnalyzer.p("powershell -enc", Severity.CRITICAL, "ShellExecution", "PowerShell con comando encoded (Base64) \u2014 offuscamento"), JavawAnalyzer.p("powershell -nop", Severity.HIGH, "ShellExecution", "PowerShell -NoProfile \u2014 evita configurazione utente"), JavawAnalyzer.p("powershell -exec bypass", Severity.CRITICAL, "ShellExecution", "PowerShell execution policy bypass"), JavawAnalyzer.p("wscript.exe", Severity.HIGH, "ShellExecution", "Windows Script Host"), JavawAnalyzer.p("cscript.exe", Severity.HIGH, "ShellExecution", "CScript \u2014 esecuzione VBScript/JScript"), JavawAnalyzer.p("mshta.exe", Severity.CRITICAL, "ShellExecution", "MSHTA \u2014 esecuzione HTA (HTML Application) \u2014 LOLBin"), JavawAnalyzer.p("regsvr32", Severity.CRITICAL, "ShellExecution", "Regsvr32 \u2014 LOLBin per eseguire DLL remote"), JavawAnalyzer.p("rundll32", Severity.CRITICAL, "ShellExecution", "Rundll32 \u2014 LOLBin"), JavawAnalyzer.p("certutil -decode", Severity.CRITICAL, "ShellExecution", "CertUtil per decodificare payload Base64 \u2014 LOLBin"), JavawAnalyzer.p("bitsadmin /transfer", Severity.CRITICAL, "ShellExecution", "BITSAdmin download remoto \u2014 LOLBin"), JavawAnalyzer.p("wmic process call create", Severity.CRITICAL, "ShellExecution", "WMIC per creare processo \u2014 LOLBin"), JavawAnalyzer.p("sh -i", Severity.CRITICAL, "ShellExecution", "Shell interattiva \u2014 reverse shell indicator"), JavawAnalyzer.p("bash -i", Severity.CRITICAL, "ShellExecution", "Bash interattiva \u2014 reverse shell indicator"));
    private static final List<PatternEntry> JVM_ARG_PATTERNS = List.of(JavawAnalyzer.p("-agentlib:jdwp", Severity.HIGH, "DebugPort", "Apertura porta JDWP debug sul processo figlio"), JavawAnalyzer.p("transport=dt_socket", Severity.HIGH, "DebugPort", "Debug socket transport \u2014 debug remoto abilitato"), JavawAnalyzer.p("address=0.0.0.0", Severity.CRITICAL, "DebugPort", "Debug aperto su tutte le interfacce"), JavawAnalyzer.p("-Xmx", Severity.LOW, "JvmArgs", "Override heap massimo"), JavawAnalyzer.p("-Xms", Severity.LOW, "JvmArgs", "Override heap minimo"), JavawAnalyzer.p("-XX:+DisableAttachMechanism", Severity.MEDIUM, "AntiAnalysis", "Disabilita Attach API \u2014 anti-debug"), JavawAnalyzer.p("-XX:-UsePerfData", Severity.MEDIUM, "AntiAnalysis", "Disabilita JVM perf data \u2014 anti-profiling"), JavawAnalyzer.p("com.sun.jndi", Severity.CRITICAL, "JNDIConfig", "Configurazione JNDI nella command line JVM"), JavawAnalyzer.p("-Dlog4j2.formatMsgNoLookups", Severity.MEDIUM, "Log4ShellMitigation", "Mitigazione Log4Shell \u2014 presenza sospetta in runtime arg"), JavawAnalyzer.p("-Djava.rmi.server.codebase", Severity.CRITICAL, "RMICodebase", "RMI codebase remoto \u2014 carica classi da URL esterno"));
    private static final List<PatternEntry> ANTI_ANALYSIS_PATTERNS = List.of(JavawAnalyzer.p("isDebuggerPresent", Severity.HIGH, "AntiDebug", "Controllo debugger Windows (JNI)"), JavawAnalyzer.p("CheckRemoteDebuggerPresent", Severity.HIGH, "AntiDebug", "Controllo debugger remoto Windows (JNI)"), JavawAnalyzer.p("jdwp", Severity.HIGH, "AntiDebug", "Rilevamento porta JDWP \u2014 anti-debug"), JavawAnalyzer.p("dt_socket", Severity.HIGH, "AntiDebug", "Rilevamento debug socket \u2014 anti-debug"), JavawAnalyzer.p("VBOX", Severity.HIGH, "AntiVM", "Rilevamento VirtualBox"), JavawAnalyzer.p("VMWARE", Severity.HIGH, "AntiVM", "Rilevamento VMware"), JavawAnalyzer.p("QEMU", Severity.HIGH, "AntiVM", "Rilevamento QEMU"), JavawAnalyzer.p("vmtoolsd", Severity.HIGH, "AntiVM", "Processo VMware Tools"), JavawAnalyzer.p("VBoxService", Severity.HIGH, "AntiVM", "Servizio VirtualBox"), JavawAnalyzer.p("SANDBOX", Severity.HIGH, "AntiSandbox", "Stringa SANDBOX \u2014 possibile controllo ambiente"), JavawAnalyzer.p("sandbox", Severity.HIGH, "AntiSandbox", "Stringa sandbox \u2014 possibile controllo ambiente"), JavawAnalyzer.p("wireshark", Severity.HIGH, "AntiAnalysis", "Rilevamento Wireshark"), JavawAnalyzer.p("procmon", Severity.HIGH, "AntiAnalysis", "Rilevamento Process Monitor"), JavawAnalyzer.p("processhacker", Severity.HIGH, "AntiAnalysis", "Rilevamento Process Hacker"), JavawAnalyzer.p("x64dbg", Severity.HIGH, "AntiAnalysis", "Rilevamento x64dbg debugger"), JavawAnalyzer.p("ollydbg", Severity.HIGH, "AntiAnalysis", "Rilevamento OllyDbg debugger"), JavawAnalyzer.p("getInputArguments", Severity.MEDIUM, "AntiAnalysis", "Lettura JVM args \u2014 rileva -javaagent o -agentlib"), JavawAnalyzer.p("ManagementFactory.getRuntimeMXBean", Severity.MEDIUM, "AntiAnalysis", "RuntimeMXBean \u2014 legge args JVM per anti-agent check"), JavawAnalyzer.p("sun.java.command", Severity.MEDIUM, "AntiAnalysis", "Lettura propriet\u00e0 sun.java.command \u2014 self-inspect"));
    private static final List<PatternEntry> PERSISTENCE_PATTERNS = List.of(JavawAnalyzer.p("reg add", Severity.CRITICAL, "Persistence", "Aggiunta chiave registro Windows"), JavawAnalyzer.p("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", Severity.CRITICAL, "Persistence", "Registry Run key \u2014 autostart utente"), JavawAnalyzer.p("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", Severity.CRITICAL, "Persistence", "Registry Run key \u2014 autostart sistema"), JavawAnalyzer.p("Start Menu\\Programs\\Startup", Severity.CRITICAL, "Persistence", "Cartella Startup Windows \u2014 autoavvio"), JavawAnalyzer.p("AppData\\Roaming\\Microsoft\\Windows\\Start Menu", Severity.CRITICAL, "Persistence", "Path Startup in AppData"), JavawAnalyzer.p("schtasks /create", Severity.CRITICAL, "Persistence", "Scheduled Task \u2014 esecuzione pianificata"), JavawAnalyzer.p("schtasks /run", Severity.HIGH, "Persistence", "Esecuzione Scheduled Task"), JavawAnalyzer.p("sc create", Severity.CRITICAL, "Persistence", "Creazione servizio Windows"), JavawAnalyzer.p("launchctl load", Severity.HIGH, "Persistence", "macOS LaunchDaemon/LaunchAgent"), JavawAnalyzer.p("/etc/cron", Severity.HIGH, "Persistence", "Crontab Linux \u2014 esecuzione pianificata"), JavawAnalyzer.p("crontab -e", Severity.HIGH, "Persistence", "Modifica crontab utente"), JavawAnalyzer.p("/etc/init.d/", Severity.HIGH, "Persistence", "Init.d script Linux \u2014 autostart"), JavawAnalyzer.p("~/.bashrc", Severity.HIGH, "Persistence", "Modifica .bashrc \u2014 persistence shell"), JavawAnalyzer.p("~/.profile", Severity.HIGH, "Persistence", "Modifica .profile \u2014 persistence shell"), JavawAnalyzer.p(".minecraft/mods/", Severity.HIGH, "Persistence", "Scrittura nella cartella mods di Minecraft"));
    private static final List<PatternEntry> PROCESS_SELF_PATTERNS = List.of(JavawAnalyzer.p("Runtime.halt", Severity.HIGH, "ProcessControl", "Runtime.halt() \u2014 terminazione forzata JVM"), JavawAnalyzer.p("System.exit", Severity.MEDIUM, "ProcessControl", "System.exit() \u2014 autoterminazione (possibile anti-debug)"), JavawAnalyzer.p("addShutdownHook", Severity.MEDIUM, "ProcessControl", "Shutdown hook \u2014 codice eseguito all'uscita della JVM"), JavawAnalyzer.p("ProcessHandle.current", Severity.MEDIUM, "ProcessControl", "ProcessHandle.current() \u2014 ottiene PID del processo corrente"), JavawAnalyzer.p("ProcessHandle.allProcesses", Severity.HIGH, "ProcessEnum", "Enumerazione di tutti i processi del sistema"), JavawAnalyzer.p(".pid()", Severity.MEDIUM, "ProcessEnum", "Lettura PID processo"), JavawAnalyzer.p("ProcessHandle.of(", Severity.HIGH, "ProcessEnum", "Apertura handle su processo specifico per PID"), JavawAnalyzer.p(".destroy()", Severity.HIGH, "ProcessControl", "Terminazione processo \u2014 possibile process killing"), JavawAnalyzer.p(".destroyForcibly()", Severity.HIGH, "ProcessControl", "Terminazione forzata processo"));
    private static final List<PatternEntry> USER_CUSTOM_STRINGS = List.of();
    private static final Map<String, String> SUSPICIOUS_METHOD_OWNERS = Map.ofEntries(Map.entry("java/lang/Runtime", "Runtime.exec \u2014 esecuzione processo"), Map.entry("java/lang/ProcessBuilder", "ProcessBuilder \u2014 costruzione processo"), Map.entry("java/lang/ProcessHandle", "ProcessHandle \u2014 gestione processi OS"), Map.entry("java/awt/Desktop", "Desktop.open/browse \u2014 apertura file OS"), Map.entry("javax/swing/JOptionPane", "JOptionPane \u2014 UI visibile (pu\u00f2 essere usata per ingannare l'utente)"), Map.entry("com/sun/tools/attach/VirtualMachine", "Attach API \u2014 injection JVM"));

    @Override
    public String getName() {
        return "Javaw / Process Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        EntryBytes.SkipLog textSkips = new EntryBytes.SkipLog();
        log.info("Starting javaw/process analysis on {}", (Object)jarFile.getName());
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                String entryName = entry.getName();
                if (entryName.endsWith(".class")) {
                    this.analyzeClassBytecode(jar, entry, findings, skips);
                    continue;
                }
                if (entry.getSize() <= 0L || entry.getSize() > 0x500000L) continue;
                this.analyzeTextEntry(jar, entry, findings, textSkips);
            }
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        if (!textSkips.isEmpty()) {
            findings.add(textSkips.toFinding(jarFile.getName(), 0x500000L));
        }
        log.info("Javaw/process analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private void analyzeTextEntry(JarFile jar, JarEntry entry, List<Finding> findings, EntryBytes.SkipLog skips) throws Exception {
        byte[] bytes = EntryBytes.read(jar, entry, 0x500000L, skips);
        if (bytes == null) {
            return;
        }
        String content = new String(bytes, StandardCharsets.UTF_8);
        if (!this.isMostlyText(content)) {
            return;
        }
        findings.addAll(this.matchText(content, entry.getName()));
    }

    /**
     * Confronta un testo libero (es. riga di comando di un processo live) con tutti
     * i gruppi di pattern. Stesso codice del percorso statico: nessun duplicato.
     * La location non deve contenere percorsi assoluti (cura del chiamante).
     */
    public List<Finding> matchText(String content, String location) {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        if (content == null || content.isEmpty()) {
            return findings;
        }
        HashSet<String> reported = new HashSet<String>();
        this.scanPatternList(LAUNCHER_PATTERNS, content, location, findings, reported);
        this.scanPatternList(HIDDEN_WINDOW_PATTERNS, content, location, findings, reported);
        this.scanPatternList(SHELL_PATTERNS, content, location, findings, reported);
        this.scanPatternList(JVM_ARG_PATTERNS, content, location, findings, reported);
        this.scanPatternList(ANTI_ANALYSIS_PATTERNS, content, location, findings, reported);
        this.scanPatternList(PERSISTENCE_PATTERNS, content, location, findings, reported);
        this.scanPatternList(PROCESS_SELF_PATTERNS, content, location, findings, reported);
        this.scanPatternList(USER_CUSTOM_STRINGS, content, location, findings, reported);
        return findings;
    }

    private void scanPatternList(List<PatternEntry> patterns, String content, String location, List<Finding> findings, Set<String> reported) {
        for (PatternEntry pe : patterns) {
            if (!content.contains(pe.pattern()) || !reported.add(pe.pattern())) continue;
            String snippet = this.extractSnippet(content, pe.pattern());
            findings.add(new Finding.Builder().title(this.buildTitle(pe)).description(pe.description()).severity(pe.severity()).category(Category.EXECUTION).location(location).evidence("Pattern: \"" + pe.pattern() + "\"\nContesto: " + snippet).family(pe.family()).build());
        }
    }

    private void analyzeClassBytecode(JarFile jar, JarEntry entry, List<Finding> findings, EntryBytes.SkipLog skips) throws Exception {
        byte[] bytecode = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
        if (bytecode == null) {
            return;
        }
        final String location = entry.getName();
        final LinkedHashMap<PatternEntry, List<String>> ldcHits = new LinkedHashMap<PatternEntry, List<String>>();
        final ArrayList suspiciousMethodCalls = new ArrayList();
        ClassReader cr = new ClassReader(bytecode);
        cr.accept(new ClassVisitor(589824){

            public MethodVisitor visitMethod(int access, String mName, String desc, String sig, String[] exc) {
                return new MethodVisitor(589824){

                    public void visitLdcInsn(Object value) {
                        if (value instanceof String) {
                            String str = (String)value;
                            JavawAnalyzer.this.checkStringAgainstPatterns(str, location, ldcHits);
                        }
                        super.visitLdcInsn(value);
                    }

                    public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                        String call;
                        String ownerDesc = SUSPICIOUS_METHOD_OWNERS.get(owner);
                        if (ownerDesc != null && !suspiciousMethodCalls.contains(call = owner.replace('/', '.') + "." + name + "()") && suspiciousMethodCalls.size() < 10) {
                            suspiciousMethodCalls.add(call);
                        }
                        super.visitMethodInsn(opc, owner, name, d, itf);
                    }
                };
            }
        }, 4);
        for (Map.Entry<PatternEntry, List<String>> hit : ldcHits.entrySet()) {
            PatternEntry pe = hit.getKey();
            findings.add(new Finding.Builder().title("[Bytecode] " + this.buildTitle(pe)).description(pe.description() + " \u2014 rilevato nel bytecode come stringa costante.").severity(pe.severity()).category(Category.EXECUTION).location(location).evidence("Pattern: \"" + pe.pattern() + "\"\nStringhe trovate:\n" + String.join("\n", hit.getValue())).family(pe.family()).build());
        }
        if (!suspiciousMethodCalls.isEmpty()) {
            findings.add(new Finding.Builder().title("Chiamate a API di processo/esecuzione").description("La classe contiene chiamate a API Java per la creazione o gestione di processi di sistema (Runtime.exec, ProcessBuilder, Desktop.open, Attach API, ecc.).").severity(Severity.HIGH).category(Category.EXECUTION).location(location).evidence("Metodi rilevati:\n" + String.join((CharSequence)"\n", suspiciousMethodCalls)).family("ProcessAPI").build());
        }
    }

    private void checkStringAgainstPatterns(String str, String location, Map<PatternEntry, List<String>> hits) {
        String truncated = str.length() > 150 ? str.substring(0, 150) + "\u2026" : str;
        for (List<PatternEntry> group : List.of(LAUNCHER_PATTERNS, HIDDEN_WINDOW_PATTERNS, SHELL_PATTERNS, JVM_ARG_PATTERNS, ANTI_ANALYSIS_PATTERNS, PERSISTENCE_PATTERNS, PROCESS_SELF_PATTERNS, USER_CUSTOM_STRINGS)) {
            for (PatternEntry pe : group) {
                if (!str.contains(pe.pattern())) continue;
                hits.computeIfAbsent(pe, k -> new ArrayList()).add(truncated);
            }
        }
    }

    private String buildTitle(PatternEntry pe) {
        return switch (pe.family()) {
            case "JavawLauncher" -> "Lancio java/javaw rilevato";
            case "JavaAgent" -> "Java Agent flag in processo figlio";
            case "ClasspathHijack" -> "Classpath hijacking JVM";
            case "HiddenProcess" -> "Processo nascosto / finestra invisibile";
            case "ShellExecution" -> "Esecuzione shell di sistema";
            case "JvmArgs" -> "JVM args passati a processo figlio";
            case "AntiDebug" -> "Anti-debug rilevato";
            case "AntiVM" -> "Anti-VM rilevato";
            case "AntiSandbox" -> "Anti-sandbox rilevato";
            case "AntiAnalysis" -> "Evasione analisi rilevata";
            case "Persistence" -> "Meccanismo di persistence rilevato";
            case "ProcessControl" -> "Controllo/terminazione processo";
            case "ProcessEnum" -> "Enumerazione processi di sistema";
            case "DebugPort" -> "Porta debug JVM aperta";
            case "Execution" -> "Esecuzione processo";
            default -> "Comportamento sospetto: " + pe.family();
        };
    }

    private String extractSnippet(String content, String pattern) {
        int idx = content.indexOf(pattern);
        if (idx < 0) {
            return pattern;
        }
        int start = Math.max(0, idx - 60);
        int end = Math.min(content.length(), idx + pattern.length() + 60);
        String snippet = content.substring(start, end).replace("\n", "\\n").replace("\r", "");
        return (start > 0 ? "\u2026" : "") + snippet + (end < content.length() ? "\u2026" : "");
    }

    private boolean isMostlyText(String content) {
        if (content.isEmpty()) {
            return false;
        }
        int nonPrintable = 0;
        int sample = Math.min(content.length(), 512);
        for (int i = 0; i < sample; ++i) {
            char c = content.charAt(i);
            if (c >= '\t' && (c <= '\r' || c >= ' ')) continue;
            ++nonPrintable;
        }
        return (double)nonPrintable < (double)sample * 0.05;
    }

    private static PatternEntry p(String pattern, Severity severity, String family, String description) {
        return new PatternEntry(pattern, severity, family, description);
    }

    private record PatternEntry(String pattern, Severity severity, String family, String description) {
    }
}
