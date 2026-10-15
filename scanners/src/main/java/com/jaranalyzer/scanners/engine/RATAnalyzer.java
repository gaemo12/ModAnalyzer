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
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RATAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(RATAnalyzer.class);
    private static final Set<String> KEYLOGGER_OWNERS = Set.of("java/awt/event/AWTEventListener", "java/awt/Toolkit", "java/awt/event/KeyEvent", "org/jnativehook/keyboard/NativeKeyListener", "com/github/kwhat/jnativehook/keyboard/NativeKeyListener");
    private static final Set<String> KEYLOGGER_METHODS = Set.of("addAWTEventListener", "getKeyCode", "getKeyChar", "getKeyText", "keyPressed", "keyReleased", "keyTyped", "nativeKeyPressed", "nativeKeyReleased", "nativeKeyTyped");
    private static final Set<String> SCREENSHOT_OWNERS = Set.of("java/awt/Robot", "java/awt/Rectangle", "java/awt/Toolkit", "java/awt/Dimension");
    private static final Set<String> SCREENSHOT_METHODS = Set.of("createScreenCapture", "getScreenSize", "getDefaultToolkit");
    private static final Set<String> WEBCAM_MIC_OWNERS = Set.of("javax/sound/sampled/AudioSystem", "javax/sound/sampled/TargetDataLine", "javax/sound/sampled/DataLine", "javax/sound/sampled/AudioFormat", "com/github/sarxos/webcam/Webcam", "com/github/sarxos/webcam/WebcamPanel", "uk/co/caprica/vlcj/player/MediaPlayer", "javax/media/Player", "javax/media/Manager");
    private static final Set<String> CLIPBOARD_OWNERS = Set.of("java/awt/datatransfer/Clipboard", "java/awt/datatransfer/SystemFlavorMap", "java/awt/datatransfer/DataFlavor", "java/awt/datatransfer/StringSelection", "java/awt/datatransfer/Transferable");
    private static final Set<String> CLIPBOARD_METHODS = Set.of("getContents", "setContents", "getSystemClipboard", "getTransferData", "getText", "setText");
    private static final Set<String> REVERSE_SHELL_OWNERS = Set.of("java/net/Socket", "java/net/ServerSocket", "java/io/BufferedReader", "java/io/BufferedWriter", "java/io/PrintWriter", "java/io/InputStreamReader", "java/io/OutputStreamWriter");
    private static final Set<String> SHELL_METHODS = Set.of("getInputStream", "getOutputStream", "readLine", "write", "println", "flush");
    private static final Set<String> PROCESS_OWNERS = Set.of("java/lang/Runtime", "java/lang/ProcessBuilder", "java/lang/Process");
    private static final Set<String> PROCESS_METHODS = Set.of("exec", "start");
    private static final Set<String> TEMP_FILE_OWNERS = Set.of("java/io/File", "java/io/FileOutputStream", "java/io/FileWriter", "java/nio/file/Files");
    private static final Set<String> TEMP_FILE_PATTERNS = Set.of("C:\\Users\\", "%TEMP%", "%APPDATA%", "\\AppData\\Local\\Temp", ".exe", ".vbs", ".bat", ".ps1", ".dll");
    private static final Set<String> RAT_STRINGS = Set.of("keylogger", "KeyLogger", "KEYLOGGER", "ScreenCapture", "screencapture", "screenshot", "webcam", "Webcam", "WEBCAM", "microphone", "Microphone", "audioCapture", "clipboard", "Clipboard", "CLIPBOARD", "reverseShell", "ReverseShell", "backconnect", "bindShell", "BindShell", "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "C2 ", "commandQueue", "executeCommand", "remoteDesktop", "RemoteDesktop", "fileManager", "FileManager", "processManager", "ProcessManager");
    /**
     * Anti-FP: "cmd.exe" è sottostringa di "jcmd.exe" (tool JDK legittimo usato
     * anche da ModScanOpen). I token shell corti richiedono boundary a sinistra.
     */
    private static final Pattern CMD_EXE = Pattern.compile("(?<![A-Za-z0-9_])cmd\\.exe", Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() {
        return "RAT Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting RAT analysis on {}", (Object)jarFile.getName());
        final AtomicInteger keylogCount = new AtomicInteger();
        final AtomicInteger screenCount = new AtomicInteger();
        final AtomicInteger webcamCount = new AtomicInteger();
        final AtomicInteger clipCount = new AtomicInteger();
        final AtomicInteger reverseShellCount = new AtomicInteger();
        final AtomicInteger execCount = new AtomicInteger();
        final List keylogLocs = Collections.synchronizedList(new ArrayList());
        final List screenLocs = Collections.synchronizedList(new ArrayList());
        final List webcamLocs = Collections.synchronizedList(new ArrayList());
        final List clipLocs = Collections.synchronizedList(new ArrayList());
        final List shellLocs = Collections.synchronizedList(new ArrayList());
        final List ratStringLocs = Collections.synchronizedList(new ArrayList());
        final Map comboDetected = Collections.synchronizedMap(new LinkedHashMap());
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
                catch (Exception e) {
                    continue;
                }
                final String classRef = entry.getName();
                try {
                    cr = new ClassReader(bytes);
                }
                catch (Exception e) {
                    continue;
                }
                cr.accept(new ClassVisitor(589824){

                    public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                        return new MethodVisitor(589824){
                            boolean hasKeylog;
                            boolean hasScreen;
                            boolean hasWebcam;
                            boolean hasClip;
                            boolean hasShellProcess;
                            boolean hasProcessExec;
                            boolean hasTempFile;
                            boolean hasSocket;
                            boolean hasReaderWriter;
                            boolean hasRatString;
                            boolean hasShellMethod;
                            {
                                this.hasKeylog = false;
                                this.hasScreen = false;
                                this.hasWebcam = false;
                                this.hasClip = false;
                                this.hasShellProcess = false;
                                this.hasProcessExec = false;
                                this.hasTempFile = false;
                                this.hasSocket = false;
                                this.hasReaderWriter = false;
                                this.hasRatString = false;
                                this.hasShellMethod = false;
                            }

                            public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                                String loc = classRef + "::" + mName;
                                if (KEYLOGGER_OWNERS.contains(owner) || KEYLOGGER_METHODS.contains(name)) {
                                    this.hasKeylog = true;
                                    if (keylogLocs.size() < 5) {
                                        keylogLocs.add(loc + " -> " + owner + "." + name);
                                    }
                                }
                                if (SCREENSHOT_OWNERS.contains(owner) && SCREENSHOT_METHODS.contains(name)) {
                                    this.hasScreen = true;
                                    if (screenLocs.size() < 5) {
                                        screenLocs.add(loc + " -> " + owner + "." + name);
                                    }
                                }
                                if (WEBCAM_MIC_OWNERS.contains(owner)) {
                                    this.hasWebcam = true;
                                    if (webcamLocs.size() < 5) {
                                        webcamLocs.add(loc + " -> " + owner + "." + name);
                                    }
                                }
                                if (CLIPBOARD_OWNERS.contains(owner) || CLIPBOARD_METHODS.contains(name)) {
                                    this.hasClip = true;
                                    if (clipLocs.size() < 5) {
                                        clipLocs.add(loc + " -> " + owner + "." + name);
                                    }
                                }
                                if (REVERSE_SHELL_OWNERS.contains(owner) && "readLine".equals(name)) {
                                    this.hasReaderWriter = true;
                                }
                                if (REVERSE_SHELL_OWNERS.contains(owner) && ("write".equals(name) || "println".equals(name) || "flush".equals(name))) {
                                    this.hasShellMethod = true;
                                }
                                if ("java/net/Socket".equals(owner) || "java/net/ServerSocket".equals(owner)) {
                                    this.hasSocket = true;
                                }
                                if (PROCESS_OWNERS.contains(owner) && PROCESS_METHODS.contains(name)) {
                                    this.hasProcessExec = true;
                                    if (execCount.get() < 5) {
                                        execCount.incrementAndGet();
                                    }
                                }
                                super.visitMethodInsn(opc, owner, name, d, itf);
                            }

                            public void visitLdcInsn(Object value) {
                                if (value instanceof String) {
                                    String s = (String)value;
                                    String lower = s.toLowerCase(Locale.ROOT);
                                    for (String ratStr : RAT_STRINGS) {
                                        if (!s.equals(ratStr) && (ratStr.length() <= 3 || !lower.contains(ratStr.toLowerCase(Locale.ROOT)))) continue;
                                        // Anti-FP jcmd.exe (vedi CMD_EXE): salta il match spurio.
                                        if ("cmd.exe".equalsIgnoreCase(ratStr) && !CMD_EXE.matcher(s).find()) continue;
                                        this.hasRatString = true;
                                        if (ratStringLocs.size() >= 10) break;
                                        ratStringLocs.add(classRef + "::" + mName + " -> \"" + s.substring(0, Math.min(40, s.length())) + "\"");
                                        break;
                                    }
                                    if (CMD_EXE.matcher(s).find() || lower.contains("powershell") || lower.contains("/bin/sh") || lower.contains("/bin/bash")) {
                                        this.hasShellProcess = true;
                                    }
                                    if (lower.contains("%temp%") || lower.contains("%appdata%") || lower.contains("\\appdata\\local\\temp")) {
                                        this.hasTempFile = true;
                                    }
                                }
                                super.visitLdcInsn(value);
                            }

                            public void visitEnd() {
                                String loc = classRef + "::" + mName;
                                if (this.hasKeylog) {
                                    keylogCount.incrementAndGet();
                                }
                                if (this.hasScreen) {
                                    screenCount.incrementAndGet();
                                }
                                if (this.hasWebcam) {
                                    webcamCount.incrementAndGet();
                                }
                                if (this.hasClip) {
                                    clipCount.incrementAndGet();
                                }
                                if (this.hasSocket && this.hasReaderWriter && this.hasShellMethod) {
                                    reverseShellCount.incrementAndGet();
                                    if (shellLocs.size() < 5) {
                                        shellLocs.add(loc);
                                    }
                                    comboDetected.put("reverse-shell", true);
                                }
                                if (this.hasKeylog && this.hasClip) {
                                    comboDetected.put("keylogger+clipboard", true);
                                }
                                if (this.hasScreen && this.hasSocket) {
                                    comboDetected.put("screenshot-exfil", true);
                                }
                                if (this.hasProcessExec && this.hasSocket && this.hasReaderWriter) {
                                    comboDetected.put("remote-shell", true);
                                }
                            }
                        };
                    }
                }, 4);
            }
        }
        if (comboDetected.containsKey("reverse-shell")) {
            findings.add(new Finding.Builder().title("Reverse Shell \u2014 backdoor remota").description("Socket + InputStream/OutputStream + comandi shell. Pattern esatto di reverse shell o bind shell: esegue comandi sulla macchina vittima e comunica su rete.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli .class").evidence("Reverse shell calls:\n" + String.join((CharSequence)"\n", shellLocs)).family("ReverseShell").recommendation("RAT con capacit\u00e0 di shell remota. Il JAR contiene un backdoor completo.").build());
        }
        if (keylogCount.get() > 0) {
            findings.add(new Finding.Builder().title("Keylogger \u2014 " + keylogCount.get() + " metodi").description("AWTEventListener o NativeKeyListener per catturare la pressione dei tasti. I keylogger registrano tutto ci\u00f2 che viene digitato: password, messaggi, dati bancari.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Keylogger calls:\n" + String.join((CharSequence)"\n", keylogLocs)).family("Keylogger").recommendation("Verifica se i tasti vengono salvati o inviati in rete.").build());
        }
        if (screenCount.get() > 0) {
            findings.add(new Finding.Builder().title("Screen Capture \u2014 " + screenCount.get() + " metodi").description("Uso di java.awt.Robot.createScreenCapture() per catturare lo schermo. I RAT usano questa tecnica per rubare dati visivi, 2FA, o monitorare l'utente.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Screen capture calls:\n" + String.join((CharSequence)"\n", screenLocs)).family("ScreenCapture").recommendation("createScreenCapture combinato con Socket = esfiltrazione di screenshot.").build());
        }
        if (webcamCount.get() > 0) {
            findings.add(new Finding.Builder().title("Webcam / Microfono \u2014 " + webcamCount.get() + " riferimenti").description("Librerie per accesso a webcam (sarxos Webcam) o microfono (javax.sound). I RAT sofisticati possono attivare webcam e microfono per spiare l'utente.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Webcam/mic references:\n" + String.join((CharSequence)"\n", webcamLocs)).family("WebcamMicCapture").build());
        }
        if (clipCount.get() > 0) {
            findings.add(new Finding.Builder().title("Clipboard access \u2014 " + clipCount.get() + " metodi").description("Accesso alla clipboard di sistema. Usato per rubare dati copiati (password, chiavi crypto, indirizzi wallet).").severity(Severity.HIGH).category(Category.CHEAT).location("Multipli .class").evidence("Clipboard calls:\n" + String.join((CharSequence)"\n", clipLocs)).family("ClipboardTheft").build());
        }
        if (!ratStringLocs.isEmpty()) {
            findings.add(new Finding.Builder().title("Stringhe RAT \u2014 " + ratStringLocs.size() + " riferimenti").description("Il JAR contiene stringhe tipiche di RAT: keylogger, screenshot, reverseShell, C2, remoteDesktop, fileManager.").severity(Severity.HIGH).category(Category.CHEAT).location("Multipli .class").evidence("RAT strings:\n" + String.join((CharSequence)"\n", ratStringLocs)).family("RATString").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("RAT analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }
}
