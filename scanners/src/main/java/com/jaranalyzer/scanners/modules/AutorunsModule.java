package com.jaranalyzer.scanners.modules;

import com.jaranalyzer.common.ModuleId;
import com.jaranalyzer.common.ModuleResult;
import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.FindingMapper;
import com.jaranalyzer.scanners.ProgressSink;
import com.jaranalyzer.scanners.ScanContext;
import com.jaranalyzer.scanners.ScanException;
import com.jaranalyzer.scanners.ScanModule;
import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.SignatureSet;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code autoruns}: chiavi Run/RunOnce (HKCU/HKLM, 64 e 32 bit), cartelle
 * «Startup» e valori Winlogon/AppInit. Sola lettura. Classificazione stile
 * anticheat: HIGH (Detection) per payload tipicamente usati dai dropper
 * (powershell -enc, wscript/mshta/certutil, doppie estensioni, percorsi in
 * AppData/Temp), MEDIUM (Warning) per eseguibili fuori dai percorsi canonici,
 * INFO solo per inventario.
 */
public final class AutorunsModule implements ScanModule {

    private static final String DU_RUN = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String DU_RUNONCE = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    private static final String DM_RUN = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String DM_RUNONCE = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    private static final String DM_WOWRUN = "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String DM_WINLOGON = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    private static final String DM_APPINIT = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    private static final String DU_APPINIT = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

    @Override
    public String id() {
        return ModuleId.AUTORUNS;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        ScanContext.HostContext host = (ScanContext.HostContext) ctx;
        if (!com.jaranalyzer.scanners.engine.WindowsProbe.isWindows()) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("autoruns", 0L, "windows", 0L), null);
        }
        List<Finding> findings = new ArrayList<>();
        long total = 0;
        int index = 0;
        for (String[] key : new String[][]{
                {DU_RUN, "HKCU Run"}, {DU_RUNONCE, "HKCU RunOnce"},
                {DM_RUN, "HKLM Run"}, {DM_RUNONCE, "HKLM RunOnce"}, {DM_WOWRUN, "HKLM Run (32)"},
                {DM_WINLOGON, "HKLM Winlogon"}, {DM_APPINIT, "HKLM AppInit_DLLs"}, {DU_APPINIT, "HKCU AppInit_DLLs"}}) {
            checkCancelled(progress);
            progress.report(id(), "analyze", 10 + (index++) * 10);
            Map<String, String> vals;
            try {
                vals = com.jaranalyzer.scanners.engine.WindowsProbe.regValues(key[0]);
            } catch (IOException | RuntimeException e) {
                continue; // chiave assente o permesso negato: non è un rilevamento
            }
            for (Map.Entry<String, String> v : vals.entrySet()) {
                if (!isInteresting(key, v.getKey())) {
                    continue;
                }
                total++;
                classify(findings, key[1], v.getKey(), v.getValue(), host);
            }
        }
        // Cartelle Startup (utente e tutti gli utenti)
        total += startupFolder(findings, host.appData() == null ? null
                : host.appData().resolve("Microsoft\\Windows\\Start Menu\\Programs\\Startup"), "Startup (utente)",
                host, progress);
        total += startupFolder(findings, host.systemRoot() == null ? null
                        : host.systemRoot().resolve("ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"),
                "Startup (tutti)", host, progress);
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new java.util.LinkedHashMap<>(); // ordine stabile nel JSON (determinismo)
        counters.put("autoruns", total);
        counters.put("findings", (long) findings.size());
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
    }

    /** Filtra i valori non pertinenti per la chiave (es. Solo Shell/Userinit sono figurati e canonici). */
    private static boolean isInteresting(String[] key, String name) {
        String k = key[0];
        String n = name.toLowerCase();
        if (k.endsWith("\\Winlogon")) {
            return n.equals("shell") || n.equals("userinit");
        }
        if (k.endsWith("\\Windows")) { // AppInit
            return n.equals("appinit_dlls") || n.equals("appinit_x64_dlls");
        }
        return true;
    }

    private void classify(List<Finding> findings, String source, String name, String value, ScanContext.HostContext host) {
        String v = value == null ? "" : value.strip();
        String lowered = v.toLowerCase();
        Severity severity;
        String reason;
        if (lowered.contains("powershell") && (lowered.contains("-enc") || lowered.contains("-encodedcommand")
                || lowered.contains("-w hidden") || lowered.contains("-nop -w b"))) {
            severity = Severity.HIGH;
            reason = "comando PowerShell offuscato/finestra nascosta tipico dei dropper";
        } else if (lowered.contains("mshta") || lowered.contains("wscript") || lowered.contains("cscript")
                || lowered.contains("regsvr32") || lowered.contains("rundll32") && lowered.indexOf(".dll") >= 0
                || lowered.contains("certutil") || lowered.contains("-download")) {
            severity = Severity.HIGH;
            reason = "esecuzione via host di script/DLL: used dagli auto-exec; verifica il file";
        } else if (lowered.contains("\\appdata\\") || lowered.contains("\\temp\\") || lowered.contains("\\roaming\\")
                || lowered.matches(".*(\\.(vbs|js|bat|cmd|cmdfile|hta))\\s*(\"|$).*")) {
            severity = Severity.MEDIUM;
            reason = "eseguibile/avviatore in cartella utente o script: non firmato per definizione";
        } else if (!lowered.contains("program files") && !lowered.contains("\\windows\\")
                && !lowered.contains("\\system32") && !lowered.contains("\\windowsapps")) {
            severity = Severity.MEDIUM;
            reason = "percorso non canonico (fuori da Program Files/Windows): da verificare";
        } else {
            findings.add(new Finding("autorun-" + source, "Esecuzione automatica: " + name,
                    Severity.INFO, Category.SYSTEM, source, v));
            return;
        }
        findings.add(new Finding("autorun-" + source, "Autorun sospetto: " + name,
                severity, Category.SYSTEM, source + "\\" + name, v + " — " + reason));
    }

    private long startupFolder(List<Finding> findings, java.nio.file.Path dir, String source,
            ScanContext.HostContext host, ProgressSink progress) throws ScanException {
        List<String> files = com.jaranalyzer.scanners.engine.WindowsProbe.listFiles(dir);
        long count = files.size();
        progress.report(id(), "startup", 80);
        for (String f : files) {
            String lowered = f.toLowerCase();
            boolean dangerous = lowered.endsWith(".vbs") || lowered.endsWith(".js") || lowered.endsWith(".jse")
                    || lowered.endsWith(".wsf") || lowered.endsWith(".bat") || lowered.endsWith(".cmd")
                    || lowered.endsWith(".hta") || lowered.endsWith(".scr");
            // .lnk e .exe in Startup sono normali; script sospetti no
            findings.add(new Finding("startup-folder", "Voce in cartella di avvio: " + f,
                    dangerous ? Severity.MEDIUM : Severity.INFO, Category.SYSTEM, source + "\\" + f,
                    dir == null ? "" : dir.toString()));
        }
        return count;
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }
}
