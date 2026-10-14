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
import com.jaranalyzer.scanners.SignatureSet;
import com.jaranalyzer.scanners.Severity;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * {@code software_installed}: elenco dei programmi installati (registry Uninstall
 * HKLM/HKCU, 64+32+Wow6432Navbar, sola lettura). INFO per l'inventario;
 * MEDIUM per programmi installati in cartelle utente (AppData/Temp/Downloads):
 * Packet di installazione mancante di firma è già motivo di rinvio.
 */
public final class InstalledSoftwareModule implements ScanModule {

    private static final String[] KEYS = {
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    };

    @Override
    public String id() {
        return ModuleId.SOFTWARE_INSTALLED;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        if (!com.jaranalyzer.scanners.engine.WindowsProbe.isWindows()) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("programs", 0L, "windows", 0L), null);
        }
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        long programs = 0;
        int k = 0;
        for (String key : KEYS) {
            checkCancelled(progress);
            try {
                List<String> raw = com.jaranalyzer.scanners.engine.WindowsProbe.exec(new String[]{
                        "reg", "query", key, "/s", "/v", "DisplayName"});
                String current = null;
                for (String line : raw) {
                    String t = line == null ? "" : line.strip();
                    if (t.startsWith("HKEY_")) {
                        current = t.substring(t.lastIndexOf('\\') + 1);
                        continue;
                    }
                    if (current == null || !t.contains("DisplayName")) {
                        continue;
                    }
                    int space = t.indexOf(' ', t.indexOf("DisplayName") + "DisplayName".length());
                    if (space < 0) {
                        continue;
                    }
                    String name = t.substring(space).strip();
                    if (name.isEmpty() || name.startsWith("{") || !seen.add(name.toLowerCase(Locale.ROOT))) {
                        continue;
                    }
                    programs++;
                    name = sanitize(name);
                    findings.add(new Finding("installed-software", "Programma installato: " + name,
                            Severity.INFO, Category.SYSTEM, key, name));
                }
            } catch (IOException | RuntimeException ignored) {
                // chiave assente: non e' un rilevamento
            }
            progress.report(id(), "analyze", 20 + (k++) * 30);
        }
        // segnalazione dei programmi sospetti (panno user-writable install path)
        for (String key : KEYS) {
            checkCancelled(progress);
            try {
                List<String> raw = com.jaranalyzer.scanners.engine.WindowsProbe.exec(new String[]{
                        "reg", "query", key, "/s", "/v", "InstallLocation"});
                String current = null;
                for (String line : raw) {
                    String t = line == null ? "" : line.strip();
                    if (t.startsWith("HKEY_")) {
                        current = t.substring(t.lastIndexOf('\\') + 1);
                        continue;
                    }
                    if (current == null || !t.contains("InstallLocation")) {
                        continue;
                    }
                    int space = t.indexOf(' ', t.indexOf("InstallLocation") + "InstallLocation".length());
                    if (space < 0) {
                        continue;
                    }
                    String path = t.substring(space).strip();
                    String lowered = path.toLowerCase();
                    if (lowered.contains("\\appdata\\") || lowered.contains("\\temp\\")
                            || lowered.contains("\\downloads") || lowered.contains("\\desktop")) {
                        findings.add(new Finding("software-user-location",
                                "Programma installato in zona utente: " + current,
                                Severity.MEDIUM, Category.SYSTEM, key + "\\" + current,
                                path + " — binario in cartella scrivibile dall'utente"));
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // chiave assente
            }
            progress.report(id(), "sentries", 60 + (k++) * 15);
        }
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new HashMap<>();
        counters.put("programs", programs);
        counters.put("findings", (long) findings.size());
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
    }

    private static String sanitize(String s) {
        return s.replace('\0', ' ').strip();
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }
}
