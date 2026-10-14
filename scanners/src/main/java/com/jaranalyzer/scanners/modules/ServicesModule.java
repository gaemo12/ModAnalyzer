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
import com.jaranalyzer.scanners.engine.WindowsProbe;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code services}: ImagePath di tutti i servizi registrati (HKLM\\...\\Services,
 * sola lettura). HIGH se il binario del servizio vive in cartelle utente
 * (AppData/Temp/ProgramData/UserProfile): persistenza via servizio. INFO per
 * svchost illegittimi? no: solo inventario con contatori.
 */
public final class ServicesModule implements ScanModule {

    @Override
    public String id() {
        return ModuleId.SERVICES;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        ScanContext.HostContext host = (ScanContext.HostContext) ctx;
        if (!WindowsProbe.isWindows()) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("services", 0L, "windows", 0L), null);
        }
        List<String> raw;
        try {
            raw = WindowsProbe.exec(new String[]{"reg", "query",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ImagePath"});
        } catch (IOException | RuntimeException e) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("services", 0L, "unreachable", 1L), null);
        }
        List<Finding> findings = new ArrayList<>();
        long services = 0;
        String current = null;
        int i = 0;
        for (String line : raw) {
            checkCancelled(progress);
            String t = line == null ? "" : line.strip();
            if (t.startsWith("HKEY_LOCAL_MACHINE")) {
                current = t.substring(t.lastIndexOf('\\') + 1);
                services++;
                continue;
            }
            if (current == null || !t.contains("ImagePath") || t.indexOf("REG_SZ") < 0) {
                continue;
            }
            int type = t.indexOf("REG_SZ");
            String data = t.substring(t.indexOf(' ', type + 5)).strip();
            if (data.isEmpty() || data.indexOf('\\') < 0) {
                continue;
            }
            String lowered = data.toLowerCase();
            String reason; Severity sev;
            if (lowered.contains("\\appdata\\") || lowered.contains("\\temp\\")
                    || lowered.contains("\\users\\public\\") || lowered.contains("\\programdata\\")) {
                sev = Severity.HIGH;
                reason = "binario del servizio eseguito da cartella utente: persistenza classica";
                findings.add(new Finding("service-user-dir", "Servizio creato in zona utente: " + current,
                        sev, Category.SYSTEM, "HKLM\\Services\\" + current, data + " — " + reason));
            } else if (lowered.contains("\\downloads\\") || lowered.contains("\\desktop\\")
                    || lowered.matches(".*(\\.(vbs|js|bat|cmd|hta)).*")) {
                sev = Severity.MEDIUM;
                reason = "servizio con binario/script da percorsi anomali";
                findings.add(new Finding("service-anomalous", "Servizio con percorso anomalo: " + current,
                        sev, Category.SYSTEM, "HKLM\\Services\\" + current, data + " — " + reason));
            }
            if (++i % 256 == 0) {
                progress.report(id(), "analyze", 30);
            }
        }
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new HashMap<>();
        counters.put("services", services);
        counters.put("findings", (long) findings.size());
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }
}
