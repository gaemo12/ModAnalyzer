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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code hosts_file}: legge System32\\drivers\\etc\\hosts (sola lettura).
 * Mappature verso host non-loopback non commentate sono MEDIUM (warning):
 * reindirizzamenti di domini di launcher/server sono marcature tipiche di
 * tool di spoofing MITM. Loopback=INFO innocuo.
 */
public final class HostsFileModule implements ScanModule {

    @Override
    public String id() {
        return ModuleId.HOSTS_FILE;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        Path systemRoot = ((ScanContext.HostContext) ctx).systemRoot();
        if (systemRoot == null) {
            // Su Windows il modulo è utile solo con systemRoot; altrove è no-op pulito.
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("entries", 0L), null);
        }
        Path hosts = systemRoot.resolve("System32").resolve("drivers").resolve("etc").resolve("hosts");
        List<String> lines;
        try {
            lines = Files.readAllLines(hosts, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("entries", 0L, "missing", 1L), null);
        }
        List<Finding> findings = new ArrayList<>();
        long entries = 0;
        for (String line : lines) {
            checkCancelled(progress);
            String t = line == null ? "" : line.strip();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            entries++;
            String[] parts = t.split("\\s+");
            if (parts.length < 2) {
                continue;
            }
            String ip = parts[0].toLowerCase(Locale.ROOT);
            String domains = t.substring(t.indexOf(' ')).strip();
            boolean loopback = ip.equals("127.0.0.1") || ip.equals("::1") || ip.startsWith("127.");
            Severity sev = loopback ? Severity.INFO : Severity.MEDIUM;
            String reason = loopback
                    ? "blocco locale: non determina diretta reindirizzamenti"
                    : "mappatura verso un host esterno: possibile MITM/spoofing di domini di gioco";
            findings.add(new Finding("hosts-entry", "Hosts: " + ip + " → " + domains,
                    sev, Category.SYSTEM, hosts.toString(), t + " — " + reason));
        }
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new java.util.LinkedHashMap<>(); // ordine stabile nel JSON (determinismo)
        counters.put("entries", entries);
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }
}
