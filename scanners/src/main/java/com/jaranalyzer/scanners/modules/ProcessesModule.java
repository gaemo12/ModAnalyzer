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
import com.jaranalyzer.scanners.engine.JavawAnalyzer;
import com.jaranalyzer.scanners.engine.ProcessInventory;
import com.jaranalyzer.scanners.engine.Sanitizer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@code processes}: inventario dei processi (solo JDK) + segnali di
 * argomenti JVM sospetti sui processi Java. Niente attach, niente dump di
 * memoria, niente JNA, niente escalation: solo enumerazione e matching su
 * righe di comando (home oscurata). I processi non leggibili vengono contati,
 * non bloccano la scansione.
 */
public final class ProcessesModule implements ScanModule {
    private static final Logger log = LoggerFactory.getLogger(ProcessesModule.class);

    @Override
    public String id() {
        return ModuleId.PROCESSES;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        Path home = ((ScanContext.HostContext) ctx).home();
        String homeStr = home == null ? "" : home.toString();
        progress.report(id(), "enumerate", 10);
        List<ProcessInventory.ProcInfo> all;
        try {
            all = ProcessInventory.snapshot();
        } catch (Exception e) {
            throw ScanException.fatal(id(), "enumerazione processi fallita: " + message(e));
        }
        checkCancelled(progress);
        progress.report(id(), "analyze", 40);
        JavawAnalyzer javaw = new JavawAnalyzer();
        List<Finding> findings = new ArrayList<>();
        long javaCount = 0;
        long mcCount = 0;
        long matched = 0;
        int i = 0;
        for (ProcessInventory.ProcInfo p : all) {
            checkCancelled(progress);
            if (p.java()) {
                javaCount++;
            }
            if (p.minecraftLike()) {
                mcCount++;
            }
            // Matching solo su processi Java (o con riferimenti java): evita falsi positivi
            // su righe di comando legittime di altri software.
            if (p.java() && p.detailsAvailable()) {
                String redacted = Sanitizer.redactHome(p.commandLine(), homeStr);
                List<Finding> hits = javaw.matchText(redacted, "pid:" + p.pid() + " " + p.executable());
                if (!hits.isEmpty()) {
                    matched++;
                    findings.addAll(hits);
                }
                if (p.minecraftLike()) {
                    findings.add(new Finding("minecraft-process",
                            "Processo Java legato a Minecraft: " + p.executable() + " (pid " + p.pid() + ")",
                            Severity.INFO, Category.PROCESS, "pid:" + p.pid(),
                            "Cmdline: " + redacted));
                }
            }
            if (++i % 64 == 0) {
                progress.report(id(), "analyze", 40 + (50 * i) / Math.max(1, all.size()));
            }
        }
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new HashMap<>();
        counters.put("processes", (long) all.size());
        counters.put("java", javaCount);
        counters.put("minecraftLike", mcCount);
        counters.put("matched", matched);
        log.info("processes: {} processi, {} java, {} minecraft-like, {} con segnali",
                all.size(), javaCount, mcCount, matched);
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }

    private static String message(Exception e) {
        String m = e.getMessage();
        return m == null ? e.getClass().getSimpleName() : m;
    }
}
