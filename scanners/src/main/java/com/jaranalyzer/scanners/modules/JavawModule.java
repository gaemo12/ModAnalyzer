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
 * {@code javaw}: controlli sulle istanze Java/Minecraft live (righe di comando,
 * argomenti JVM, classificazione). Distingue informazioni mancanti
 * (processi protetti: finding INFO con dettagli non disponibili) da esiti
 * negativi. Niente privilegi amministrativi, niente attach, niente memoria.
 */
public final class JavawModule implements ScanModule {
    private static final Logger log = LoggerFactory.getLogger(JavawModule.class);

    @Override
    public String id() {
        return ModuleId.JAVAW;
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
        progress.report(id(), "analyze", 30);
        JavawAnalyzer javaw = new JavawAnalyzer();
        List<Finding> findings = new ArrayList<>();
        long javaCount = 0;
        long mcCount = 0;
        long noDetails = 0;
        for (ProcessInventory.ProcInfo p : all) {
            checkCancelled(progress);
            if (!p.java()) {
                continue;
            }
            javaCount++;
            if (p.minecraftLike()) {
                mcCount++;
            }
            String location = "pid:" + p.pid() + " " + p.executable();
            if (!p.detailsAvailable()) {
                noDetails++;
                findings.add(new Finding("java-no-details",
                        "Processo Java senza dettagli leggibili (pid " + p.pid() + "): "
                                + "può essere un processo protetto o terminato durante la scansione.",
                        Severity.INFO, Category.PROCESS, location, null));
                continue;
            }
            String redacted = Sanitizer.redactHome(p.commandLine(), homeStr);
            findings.add(new Finding("java-process",
                    "Istanza Java: " + p.executable() + " (pid " + p.pid() + ")"
                            + (p.minecraftLike() ? " legata a Minecraft" : ""),
                    Severity.INFO, Category.PROCESS, location, "Cmdline: " + redacted));
            findings.addAll(javaw.matchText(redacted, location));
        }
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new HashMap<>();
        counters.put("javaProcesses", javaCount);
        counters.put("minecraftLike", mcCount);
        counters.put("noDetails", noDetails);
        log.info("javaw: {} istanze java ({} minecraft-like, {} senza dettagli)",
                javaCount, mcCount, noDetails);
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
