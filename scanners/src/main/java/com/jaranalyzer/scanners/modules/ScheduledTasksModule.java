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
 * {@code scheduled_tasks}: tutte le task pianificate Windows con la riga di
 * comando eseguita (schtasks /query /fo CSV /v, sola lettura). Segnala le
 * task con payload tipicamente usati dai dropper (powershell -enc / nascosto,
 * wscript/cscript/mshta, certutil -urlcache, downloader), con caffeinazione
 * MEDIUM/HIGH. Le task di Windows rimangono nell'inventario INFO.
 */
public final class ScheduledTasksModule implements ScanModule {

    @Override
    public String id() {
        return ModuleId.SCHEDULED_TASKS;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        if (!WindowsProbe.isWindows()) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("tasks", 0L, "windows", 0L), null);
        }
        List<String> raw;
        try {
            raw = WindowsProbe.exec(new String[]{"schtasks", "/query", "/fo", "CSV", "/v", "/nh"});
        } catch (IOException | RuntimeException e) {
            return new ModuleResult(id(), true, System.currentTimeMillis() - start, List.of(),
                    Map.of("tasks", 0L, "unreachable", 1L), null);
        }
        List<Row> rows = parseCsv(raw);
        List<Finding> findings = new ArrayList<>();
        long suspicious = 0;
        int i = 0;
        for (Row r : rows) {
            checkCancelled(progress);
            progress.report(id(), "analyze", 10 + (95 * ++i) / Math.max(1, rows.size()));
            String run = r.taskToRun == null ? "" : r.taskToRun;
            String lowered = run.toLowerCase();
            String reason;
            Severity sev;
            if (lowered.contains("powershell") && (lowered.contains("-enc") || lowered.contains("-e ")
                    || lowered.contains("-w hidden") || lowered.contains("-bypass"))) {
                sev = Severity.HIGH; reason = "payload PowerShell offuscato/hidden in una task pianificata";
            } else if (lowered.contains("mshta") || lowered.contains("wscript") || lowered.contains("cscript")
                    || lowered.contains("certutil") || lowered.contains("-urlcache") || lowered.contains("bitsadmin")
                    || lowered.contains("invoke-webrequest") || lowered.contains("invoke-item http")
                    || lowered.contains("curl.exe") || lowered.contains("downloadfile")) {
                sev = Severity.HIGH; reason = "task pianificata che scarica o esegue script/DLL: pattern da verificare";
            } else if (lowered.contains("\\appdata\\") || lowered.contains("\\temp\\")) {
                sev = Severity.MEDIUM; reason = "eseguibile della task in cartella utente:: non firmato";
            } else {
                continue; // task normale: solo inventario (counter)
            }
            suspicious++;
            findings.add(new Finding("scheduled-task", "Task pianificata sospetta: " + r.taskName,
                    sev, Category.SYSTEM, r.taskName, run + " — " + reason));
        }
        progress.report(id(), "done", 100);
        Map<String, Long> counters = new java.util.LinkedHashMap<>(); // ordine stabile nel JSON (determinismo)
        counters.put("tasks", (long) rows.size());
        counters.put("tasksFindings", suspicious);
        return new ModuleResult(id(), true, System.currentTimeMillis() - start,
                FindingMapper.toProtocol(findings), counters, null);
    }

    /** Righe CSV velocizzate (30+ campi: bastano Nome, Comando, Autore). */
    private static List<Row> parseCsv(List<String> lines) {
        List<Row> rows = new ArrayList<>();
        int iName = -1, iRun = -1, iAuthor = -1;
        for (String line : lines) {
            String t = line == null ? "" : line.strip();
            if (t.isEmpty()) {
                continue;
            }
            List<String> cols = csvSplit(t);
            if (iName < 0) {
                for (int i = 0; i < cols.size(); i++) {
                    String h = cols.get(i).toLowerCase();
                    if (h.contains("taskname")) iName = i;
                    else if (h.contains("task to run")) iRun = i;
                    else if (h.contains("author")) iAuthor = i;
                }
                continue;
            }
            if (cols.size() <= Math.max(iName, Math.max(iRun, iAuthor))) {
                continue;
            }
            Row r = new Row();
            r.taskName = iName >= 0 ? cols.get(iName) : "";
            r.taskToRun = iRun >= 0 ? cols.get(iRun) : "";
            r.author = iAuthor >= 0 ? cols.get(iAuthor) : "";
            rows.add(r);
        }
        return rows;
    }

    private static List<String> csvSplit(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inq = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inq = !inq;
            } else if (c == ',' && !inq) {
                out.add(cur.toString());
                cur = new StringBuilder();
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }

    private static final class Row {
        String taskName = "", taskToRun = "", author = "";
    }

    private void checkCancelled(ProgressSink progress) throws ScanException {
        if (progress.isCancelled()) {
            throw ScanException.cancelled(id());
        }
    }
}
