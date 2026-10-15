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
import com.jaranalyzer.scanners.engine.AccountScanner;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@code minecraft_accounts}: inventario degli account Minecraft (solo username
 * e UUID: identificativi pubblici, già visibili in gioco). Mai password, token,
 * refresh token, cookie o credenziali: il record {@code Account} ha solo 4
 * campi e i parser scartano tutto il resto. Nessun percorso assoluto nei risultati.
 */
public final class MinecraftAccountsModule implements ScanModule {
    private static final Logger log = LoggerFactory.getLogger(MinecraftAccountsModule.class);

    @Override
    public String id() {
        return ModuleId.MINECRAFT_ACCOUNTS;
    }

    @Override
    public ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException {
        long start = System.currentTimeMillis();
        if (!(ctx instanceof ScanContext.HostContext)) {
            throw ScanException.fatal(id(), "contesto non valido: serve HostContext");
        }
        ScanContext.HostContext host = (ScanContext.HostContext) ctx;
        progress.report(id(), "scan", 20);
        checkCancelled(progress);
        List<AccountScanner.Account> accounts;
        try {
            accounts = AccountScanner.detect(host.appData(), host.userProfile());
        } catch (Exception e) {
            throw ScanException.fatal(id(), "rilevamento account fallito: " + message(e));
        }
        checkCancelled(progress);
        progress.report(id(), "done", 100);
        List<Finding> findings = new ArrayList<>();
        Set<String> launchers = new HashSet<>();
        for (AccountScanner.Account a : accounts) {
            launchers.add(a.launcher());
            findings.add(new Finding("minecraft-account", "Account Minecraft: " + a.username(),
                    Severity.INFO, Category.STRUCTURE, a.launcher(),
                    "Launcher: " + a.launcher() + "\nTipo: " + a.type()
                            + (a.uuid().isEmpty() ? "" : "\nUUID: " + a.uuid())));
        }
        Map<String, Long> counters = new java.util.LinkedHashMap<>(); // ordine stabile nel JSON (determinismo)
        counters.put("accounts", (long) accounts.size());
        counters.put("launchers", (long) launchers.size());
        log.info("minecraft_accounts: {} account, {} launcher", accounts.size(), launchers.size());
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
