package com.jaranalyzer.scanners.modules;

import com.jaranalyzer.common.ModuleId;
import com.jaranalyzer.scanners.ScanModule;
import java.util.List;

/**
 * Registro dei moduli (ordine stabile). Rifiuta identificatori fuori allowlist:
 * il backend accetta solo questi id e il Player esegue solo quelli del job.
 */
public final class ScanModules {
    private static final List<ScanModule> ALL = List.of(
            new ModsFolderModule(),
            new ProcessesModule(),
            new JavawModule(),
            new MinecraftAccountsModule(),
            new SingleJarModule(),
            new AutorunsModule(),
            new ScheduledTasksModule(),
            new ServicesModule(),
            new HostsFileModule(),
            new InstalledSoftwareModule());

    private ScanModules() {
    }

    public static List<ScanModule> all() {
        return ALL;
    }

    /** @throws IllegalArgumentException se l'id non è autorizzato (allowlist {@code ModuleId}). */
    public static ScanModule byId(String id) {
        if (!ModuleId.isAllowed(id)) {
            throw new IllegalArgumentException("modulo non autorizzato: " + id);
        }
        for (ScanModule m : ALL) {
            if (m.id().equals(id)) {
                return m;
            }
        }
        throw new IllegalStateException("modulo autorizzato ma non implementato: " + id);
    }
}
