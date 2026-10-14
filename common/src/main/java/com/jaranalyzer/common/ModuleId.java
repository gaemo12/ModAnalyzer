package com.jaranalyzer.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Identificatori dei moduli di scansione. Unica allowlist condivisa da Staff,
 * Player e backend (BACKEND/index.js MODULES, stesso ordine e contenuto).
 * Versionata con {@link Protocol#ALLOWLIST_VERSION}.
 */
public final class ModuleId {
    public static final String MODS_FOLDER = "mods_folder";
    public static final String PROCESSES = "processes";
    public static final String JAVAW = "javaw";
    public static final String MINECRAFT_ACCOUNTS = "minecraft_accounts";
    public static final String SINGLE_JAR = "single_jar";
    /** Scan completa (stile anticheat): eseguiti localmente e da remota. */
    public static final String AUTORUNS = "autoruns";
    public static final String SCHEDULED_TASKS = "scheduled_tasks";
    public static final String SERVICES = "services";
    public static final String HOSTS_FILE = "hosts_file";
    public static final String SOFTWARE_INSTALLED = "software_installed";

    /** Allowlist completa, non modificabile. */
    public static final List<String> ALLOWED = List.of(
            MODS_FOLDER, PROCESSES, JAVAW, MINECRAFT_ACCOUNTS, SINGLE_JAR,
            AUTORUNS, SCHEDULED_TASKS, SERVICES, HOSTS_FILE, SOFTWARE_INSTALLED);

    private ModuleId() {
    }

    public static boolean isAllowed(String id) {
        return id != null && ALLOWED.contains(id);
    }

    /**
     * Valida una lista di moduli (richiesta staff o job ricevuto): non nulla,
     * non vuota, solo identificatori noti. Deduplica preservando l'ordine,
     * come il server ([...new Set(modules)]).
     */
    public static List<String> requireAllowedList(Collection<String> ids) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("lista moduli assente o vuota");
        }
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String id : ids) {
            if (!isAllowed(id)) {
                throw new IllegalArgumentException("modulo non consentito: " + id);
            }
            out.add(id);
        }
        return List.copyOf(out);
    }

    /** Variante tollerante per mappe ricevute (es. risultati): scarta chiavi ignote. */
    public static List<String> knownModules(Collection<String> ids) {
        List<String> out = new ArrayList<>();
        if (ids != null) {
            for (String id : ids) {
                if (isAllowed(id) && !out.contains(id)) {
                    out.add(id);
                }
            }
        }
        return List.copyOf(out);
    }
}
