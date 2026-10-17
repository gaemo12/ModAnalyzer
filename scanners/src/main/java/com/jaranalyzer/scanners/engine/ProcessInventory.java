package com.jaranalyzer.scanners.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Istantanea dei processi via {@code ProcessHandle} (solo JDK, nessuna JNA,
 * nessun attach, nessuna lettura di memoria). Le informazioni mancanti
 * (processi protetti) restano vuote: mai eccezioni per singolo processo.
 */
public final class ProcessInventory {
    /** Indicatori euristici di istanze Minecraft/Java (logica, non firme). */
    static final String[] MINECRAFT_HINTS = {
            "minecraft", ".minecraft", "mojang", "tlauncher", "feather", "lunarclient",
            "prism", "multimc", "atlauncher", "modrinth", "fabric", "forge", "quilt",
            "neoforge", "gamedir", "assets/indexes", "skyclient", "badlion"
    };

    public record ProcInfo(long pid, String executable, String commandLine,
            boolean java, boolean minecraftLike, boolean detailsAvailable, long startEpochMillis) {
    }

    private ProcessInventory() {
    }

    /** Istantanea ordinata per pid; mai null, mai eccezioni per singolo processo. */
    public static List<ProcInfo> snapshot() {
        List<ProcInfo> out = new ArrayList<>();
        try {
            ProcessHandle.allProcesses().forEach(h -> {
                try {
                    out.add(describe(h));
                } catch (Exception e) {
                    // Processo sparito o inaccessibile: si salta, non si abortisce.
                }
            });
        } catch (Exception e) {
            throw new IllegalStateException("enumerazione processi fallita: " + e.getMessage(), e);
        }
        out.sort(Comparator.comparingLong(ProcInfo::pid));
        return List.copyOf(out);
    }

    static ProcInfo describe(ProcessHandle h) {
        long pid = h.pid();
        ProcessHandle.Info info = h.info();
        String command = info.command().orElse("");
        String cmdline = info.commandLine().orElse("");
        if (cmdline.isEmpty() && !command.isEmpty()) {
            String[] args = info.arguments().orElse(new String[0]);
            StringBuilder sb = new StringBuilder(command);
            for (String a : args) {
                sb.append(' ').append(a);
            }
            cmdline = sb.toString();
        }
        String exe = executableName(command);
        boolean java = isJava(exe, cmdline);
        boolean mc = isMinecraftLike(cmdline);
        long startMillis = 0L;
        try {
            startMillis = info.startInstant().map(i -> i.toEpochMilli()).orElse(0L);
        } catch (Exception ignored) {
            // processo protetto: start time non disponibile
        }
        return new ProcInfo(pid, exe, cmdline, java, mc, !cmdline.isEmpty(), startMillis);
    }

    public static String executableName(String command) {
        if (command == null) {
            return "";
        }
        String c = command.trim();
        if (c.length() >= 2 && c.startsWith("\"") && c.endsWith("\"")) {
            c = c.substring(1, c.length() - 1);
        }
        int cut = Math.max(c.lastIndexOf('/'), c.lastIndexOf('\\'));
        return cut >= 0 ? c.substring(cut + 1) : c;
    }

    public static boolean isJava(String executable, String cmdline) {
        String exe = executable.toLowerCase(Locale.ROOT);
        if (exe.equals("java") || exe.equals("javaw") || exe.equals("java.exe")
                || exe.equals("javaw.exe") || exe.startsWith("java_") || exe.startsWith("javaw_")) {
            return true;
        }
        String cl = cmdline.toLowerCase(Locale.ROOT);
        return cl.contains("java ") || cl.contains("javaw ") || cl.contains("java.exe")
                || cl.contains("javaw.exe") || cl.contains("-classpath") || cl.contains("-jar ");
    }

    public static boolean isMinecraftLike(String cmdline) {
        String cl = cmdline.toLowerCase(Locale.ROOT);
        for (String hint : MINECRAFT_HINTS) {
            if (cl.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}
