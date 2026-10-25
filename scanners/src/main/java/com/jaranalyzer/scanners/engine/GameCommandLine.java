package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Controllo della riga di comando del processo javaw del gioco (screening SS):
 * flag tipici dei "ghost client" e delle iniezioni a runtime
 * ({@code -javaagent}, {@code -Xbootclasspath}, {@code --tweakClass} non
 * standard, classpath fuori dai percorsi del launcher).
 *
 * <p>Anti-falsi-positivi: i valori di {@code --tweakClass} dei loader storici
 * (Forge, OptiFine, LiteLoader, ShadersMod) sono legittimi e non generano
 * finding; il classpath dei launcher noti (minecraft/libraries/versions,
 * theseus di Modrinth, Prism/MultiMC/ATLauncher, JavaFX) viene accettato.
 * Solo matching locale sulla stringa: niente processi spawnati, niente rete.
 */
public final class GameCommandLine {

    /** Segnalazione su un flag della riga di comando. */
    public record Flag(String flag, Severity severity, String title, String detail) {
    }

    /** Prefissi dei Tweaker storici considerati standard (case-insensitive). */
    private static final String[] STANDARD_TWEAKERS = {
            "net.minecraftforge.", "cpw.mods.", "optifine.", "net.optifine.",
            "com.mumfrey.liteloader.", "shadersmod.", "net.fabricmc.", "org.quiltmc."
    };

    /** Marcatori dei percorsi che i launcher mettono nel classpath. */
    private static final String[] LAUNCHER_CP_MARKERS = {
            "minecraft", "libraries", "versions", "theseus", ".tmp", "javafx",
            "prism", "multimc", "atlauncher", "technic", "badlion", "lunar",
            "feather", "java", "jbr", "fabric", "forge", "quilt", "mojang",
            "modrinth", "gradle", "maven"
    };

    private GameCommandLine() {
    }

    /** Analizza la riga di comando (percorsi utente già redatti dal chiamante). */
    public static List<Flag> check(String commandLine) {
        List<Flag> out = new ArrayList<>();
        if (commandLine == null || commandLine.isBlank()) {
            return out;
        }
        String cmd = commandLine;
        String lower = cmd.toLowerCase(Locale.ROOT);

        String agent = tokenOf(cmd, "-javaagent:");
        if (agent != null) {
            out.add(new Flag("-javaagent", Severity.HIGH, "Java Agent caricato all'avvio",
                    "La JVM del gioco parte con -javaagent: un jar esterno instrumenta il bytecode"
                            + " prima ancora che il gioco parta. I launcher standard non lo usano."
                            + " Agente: " + agent));
        }
        for (String boot : new String[] {"-xbootclasspath/a:", "-xbootclasspath/p:", "-xbootclasspath:"}) {
            String v = tokenOf(lower, boot);
            if (v != null) {
                out.add(new Flag("-Xbootclasspath", Severity.HIGH,
                        "Bootstrap classpath manomesso",
                        "Il processo usa " + boot.replace(':', ':')
                                + ": classi prime rispetto al runtime — tecnica classica di injection."));
                break;
            }
        }
        String sysLoader = tokenOf(lower, "-djava.system.class.loader=");
        if (sysLoader != null) {
            out.add(new Flag("-Djava.system.class.loader", Severity.HIGH,
                    "System class loader sostituito",
                    "Classloader custom impostato via proprietà JVM: tutto il codice del gioco"
                            + " passa da una classe esterna. Valore: " + sysLoader));
        }
        String tweak = tweakClassOf(cmd);
        if (tweak != null) {
            String tl = tweak.toLowerCase(Locale.ROOT);
            boolean standard = false;
            for (String p : STANDARD_TWEAKERS) {
                if (tl.startsWith(p)) {
                    standard = true;
                    break;
                }
            }
            if (!standard) {
                out.add(new Flag("--tweakClass", Severity.MEDIUM,
                        "TweakClass non standard",
                        "Il gioco parte con --tweakClass " + tweak
                                + ": i loader storici (Forge, OptiFine, LiteLoader) usano classi"
                                + " note; un valore sconosciuto è il tipico aggancio di un ghost client."));
            }
        }
        List<String> unknownCp = unknownClasspathEntries(cmd);
        if (!unknownCp.isEmpty()) {
            out.add(new Flag("-cp", Severity.MEDIUM, "Classpath fuori dai percorsi del launcher",
                    "Il classpath contiene voci che non appartengono ai launcher noti"
                            + " (potrebbero caricare classi esterne alla cartella mods):\n"
                            + String.join("\n", unknownCp)));
        }
        if (lower.contains("-agentlib:jdwp") || lower.contains("transport=dt_socket")) {
            out.add(new Flag("-agentlib:jdwp", Severity.MEDIUM, "Debug remoto attivo sulla JVM",
                    "JDWP/socket di debug aperti sul processo di gioco: può essere strumento"
                            + " di sviluppo ma anche via di iniezione/comando runtime."));
        }
        if (lower.contains("-xx:+disableattachmechanism")) {
            out.add(new Flag("-XX:+DisableAttachMechanism", Severity.MEDIUM,
                    "Attach API disabilitata (anti-analisi)",
                    "Il processo rifiuta l'Attach API: di solito serve agli strumenti di analisi,"
                            + " disattivarlo ostacola la verifica (comportamento anti-SS)."));
        }
        if (lower.contains("--mixin")) {
            out.add(new Flag("--mixin", Severity.LOW, "Configurazione Mixin esplicita",
                    "Il comando passa --mixin: legittimo in molti setup (bootstrap Mixin),"
                            + " vale come contesto per gli altri controlli."));
        }
        return out;
    }

    /** Valore del token subito dopo il prefisso (fino a spazio o quote). */
    private static String tokenOf(String cmd, String prefixLower) {
        String lower = cmd.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf(prefixLower);
        if (idx < 0) {
            return null;
        }
        int from = idx + prefixLower.length();
        int end = from;
        while (end < cmd.length() && cmd.charAt(end) != ' ' && cmd.charAt(end) != '"') {
            end++;
        }
        String v = cmd.substring(from, end).trim();
        return v.isEmpty() ? "(vuoto)" : v;
    }

    /** Valore di --tweakClass (o --tweakClass=…), null se assente. */
    static String tweakClassOf(String cmd) {
        String lower = cmd.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("--tweakclass");
        if (idx < 0) {
            return null;
        }
        int eq = cmd.indexOf('=', idx);
        if (eq >= 0 && eq < idx + 20) {
            int end = eq + 1;
            while (end < cmd.length() && cmd.charAt(end) != ' ' && cmd.charAt(end) != '"') {
                end++;
            }
            return cmd.substring(eq + 1, end).trim();
        }
        int from = idx + "--tweakclass".length();
        while (from < cmd.length() && Character.isWhitespace(cmd.charAt(from))) {
            from++;
        }
        int end = from;
        while (end < cmd.length() && cmd.charAt(end) != ' ' && cmd.charAt(end) != '"') {
            end++;
        }
        return cmd.substring(from, end).trim();
    }

    /** Voci del classpath (-cp/-classpath) fuori dai marcatori dei launcher noti. */
    static List<String> unknownClasspathEntries(String cmd) {
        String lower = cmd.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("-cp ");
        if (idx < 0) {
            idx = lower.indexOf("-classpath ");
        }
        if (idx < 0) {
            return List.of();
        }
        int from = idx + 4;
        while (from < cmd.length() && Character.isWhitespace(cmd.charAt(from))) {
            from++;
        }
        int end = from;
        while (end < cmd.length() && cmd.charAt(end) != ' ' && cmd.charAt(end) != '"') {
            end++;
        }
        String cp = cmd.substring(from, end);
        if (cp.isBlank()) {
            return List.of();
        }
        List<String> unknown = new ArrayList<>();
        for (String raw : cp.split(";")) {
            String entry = raw.trim().toLowerCase(Locale.ROOT).replace('\\', '/');
            if (entry.isEmpty()) {
                continue;
            }
            boolean known = false;
            for (String marker : LAUNCHER_CP_MARKERS) {
                if (entry.contains(marker)) {
                    known = true;
                    break;
                }
            }
            if (!known && unknown.size() < 6) {
                unknown.add(raw.trim());
            }
        }
        return unknown;
    }
}
