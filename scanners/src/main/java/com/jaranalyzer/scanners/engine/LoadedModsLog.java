package com.jaranalyzer.scanners.engine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Confronto "mod caricate a runtime vs mod su disco" (screening SS): legge
 * {@code logs/latest.log} della partita (formati Fabric/Quilt e Forge), ricava
 * gli id (o i nomi file) delle mod effettivamente caricate dal loader e li
 * confronta con quelli dichiarati dai jar della cartella mods, jar annidati
 * (JiJ) inclusi.
 *
 * <p>Il segnale interessante per gli screenshare è la differenza in senso
 * "caricata ma non presente su disco": un client ghost iniettato via
 * -javaagent/tweakClass si presenta come pseudo-mod con un id che non ha
 * nessun jar nella cartella. Il senso inverso (jar mai caricato) è solo una
 * nota informativa: la mod può essere semplicemente disabilitata o fallita.
 *
 * <p>Solo lettura di file locali, mai contenuto personale: dal log si leggono
 * solo id/nomi di mod, mai messaggi utente. Il log di una sessione precedente
 * all'avvio del gioco corrente viene marcato {@code stale} (il chiamante
 * declassa i finding).
 */
public final class LoadedModsLog {

    /** Dimensione massima del log letta dall'inizio (la lista mod sta all'inizio). */
    private static final int LOG_CAP = 8 * 1024 * 1024;
    /** Budget totale per la lettura metadati dei jar annidati (come MemSkip). */
    private static final long NESTED_BUDGET = 128L * 1024 * 1024;
    private static final long NESTED_ENTRY_CAP = 16L * 1024 * 1024;
    private static final int NESTED_DEPTH = 3;

    /** Id caricati dal loader ma che non hanno base nell'ecosistema mod. */
    private static final Set<String> BUILTIN_IDS = Set.of(
            "minecraft", "java", "fabricloader", "fabric", "quilt_loader", "quilt_base");

    /** Fabric/Quilt: "[..]: Loading 87 mods: minecraft@1.20.1, …". */
    private static final Pattern FABRIC_LOADING =
            Pattern.compile("Loading\\s+\\d+\\s+mods[^\\n]*?:");
    /** Token id@version nella lista Fabric/Quilt. */
    private static final Pattern ID_VERSION = Pattern.compile("([A-Za-z][A-Za-z0-9_-]{0,63})@[A-Za-z0-9.+-]+");
    /** Forge 1.17+: "[..]: Found mod file nome.jar of type MOD …". */
    private static final Pattern FORGE_FILE = Pattern.compile("Found mod file (\\S+)");
    /** fabric.mod.json / quilt.mod.json: primo "id":"…". */
    private static final Pattern JSON_ID = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]{1,100})\"");
    /** mods.toml: modId="…". */
    private static final Pattern TOML_ID = Pattern.compile("modId\\s*=\\s*\"([^\"]{1,100})\"");

    /** Esito del confronto: dati neutri, le severità le assegna il chiamante. */
    public record Result(boolean logFound, String logFile, long logModifiedMillis, boolean stale,
            String format, int loadedCount, int diskCount,
            List<String> loadedNotOnDisk, List<String> onDiskNotLoaded,
            List<String> loadedFilesNotOnDisk, List<String> notes) {
    }

    private LoadedModsLog() {
    }

    /**
     * Confronta il log della partita con la cartella mods.
     *
     * @param gameDir cartella del gioco (contiene {@code logs/latest.log})
     * @param modsDir cartella mods (jar di primo livello)
     * @param gameStartMillis istante di avvio del processo di gioco
     *        (0 = sconosciuto: nessun controllo di freschezza)
     */
    public static Result diff(Path gameDir, Path modsDir, long gameStartMillis) throws IOException {
        List<String> notes = new ArrayList<>();
        Path log = gameDir == null ? null : gameDir.resolve("logs").resolve("latest.log");
        if (log == null || !Files.isRegularFile(log)) {
            return new Result(false, log == null ? "logs/latest.log" : log.getFileName().toString(),
                    0L, false, "none", 0, diskIds(modsDir, null, notes).size(),
                    List.of(), List.of(), List.of(), notes);
        }
        String text = readHead(log, LOG_CAP);
        long mtime;
        try {
            mtime = Files.getLastModifiedTime(log).toMillis();
        } catch (Exception e) {
            mtime = 0L;
        }
        boolean stale = gameStartMillis > 0 && mtime > 0 && mtime < gameStartMillis - 2_000L;
        if (stale) {
            notes.add("Il log è più vecchio dell'avvio del gioco: si riferisce alla sessione precedente.");
        }

        Set<String> loaded = new LinkedHashSet<>();
        Set<String> loadedFiles = new LinkedHashSet<>();
        String format = parseLog(text, loaded, loadedFiles);
        if (loaded.isEmpty() && loadedFiles.isEmpty()) {
            notes.add("Nessuna lista mod riconosciuta nel log (formato loader non noto o log vuoto).");
        }

        Set<String> disk = diskIds(modsDir, null, notes);
        Set<String> diskFiles = diskJarNames(modsDir);

        List<String> ghosts = new ArrayList<>();
        for (String id : loaded) {
            if (!BUILTIN_IDS.contains(id) && !disk.contains(id)) {
                ghosts.add(id);
            }
        }
        List<String> notLoaded = new ArrayList<>();
        for (String id : disk) {
            if (!BUILTIN_IDS.contains(id) && !loaded.contains(id) && !"unknown".equals(format)) {
                notLoaded.add(id);
            }
        }
        List<String> filesGhost = new ArrayList<>();
        for (String f : loadedFiles) {
            if (!diskFiles.contains(f)) {
                filesGhost.add(f);
            }
        }
        return new Result(true, log.getFileName().toString(), mtime, stale, format,
                loaded.size(), disk.size(), List.copyOf(ghosts), List.copyOf(notLoaded),
                List.copyOf(filesGhost), notes);
    }

    /** Estrae id (Fabric/Quilt) e nomi file (Forge) dal testo del log. */
    static String parseLog(String text, Set<String> loadedIds, Set<String> loadedFiles) {
        String format = "none";
        // Tutte le righe "Loading N mods…" (l'intestazione può stare su una riga
        // e la lista su quella dopo: si accumula da ogni match).
        Matcher fabricList = FABRIC_LOADING.matcher(text);
        while (fabricList.find()) {
            int nl = text.indexOf('\n', fabricList.end());
            String list = nl > fabricList.end() ? text.substring(fabricList.end(), nl) : "";
            Matcher id = ID_VERSION.matcher(list);
            while (id.find()) {
                loadedIds.add(id.group(1).toLowerCase(Locale.ROOT));
            }
        }
        if (!loadedIds.isEmpty()) {
            format = "fabric";
        }
        Matcher forgeFile = FORGE_FILE.matcher(text);
        while (forgeFile.find()) {
            String f = forgeFile.group(1);
            if (f.toLowerCase(Locale.ROOT).endsWith(".jar")) {
                loadedFiles.add(f.toLowerCase(Locale.ROOT));
                format = "fabric".equals(format) ? format : "forge";
            }
        }
        return format;
    }

    /** Id dichiarati dai jar della cartella (metadati + JiJ annidati, depth ≤ 3). */
    static Set<String> diskIds(Path modsDir, Set<String> jarNames, List<String> notes) {
        Set<String> ids = new LinkedHashSet<>();
        if (modsDir == null || !Files.isDirectory(modsDir)) {
            if (notes != null) {
                notes.add("Cartella mods non leggibile: confronto solo col log.");
            }
            return ids;
        }
        long[] budget = {NESTED_BUDGET};
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(modsDir)) {
            for (Path p : stream) {
                String name = p.getFileName() == null ? "" : p.getFileName().toString();
                if (!name.toLowerCase(Locale.ROOT).endsWith(".jar") || !Files.isRegularFile(p)) {
                    continue;
                }
                if (jarNames != null) {
                    jarNames.add(name.toLowerCase(Locale.ROOT));
                }
                collectIds(p, ids, 0, budget);
            }
        } catch (Exception e) {
            if (notes != null) {
                notes.add("Lettura cartella mods parziale: " + e.getMessage());
            }
        }
        return ids;
    }

    private static Set<String> diskJarNames(Path modsDir) {
        Set<String> names = new LinkedHashSet<>();
        if (modsDir == null || !Files.isDirectory(modsDir)) {
            return names;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(modsDir)) {
            for (Path p : stream) {
                String name = p.getFileName() == null ? "" : p.getFileName().toString();
                if (name.toLowerCase(Locale.ROOT).endsWith(".jar") && Files.isRegularFile(p)) {
                    names.add(name.toLowerCase(Locale.ROOT));
                }
            }
        } catch (Exception ignored) {
            // elenco parziale: il confronto file resta best-effort
        }
        return names;
    }

    /** Id dichiarati da un jar (fabric/quilt/toml) + ricorsione sui JiJ. */
    private static void collectIds(Path jar, Set<String> into, int depth, long[] budget) {
        if (depth >= NESTED_DEPTH) {
            return;
        }
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            for (String meta : new String[] {"fabric.mod.json", "quilt.mod.json"}) {
                ZipEntry e = zip.getEntry(meta);
                if (e != null) {
                    addId(readText(zip, e, 256 * 1024), JSON_ID, into);
                }
            }
            for (String meta : new String[] {"META-INF/mods.toml", "META-INF/neoforge.mods.toml"}) {
                ZipEntry e = zip.getEntry(meta);
                if (e != null) {
                    addId(readText(zip, e, 256 * 1024), TOML_ID, into);
                }
            }
            var en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String name = e.getName();
                if (!name.startsWith("META-INF/jars/") || !name.endsWith(".jar")) {
                    continue;
                }
                long size = e.getSize();
                if (size <= 0 || size > NESTED_ENTRY_CAP || budget[0] - size < 0) {
                    continue;
                }
                budget[0] -= size;
                try (InputStream in = zip.getInputStream(e)) {
                    byte[] bytes = readAtMost(in, (int) NESTED_ENTRY_CAP);
                    collectNestedIds(bytes, into, depth + 1, budget);
                }
            }
        } catch (Exception ignored) {
            // jar illeggibile: nessun id da questo file, si prosegue
        }
    }

    private static void collectNestedIds(byte[] nestedJar, Set<String> into, int depth, long[] budget) {
        if (depth >= NESTED_DEPTH || nestedJar.length == 0) {
            return;
        }
        try (var zip = new java.util.zip.ZipInputStream(
                new java.io.ByteArrayInputStream(nestedJar), StandardCharsets.UTF_8)) {
            ZipEntry e;
            while ((e = zip.getNextEntry()) != null) {
                String name = e.getName();
                if (name.equals("fabric.mod.json") || name.equals("quilt.mod.json")) {
                    addId(new String(readAtMost(zip, 256 * 1024), StandardCharsets.UTF_8), JSON_ID, into);
                } else if (name.endsWith("mods.toml")) {
                    addId(new String(readAtMost(zip, 256 * 1024), StandardCharsets.UTF_8), TOML_ID, into);
                } else if (name.startsWith("META-INF/jars/") && name.endsWith(".jar")) {
                    long size = e.getSize();
                    if (size > 0 && size <= NESTED_ENTRY_CAP && budget[0] - size >= 0) {
                        budget[0] -= size;
                        collectNestedIds(readAtMost(zip, (int) NESTED_ENTRY_CAP), into, depth + 1, budget);
                    }
                }
            }
        } catch (Exception ignored) {
            // annidato illeggibile: si salta
        }
    }

    private static void addId(String meta, Pattern pattern, Set<String> into) {
        if (meta == null || meta.isEmpty()) {
            return;
        }
        Matcher m = pattern.matcher(meta);
        if (m.find()) {
            String id = m.group(1).trim().toLowerCase(Locale.ROOT);
            if (!id.isBlank()) {
                into.add(id);
            }
        }
    }

    private static String readText(ZipFile zip, ZipEntry e, int cap) throws IOException {
        try (InputStream in = zip.getInputStream(e)) {
            return new String(readAtMost(in, cap), StandardCharsets.UTF_8);
        }
    }

    private static byte[] readAtMost(InputStream in, int max) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] b = new byte[8192];
        int n;
        while ((n = in.read(b)) != -1 && buf.size() < max) {
            buf.write(b, 0, Math.min(n, max - buf.size()));
        }
        return buf.toByteArray();
    }

    private static String readHead(Path file, int cap) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return new String(readAtMost(in, cap), StandardCharsets.UTF_8);
        }
    }
}
