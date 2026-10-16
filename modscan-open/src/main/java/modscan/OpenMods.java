package modscan;

import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.scanners.engine.MinecraftPathResolver;
import com.jaranalyzer.scanners.engine.ProcessInventory;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Versione open source delle rotte mods della vecchia interfaccia, completamente offline:
 * <ul>
 *   <li>{@link #folder(String)} elenca i .jar di una cartella con hash SHA-256, metadati
 *       (fabric.mod.json / mods.toml / mcmod.info) e flag di cheat noti ispezionando le voci dell'archivio.
 *       Nella vecchia app lo stato "VERIFIED" arrivava da Modrinth o dalla reputazione delle hash
 *       del backend: qui non dichiaro mai una mod come verificata, solo "SUSPICIOUS"
 *       o "UNVERIFIED".</li>
 *   <li>{@link #locate()} riproduce la ricerca della cartella mods tra i processi javaw attivi
 *       (stesso motore {@link MinecraftPathResolver} della vecchia app).</li>
 * </ul>
 */
final class OpenMods {

    /** Come la vecchia app (e il Player): oltre questa soglia la scansione è rifiutata esplicitamente. */
    static final int MAX_MOD_FILES = 5_000;

    /* Marker classici di client/cheat: si cercano nei Percorsi delle voci di ogni jar. Lista locale, nessuna rete.
     * NOTA ATTRIBUZIONE (rev. ott-2026): questa lista coincide in larga parte con gli indicatori dello
     * script "Meow Mod Analyzer" (MeowTonynoh). Se deriva da lì, verificare compatibilità di licenza
     * e aggiungere credito esplicito prima di estenderla. */
    private static final String[] QUICK_FLAG_PREFIXES = {
            "aimassist", "anchortweaks", "autoanchor", "autocrystal", "autodoublehand", "autohitcrystal",
            "autopot", "autototem", "autoarmor", "inventorytotem", "legittotem", "pingspoof", "selfdestruct",
            "shieldbreaker", "triggerbot", "axespam", "webmacro", "fastplace", "walskyoptimizer",
            "walksyoptimizer", "walksycrystaloptimizermod", "donut", "replacemod", "shielddisabler",
            "silentaim", "totemhit", "wtap", "fakelag", "blockesp", "dev/krypton", "skid/krypton",
            "antimissclick", "lagreach", "popswitch", "sprintreset", "cheststeal", "antibot", "elytraswap",
            "fastxp", "fastexp", "refill", "airanchor", "jnativehook", "fakeinv", "hovertotem",
            "autoclicker", "autofirework", "packspoof", "antiknockback", "catlean", "authbypass",
            "asteria", "prestige", "autoeat", "automine", "maceswap", "macro198", "stunslam", "safeanchor",
            "doubleanchor", "autotpa", "basefinder", "xenon", "gypsy", "autopotrefill", "keypearl",
            "autonethpot", "autodtap", "autoweb", "anchoraction", "org/chainlibs/module", "imgui.gl3",
            "imgui.glfw", "bowaim", "criticals", "fakenick", "fakeitem", "invsee", "itemexploit", "hellion",
            "licensecheckmixin", "clientplayerinteractionmanageraccessor", "clientplayerentitymixim",
            "dev.gambleclient", "obfuscatedauth", "phantom-refmap.json", "xyz.greaj", "meteordevelopment",
            "wurstclient", "wurst-imperium", "minecraft/client/impact", "aristois", "futureclient", "konas",
            "rusherhack", "inertia", "exhibition", "novoline", "novoclient", "doomsdayclient", "vapeclient",
            "vape/", "intentclient", "riseclient", "dev/lvstrng/argon", "asteriaclient", "prestigeclient",
            "gypsyclient", "xenonclient", "catleanclient", "grimclient", "liquidbounce", "cc/ccbluex",
            "net/ccbluex", "me/zeroeightsix/kami", "today/opai", "wtf/moonlight", "club/maxstats",
            "com/cheatbreaker", "com/moonsworth"
    };

    private static final Pattern FABRIC_NAME = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]{1,120})\"");
    private static final Pattern FABRIC_AUTHOR = Pattern.compile("\"authors\"\\s*:\\s*\\[\"([^\"]{1,80})\"");
    private static final Pattern TOML_DISPLAY = Pattern.compile("displayName\\s*=\\s*\"([^\"]{1,120})\"");
    private static final Pattern TOML_AUTHOR = Pattern.compile("authors\\s*=\\s*\"([^\"]{1,80})\"");
    private static final Pattern MCMOD_NAME = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]{1,120})\"");

    private OpenMods() {
    }

    /* ------------------------------------------------------------ GET /api/mods/folder */

    static OpenApi.Response folder(String path) {
        File folder = path == null ? null : new File(path);
        if (folder == null || !folder.exists() || !folder.isDirectory()) {
            return new OpenApi.Response(400, JsonCodec.write(Map.of(
                    "error", "Bad Request", "message", "La cartella specificata non esiste o non è accessibile.")));
        }
        try {
            List<Map<String, Object>> mods = scanFolder(folder);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("path", folder.getAbsolutePath().replace("\\", "/"));
            out.put("count", mods.size());
            out.put("mods", mods);
            return new OpenApi.Response(200, JsonCodec.write(out));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new OpenApi.Response(500, JsonCodec.write(Map.of(
                    "error", "Internal Server Error", "message", "Scansione cartella fallita: " + m)));
        }
    }

    /** Analisi rapida di ogni .jar della cartella: struttura, hash, autore dichiarato, flag cheat. */
    static List<Map<String, Object>> scanFolder(File folder) {
        List<Map<String, Object>> results = new ArrayList<>();
        File[] listed = folder.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (listed == null) {
            return results;
        }
        Arrays.sort(listed, Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));
        List<File> files = new ArrayList<>();
        for (File f : listed) {
            if (f.isFile()) {
                files.add(f);
            }
        }
        if (files.size() > MAX_MOD_FILES) {
            throw new IllegalArgumentException("Troppi file .jar nella cartella (" + files.size() + "): massimo " + MAX_MOD_FILES + ".");
        }
        for (File f : files) {
            results.add(inspect(f));
        }
        verifyAgainstDatabases(results);
        return results;
    }

    /**
     * Verifica online (richiesta esplicitamente): Modrinth (batch POST) per tutti gli hash,
     * Megabase come riserva per ciò che Modrinth non conosce. Una mod trovata in uno dei due
     * diventa VERIFIED; errori di rete → nota esplicita, mai esiti inventati.
     */
    private static void verifyAgainstDatabases(List<Map<String, Object>> results) {
        List<Map<String, Object>> pending = new ArrayList<>();
        List<String> hashes = new ArrayList<>();
        for (Map<String, Object> m : results) {
            String sha1 = sha1Of(m);
            if (sha1 != null) {
                pending.add(m);
                hashes.add(sha1);
            }
        }
        if (pending.isEmpty()) {
            return;
        }
        Map<String, OpenModVerify.ModHit> found;
        try {
            found = OpenModVerify.modrinthBatch(hashes);
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            for (Map<String, Object> m : pending) {
                if (m.get("verificationNote") == null) {
                    m.put("verificationNote", "Verifica online non disponibile (" + msg + ")");
                }
            }
            return;
        }
        for (Map<String, Object> m : pending) {
            String sha1 = sha1Of(m);
            OpenModVerify.ModHit hit = found.get(sha1);
            if (hit == null) {
                hit = OpenModVerify.verify(sha1); // Megabase di riserva
            }
            if (hit != null) {
                m.put("status", "VERIFIED");
                m.put("verifiedBy", hit.source());
                if (hit.name() != null) {
                    m.put("modName", hit.name());
                }
                if (hit.slug() != null) {
                    m.put("projectSlug", hit.slug());
                }
                if (hit.projectId() != null) {
                    m.put("modrinthProjectId", hit.projectId());
                    m.put("modrinthProjectUrl", "https://modrinth.com/project/" + hit.projectId());
                }
                if (hit.version() != null) {
                    m.put("modrinthVersion", hit.version());
                }
                m.put("verificationNote", "Rilascio ufficiale trovato su " + hit.source()
                        + (hit.version() != null ? " (v" + hit.version() + ")" : ""));
            } else if (m.get("verificationNote") == null) {
                m.put("verificationNote", "Nessuna corrispondenza su Modrinth o Megabase (build custom o non pubblicata)");
            }
        }
    }

    /** SHA-1 dell'entry se già calcolato, altrimenti lo calcola ora (una sola volta per sessione). */
    private static String sha1Of(Map<String, Object> m) {
        Object v = m.get("sha1");
        if (v instanceof String s && !s.isBlank()) {
            return s;
        }
        return null;
    }

    /** Ispirata al vecchio ModsFolderService ma con solo controlli locali (nessun servizio esterno). */
    private static Map<String, Object> inspect(File f) {
        Map<String, Object> m = new LinkedHashMap<>();
        String name = f.getName();
        m.put("fileName", name);
        m.put("path", f.getAbsolutePath().replace("\\", "/"));
        m.put("fileSize", f.length());
        try {
            m.put("sha256", OpenAnalysis.sha256(f.toPath()));
        } catch (Exception e) {
            // hash non calcolabile: la UI mostra "hash non disponibile"
        }
        try {
            m.put("sha1", OpenAnalysis.sha1(f.toPath()));
        } catch (Exception e) {
            // SHA-1 non calcolabile: la verifica online salta questo file
        }

        String modName = null, author = null, fabric = null, toml = null, mcmod = null;
        boolean flagged = false;
        try (ZipFile zip = new ZipFile(f)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String ename = e.getName().toLowerCase(Locale.ROOT);
                for (String flag : QUICK_FLAG_PREFIXES) {
                    if (ename.contains(flag)) {
                        flagged = true;
                        break;
                    }
                }
                if ("fabric.mod.json".equals(e.getName()) && fabric == null) {
                    fabric = readAtMost(zip.getInputStream(e), 65536);
                } else if (e.getName().endsWith("mods.toml") && toml == null) {
                    toml = readAtMost(zip.getInputStream(e), 65536);
                } else if ("mcmod.info".equals(e.getName()) && mcmod == null) {
                    mcmod = readAtMost(zip.getInputStream(e), 65536);
                }
            }
        } catch (Exception e) {
            m.put("verificationNote", "File non leggibile come archivio JAR.");
            m.put("status", "SUSPICIOUS");
            return m;
        }

        if (fabric != null) {
            Matcher nm = FABRIC_NAME.matcher(fabric);
            if (nm.find()) modName = nm.group(1);
            Matcher au = FABRIC_AUTHOR.matcher(fabric);
            if (au.find()) author = au.group(1);
        } else if (toml != null) {
            Matcher nm = TOML_DISPLAY.matcher(toml);
            if (nm.find()) modName = nm.group(1);
            Matcher au = TOML_AUTHOR.matcher(toml);
            if (au.find()) author = au.group(1);
        } else if (mcmod != null) {
            Matcher nm = MCMOD_NAME.matcher(mcmod);
            if (nm.find()) modName = nm.group(1);
        }
        if (modName != null) {
            m.put("modName", modName);
        }
        if (author != null) {
            m.put("author", author);
        }

        if (flagged) {
            m.put("status", "SUSPICIOUS");
            m.put("verificationNote", "Contenuto di un client/cheat noto rilevato nell'archivio (controllo locale).");
        } else {
            m.put("status", "UNVERIFIED");
            m.put("verificationNote", "Non verificata: la versione open source non consulta rilasci online. Usa «Analizza» per il controllo completo.");
        }
        return m;
    }

    private static String readAtMost(InputStream in, int max) {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] b = new byte[8192];
        int n;
        try {
            while ((n = in.read(b)) != -1 && buf.size() < max) {
                buf.write(b, 0, Math.min(n, max - buf.size()));
            }
            in.close();
        } catch (IOException e) {
            // lettura parziale
        }
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    /* ------------------------------------------------------------ GET /api/mods/locate */

    /** jcmd.exe da PATH, JAVA_HOME o java.home (stessa ricerca della vecchia ProcessScannerService). */
    private static String findJcmd() {
        try {
            boolean isWin = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
            ProcessBuilder pb = new ProcessBuilder(isWin ? "where" : "which", "jcmd");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            if (p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0) {
                try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()))) {
                    String path = r.readLine();
                    if (path != null && !path.isBlank()) {
                        return path.trim();
                    }
                }
            }
        } catch (Exception ignored) {
            // non in PATH: si prova con java.home/JAVA_HOME
        }
        String javaHome = System.getProperty("java.home");
        if (javaHome != null) {
            for (java.nio.file.Path c : new java.nio.file.Path[]{
                    java.nio.file.Path.of(javaHome, "bin", "jcmd.exe"), java.nio.file.Path.of(javaHome, "bin", "jcmd"),
                    java.nio.file.Path.of(javaHome, "..", "bin", "jcmd.exe"), java.nio.file.Path.of(javaHome, "..", "bin", "jcmd")}) {
                if (Files.exists(c.normalize())) {
                    return c.normalize().toString();
                }
            }
        }
        String home = System.getenv("JAVA_HOME");
        if (home != null) {
            for (java.nio.file.Path c : new java.nio.file.Path[]{
                    java.nio.file.Path.of(home, "bin", "jcmd.exe"), java.nio.file.Path.of(home, "bin", "jcmd")}) {
                if (Files.exists(c)) {
                    return c.toString();
                }
            }
        }
        return null;
    }

    /**
     * user.dir (o user.home) della JVM di un altro processo via {@code jcmd <pid> VM.system_properties}.
     * Necessario per i launcher che non passano --gameDir (l'exe java dell'utente ha la command line
     * senza argomenti): la vecchia app usava lo stesso aggancio in ModsLocatorService.
     */
    private static Map<String, String> readJvmSystemProperties(String pid) {
        Map<String, String> out = new LinkedHashMap<>();
        if (pid == null || !pid.matches("\\d{1,10}")) {
            return out;
        }
        String jcmd = findJcmd();
        if (jcmd == null) {
            return out;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(jcmd, pid, "VM.system_properties");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder sb = new StringBuilder();
            try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
            if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
            java.util.Properties props = new java.util.Properties();
            props.load(new java.io.StringReader(sb.toString()));
            for (String key : props.stringPropertyNames()) {
                out.put(key, props.getProperty(key));
            }
        } catch (Exception e) {
            // processo non accessibile o jcmd fallito: mappa vuota, si passa oltre
        }
        return out;
    }

    static OpenApi.Response locate() {
        List<Map<String, Object>> processes = new ArrayList<>();
        Map<String, Object> best = null;
        int bestScore = -1;
        try {
            for (ProcessInventory.ProcInfo p : ProcessInventory.snapshot()) {
                if (!p.java() || !p.detailsAvailable()) {
                    continue;
                }
                boolean mcLike = p.minecraftLike();
                List<MinecraftPathResolver.Hint> hints = MinecraftPathResolver.resolve(p.commandLine(), null);
                if (!mcLike && hints.isEmpty()) {
                    continue;
                }
                /* Come la vecchia ModsLocatorService: senza un --gameDir con alta confidenza
                   la command line non basta (launcher come Modrinth/Prism non la espongono
                   su Windows), quindi si interroga la JVM del processo con jcmd e si ripete
                   la risoluzione partendo da user.dir. */
                if (hints.isEmpty() || hints.get(0).confidence < 90) {
                    String userDir = readJvmSystemProperties(String.valueOf(p.pid())).get("user.dir");
                    if (userDir != null && !userDir.isBlank()) {
                        List<MinecraftPathResolver.Hint> more = MinecraftPathResolver.resolve(null, userDir);
                        for (MinecraftPathResolver.Hint h : more) {
                            if (!hints.contains(h)) {
                                hints = new ArrayList<>(hints);
                                hints.add(h);
                            }
                        }
                    }
                }
                List<Map<String, Object>> candidates = new ArrayList<>();
                for (MinecraftPathResolver.Hint h : hints) {
                    String dir = MinecraftPathResolver.modsDirOf(h.gameDir);
                    addCandidate(candidates, dir, h.source);
                }
                Map<String, Object> proc = new LinkedHashMap<>();
                proc.put("pid", String.valueOf(p.pid()));
                proc.put("processName", p.executable() == null ? "java" : p.executable());
                proc.put("candidates", candidates);
                processes.add(proc);
                for (Map<String, Object> c : candidates) {
                    int score = candidateScore(c);
                    if (score > bestScore) {
                        bestScore = score;
                        best = new LinkedHashMap<>();
                        best.put("path", c.get("path"));
                        best.put("pid", proc.get("pid"));
                        best.put("processName", proc.get("processName"));
                        best.put("source", c.get("source"));
                        best.put("exists", c.get("exists"));
                        best.put("jarCount", c.get("jarCount"));
                    }
                }
            }
        } catch (Exception e) {
            // enumerazione fallita: best resta null, la UI propone la scelta manuale
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("processes", processes);
        out.put("best", best);
        return new OpenApi.Response(200, JsonCodec.write(out));
    }

    private static void addCandidate(List<Map<String, Object>> candidates, String dir, String source) {
        if (dir == null || dir.isBlank()) {
            return;
        }
        for (Map<String, Object> existing : candidates) {
            if (String.valueOf(existing.get("path")).equalsIgnoreCase(dir)) {
                return;
            }
        }
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("path", dir.replace("\\", "/"));
        c.put("source", source);
        File d = new File(dir);
        boolean exists = d.isDirectory();
        c.put("exists", exists);
        int jars = 0;
        if (exists) {
            File[] j = d.listFiles((x, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
            jars = j == null ? 0 : j.length;
        }
        c.put("jarCount", jars);
        candidates.add(c);
    }

    private static int candidateScore(Map<String, Object> c) {
        int score = (Integer) c.get("jarCount");
        if (Boolean.TRUE.equals(c.get("exists"))) {
            score += 1;
        }
        return score;
    }
}
