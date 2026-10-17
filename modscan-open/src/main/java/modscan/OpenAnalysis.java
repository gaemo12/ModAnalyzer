package modscan;

import com.jaranalyzer.common.Finding;
import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.common.ModuleResult;
import com.jaranalyzer.scanners.ProgressSink;
import com.jaranalyzer.scanners.ScanContext;
import com.jaranalyzer.scanners.SignatureSet;
import com.jaranalyzer.scanners.SignatureSets;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Analisi completa di un file .jar per la UI di ModScanOpen: usa lo stesso motore della CLI
 * (modulo {@code single_jar}) e costruisce il JSON nello stesso formato della vecchia
 * interfaccia (metadata, modInfo, riskScore/riskLevel). Nessun controllo online: Modrinth e
 * VirusTotal non esistono qui, la modInfo è ricavata dalla struttura del jar (fabric.mod.json,
 * mods.toml, mcmod.info).
 */
final class OpenAnalysis {

    private OpenAnalysis() {
    }

    static OpenApi.Response analyzeLocal(String path) {
        if (path == null || path.isBlank()) {
            return bad("Percorso del file mancante.");
        }
        File file = new File(path);
        if (!file.exists() || !file.isFile()) {
            return bad("Il file specificato non esiste o non è accessibile.");
        }
        if (!path.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            return bad("Solo i file .jar sono accettati.");
        }
        long len = file.length();
        if (len <= 0) {
            return bad("Il file è vuoto.");
        }
        if (len > OpenApi.MAX_LOCAL_JAR_BYTES) {
            return bad("Il file è troppo grande (" + DragValidator.fmtBytes(len) + "). Massimo 512 MB.");
        }
        long t0 = System.currentTimeMillis();
        try {
            JarStats stats = jarStats(file.toPath());

            /* Set firme vuoto: le firme riservate allo Staff (scanner-data-staff) non entrano
               nell'edizione open. Le regole operative (bytecode, rete, offuscamento, entropy,
               API sospette, structure) funzionano con il set vuoto: nessun confronto con firme note. */
            SignatureSet sigs = SignatureSets.empty();
            ModuleResult mr = ModScanOpen.scanModule("single_jar", new ScanContext.JarFileContext(file.toPath()), sigs, ProgressSink.noop());

            List<Map<String, Object>> findings = new ArrayList<>();
            if (mr.findings() != null) {
                for (Finding f : mr.findings()) {
                    if (f != null) {
                        findings.add(f.toMap());
                    }
                }
            }
            Map<String, Object> modInfo = modInfo(findings, stats, file.toPath());
            // Mod con release ufficiale verificata: gli euristici (cheat/offuscamento)
            // scendono di un livello, perché Mixin/ASM/reflection sono normali nelle
            // mod legittime (Fase 4). Le evidenze forti (rete, firme) restano intatte.
            int downgraded = 0;
            if ("VERIFIED".equals(modInfo.get("modrinthStatus"))) {
                downgraded = downgradeHeuristics(findings);
            }
            int riskScore = riskScore(findings);
            String riskLevel = riskLevel(riskScore, findings);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("kind", "jar");
            out.put("success", mr.success());
            out.put("riskScore", riskScore);
            out.put("riskLevel", riskLevel);
            out.put("verifiedDowngrade", downgraded);
            out.put("analysisTimeMs", System.currentTimeMillis() - t0);
            out.put("timestamp", java.time.Instant.now().toString());
            out.put("metadata", stats.meta);
            out.put("modInfo", modInfo);
            out.put("findings", findings);
            if (!mr.success() && mr.error() != null) {
                out.put("error", mr.error());
                return new OpenApi.Response(200, JsonCodec.write(out));
            }
            return new OpenApi.Response(200, JsonCodec.write(out));
        } catch (Exception e) {
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return new OpenApi.Response(500, JsonCodec.write(Map.of(
                    "error", "Internal Server Error", "message", "Analisi locale fallita: " + m)));
        }
    }

    private static OpenApi.Response bad(String message) {
        return new OpenApi.Response(400, JsonCodec.write(Map.of("error", "Bad Request", "message", message)));
    }

    /* ---------- punteggio di rischio (identico alla vecchia AnalysisService) ---------- */

    /** Categorie euristiche: indizi comportamentali, non prove (Fase 4). */
    private static final Set<String> HEURISTIC_CATEGORIES = Set.of(
            "CHEAT", "EXECUTION", "OBFUSCATION", "MALWARE_BEHAVIOR");

    /**
     * Declassa di un livello i finding euristici (mai sotto LOW, mai INFO):
     * una mod VERIFIED su Modrinth/Megabase con Mixin o reflection resta
     * normale. Ritorna il numero di finding declassati; aggiunge nota
     * all'evidence per trasparenza. Opera in place sulla lista.
     */
    static int downgradeHeuristics(List<Map<String, Object>> findings) {
        int n = 0;
        for (Map<String, Object> f : findings) {
            String sev = String.valueOf(f.get("severity")).toUpperCase(Locale.ROOT);
            String cat = String.valueOf(f.get("category")).toUpperCase(Locale.ROOT);
            if (!HEURISTIC_CATEGORIES.contains(cat)) {
                continue;
            }
            String next = switch (sev) {
                case "CRITICAL" -> "HIGH";
                case "HIGH" -> "MEDIUM";
                case "MEDIUM" -> "LOW";
                default -> null;
            };
            if (next == null) {
                continue;
            }
            f.put("severity", next);
            Object ev = f.get("evidence");
            f.put("evidence", (ev == null ? "" : String.valueOf(ev) + "\n")
                    + "(Declassato di un livello: mod VERIFIED su database pubblico.)");
            n++;
        }
        return n;
    }

    static int riskScore(List<Map<String, Object>> findings) {
        Set<String> seen = new HashSet<>();
        // Peso evidenza per categoria (Fase 5): firme/rete valgono più di
        // euristici e metadati strutturali a parità di severity.
        // P0-1 (rev. ott-2026): la chiave include categoria e titolo, perché
        // quasi tutti i finding storici hanno rule="unspecified" e con la sola
        // coppia rule|severity tre HIGH diversi contavano come uno solo.
        int base = 0;
        int bonus = 0;
        for (Map<String, Object> f : findings) {
            String rule = String.valueOf(f.get("rule"));
            String sev = String.valueOf(f.get("severity")).toUpperCase(Locale.ROOT);
            String cat = String.valueOf(f.getOrDefault("category", "")).toUpperCase(Locale.ROOT);
            String title = String.valueOf(f.getOrDefault("title", ""));
            if (!seen.add(rule + "|" + cat + "|" + sev + "|" + title)) {
                continue;
            }
            int w = categoryWeight(cat);
            switch (sev) {
                case "CRITICAL": base = Math.max(base, 65); bonus += 8 * w; break;
                case "HIGH": base = Math.max(base, 45); bonus += 5 * w; break;
                case "MEDIUM": base = Math.max(base, 25); bonus += 3 * w; break;
                case "LOW": base = Math.max(base, 5); bonus += 1 * w; break;
                default: break;
            }
        }
        return Math.min(base + bonus, 100);
    }

    /** Moltiplicatore evidenza per categoria: 3 = prova forte, 1 = indizio/contesto. */
    static int categoryWeight(String category) {
        return switch (category) {
            case "MALWARE_SIGNATURE", "NETWORK" -> 3;
            case "EXECUTION", "CHEAT", "MALWARE_BEHAVIOR", "CODE_INJECTION", "CRYPTO",
                    "SUSPICIOUS_API", "FILE_ACCESS" -> 2;
            default -> 1;
        };
    }

    static String riskLevel(int score) {
        return riskLevel(score, null);
    }

    /**
     * Livello di rischio dal punteggio, con un tetto di buon senso: il verdetto
     * non può superare il peso della prova più forte presente. Senza finding
     * CRITICAL non si dice "CRITICO" (molti indizi sommati non equivalgono a
     * un'evidenza grave); senza HIGH non si va oltre MEDIO. Evita i "CRITICO
     * 100" con zero prove forti, che rendono il report poco credibile.
     */
    static String riskLevel(int score, List<Map<String, Object>> findings) {
        String level = riskLevelByScore(score);
        if (findings != null) {
            boolean hasCritical = false;
            boolean hasHigh = false;
            for (Map<String, Object> f : findings) {
                String sev = String.valueOf(f.get("severity")).toUpperCase(Locale.ROOT);
                if ("CRITICAL".equals(sev)) {
                    hasCritical = true;
                } else if ("HIGH".equals(sev)) {
                    hasHigh = true;
                }
            }
            if (!hasCritical && "CRITICAL".equals(level)) {
                level = "HIGH";
            }
            if (!hasCritical && !hasHigh && "HIGH".equals(level)) {
                level = "MEDIUM";
            }
        }
        return level;
    }

    private static String riskLevelByScore(int score) {
        if (score <= 10) return "SAFE";
        if (score <= 30) return "LOW";
        if (score <= 50) return "MEDIUM";
        if (score <= 75) return "HIGH";
        return "CRITICAL";
    }

    /* ---------- metadata e modInfo ---------- */

    /** Statistiche del jar (classi, entries, pacchetti, sha256) + flag struttura mod. */
    record JarStats(Map<String, Object> meta, Map<String, Object> modInfo, boolean minecraftMod) {
    }

    static JarStats jarStats(Path path) throws IOException {
        Map<String, Object> meta = new LinkedHashMap<>();
        Map<String, Object> modInfo = new LinkedHashMap<>();
        String fileName = path.getFileName() == null ? String.valueOf(path) : path.getFileName().toString();
        long size;
        try {
            size = Files.size(path);
        } catch (IOException e) {
            size = 0;
        }
        meta.put("fileName", fileName);
        meta.put("fileSize", size);
        String sha = "#";
        try {
            sha = sha256(path);
        } catch (Exception e) {
            // hash non calcolabile: la UI mostra "hash non disponibile"
        }
        meta.put("sha256", sha);

        int totalEntries = 0, totalClasses = 0, totalResources = 0;
        Set<String> packages = new HashSet<>();
        boolean fabric = false, forgeModern = false, forgeLegacy = false;
        String fabricText = null;
        String tomlText = null;
        String mcmodText = null;

        try (JarFile jar = new JarFile(path.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                totalEntries++;
                String name = entry.getName();
                if (name.endsWith(".class")) {
                    totalClasses++;
                    int slash = name.lastIndexOf('/');
                    packages.add(slash > 0 ? name.substring(0, slash).replace('/', '.') : "(default)");
                    continue;
                }
                totalResources++;
                if ("fabric.mod.json".equals(name) && fabricText == null) {
                    fabric = true;
                    fabricText = readAtMost(jar.getInputStream(entry), 65536);
                } else if (name.endsWith("mods.toml") && tomlText == null) {
                    tomlText = readAtMost(jar.getInputStream(entry), 65536);
                    if (name.startsWith("META-INF")) {
                        forgeModern = true;
                    }
                } else if ("mcmod.info".equals(name) && mcmodText == null) {
                    mcmodText = readAtMost(jar.getInputStream(entry), 65536);
                    forgeLegacy = true;
                }
            }
        }

        boolean mc = fabric || forgeModern || forgeLegacy;
        String platform = fabric ? "Fabric" : (forgeModern ? "Forge (Modern)" : (forgeLegacy ? "Forge (Legacy)" : null));
        modInfo.put("minecraftMod", mc);
        modInfo.put("modrinthStatus", "NOT_CHECKED");
        if (mc) {
            modInfo.put("platform", platform);
            if (fabricText != null) {
                String id = jsonValue(fabricText, "id");
                String ver = jsonValue(fabricText, "version");
                if (id != null) modInfo.put("modId", id);
                if (ver != null) modInfo.put("modVersion", ver);
                String mcv = jsonNested(fabricText, "minecraft");
                if (mcv != null) modInfo.put("mcVersion", mcv);
            } else if (tomlText != null) {
                String dn = tomlValue(tomlText, "displayName");
                String ver = tomlValue(tomlText, "version");
                if (ver != null) modInfo.put("modVersion", ver);
                // modId come fallback del nome
                if (dn != null && dn.length() <= 60) modInfo.put("modId", dn);
            }
        }
        meta.put("classCount", totalClasses);
        meta.put("totalEntries", totalEntries);
        meta.put("resourceCount", totalResources);
        meta.put("packages", new ArrayList<>(packages));
        return new JarStats(meta, modInfo, mc);
    }

    private static String readAtMost(InputStream in, int max) {
        ByteArrayOutputStreamLike buf = new ByteArrayOutputStreamLike();
        byte[] b = new byte[8192];
        int n;
        try {
            while ((n = in.read(b)) != -1 && buf.size() < max) {
                buf.write(b, 0, Math.min(n, max - buf.size()));
            }
            in.close();
        } catch (IOException e) {
            // lettura parziale: si usa quello letto
        }
        return new String(buf.bytes(), 0, buf.size(), StandardCharsets.UTF_8);
    }

    /** Piccolo buffer di byte (evito di tirare dentro altri tipi). */
    private static final class ByteArrayOutputStreamLike {
        private byte[] data = new byte[8192];
        private int len;

        void write(byte[] b, int off, int n) {
            if (len + n > data.length) {
                byte[] bigger = new byte[Math.max(data.length * 2, len + n)];
                System.arraycopy(data, 0, bigger, 0, len);
                data = bigger;
            }
            System.arraycopy(b, off, data, len, n);
            len += n;
        }

        int size() {
            return len;
        }

        byte[] bytes() {
            return data;
        }
    }

    /* Valori minimi da JSON non strutturato (solo per etichettare la mod). */
    static String jsonValue(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]{1,120})\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    static String jsonNested(String json, String section) {
        int i = json.indexOf("\"" + section + "\"");
        if (i < 0) {
            return null;
        }
        Matcher m = Pattern.compile("\"minecraft\"\\s*:\\s*\"([^\"]{1,40})\"").matcher(json.substring(i, Math.min(json.length(), i + 800)));
        return m.find() ? m.group(1) : null;
    }

    static String tomlValue(String toml, String key) {
        Matcher m = Pattern.compile(key + "\\s*=\\s*\"([^\"]{1,120})\"").matcher(toml);
        return m.find() ? m.group(1) : null;
    }

    static String sha1(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = is.read(buffer)) != -1) {
                digest.update(buffer, 0, n);
            }
        }
        StringBuilder hex = new StringBuilder(40);
        for (byte b : digest.digest()) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = is.read(buffer)) != -1) {
                digest.update(buffer, 0, n);
            }
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /* Riepilogo modInfo arricchito col testo dell'evidenza del motore, se presente. */
    static Map<String, Object> modInfo(List<Map<String, Object>> findings, JarStats stats, Path jarPath) {
        Map<String, Object> mi = new LinkedHashMap<>(stats.modInfo());
        if (!stats.minecraftMod()) {
            return mi;
        }
        /* Verifica online (richiesta esplicitamente): Modrinth per prima, Megabase di riserva. */
        try {
            OpenModVerify.ModHit hit = OpenModVerify.verify(sha1(jarPath));
            if (hit != null) {
                mi.put("modrinthStatus", "VERIFIED");
                if (hit.projectId() != null) {
                    mi.put("modrinthProjectId", hit.projectId());
                    mi.put("modrinthProjectUrl", "https://modrinth.com/project/" + hit.projectId());
                }
                if (hit.version() != null) {
                    mi.put("modrinthVersion", hit.version());
                }
            } else {
                mi.put("modrinthStatus", "NOT_FOUND");
            }
        } catch (Exception e) {
            mi.put("modrinthStatus", "ERROR");
        }
        for (Map<String, Object> f : findings) {
            String ev = f.get("evidence") == null ? "" : String.valueOf(f.get("evidence"));
            String title = f.get("title") == null ? "" : String.valueOf(f.get("title"));
            if (!ev.isBlank() && (title.contains("Fabric") || title.contains("Forge"))) {
                for (String line : ev.split("\n")) {
                    String[] p = line.split(":\\s*", 2);
                    if (p.length != 2) continue;
                    String key = p[0].trim(), v = p[1].trim();
                    switch (key) {
                        case "Mod ID" -> mi.putIfAbsent("modId", v);
                        case "Version" -> mi.putIfAbsent("modVersion", v);
                        case "Minecraft" -> mi.putIfAbsent("mcVersion", v);
                        default -> { }
                    }
                }
            }
        }
        return mi;
    }
}
