package com.jaranalyzer.scanners.engine;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Metadati mod offline (stessa logica del codice originale, senza rete e senza
 * Jackson): fabric.mod.json, quilt.mod.json, mods.toml/neoforge, MANIFEST.MF.
 * Solo parsing locale: nessuna verifica Modrinth qui (resta allo Staff).
 */
public final class ModMetadata {
    public record Info(String modName, String author, boolean knownAuthor, String source, String id) {
        public static Info empty() {
            return new Info(null, null, false, "unknown", null);
        }
    }

    private static final Pattern FABRIC_AUTHORS = Pattern.compile("\"authors\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL);
    private static final Pattern FABRIC_NAME = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern FABRIC_ID = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]{1,100})\"");
    private static final Pattern FABRIC_STRING = Pattern.compile("\"([^\"]+)\"");
    private static final Pattern TOML_AUTHORS = Pattern.compile("authors\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern TOML_DISPLAY_NAME = Pattern.compile("displayName\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern TOML_ID = Pattern.compile("modId\\s*=\\s*\"([^\"]{1,100})\"");

    private ModMetadata() {
    }

    /** Legge i metadati dal JAR; mai eccezioni per metadati assenti (Info.empty). */
    public static Info read(ZipFile zip) {
        try {
            ZipEntry fabric = zip.getEntry("fabric.mod.json");
            if (fabric != null) {
                Info info = fabricLike(text(zip, fabric), "fabric");
                if (info.knownAuthor() || info.modName() != null || info.id() != null) {
                    return info;
                }
            }
            ZipEntry quilt = zip.getEntry("quilt.mod.json");
            if (quilt != null) {
                Info info = fabricLike(text(zip, quilt), "quilt");
                if (info.knownAuthor() || info.modName() != null || info.id() != null) {
                    return info;
                }
            }
            for (String tomlPath : new String[] { "META-INF/mods.toml", "META-INF/neoforge.mods.toml" }) {
                ZipEntry toml = zip.getEntry(tomlPath);
                if (toml == null) {
                    continue;
                }
                Info info = forgeToml(text(zip, toml));
                if (info.knownAuthor() || info.id() != null) {
                    return info;
                }
            }
            ZipEntry manifest = zip.getEntry("META-INF/MANIFEST.MF");
            if (manifest != null) {
                Info info = manifest(text(zip, manifest));
                if (info.knownAuthor()) {
                    return info;
                }
            }
        } catch (Exception e) {
            // Metadati illeggibili: il chiamante registra l'errore per-file.
        }
        return Info.empty();
    }

    static Info fabricLike(String json, String source) {
        String modName = null;
        String id = null;
        Matcher name = FABRIC_NAME.matcher(json);
        if (name.find()) {
            modName = name.group(1).trim();
        }
        Matcher idMatcher = FABRIC_ID.matcher(json);
        if (idMatcher.find()) {
            id = idMatcher.group(1).trim();
        }
        Matcher block = FABRIC_AUTHORS.matcher(json);
        if (block.find()) {
            Matcher strings = FABRIC_STRING.matcher(block.group(1));
            List<String> names = new ArrayList<>();
            while (strings.find()) {
                String v = strings.group(1).trim();
                if (v.equalsIgnoreCase("name") || v.isBlank()) {
                    continue;
                }
                names.add(v);
            }
            if (!names.isEmpty()) {
                return new Info(modName, String.join(", ", names), true, source, id);
            }
        }
        return new Info(modName, null, false, source, id);
    }

    static Info forgeToml(String toml) {
        String author = null;
        String modName = null;
        String id = null;
        boolean known = false;
        Matcher am = TOML_AUTHORS.matcher(toml);
        if (am.find() && !am.group(1).isBlank()) {
            author = am.group(1).trim();
            known = true;
        }
        Matcher nm = TOML_DISPLAY_NAME.matcher(toml);
        if (nm.find()) {
            modName = nm.group(1).trim();
        }
        Matcher im = TOML_ID.matcher(toml);
        if (im.find()) {
            id = im.group(1).trim();
        }
        return new Info(modName, author, known, "forge", id);
    }

    static Info manifest(String content) {
        String vendor = field(content, "Implementation-Vendor");
        if (vendor == null) {
            vendor = field(content, "Specification-Vendor");
        }
        if (vendor != null && !vendor.isBlank()) {
            return new Info(null, vendor.trim(), true, "manifest", null);
        }
        return Info.empty();
    }

    private static String field(String content, String name) {
        Matcher m = Pattern.compile(Pattern.quote(name) + ":\\s*(.+)").matcher(content);
        return m.find() ? m.group(1).trim() : null;
    }

    private static String text(ZipFile zip, ZipEntry entry) throws Exception {
        return new String(ZipWalk.readMetadata(zip, entry), StandardCharsets.UTF_8);
    }
}
