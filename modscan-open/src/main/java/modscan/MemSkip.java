package modscan;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Costruisce la "skip list" per il memory-dump (v1.2.0): le classi delle
 * <b>mod verificate</b> su Modrinth/Megabase, i loro jar annidati estratti da
 * Fabric in {@code .fabric/processedMods}, le <b>librerie del launcher</b>
 * ({@code meta/libraries}) e l'agent del launcher Modrinth ({@code theseus.jar})
 * non vengono né ri-trasformati né dumpati: sarebbe tempo sprecato e rumore.
 *
 * <p>Mappatura dei jar processati: Fabric estrae i JiJ in
 * {@code <nome-entry>-[hash].jar} (a volte con prefisso di coordinate maven);
 * il nome del file processato <i>termina</i> con il nome-base dell'entry
 * annidata nella mod verificata, quindi il confronto per suffisso basta.
 *
 * <p>Il file scritto per l'agent contiene righe {@code path:…} (percorso esatto)
 * e {@code prefix:…} (cartella): vedi MemAgent#loadSkip.
 */
final class MemSkip {

    /** Esito della costruzione: righe per l'agent + riepilogo per il report. */
    static final class Result {
        final List<String> lines = new ArrayList<>();
        final List<String> verifiedFiles = new ArrayList<>();
        final Set<String> verifiedNames = new TreeSet<>();
        int nestedMapped;
        int theseus;
        boolean libraries;

        Map<String, Object> summary() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verifiedMods", verifiedNames.size());
            m.put("verifiedFiles", verifiedFiles);
            m.put("nestedMapped", nestedMapped);
            m.put("libraries", libraries);
            m.put("theseus", theseus);
            m.put("entries", lines.size());
            return m;
        }
    }

    private MemSkip() {
    }

    /** Scansione + costruzione in un colpo (rete: la verifica resta quella di OpenMods). */
    static Result buildFor(File modsDir) {
        try {
            return build(modsDir, OpenMods.folderCached(modsDir));
        } catch (Exception e) {
            Result r = new Result();
            return r;
        }
    }

    /**
     * Righe di skip per le mod marcate {@code VERIFIED} nella scansione della
     * cartella. Mai errori, mai inventare: in caso di dubbio si salta nulla.
     */
    static Result build(File modsDir, List<Map<String, Object>> scan) {
        Result r = new Result();
        if (modsDir == null || scan == null) {
            return r;
        }
        Set<String> lines = new LinkedHashSet<>();
        Set<String> nestedBases = new LinkedHashSet<>();
        for (Map<String, Object> m : scan) {
            if (!"VERIFIED".equals(m.get("status"))) {
                continue;
            }
            Object p = m.get("path");
            Object f = m.get("fileName");
            if (p instanceof String s && !s.isBlank()) {
                lines.add("path:" + s);
                if (f instanceof String fn) {
                    r.verifiedFiles.add(fn);
                }
                String label = m.get("modName") instanceof String mn && !mn.isBlank()
                        ? mn + " (" + (f instanceof String fn2 ? fn2 : s) + ")"
                        : (f instanceof String fn3 ? fn3 : new File(s).getName());
                r.verifiedNames.add(label);
                collectNestedBases(Path.of(s), nestedBases, 0);
            }
        }
        // Jar annidati (JiJ) estratti da Fabric in processedMods.
        File pm = new File(modsDir.getParentFile() == null ? modsDir : modsDir.getParentFile(), ".fabric/processedMods");
        File[] pmFiles = pm.isDirectory() ? pm.listFiles(File::isFile) : null;
        if (pmFiles != null && !nestedBases.isEmpty()) {
            for (File f : pmFiles) {
                String name = f.getName().toLowerCase(Locale.ROOT);
                if (!name.endsWith(".jar")) {
                    continue;
                }
                String stem = name.substring(0, name.length() - 4);
                stem = stem.replaceFirst("-[0-9a-f]{16}$", "");
                for (String base : nestedBases) {
                    if (stem.endsWith(base)) {
                        lines.add("path:" + f.getAbsolutePath().replace('/', '\\'));
                        r.nestedMapped++;
                        break;
                    }
                }
            }
        }
        // Agent del launcher Modrinth (theseus.jar in una dir temporanea .tmp*).
        String tmp = System.getProperty("java.io.tmpdir", "");
        if (!tmp.isBlank()) {
            File[] tmpDirs = new File(tmp).listFiles(x -> x.isDirectory() && x.getName().startsWith(".tmp"));
            if (tmpDirs != null) {
                for (File d : tmpDirs) {
                    File th = new File(d, "theseus.jar");
                    if (th.isFile()) {
                        lines.add("path:" + th.getAbsolutePath().replace('/', '\\'));
                        r.theseus++;
                    }
                }
            }
        }
        // Librerie del launcher Modrinth: <ModrinthApp>/meta/libraries (installazioni locali).
        File app = parent(parent(parent(modsDir)));
        if (app != null) {
            File metaLibs = new File(new File(app, "meta"), "libraries");
            if (metaLibs.isDirectory()) {
                lines.add("prefix:" + metaLibs.getAbsolutePath().replace('/', '\\'));
                r.libraries = true;
            }
        }
        r.lines.addAll(lines);
        return r;
    }

    private static File parent(File f) {
        return f == null ? null : f.getParentFile();
    }

    /**
     * Raccoglie i nomi-base dei jar annidati ({@code META-INF/jars/*.jar}),
     * ricorsivamente e senza pretese: un jar illeggibile semplicemente non
     * contribuisce alla mappa.
     */
    static void collectNestedBases(Path jar, Set<String> bases, int depth) {
        if (depth > 2 || jar == null || !Files.isRegularFile(jar)) {
            return;
        }
        try (ZipFile z = new ZipFile(jar.toFile())) {
            var en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String name = e.getName();
                if (!name.startsWith("META-INF/jars/") || !name.endsWith(".jar")) {
                    continue;
                }
                String base = name.substring(name.lastIndexOf('/') + 1, name.length() - 4).toLowerCase(Locale.ROOT);
                if (!base.isBlank()) {
                    bases.add(base);
                }
                try (InputStream in = z.getInputStream(e)) {
                    byte[] bytes = readAtMost(in, 64 * 1024 * 1024);
                    collectNestedBases(bytes, bases, depth + 1);
                }
            }
        } catch (Exception ignored) {
            // jar non leggibile (mod rotta, formato strano): si salta
        }
    }

    private static void collectNestedBases(byte[] nestedJar, Set<String> bases, int depth) {
        if (depth > 2 || nestedJar == null || nestedJar.length == 0) {
            return;
        }
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(nestedJar), StandardCharsets.UTF_8)) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                String name = e.getName();
                if (!name.startsWith("META-INF/jars/") || !name.endsWith(".jar")) {
                    continue;
                }
                String base = name.substring(name.lastIndexOf('/') + 1, name.length() - 4).toLowerCase(Locale.ROOT);
                if (!base.isBlank()) {
                    bases.add(base);
                }
                collectNestedBases(readAtMost(z, 64 * 1024 * 1024), bases, depth + 1);
            }
        } catch (Exception ignored) {
            // contenuto non leggibile: si salta
        }
    }

    private static byte[] readAtMost(InputStream in, int max) {
        try {
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) != -1 && buf.size() < max) {
                buf.write(b, 0, n);
            }
            return buf.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }
}
