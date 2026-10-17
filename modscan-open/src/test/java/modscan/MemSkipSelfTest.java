package modscan;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Self-test di MemSkip (v1.7.0, stile progetto: main(), zero dipendenze):
 * la skip-list del memory-dump deve contenere la mod verificata e il suo jar
 * annidato processato da Fabric, e NON deve contenere le mod non verificate
 * né i jar processati non collegati.
 * Uso: MemSkipSelfTest
 */
public class MemSkipSelfTest {
    static int fails = 0;

    static void check(String n, boolean ok) {
        System.out.println((ok ? "OK   " : "FAIL ") + n);
        if (!ok) {
            fails++;
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("memskip-test");
        /* Struttura tipica Modrinth: App/profiles/p/mods + .fabric/processedMods + App/meta/libraries */
        Path mods = root.resolve("App/profiles/p/mods");
        Path pm = root.resolve("App/profiles/p/.fabric/processedMods");
        Path metaLibs = root.resolve("App/meta/libraries");
        Files.createDirectories(mods);
        Files.createDirectories(pm);
        Files.createDirectories(metaLibs);

        /* Mod finta "verificata" con due jar annidati (META-INF/jars). */
        Path modJar = mods.resolve("fakemod-1.0.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(modJar), StandardCharsets.UTF_8)) {
            z.putNextEntry(new ZipEntry("fabric.mod.json"));
            z.write("{\"id\":\"fakemod\"}".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("META-INF/jars/foo-1.0.jar"));
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            try (ZipOutputStream zi = new ZipOutputStream(inner, StandardCharsets.UTF_8)) {
                zi.putNextEntry(new ZipEntry("foo/Main.class"));
                zi.write(new byte[] { 1, 2, 3, 4 });
                zi.closeEntry();
            }
            z.write(inner.toByteArray());
            z.closeEntry();
            z.putNextEntry(new ZipEntry("META-INF/jars/fabric-renderer-api-v1-5.0.3.jar"));
            z.write(new byte[] { 0 });
            z.closeEntry();
        }

        /* Copia processata di Fabric del jar annidato (nome = coordinate + base + hash)
           e un altro jar processato NON collegato alla mod verificata. */
        Path mapped = pm.resolve("org_test_foo-1.0-0123456789abcdef.jar");
        Files.write(mapped, new byte[] { 1 });
        Path unmapped = pm.resolve("anotherlib-2.0-fedcba9876543210.jar");
        Files.write(unmapped, new byte[] { 1 });

        List<Map<String, Object>> scan = new ArrayList<>();
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("status", "VERIFIED");
        v.put("path", modJar.toAbsolutePath().toString());
        v.put("fileName", "fakemod-1.0.jar");
        v.put("modName", "Fake Mod");
        scan.add(v);
        Map<String, Object> u = new LinkedHashMap<>();
        u.put("status", "UNVERIFIED");
        u.put("path", mods.resolve("other-2.0.jar").toAbsolutePath().toString());
        u.put("fileName", "other-2.0.jar");
        scan.add(u);

        MemSkip.Result r = MemSkip.build(mods.toFile(), scan);
        String joined = String.join("\n", r.lines).toLowerCase();
        check("mod verificata nella lista", r.lines.contains("path:" + modJar.toAbsolutePath()));
        check("jar annidato processato mappato", r.lines.contains("path:" + mapped.toAbsolutePath()));
        check("jar processato non collegato fuori", !joined.contains(unmapped.getFileName().toString().toLowerCase()));
        check("mod non verificata fuori", !joined.contains("other-2.0.jar"));
        check("prefisso librerie del launcher",
                r.libraries && joined.contains("prefix:" + metaLibs.toAbsolutePath().toString().toLowerCase()));
        check("riepilogo: 1 mod verificata", ((Number) r.summary().get("verifiedMods")).intValue() == 1);
        check("riepilogo: 1 annidato mappato", ((Number) r.summary().get("nestedMapped")).intValue() == 1);
        check("riepilogo: nomi delle mod verificate",
                String.valueOf(r.summary().get("verifiedFiles")).contains("fakemod-1.0.jar"));

        System.out.println(fails == 0 ? "MEMSKIP-SELFTEST PASS" : "MEMSKIP-SELFTEST FAIL(" + fails + ")");
        if (fails != 0) {
            System.exit(1);
        }
    }
}
