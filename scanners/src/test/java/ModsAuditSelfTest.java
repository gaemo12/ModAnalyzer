import com.jaranalyzer.scanners.engine.ModsFolderAudit;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Self-test del controllo strutturale della cartella mods v1.3.2 (stile
 * progetto, zero dipendenze): nomi disabilitati, firme non-JAR, id duplicati,
 * rename sospetto e ricerca degli indicatori nelle mod disabilitate.
 * Esecuzione: scripts/run-selftests.bat.
 */
public class ModsAuditSelfTest {
  static int fails = 0;

  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }

  public static void main(String[] a) throws Exception {
    names();
    magic();
    flagInId();
    report();
    disabledScan();
    System.out.println(fails == 0 ? "MODS-AUDIT-SELFTEST PASS" : "MODS-AUDIT-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }

  static void names() {
    check("jar.disabled riconosciuto", ModsFolderAudit.isDisabledName("Sodium.jar.disabled"));
    check("jar.off riconosciuto", ModsFolderAudit.isDisabledName("mod.jar.off"));
    check("jar.bak riconosciuto", ModsFolderAudit.isDisabledName("vecchia-1.2.jar.bak"));
    check("jar attivo non è disabilitato", !ModsFolderAudit.isDisabledName("sodium.jar"));
    check("file non-jar non è disabilitato", !ModsFolderAudit.isDisabledName("note.txt.disabled"));
    check("nome nullo gestito", !ModsFolderAudit.isDisabledName(null));
  }

  static void magic() throws Exception {
    Path dir = Files.createTempDirectory("audit-magic");
    check("MZ = eseguibile Windows", kind(dir.resolve("finto.jar"), new byte[] {'M', 'Z', 0, 0})
        .contains("Windows"));
    check("ELF = eseguibile Linux", kind(dir.resolve("elf.jar"), new byte[] {0x7f, 'E', 'L', 'F'})
        .contains("Linux"));
    check("script con shebang", kind(dir.resolve("script.jar"), "#! /bin/sh\n".getBytes(StandardCharsets.UTF_8))
        .contains("script"));
    check("RAR riconosciuto", kind(dir.resolve("raro.jar"), new byte[] {'R', 'a', 'r', '!'}).contains("RAR"));
    check("ZIP/JAR accettato", kind(dir.resolve("buono.jar"), new byte[] {'P', 'K', 3, 4}) == null);
    check("file vuoto segnalato", kind(dir.resolve("vuoto.jar"), new byte[0]).contains("vuoto"));
    check("firma sconosciuta mostrata in esadecimale",
        kind(dir.resolve("strano.jar"), new byte[] {0x01, 0x02, 0x03, 0x04}).contains("01020304"));
  }

  static void flagInId() {
    List<String> flags = List.of("meteor", "wurst", "cheatclient", "C:/percorso");
    check("id esatto", "meteor".equals(ModsFolderAudit.flagInId("meteor", flags)));
    check("id con separatori", "wurst".equals(ModsFolderAudit.flagInId("wurst-client", flags)));
    check("id compattato", "cheatclient".equals(ModsFolderAudit.flagInId("cheat_client", flags)));
    check("prefisso lungo", "meteor".equals(ModsFolderAudit.flagInId("meteorclient-addon", flags)));
    check("flag corto non matcha dentro parola",
        ModsFolderAudit.flagInId("sodium", List.of("dium")) == null);
    check("indicatore di percorso ignorato",
        ModsFolderAudit.flagInId("C:/percorso", flags) == null);
    check("id pulito", ModsFolderAudit.flagInId("sodium", flags) == null);
    check("id nullo", ModsFolderAudit.flagInId(null, flags) == null);
  }

  static void report() throws Exception {
    List<ModsFolderAudit.Entry> entries = List.of(
        new ModsFolderAudit.Entry("sodium.jar", "sodium", "Sodium", null),
        new ModsFolderAudit.Entry("sodium-duplicate.jar", "Sodium", "Sodium", null),
        new ModsFolderAudit.Entry("Sodium-1.20.jar", "freemod", "Free Mod", null),
        new ModsFolderAudit.Entry("eseguibile.jar", "x", "X", "eseguibile Windows (.exe/.dll)"),
        new ModsFolderAudit.Entry("senza-id.jar", null, null, null));

    ModsFolderAudit.Report r = ModsFolderAudit.audit(
        Files.createTempDirectory("audit-empty"), entries, List.of());
    check("id duplicato case-insensitive", r.duplicateIds().size() == 1
        && r.duplicateIds().get(0).id().equals("sodium")
        && r.duplicateIds().get(0).files().size() == 2);
    check("jar camuffato elencato", r.disguised().size() == 1
        && r.disguised().get(0).contains("eseguibile.jar"));
    check("rename di sodium segnalato", r.mismatches().size() == 1
        && r.mismatches().get(0).fileName().equals("Sodium-1.20.jar"));
    check("issues conta duplicati, camuffati e mismatch", r.issues() == 3);
    check("nessuna mod disabilitata", r.disabled().isEmpty());
    check("audit con lista nulla non esplode", ModsFolderAudit.audit(null, null, null).issues() == 0);
  }

  static void disabledScan() throws Exception {
    Path dir = Files.createTempDirectory("audit-disabled");
    // Mod disabilitata con indicatore nel nome dell'entry.
    writeJar(dir.resolve("vecchia.jar.disabled"), "meteor/client/Main.class", new byte[] {1});
    // Mod disabilitata con indicatore nell'id (non nel nome dell'entry).
    writeJar(dir.resolve("anonima.jar.off"), "fabric.mod.json",
        "{\"id\":\"wurst-addon\",\"name\":\"Addon\"}".getBytes(StandardCharsets.UTF_8));
    // Mod disabilitata pulita.
    writeJar(dir.resolve("sodium.jar.bak"), "fabric.mod.json",
        "{\"id\":\"sodium\",\"name\":\"Sodium\"}".getBytes(StandardCharsets.UTF_8));
    // File .jar.disabled che in realtà è un eseguibile.
    Files.write(dir.resolve("strano.jar.disabled"), new byte[] {'M', 'Z', 0, 0});
    // Attiva: non deve finire nell'elenco delle disabilitate.
    writeJar(dir.resolve("attiva.jar"), "fabric.mod.json",
        "{\"id\":\"ok\",\"name\":\"Ok\"}".getBytes(StandardCharsets.UTF_8));

    ModsFolderAudit.Report r = ModsFolderAudit.audit(dir, List.of(),
        List.of("meteor", "wurst"));
    check("quattro mod disabilitate elencate", r.disabled().size() == 4);
    check("la mod attiva non è nell'elenco", !r.disabled().contains("attiva.jar"));
    check("indicatore nel nome dell'entry trovato", hasFinding(r, "vecchia.jar.disabled", "meteor"));
    check("indicatore nell'id trovato", hasFinding(r, "anonima.jar.off", "wurst"));
    check("mod disabilitata pulita non è sospetta", !hasFinding(r, "sodium.jar.bak", null));
    check("magic non-JAR su mod disabilitata segnalata",
        hasFinding(r, "strano.jar.disabled", "Windows"));

    ModsFolderAudit.Report senzaFlags = ModsFolderAudit.audit(dir, List.of(), List.of());
    check("senza indicatori le disabilitate restano elencate e il magic viene comunque controllato",
        senzaFlags.disabled().size() == 4 && senzaFlags.suspiciousDisabled().size() == 1
            && hasFinding(senzaFlags, "strano.jar.disabled", "Windows"));

    ModsFolderAudit.Report mancante = ModsFolderAudit.audit(dir.resolve("non-esiste"), List.of(), List.of());
    check("cartella inesistente dichiarata nelle note", !mancante.notes().isEmpty());
  }

  static boolean hasFinding(ModsFolderAudit.Report r, String file, String text) {
    for (ModsFolderAudit.DisabledFinding f : r.suspiciousDisabled()) {
      if (f.fileName().equals(file) && (text == null || f.reason().contains(text))) {
        return true;
      }
    }
    return false;
  }

  /* ------------------------------------------------------------ helper */

  static String kind(Path file, byte[] head) throws Exception {
    Files.write(file, head);
    return ModsFolderAudit.nonJarMagic(file);
  }

  static void writeJar(Path file, String entry, byte[] content) throws Exception {
    try (ZipOutputStream j = new ZipOutputStream(Files.newOutputStream(file))) {
      j.putNextEntry(new ZipEntry(entry));
      j.write(content);
      j.closeEntry();
    }
  }
}
