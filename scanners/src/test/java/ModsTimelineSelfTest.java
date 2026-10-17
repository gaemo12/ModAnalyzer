import com.jaranalyzer.scanners.engine.ModsTimeline;
import java.nio.file.*;
import java.nio.file.attribute.FileTime;

/**
 * Self-test di ModsTimeline (stile progetto, zero dipendenze): logica degli stati
 * e controllo reale su file temporanei. Esecuzione: scripts/run-selftests.bat
 * (o javac + java -cp ... ModsTimelineSelfTest).
 */
public class ModsTimelineSelfTest {
  static int fails = 0;

  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }

  public static void main(String[] a) throws Exception {
    // Istante di riferimento fisso (2023) per la sola logica degli stati.
    long now = 1_700_000_000_000L;
    check("creato dopo l'avvio = added",
        ModsTimeline.ADDED.equals(ModsTimeline.state(now - 1_000, now - 2_000, now - 5_000)));
    check("modificato dopo l'avvio = modified",
        ModsTimeline.MODIFIED.equals(ModsTimeline.state(now - 60_000, now - 1_000, now - 5_000)));
    check("anteriore all'avvio = ok",
        ModsTimeline.OK.equals(ModsTimeline.state(now - 60_000, now - 30_000, now - 5_000)));
    check("confine: creato esattamente all'avvio = ok",
        ModsTimeline.OK.equals(ModsTimeline.state(now, now - 1, now)));

    Path dir = Files.createTempDirectory("mods-timeline-test");
    Path jar = Files.createFile(dir.resolve("mod-uno.jar"));
    Files.write(jar, new byte[] { 1, 2, 3 });
    Files.setLastModifiedTime(jar, FileTime.fromMillis(now - 120_000));
    Files.createDirectory(dir.resolve("sub"));

    ModsTimeline.Result prima = ModsTimeline.check(dir, now - 60_000);
    check("file controllati = 1 (directory esclusa)", prima.files() == 1);
    check("creato dopo un avvio nel passato = added", prima.added() == 1);
    check("suspects contiene il jar", prima.suspects().size() == 1
        && "mod-uno.jar".equals(prima.suspects().get(0).fileName()));

    ModsTimeline.Result dopo = ModsTimeline.check(dir, System.currentTimeMillis() + 60_000);
    check("avvio nel futuro = nessun sospetto",
        dopo.added() == 0 && dopo.modified() == 0 && dopo.suspects().isEmpty());
    check("file controllati ancora 1", dopo.files() == 1);

    System.out.println(fails == 0 ? "MODS-TIMELINE-SELFTEST PASS" : "MODS-TIMELINE-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }
}
