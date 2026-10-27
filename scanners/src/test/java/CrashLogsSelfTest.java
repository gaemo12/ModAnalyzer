import com.jaranalyzer.scanners.engine.CrashLogs;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Self-test dell'analisi dei crash log v1.3.2 (stile progetto, zero dipendenze):
 * estrazione dei soli flag sospetti dalle intestazioni JVM, esclusione di
 * classpath/mixin e scansione reale di hs_err/crash-reports su file temporanei.
 * Esecuzione: scripts/run-selftests.bat.
 */
public class CrashLogsSelfTest {
  static int fails = 0;

  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }

  public static void main(String[] a) throws Exception {
    extraction();
    scan();
    System.out.println(fails == 0 ? "CRASH-LOGS-SELFTEST PASS" : "CRASH-LOGS-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }

  static void extraction() {
    String hsErr = String.join("\n",
        "# There is insufficient memory for the Java Runtime Environment to continue.",
        "---------------  S U M M A R Y ------------",
        "Command Line: -Xmx2G -javaagent:C:\\temp\\agent.jar -Djava.system.class.loader=ghost.Loader -Xbootclasspath/a:C:\\temp\\patch.jar --username Steve",
        "Host: Windows 11, x86_64",
        "JVM Flags: 2 total; -Xmx2G -XX:+DisableAttachMechanism",
        "");
    List<String> flags = CrashLogs.flagsIn(hsErr);
    check("-javaagent estratto", flags.contains("-javaagent"));
    check("class loader sostituito estratto", flags.contains("-Djava.system.class.loader"));
    check("-Xbootclasspath estratto", flags.contains("-Xbootclasspath"));
    check("flag anti-analisi estratto", flags.contains("-XX:+DisableAttachMechanism"));
    check("nessun duplicato", new HashSet<>(flags).size() == flags.size());

    String crash = String.join("\n",
        "---- Minecraft Crash Report ----",
        "// Who set us up the TNT?",
        "Time: 2026-10-16 22:47:00",
        "java_command: javaw.exe -Xmx4G -javaagent:C:\\x\\y.jar net.minecraft.client.main.Main",
        "JVM Flags: -cp C:\\Users\\Steve\\.minecraft\\libraries\\a.jar;C:\\temp\\ghost.jar",
        "--mixin mixins.ghost.json",
        "");
    List<String> c = CrashLogs.flagsIn(crash);
    check("java_command letto", c.contains("-javaagent"));
    check("-cp non esposto (rumoroso, gestito dal processo vivo)", !c.contains("-cp"));
    check("--mixin non esposto", !c.contains("--mixin"));

    check("testo nullo = lista vuota", CrashLogs.flagsIn(null).isEmpty());
    check("testo pulito = lista vuota", CrashLogs.flagsIn("Command Line: -Xmx2G --username Steve").isEmpty());
    check("riga non di intestazione ignorata",
        CrashLogs.flagsIn("pre Command Line: -javaagent:x.jar").isEmpty());
    check("BOM iniziale ignorato",
        CrashLogs.flagsIn("\uFEFFjava_command: javaw.exe -javaagent:x.jar").contains("-javaagent"));
  }

  static void scan() throws Exception {
    Path game = Files.createTempDirectory("crash-game");
    Files.createDirectories(game.resolve("crash-reports"));

    Files.write(game.resolve("hs_err_pid1234.log"), String.join("\n",
        "Command Line: -javaagent:C:\\temp\\a.jar -Xmx2G",
        "Host: Windows 11",
        "").getBytes(StandardCharsets.UTF_8));
    Files.write(game.resolve("crash-reports").resolve("crash-2026-10-16_22.47.00-client.txt"),
        String.join("\n",
            "java_command: javaw.exe -Xbootclasspath/a:C:\\temp\\b.jar --username Steve",
            "").getBytes(StandardCharsets.UTF_8));
    Files.write(game.resolve("crash-reports").resolve("nota.txt"),
        "nessun flag\n".getBytes(StandardCharsets.UTF_8));

    List<CrashLogs.Trace> found = CrashLogs.scan(game);
    check("due tracce trovate", found.size() == 2);
    check("hs_err riconosciuto", found.stream().anyMatch(t -> t.kind().equals("hs_err")
        && t.file().equals("hs_err_pid1234.log") && t.flags().contains("-javaagent")));
    check("crash report riconosciuto", found.stream().anyMatch(t -> t.kind().equals("crash-report")
        && t.file().startsWith("crash-reports/") && t.flags().contains("-Xbootclasspath")));
    check("file senza flag non elencato", found.stream().noneMatch(t -> t.file().contains("nota")));
    check("timestamp presente", found.stream().allMatch(t -> t.modifiedMillis() > 0));

    check("game dir nullo = lista vuota", CrashLogs.scan(null).isEmpty());
    check("game dir inesistente = lista vuota",
        CrashLogs.scan(game.resolve("non-esiste")).isEmpty());
  }
}
