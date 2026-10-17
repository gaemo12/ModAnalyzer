import com.sun.tools.attach.VirtualMachine;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.jar.JarFile;

/**
 * Self-test di memagent (stile progetto, zero dipendenze di test):
 * manifest + auto-attach al proprio PID + dump verificato.
 * v1.7.0: verifica anche la skip-list (skip.txt): le classi JDK e le origini
 * indicate non devono essere né ri-trasformate né dumpate.
 * Uso: MemAgentSelfTest <memagent-target-MemAgent.jar>
 */
public class MemAgentSelfTest {
  static int fails = 0;
  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }

  public static void main(String[] a) throws Exception {
    Path agent = Paths.get(a[0]);
    check("agent jar esiste", Files.isRegularFile(agent));
    try (JarFile j = new JarFile(agent.toFile())) {
      var mf = j.getManifest().getMainAttributes();
      check("Premain-Class presente",
          "com.jaranalyzer.memagent.MemAgent".equals(mf.getValue("Premain-Class")));
      check("Agent-Class presente",
          "com.jaranalyzer.memagent.MemAgent".equals(mf.getValue("Agent-Class")));
      check("Can-Retransform-Classes=true",
          "true".equalsIgnoreCase(mf.getValue("Can-Retransform-Classes")));
    }

    String pid = String.valueOf(ProcessHandle.current().pid());

    /* Fase 1: dump senza skip.txt — tutto tranne il JDK (sempre fuori scope). */
    Path out = Files.createTempDirectory("memagent-test");
    attachAndWait(agent, pid, out);
    check("marker di fine dump", Files.isRegularFile(out.resolve("done.marker")));
    Path origins = out.resolve("origins.txt");
    check("origins.txt presente", Files.isRegularFile(origins));
    boolean selfOrigin = false;
    if (Files.isRegularFile(origins)) {
      for (String line : Files.readAllLines(origins, StandardCharsets.UTF_8)) {
        if (line.startsWith("MemAgentSelfTest\t") && !line.endsWith("bootstrap")) {
          selfOrigin = true;
        }
      }
    }
    check("origine propria registrata (non bootstrap)", selfOrigin);
    long classes = Files.walk(out).filter(p -> p.toString().endsWith(".class")).count();
    check("classi catturate (>0)", classes > 0);
    check("classe propria nel dump", Files.isRegularFile(out.resolve("MemAgentSelfTest.class")));
    check("classi JDK fuori dal dump", !Files.isRegularFile(out.resolve("java/lang/String.class")));
    check("progress.txt presente", Files.isRegularFile(out.resolve("progress.txt")));

    /* Fase 2: skip.txt con la cartella di questo self-test. La classe propria
       non deve comparire né in origins.txt né nel dump, e l'agent deve
       contarla tra le origini saltate. */
    Path out2 = Files.createTempDirectory("memagent-test-skip");
    Path classesDir = Paths.get(MemAgentSelfTest.class.getProtectionDomain()
        .getCodeSource().getLocation().toURI());
    Files.writeString(out2.resolve("skip.txt"),
        "# self-test: salta le classi di questa cartella\npath:" + classesDir.toAbsolutePath() + "\n",
        StandardCharsets.UTF_8);
    attachAndWait(agent, pid, out2);
    check("marker del dump con skip", Files.isRegularFile(out2.resolve("done.marker")));
    check("origine in skip-list NON dumpata", !Files.isRegularFile(out2.resolve("MemAgentSelfTest.class")));
    boolean inOrigins = false;
    if (Files.isRegularFile(out2.resolve("origins.txt"))) {
      inOrigins = Files.readString(out2.resolve("origins.txt"), StandardCharsets.UTF_8)
          .contains("MemAgentSelfTest\t");
    }
    check("origine saltata assente da origins.txt", !inOrigins);
    boolean skipped = false;
    if (Files.isRegularFile(out2.resolve("progress.txt"))) {
      for (String part : Files.readString(out2.resolve("progress.txt"), StandardCharsets.UTF_8).split(";")) {
        String p = part.trim();
        if (p.startsWith("skipped_trusted=")) {
          try {
            skipped = Integer.parseInt(p.substring("skipped_trusted=".length())) >= 1;
          } catch (NumberFormatException ignored) {
            // conteggio non numerico: resta false
          }
        }
      }
    }
    check("agent conta l'origine saltata (skipped_trusted>=1)", skipped);
    check("classi JDK fuori dal dump con skip", !Files.isRegularFile(out2.resolve("java/lang/String.class")));

    System.out.println(fails == 0 ? "MEMAGENT-SELFTEST PASS" : "MEMAGENT-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }

  private static void attachAndWait(Path agent, String pid, Path out) throws Exception {
    VirtualMachine vm = VirtualMachine.attach(pid);
    try {
      vm.loadAgent(agent.toAbsolutePath().toString(), "out=" + out.toAbsolutePath());
    } finally {
      vm.detach();
    }
    Path marker = out.resolve("done.marker");
    long waited = 0;
    while (!Files.isRegularFile(marker) && waited < 120_000) {
      Thread.sleep(500);
      waited += 500;
    }
  }
}
