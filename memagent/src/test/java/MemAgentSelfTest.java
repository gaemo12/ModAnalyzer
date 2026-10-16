import com.sun.tools.attach.VirtualMachine;
import java.nio.file.*;
import java.util.jar.JarFile;

/**
 * Self-test di memagent (stile progetto, zero dipendenze di test):
 * manifest + auto-attach al proprio PID + dump verificato.
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

    Path out = Files.createTempDirectory("memagent-test");
    String pid = String.valueOf(ProcessHandle.current().pid());
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
    check("marker di fine dump", Files.isRegularFile(marker));
    Path origins = out.resolve("origins.txt");
    check("origins.txt presente", Files.isRegularFile(origins));
    boolean selfOrigin = false;
    if (Files.isRegularFile(origins)) {
      for (String line : Files.readAllLines(origins, java.nio.charset.StandardCharsets.UTF_8)) {
        if (line.startsWith("MemAgentSelfTest\t") && !line.endsWith("bootstrap")) {
          selfOrigin = true;
        }
      }
    }
    check("origine propria registrata (non bootstrap)", selfOrigin);
    long classes = Files.walk(out).filter(p -> p.toString().endsWith(".class")).count();
    check("classi catturate (>0)", classes > 0);
    check("classe propria nel dump", Files.isRegularFile(out.resolve("MemAgentSelfTest.class")));

    System.out.println(fails == 0 ? "MEMAGENT-SELFTEST PASS" : "MEMAGENT-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }
}
