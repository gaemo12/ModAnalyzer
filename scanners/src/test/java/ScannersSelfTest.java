import com.jaranalyzer.common.*;
import com.jaranalyzer.scanners.*;
import com.jaranalyzer.scanners.engine.*;
import com.jaranalyzer.scanners.modules.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Self-test di scanners/ (stile progetto, zero dipendenze di test):
 * contratto, firme, fixture controllate, privacy, limiti, igiene sorgenti.
 * Esecuzione: javac + `java -cp ... ScannersSelfTest` (vedere scripts/run-selftests).
 */
public class ScannersSelfTest {
  static int fails = 0;
  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }
  interface Part { void run() throws Exception; }
  static void throwsFatal(String n, Part r, String module) {
    try { r.run(); check(n, false); }
    catch (ScanException e) { check(n, e.kind() == ScanException.Kind.FATAL && e.module().equals(module)); }
    catch (Exception e) { System.out.println("  inattesa: " + e); check(n, false); }
  }

  static Path tmp;
  static SignatureSet builtin;

  public static void main(String[] a) throws Exception {
    tmp = Files.createTempDirectory("scanners-test");
    builtin = BuiltinSignatures.load();

    // ---- A. contratto / registry
    check("5 moduli = allowlist backend",
        ScanModules.all().stream().map(ScanModule::id).toList().equals(ModuleId.ALLOWED));
    for (String id : ModuleId.ALLOWED) check("byId " + id, ScanModules.byId(id).id().equals(id));
    try { ScanModules.byId("rm -rf"); check("modulo ignoto rifiutato", false); }
    catch (IllegalArgumentException e) { check("modulo ignoto rifiutato", true); }
    throwsFatal("single_jar rifiuta DirectoryContext",
        () -> ScanModules.byId("single_jar").run(new ScanContext.DirectoryContext(tmp), ProgressSink.noop(), builtin), "single_jar");
    throwsFatal("mods_folder rifiuta JarFileContext",
        () -> ScanModules.byId("mods_folder").run(new ScanContext.JarFileContext(tmp), ProgressSink.noop(), builtin), "mods_folder");
    throwsFatal("processes rifiuta JarFileContext",
        () -> ScanModules.byId("processes").run(new ScanContext.JarFileContext(tmp), ProgressSink.noop(), builtin), "processes");
    throwsFatal("javaw rifiuta DirectoryContext",
        () -> ScanModules.byId("javaw").run(new ScanContext.DirectoryContext(tmp), ProgressSink.noop(), builtin), "javaw");
    throwsFatal("minecraft_accounts rifiuta JarFileContext",
        () -> ScanModules.byId("minecraft_accounts").run(new ScanContext.JarFileContext(tmp), ProgressSink.noop(), builtin), "minecraft_accounts");

    // ---- B. SignatureSet
    check("empty valido", SignatureSets.empty().stringSignatures().isEmpty()
        && SignatureSets.empty().cheatGroups().isEmpty());
    try { SignatureSets.builder("t").addString("x", "NOPE", "", ""); check("severity invalida rifiutata", false); }
    catch (IllegalArgumentException e) { check("severity invalida rifiutata", true); }
    try { SignatureSets.builder("t").addCheatGroup("c", List.of("a")).addCheatGroup("c", List.of("b"));
      check("gruppo duplicato rifiutato", false); }
    catch (IllegalArgumentException e) { check("gruppo duplicato rifiutato", true); }
    try { SignatureSets.builder("t").maliciousHashes(Map.of("zzz", "")); check("hash invalido rifiutato", false); }
    catch (IllegalArgumentException e) { check("hash invalido rifiutato", true); }
    SignatureSet parsed = SignatureSets.parse("{\"v\":1,\"issued\":7,\"version\":\"t\","
        + "\"signatures\":[{\"pattern\":\"evil\",\"severity\":\"HIGH\",\"family\":\"F\",\"description\":\"D\"}],"
        + "\"suspiciousApis\":[{\"owner\":\"a/b\",\"method\":\"c\",\"severity\":\"LOW\"}],"
        + "\"suspiciousPaths\":[\"p\"],\"cheatGroups\":{\"c\":[\"s1\"]},\"quickFlags\":[\"qf\"],"
        + "\"maliciousHashes\":{\"" + "a".repeat(64) + "\":\"L\"},\"knownGoodHashes\":{}}");
    check("parse JS1 valido", parsed.stringSignatures().size() == 1 && parsed.cheatGroups().size() == 1
        && parsed.maliciousHashes().size() == 1 && parsed.version().equals("js1-7"));
    for (String bad : new String[] { "{}", "{\"v\":2,\"issued\":1}", "{\"v\":1}", "spazzatura",
        "{\"v\":1,\"issued\":1,\"signatures\":[{\"pattern\":\"\",\"severity\":\"HIGH\"}]}" }) {
      try { SignatureSets.parse(bad); check("parse rifiuta " + bad.substring(0, Math.min(12, bad.length())), false); }
      catch (IllegalArgumentException e) { check("parse rifiuta " + bad.substring(0, Math.min(12, bad.length())), true); }
    }
    check("builtin: 87 stringhe", builtin.stringSignatures().size() == 87);
    check("builtin: 33 api", builtin.suspiciousApis().size() == 33);
    check("builtin: 19 path", builtin.suspiciousPaths().size() == 19);
    check("builtin: doomsday numeroso", builtin.cheatGroups().getOrDefault("doomsdayclient", List.of()).size() > 500);
    check("builtin: nessun pattern vuoto (anti match-all)",
        builtin.cheatGroups().values().stream().flatMap(List::stream).noneMatch(String::isEmpty)
            && builtin.stringSignatures().stream().noneMatch(s -> s.pattern().isEmpty()));
    check("builtin: 120 quick-flag", builtin.quickFlags().size() == 120);
    check("builtin: anchor jndi:ldap",
        builtin.matchStrings("xx jndi:ldap://h/x").stream().anyMatch(s -> s.family().equals("Log4Shell")));
    check("builtin: anchor attach api",
        builtin.suspiciousApi("com/sun/tools/attach/VirtualMachine", "attach") != null);
    check("builtin: TAB round-trip nei pattern",
        builtin.cheatGroups().values().stream().flatMap(List::stream).anyMatch(p -> p.contains("\t")));
    check("builtin: reputation non nulle",
        builtin.maliciousHashes() != null && builtin.knownGoodHashes() != null);

    // ---- C+D. single_jar
    Path cleanJar = tmp.resolve("clean.jar");
    byte[] realClass = Files.readAllBytes(selfClassFile());
    writeJar(cleanJar, Map.of(
        "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: Demo\n".getBytes(StandardCharsets.UTF_8),
        "fabric.mod.json", "{\"id\":\"demo\",\"version\":\"1.0\",\"name\":\"Demo\",\"authors\":[\"Autore\"]}".getBytes(StandardCharsets.UTF_8),
        "com/demo/Demo.class", realClass));
    Path evilJar = tmp.resolve("evil.jar");
    writeJar(evilJar, Map.of("data/note.txt", "call jndi:ldap://evil/x now".getBytes(StandardCharsets.UTF_8)));
    Path brokenClass = tmp.resolve("broken.jar");
    writeJar(brokenClass, Map.of("A.class", new byte[] { 1, 2, 3, 4, 5 }));
    Path corrupt = tmp.resolve("corrupt.jar");
    Files.write(corrupt, new byte[] { 9, 8, 7, 6, 5, 4 });
    Path notJar = tmp.resolve("note.txt");
    Files.writeString(notJar, "ciao");

    ModuleResult clean = run("single_jar", new ScanContext.JarFileContext(cleanJar), builtin);
    check("single_jar valido success", clean.success() && clean.counters().get("files") == 1L
        && clean.counters().get("classes") == 1L);
    check("single_jar trova mod fabric",
        clean.findings().stream().anyMatch(f -> f.rule().equals("minecraft-mod")));
    check("single_jar round-trip esatto",
        ModuleResult.fromMap("single_jar", clean.toMap()).equals(clean));
    ModuleResult evil = run("single_jar", new ScanContext.JarFileContext(evilJar), builtin);
    check("single_jar rileva jndi:ldap",
        evil.findings().stream().anyMatch(f -> f.title().contains("jndi:ldap")));
    ModuleResult broken = run("single_jar", new ScanContext.JarFileContext(brokenClass), builtin);
    check("classe rotta tollerata (finding, non abort)",
        broken.success() && broken.findings().stream().anyMatch(f -> f.rule().equals("bytecode-read-error")));
    throwsFatal("corrotto = FATAL",
        () -> run("single_jar", new ScanContext.JarFileContext(corrupt), builtin), "single_jar");
    throwsFatal("estensione errata = FATAL",
        () -> run("single_jar", new ScanContext.JarFileContext(notJar), builtin), "single_jar");
    throwsFatal("mancante = FATAL",
        () -> run("single_jar", new ScanContext.JarFileContext(tmp.resolve("no.jar")), builtin), "single_jar");
    ModuleResult emptySet = run("single_jar", new ScanContext.JarFileContext(cleanJar), SignatureSets.empty());
    check("set vuoto: success senza match",
        emptySet.success() && emptySet.findings().stream().noneMatch(f -> f.title().contains("Malware signature match")));
    Path plainJar = tmp.resolve("plain.jar");
    writeJar(plainJar, Map.of("readme.txt", "hello world, just a test".getBytes(StandardCharsets.UTF_8)));
    ModuleResult plain = run("single_jar", new ScanContext.JarFileContext(plainJar), builtin);
    check("controllo negativo: zero signature match",
        plain.success() && plain.findings().stream().noneMatch(f -> f.title().contains("Malware signature match")));
    ModuleResult clean2 = run("single_jar", new ScanContext.JarFileContext(cleanJar), builtin);
    check("single_jar deterministico", stripDuration(clean).equals(stripDuration(clean2)));
    String cleanJson = JsonCodec.write(clean.toMap());
    // Il JSON escapa i backslash: si cerca la forma con doppie barre. L'euristica
    // looksLikeAbsolutePath NON si applica qui: gli snippet binari possono contenere
    // per caso sequenze tipo "s:\" (documentato in docs/SCANNERS.md).
    String tmpEscaped = tmp.toString().replace("\\", "\\\\");
    check("niente path host in single_jar", !cleanJson.contains(tmpEscaped));
    check("scrub messaggi I/O",
        Sanitizer.scrub("open C:\\Dir\\Nope\\f.jar failed", Path.of("C:\\Dir\\Nope\\f.jar"))
            .equals("open f.jar failed"));
    try {
      ProgressSink.Recording rec = new ProgressSink.Recording();
      rec.cancel();
      ScanModules.byId("single_jar").run(new ScanContext.JarFileContext(cleanJar), rec, builtin);
      check("single_jar cancellato", false);
    } catch (ScanException e) { check("single_jar cancellato", e.kind() == ScanException.Kind.CANCELLED); }

    // ---- E. mods_folder
    ModuleResult missing = run("mods_folder", new ScanContext.DirectoryContext(tmp.resolve("nodir")), builtin);
    check("cartella assente: success + finding",
        missing.success() && missing.counters().get("files") == 0L
            && missing.findings().stream().anyMatch(f -> f.rule().equals("mods-dir-missing")));
    Path emptyDir = Files.createDirectory(tmp.resolve("emptymods"));
    ModuleResult empty = run("mods_folder", new ScanContext.DirectoryContext(emptyDir), builtin);
    check("cartella vuota: success senza finding", empty.success() && empty.findings().isEmpty());
    Path mods = Files.createDirectory(tmp.resolve("mods"));
    Files.copy(cleanJar, mods.resolve("clean.jar"));
    Files.copy(evilJar, mods.resolve("evil.jar"));
    Files.copy(corrupt, mods.resolve("corrupt.jar"));
    Files.writeString(mods.resolve("readme.txt"), "ignora");
    Files.createDirectory(mods.resolve("subdir.jar"));
    writeJar(mods.resolve("cheatmod.jar"),
        Map.of("com/wurstclient/Hook.class", new byte[] { 10, 20, 30 }));
    String evilSha = Hashing.sha256(mods.resolve("evil.jar"));
    String cleanSha = Hashing.sha256(mods.resolve("clean.jar"));
    // Reputation + quick-flag builtin (il set del player arriverebbe via JS1).
    SignatureSets.Builder repBuilder = SignatureSets.builder("t")
        .maliciousHashes(Map.of(evilSha, "test-label"));
    for (String qf : builtin.quickFlags()) {
      repBuilder.addQuickFlag(qf);
    }
    SignatureSet rep = repBuilder.build();
    ProgressSink.Recording rec = new ProgressSink.Recording();
    ModuleResult mr = (ModuleResult) ScanModules.byId("mods_folder")
        .run(new ScanContext.DirectoryContext(mods), rec, rep);
    check("mods: 5 file (txt escluso, dir-as-jar inclusa)",
        mr.counters().get("files") == 5L);
    check("mods: evil CRITICAL con label",
        mr.findings().stream().anyMatch(f -> f.severity().equals("CRITICAL") && f.evidence().contains("test-label")));
    check("mods: quickflag wurstclient HIGH",
        mr.findings().stream().anyMatch(f -> f.rule().equals("mod-suspicious") && f.severity().equals("HIGH")));
    check("mods: corrupt + dir = illeggibili LOW",
        mr.findings().stream().filter(f -> f.rule().equals("mod-unreadable")).count() == 2L
            && mr.counters().get("failed") == 2L);
    check("mods: clean INFO con sha",
        mr.findings().stream().anyMatch(f -> f.rule().equals("mod-file") && f.evidence().contains(cleanSha)));
    String modsJson = JsonCodec.write(mr.toMap());
    check("niente path host in mods_folder",
        !modsJson.contains(tmp.toString().replace("\\", "\\\\")));
    check("progress registrati fino a done",
        !rec.events().isEmpty() && rec.events().get(rec.events().size() - 1).percent() == 100);
    ModuleResult mr2 = run("mods_folder", new ScanContext.DirectoryContext(mods), rep);
    check("mods deterministico", stripDuration(mr).equals(stripDuration(mr2)));
    try {
      ProgressSink.Recording rec2 = new ProgressSink.Recording();
      rec2.cancel();
      ScanModules.byId("mods_folder").run(new ScanContext.DirectoryContext(mods), rec2, rep);
      check("mods cancellato", false);
    } catch (ScanException e) { check("mods cancellato", e.kind() == ScanException.Kind.CANCELLED); }

    // ---- F. processi/javaw live (solo proprietà strutturali) + unità pure
    ScanContext.HostContext host = new ScanContext.HostContext(null, null, null);
    ModuleResult procs = run("processes", host, builtin);
    check("processes: success e conteggi",
        procs.success() && procs.counters().get("processes") > 0L);
    check("processes: finding ben formati",
        procs.findings().stream().allMatch(f -> !f.rule().isBlank() && !f.location().isBlank()));
    ModuleResult jw = run("javaw", host, builtin);
    long own = ProcessHandle.current().pid();
    check("javaw: vede il proprio processo JVM",
        jw.findings().stream().anyMatch(f -> f.location().contains("pid:" + own)));
    check("classificatori puri",
        ProcessInventory.executableName("\"/opt/java/bin/javaw.exe\"").equals("javaw.exe")
            && ProcessInventory.executableName("/usr/bin/java").equals("java")
            && ProcessInventory.isJava("javaw.exe", "") && !ProcessInventory.isJava("notepad.exe", "")
            && ProcessInventory.isMinecraftLike("/opt/games/.minecraft/versions")
            && !ProcessInventory.isMinecraftLike("plain-notepad"));
    check("redactHome", Sanitizer.redactHome("run /data/game --x", "/data")
        .equals("run ~/game --x")
        && Sanitizer.fileName(Path.of("/a/b/c.jar")).equals("c.jar"));
    // I casi positivi sono costruiti da char[]: nessun literal drive-letter nel
    // constant pool (questa stessa classe viene scansionata come fixture).
    String winPath = new String(new char[] { 'C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'B', 'o', 'b' });
    String nixHome = new String(new char[] { '/', 'h', 'o', 'm', 'e', '/', 'b', 'o', 'b' });
    check("looksLikeAbsolutePath preciso",
        Sanitizer.looksLikeAbsolutePath(winPath)
            && Sanitizer.looksLikeAbsolutePath(nixHome)
            && !Sanitizer.looksLikeAbsolutePath("call jndi:ldap://evil/x now")
            && !Sanitizer.looksLikeAbsolutePath("https://host/y")
            && !Sanitizer.looksLikeAbsolutePath("clean.jar"));
    JavawAnalyzer ja = new JavawAnalyzer();
    check("matchText javaagent",
        ja.matchText("javaw -javaagent:evil.jar", "pid:1").stream()
            .anyMatch(f -> f.getFamily().equals("JavaAgent")));
    check("matchText pulito", ja.matchText("plain-notepad", "pid:2").isEmpty());

    // ---- G. accounts con fixture (segreti presenti nei file, mai negli esiti)
    Path ad = Files.createDirectory(tmp.resolve("appdata"));
    Path mc = Files.createDirectories(ad.resolve(".minecraft"));
    Files.writeString(mc.resolve("launcher_accounts.json"), "{\"accounts\":{"
        + "\"a1\":{\"minecraftProfile\":{\"name\":\"PlayerOne\",\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},"
        + "\"type\":\"Microsoft\",\"accessToken\":\"SECRET-AT\",\"refreshToken\":\"SECRET-RT\"}}}");
    Files.writeString(mc.resolve("launcher_profiles.json"),
        "{\"authenticationDatabase\":{\"x\":{\"displayName\":\"LegacyBob\",\"uuid\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}}}");
    Path fe = Files.createDirectories(ad.resolve(".feather"));
    Files.writeString(fe.resolve("accounts.json"), "{\"accounts\":["
        + "{\"minecraftProfile\":{\"name\":\"PlayerOne\",\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}]}");
    Path pr = Files.createDirectories(ad.resolve("PrismLauncher"));
    Files.writeString(pr.resolve("accounts.json"), "{\"accounts\":["
        + "{\"profile\":{\"name\":\"PrismPete\",\"id\":\"cccccccccccccccccccccccccccccccc\"},"
        + "\"type\":\"Microsoft\",\"password\":\"SECRET-PW\",\"token\":\"SECRET-T\"}]}");
    Path inst = Files.createDirectories(mc.resolve("logs"));
    Files.writeString(inst.resolve("latest.log"),
        "bla LoginData{name='LogLarry', uuid=dddddddddddddddddddddddddddddddd} bla");
    Path cfg = Files.createDirectories(mc.resolve("config"));
    Files.writeString(cfg.resolve("account.txt"), "\nOfflineOllie\n");
    Path up = Files.createDirectory(tmp.resolve("userprofile"));
    Path lu = Files.createDirectories(up.resolve(".lunarclient/settings/game"));
    Files.writeString(lu.resolve("accounts.json"), "{\"accounts\":["
        + "{\"username\":\"LunarLena\",\"uuid\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"token\":\"SECRET-L\"}]}");
    ModuleResult acc = run("minecraft_accounts",
        new ScanContext.HostContext(ad, up, tmp), builtin);
    check("accounts: 6 rilevati (dedup PlayerOne)",
        acc.success() && acc.counters().get("accounts") == 6L);
    String accJson = JsonCodec.write(acc.toMap());
    check("accounts: username presenti",
        accJson.contains("PlayerOne") && accJson.contains("LunarLena") && accJson.contains("OfflineOllie"));
    check("accounts: NESSUN segreto negli esiti",
        !accJson.contains("SECRET-AT") && !accJson.contains("SECRET-RT") && !accJson.contains("SECRET-PW")
            && !accJson.contains("SECRET-T") && !accJson.contains("SECRET-L")
            && !accJson.contains("accessToken") && !accJson.contains("refreshToken")
            && !accJson.contains("password") && !accJson.contains("cookie"));
    check("accounts: niente path home",
        !accJson.contains(tmp.toString()) && !Sanitizer.looksLikeAbsolutePath(accJson));
    ModuleResult accEmpty = run("minecraft_accounts",
        new ScanContext.HostContext(null, null, null), builtin);
    check("accounts: senza basi = vuoto", accEmpty.success() && accEmpty.findings().isEmpty());

    // ---- H. ZipWalk limiti
    try {
      ZipWalk.readCapped(new InputStream() {
        @Override public int read(byte[] b, int o, int l) { Arrays.fill(b, o, o + Math.min(l, 8), (byte) 1); return Math.min(l, 8); }
        @Override public int read() { return 1; }
      }, 10);
      check("zip-bomb troncata", false);
    } catch (IOException e) { check("zip-bomb troncata", true); }
    Path traversal = tmp.resolve("trav.jar");
    writeJar(traversal, Map.of("../evil.txt", new byte[] { 1 }, "ok.txt", new byte[] { 2 }));
    List<String> seen = new ArrayList<>();
    try (ZipFile zf = new ZipFile(traversal.toFile())) {
      ZipWalk.walk(zf, e -> seen.add(e.name()));
    }
    check("nomi ../ preservati senza estrazione",
        seen.contains("../evil.txt") && !Files.exists(tmp.resolve("evil.txt")));

    // ---- I. igiene sorgenti: niente rete/UI/Spring/backend in scanners
    Path src = srcMain();
    List<String> bad = new ArrayList<>();
    Files.walk(src).filter(p -> p.toString().endsWith(".java")).forEach(p -> {
      try {
        for (String line : Files.readAllLines(p)) {
          String t = line.trim();
          if (t.startsWith("import java.net.http") || t.startsWith("import javafx")
              || t.startsWith("import org.springframework") || t.contains("BackendClient")) {
            bad.add(src.relativize(p) + ": " + t);
          }
        }
      } catch (IOException e) { bad.add(p + ": illeggibile"); }
    });
    check("sorgenti senza rete/UI/Spring" + (bad.isEmpty() ? "" : " -> " + bad), bad.isEmpty());

    // ---- J. mapper fallback
    com.jaranalyzer.scanners.Finding bare =
        new com.jaranalyzer.scanners.Finding.Builder().title("Solo titolo")
            .severity(Severity.INFO).category(Category.STRUCTURE).build();
    com.jaranalyzer.common.Finding wire = FindingMapper.toProtocol(bare);
    check("mapper: rule fallback", wire.rule().equals("unspecified") && wire.title().equals("Solo titolo"));

    System.out.println(fails == 0 ? "TUTTO OK" : "FALLITI: " + fails);
    System.exit(fails == 0 ? 0 : 1);
  }

  static ModuleResult run(String id, ScanContext ctx, SignatureSet set) throws Exception {
    ProgressSink.Recording rec = new ProgressSink.Recording();
    return ScanModules.byId(id).run(ctx, rec, set);
  }

  static void writeJar(Path jar, Map<String, byte[]> entries) throws Exception {
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
      for (Map.Entry<String, byte[]> e : entries.entrySet()) {
        zos.putNextEntry(new ZipEntry(e.getKey()));
        zos.write(e.getValue());
        zos.closeEntry();
      }
    }
  }

  static Path selfClassFile() throws Exception {
    String cls = "ScannersSelfTest.class";
    for (String dir : System.getProperty("java.class.path").split(java.util.regex.Pattern.quote(File.pathSeparator))) {
      Path p = Path.of(dir, cls);
      if (Files.isRegularFile(p)) return p;
    }
    throw new IllegalStateException("classpath senza ScannersSelfTest.class");
  }

  static Map<String, Object> stripDuration(ModuleResult r) {
    Map<String, Object> m = new LinkedHashMap<>(r.toMap());
    m.remove("durationMillis");
    return m;
  }

  static Path srcMain() {
    for (String c : new String[] { "scanners/src/main/java", "src/main/java" }) {
      if (Files.isDirectory(Path.of(c))) return Path.of(c);
    }
    throw new IllegalStateException("sorgenti scanners non trovati");
  }
}
