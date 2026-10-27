import com.jaranalyzer.scanners.Severity;
import com.jaranalyzer.scanners.engine.CheatArtifacts;
import com.jaranalyzer.scanners.engine.GameCommandLine;
import com.jaranalyzer.scanners.engine.LoadedModsLog;
import com.jaranalyzer.scanners.engine.MinecraftPathResolver;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Self-test del controllo runtime v1.3.0 (stile progetto, zero dipendenze):
 * LoadedModsLog (log vs disco, anti-FP builtin/JiJ, log vecchio), GameCommandLine
 * (flag ghost, tweaker standard, classpath) e CheatArtifacts (nomi noti, mai generici).
 * Esecuzione: scripts/run-selftests.bat.
 */
public class RuntimeSelfTest {
  static int fails = 0;

  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }

  public static void main(String[] a) throws Exception {
    loadedModsLog();
    gameCommandLine();
    cheatArtifacts();
    paths();
    System.out.println(fails == 0 ? "RUNTIME-SELFTEST PASS" : "RUNTIME-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }

  /* ------------------------------------------------------------ LoadedModsLog */

  static void loadedModsLog() throws Exception {
    Path gameDir = Files.createTempDirectory("rt-game");
    Path modsDir = Files.createDirectories(gameDir.resolve("mods"));
    Path logs = Files.createDirectories(gameDir.resolve("logs"));

    // Disco: sodium (fabric.mod.json con id) + fabric-api con JiJ annidato (id "fabric-keybindings").
    writeJar(modsDir.resolve("sodium.jar"), "fabric.mod.json",
        "{\"schemaVersion\":1,\"id\":\"sodium\",\"version\":\"0.5.8\",\"name\":\"Sodium\"}");
    byte[] nested = nestedJar("fabric.mod.json",
        "{\"schemaVersion\":1,\"id\":\"fabric-keybindings\",\"version\":\"1.0.0\"}");
    writeEntryJar(modsDir.resolve("fabric-api.jar"), "META-INF/jars/fabric-keybindings-v1.jar", nested);

    String log = "[main/INFO]: Loading 4 mods for minecraft 1.20.1:\n"
        + "[main/INFO]: Loading 4 mods: minecraft@1.20.1, sodium@0.5.8, fabric-keybindings@1.0.0,"
        + " ghostclient@1.0.0, java@17\n";
    Files.write(logs.resolve("latest.log"), log.getBytes(StandardCharsets.UTF_8));

    LoadedModsLog.Result r = LoadedModsLog.diff(gameDir, modsDir, 0L);
    check("log trovato, formato fabric", r.logFound() && "fabric".equals(r.format()));
    check("ghostclient caricata ma non su disco",
        r.loadedNotOnDisk().equals(List.of("ghostclient")));
    check("builtin (minecraft/java) esclusi dai ghost", !r.loadedNotOnDisk().contains("minecraft")
        && !r.loadedNotOnDisk().contains("java"));
    check("id del JiJ annidato riconosciuto su disco (anti-FP fabric-api)",
        !r.loadedNotOnDisk().contains("fabric-keybindings"));
    check("sodium su disco non è ghost", !r.loadedNotOnDisk().contains("sodium"));
    check("onDiskNotLoaded vuota (tutto ciò che è su disco risulta caricato)",
        r.onDiskNotLoaded().isEmpty());

    // Log vecchio: la sessione precedente non deve contare come finding pieno.
    Files.write(logs.resolve("latest.log"), ("[main/INFO]: Loading 2 mods: minecraft@1.20.1, vecchia@1.0.0\n")
        .getBytes(StandardCharsets.UTF_8));
    LoadedModsLog.Result stale = LoadedModsLog.diff(gameDir, modsDir, System.currentTimeMillis() + 60_000);
    check("log più vecchio dell'avvio = stale", stale.stale());
    check("ghost di sessione precedente comunque elencato ma declassabile",
        stale.loadedNotOnDisk().equals(List.of("vecchia")));

    // Forge: nomi file caricati vs jar presenti.
    Files.write(logs.resolve("latest.log"),
        ("[main/INFO]: Found mod file sodium.jar of type MOD\n[main/INFO]: Found mod file injected.jar of type MOD\n")
            .getBytes(StandardCharsets.UTF_8));
    LoadedModsLog.Result forge = LoadedModsLog.diff(gameDir, modsDir, 0L);
    check("forge: file caricato assente dalla cartella mods",
        forge.loadedFilesNotOnDisk().equals(List.of("injected.jar"))
            && !forge.loadedFilesNotOnDisk().contains("sodium.jar"));

    // Nessun log: esito esplicito, mai silenzioso.
    Files.delete(logs.resolve("latest.log"));
    LoadedModsLog.Result none = LoadedModsLog.diff(gameDir, modsDir, 0L);
    check("log assente dichiarato", !none.logFound());
  }

  /* ------------------------------------------------------------ GameCommandLine */

  static void gameCommandLine() {
    List<GameCommandLine.Flag> f1 = GameCommandLine.check(
        "javaw.exe -Xmx2G -Djava.system.class.loader=ghost.Loader --username Steve --gameDir C:/x");
    check("-Djava.system.class.loader HIGH",
        f1.stream().anyMatch(x -> x.flag().equals("-Djava.system.class.loader") && x.severity() == Severity.HIGH));

    List<GameCommandLine.Flag> f2 = GameCommandLine.check(
        "javaw.exe -javaagent:C:/temp/inject.jar -Xbootclasspath/a:C:/temp/patch.jar -jar game.jar");
    check("-javaagent HIGH", f2.stream().anyMatch(x -> x.flag().equals("-javaagent") && x.severity() == Severity.HIGH));
    check("-Xbootclasspath HIGH",
        f2.stream().anyMatch(x -> x.flag().equals("-Xbootclasspath") && x.severity() == Severity.HIGH));

    List<GameCommandLine.Flag> f3 = GameCommandLine.check(
        "javaw.exe --tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker --username Steve");
    check("tweaker Forge standard = nessun finding", f3.isEmpty());

    List<GameCommandLine.Flag> f4 = GameCommandLine.check(
        "javaw.exe --tweakClass ghost.client.Tweaker --username Steve");
    check("tweaker sconosciuto = MEDIUM",
        f4.stream().anyMatch(x -> x.flag().equals("--tweakClass") && x.severity() == Severity.MEDIUM));

    List<GameCommandLine.Flag> f5 = GameCommandLine.check(
        "javaw.exe -cp C:/Users/x/.minecraft/libraries/a.jar;C:/temp/ghost.jar net.minecraft.client.main.Main");
    check("classpath con voce fuori dai launcher noti = MEDIUM",
        f5.stream().anyMatch(x -> x.flag().equals("-cp") && x.severity() == Severity.MEDIUM));

    List<GameCommandLine.Flag> f6 = GameCommandLine.check(
        "javaw.exe -cp C:/Users/x/.minecraft/libraries/a.jar;C:/Users/x/.minecraft/versions/1.20.1/1.20.1.jar"
            + " net.minecraft.client.main.Main --username Steve");
    check("classpath del launcher standard = nessun finding",
        f6.stream().noneMatch(x -> x.flag().equals("-cp")));

    List<GameCommandLine.Flag> f7 = GameCommandLine.check("javaw.exe -Xmx2G --username Steve");
    check("riga di comando pulita = zero finding", f7.isEmpty());
  }

  /* ------------------------------------------------------------ CheatArtifacts */

  static void cheatArtifacts() throws Exception {
    Path gameDir = Files.createTempDirectory("rt-artifacts");
    Files.createDirectories(gameDir.resolve(".meteor-client"));
    Files.createDirectories(gameDir.resolve("config"));
    Files.write(gameDir.resolve("config").resolve("rusherhack.json"), "{}".getBytes(StandardCharsets.UTF_8));
    Files.createDirectories(gameDir.resolve("config").resolve("sodium-options.json.tmpdir")); // non deve matchare
    Files.write(gameDir.resolve("usercache.json"), "[]".getBytes(StandardCharsets.UTF_8));

    List<CheatArtifacts.Artifact> found = CheatArtifacts.scan(gameDir);
    Set<String> paths = new HashSet<>();
    for (CheatArtifacts.Artifact x : found) {
      paths.add(x.path().replace('\\', '/'));
    }
    check("regole caricate dal classpath (almeno un match)", !found.isEmpty());
    check("cartella .meteor-client rilevata", paths.contains(".meteor-client"));
    check("config/rusherhack.json rilevata (prefix)", paths.contains("config/rusherhack.json"));
    check("nessun falso positivo su file generici",
        !paths.toString().contains("usercache") && !paths.toString().contains("sodium-options"));

    List<CheatArtifacts.Artifact> none = CheatArtifacts.scan(null);
    check("gameDir nullo = lista vuota", none.isEmpty());
  }

  /* ------------------------------------------------------------ percorsi */

  static void paths() throws Exception {
    Path game = Files.createTempDirectory("rt-paths");
    Path mods = Files.createDirectories(game.resolve("mods"));
    Files.createDirectories(game.resolve("logs"));
    Files.write(game.resolve("options.txt"), new byte[0]);
    Files.createDirectories(game.resolve("mods").resolve("1.20.1"));

    check("cartella di gioco con mods/ risolta in <gioco>/mods",
        MinecraftPathResolver.resolveModsDir(game).equals(mods.toAbsolutePath().normalize()));
    check("cartella mods lasciata com'è",
        MinecraftPathResolver.resolveModsDir(mods).equals(mods.toAbsolutePath().normalize()));
    check("cartella qualsiasi lasciata com'è",
        MinecraftPathResolver.resolveModsDir(game.resolve("custom")).equals(
            game.resolve("custom").toAbsolutePath().normalize()));
    check("null gestito", MinecraftPathResolver.resolveModsDir(null) == null);

    check("gameDir da <gioco>/mods", MinecraftPathResolver.gameDirOfMods(mods).equals(
        game.toAbsolutePath().normalize()));
    check("gameDir da <gioco>/mods/<profilo> risale all'istanza",
        MinecraftPathResolver.gameDirOfMods(mods.resolve("1.20.1")).equals(game.toAbsolutePath().normalize()));
    check("gameDir di una cartella custom dentro l'istanza",
        MinecraftPathResolver.gameDirOfMods(Files.createDirectories(game.resolve("custom-mods")))
            .equals(game.toAbsolutePath().normalize()));
    check("<gioco> riconosciuto dai marcatori", MinecraftPathResolver.looksLikeGameDir(game));
    check("cartella vuota non è una game dir",
        !MinecraftPathResolver.looksLikeGameDir(Files.createTempDirectory("rt-not-game")));
    check("gameDir nullo", MinecraftPathResolver.gameDirOfMods(null) == null);

    check("modsDirOf conserva il separatore Windows",
        MinecraftPathResolver.modsDirOf("C:\\Users\\x\\.minecraft").equals("C:\\Users\\x\\.minecraft\\mods"));
    check("modsDirOf conserva il separatore Unix",
        MinecraftPathResolver.modsDirOf("/home/x/.minecraft").equals("/home/x/.minecraft/mods"));

    List<MinecraftPathResolver.Hint> hints = MinecraftPathResolver.resolve(
        "javaw.exe --gameDir C:\\Users\\x\\.minecraft -Dminecraft.applet.TargetDirectory=C:\\Users\\x\\.minecraft",
        null);
    check("--gameDir ha la precedenza", !hints.isEmpty()
        && hints.get(0).source.contains("gameDir") && hints.get(0).confidence == 95);
    check("stessa cartella da fonti diverse non duplicata", hints.size() == 1);
    check("command line di un altro programma Java non è Minecraft",
        !MinecraftPathResolver.looksLikeMinecraft("java -jar server.jar"));
    check("client Fabric riconosciuto",
        MinecraftPathResolver.looksLikeMinecraft("javaw.exe net.fabricmc.loader.impl.launch.knot.KnotClient"));
  }

  /* ------------------------------------------------------------ helper jar */

  static void writeJar(Path file, String entry, String content) throws Exception {
    try (JarOutputStream j = new JarOutputStream(Files.newOutputStream(file))) {
      j.putNextEntry(new JarEntry(entry));
      j.write(content.getBytes(StandardCharsets.UTF_8));
      j.closeEntry();
    }
  }

  static void writeEntryJar(Path file, String entry, byte[] content) throws Exception {
    try (ZipOutputStream j = new ZipOutputStream(Files.newOutputStream(file))) {
      j.putNextEntry(new ZipEntry(entry));
      j.write(content);
      j.closeEntry();
    }
  }

  static byte[] nestedJar(String entry, String content) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (JarOutputStream j = new JarOutputStream(bos)) {
      j.putNextEntry(new JarEntry(entry));
      j.write(content.getBytes(StandardCharsets.UTF_8));
      j.closeEntry();
    }
    return bos.toByteArray();
  }
}
