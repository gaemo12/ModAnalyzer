import com.jaranalyzer.common.ModuleResult;
import com.jaranalyzer.scanners.*;
import com.jaranalyzer.scanners.engine.*;
import com.jaranalyzer.scanners.modules.*;
import java.io.*;
import java.lang.management.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Benchmark manuale del motore (NON in CI: tempi/macchina dipendono dall'ambiente).
 * Esecuzione: {@code java -cp <test-cp> PerfBench [casi...]} dalla root del repo.
 * Stampa per ogni caso: dimensione/entry, durata ms, esito, limiti attivati,
 * heap usata dopo GC. Confrontare prima/dopo le modifiche a parità di macchina.
 */
public class PerfBench {
  static Path work;
  static SignatureSet sigs;
  static int ran = 0;

  public static void main(String[] a) throws Exception {
    Set<String> only = new HashSet<>(Arrays.asList(a));
    work = Files.createTempDirectory("perfbench");
    sigs = BuiltinSignatures.load();
    System.out.println("work=" + work + " maxHeap=" + (Runtime.getRuntime().maxMemory() / 1048576) + "MB");
    bench("A.many-entries", only, () -> {
      Path jar = makeJar("a.jar", 3000, 2048, false);
      return runSingle(jar);
    });
    bench("B.big-60MB", only, () -> {
      Path jar = makeJarBytes("b.jar", 60L * 1024 * 1024);
      return runSingle(jar);
    });
    bench("C.tiny-20k", only, () -> {
      Path jar = makeJar("c.jar", 20000, 64, false);
      return runSingle(jar);
    });
    bench("D.big-entry-150MB", only, () -> {
      Path jar = makeJarBigEntry("d.jar", 150L * 1024 * 1024);
      return runSingle(jar);
    });
    bench("E.corrupt", only, () -> {
      Path jar = work.resolve("e.jar");
      byte[] junk = new byte[100000];
      new Random(7).nextBytes(junk);
      Files.write(jar, junk);
      return runSingle(jar);
    });
    bench("F.truncated", only, () -> {
      Path src = makeJar("f-src.jar", 200, 4096, false);
      byte[] all = Files.readAllBytes(src);
      Path jar = work.resolve("f.jar");
      Files.write(jar, Arrays.copyOf(all, all.length / 2));
      return runSingle(jar);
    });
    bench("G.mods-300", only, () -> {
      Path dir = Files.createDirectory(work.resolve("mods"));
      Path proto = makeJar("proto.jar", 20, 2048, false);
      byte[] pb = Files.readAllBytes(proto);
      for (int i = 0; i < 300; i++) Files.write(dir.resolve("mod-" + i + ".jar"), pb);
      return runMods(dir);
    });
    bench("H.regex-obfuscation", only, () -> {
      // Costo del matching nomi su molte classi: prima/dopo l'hoisting del Pattern.
      Path jar = makeJar("h.jar", 20000, 128, true);
      return runSingle(jar);
    });
    System.out.println("casi eseguiti=" + ran + " (fixture in " + work + ", cancellare a mano)");
  }

  interface Case { String run() throws Exception; }

  static void bench(String name, Set<String> only, Case c) {
    if (!only.isEmpty() && only.stream().noneMatch(name::startsWith)) return;
    ran++;
    gc();
    long heap0 = usedHeap();
    long t0 = System.currentTimeMillis();
    String outcome;
    try {
      outcome = c.run();
    } catch (Throwable e) {
      outcome = "THREW " + e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
    }
    long dt = System.currentTimeMillis() - t0;
    gc();
    long heap1 = usedHeap();
    System.out.println(String.format("BENCH %-16s %8dms heap %6dMB->%6dMB  %s",
        name, dt, heap0 / 1048576, heap1 / 1048576, outcome));
  }

  static String runSingle(Path jar) throws Exception {
    long entries = countEntries(jar);
    long t0 = System.currentTimeMillis();
    ModuleResult r;
    try {
      r = ScanModules.byId("single_jar").run(new ScanContext.JarFileContext(jar),
          ProgressSink.noop(), sigs);
    } catch (ScanException e) {
      return "entries~" + entries + " FATAL(" + e.kind() + "): " + e.getMessage();
    }
    long dt = System.currentTimeMillis() - t0;
    int findings = r.findings().size();
    return "entries~" + entries + " success=" + r.success() + " findings=" + findings
        + " errors=" + r.counters().getOrDefault("analyzerErrors", 0L) + " scanMs=" + dt;
  }

  static String runMods(Path dir) throws Exception {
    long t0 = System.currentTimeMillis();
    ModuleResult r;
    try {
      r = ScanModules.byId("mods_folder").run(new ScanContext.DirectoryContext(dir),
          ProgressSink.noop(), sigs);
    } catch (ScanException e) {
      return "FATAL(" + e.kind() + "): " + e.getMessage();
    }
    long dt = System.currentTimeMillis() - t0;
    return "success=" + r.success() + " findings=" + r.findings().size() + " scanMs=" + dt
        + " counters=" + r.counters();
  }

  /** Jar con N classi valide (riusa il bytecode di questa stessa classe). */
  static Path makeJar(String name, int classes, int padTo, boolean trickyNames) throws Exception {
    byte[] cls;
    try (InputStream in = PerfBench.class.getResourceAsStream("PerfBench.class")) {
      cls = in.readAllBytes();
    }
    Path jar = work.resolve(name);
    String[] tricky = {"a", "b", "IIl1O0", "\u00e9\u00e8"};
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
      ZipEntry man = new ZipEntry("META-INF/MANIFEST.MF");
      zos.putNextEntry(man);
      zos.write("Manifest-Version: 1.0\n".getBytes(StandardCharsets.UTF_8));
      zos.closeEntry();
      for (int i = 0; i < classes; i++) {
        String n = trickyNames ? ("p/C" + tricky[i % tricky.length] + i + ".class")
                               : ("com/example/Class" + i + ".class");
        zos.putNextEntry(new ZipEntry(n));
        zos.write(cls);
        if (padTo > cls.length) {
          // Commento in coda alla entry (resta un .class valido per ASM: ignora i byte extra).
          byte[] pad = new byte[padTo - cls.length];
          new Random(i).nextBytes(pad);
          zos.write(pad);
        }
        zos.closeEntry();
      }
    }
    return jar;
  }

  /** Jar di dimensione totale approssimativa (entry casuali non comprimibili). */
  static Path makeJarBytes(String name, long total) throws Exception {
    Path jar = work.resolve(name);
    Random rnd = new Random(3);
    byte[] buf = new byte[1 << 20];
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
      zos.setLevel(0);
      long left = total;
      int i = 0;
      while (left > 0) {
        int n = (int) Math.min(buf.length, left);
        rnd.nextBytes(buf);
        zos.putNextEntry(new ZipEntry("data/blob" + (i++) + ".bin"));
        zos.write(buf, 0, n);
        zos.closeEntry();
        left -= n;
      }
      ZipEntry man = new ZipEntry("META-INF/MANIFEST.MF");
      zos.putNextEntry(man);
      zos.write("Manifest-Version: 1.0\n".getBytes(StandardCharsets.UTF_8));
      zos.closeEntry();
    }
    return jar;
  }

  /** Una entry .class da N byte di zeri (dichiarati e reali: stressa i cap pre-read). */
  static Path makeJarBigEntry(String name, long size) throws Exception {
    Path jar = work.resolve(name);
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
      zos.setLevel(0);
      zos.putNextEntry(new ZipEntry("com/example/Big.class"));
      byte[] buf = new byte[1 << 20];
      long left = size;
      while (left > 0) {
        int n = (int) Math.min(buf.length, left);
        zos.write(buf, 0, n);
        left -= n;
      }
      zos.closeEntry();
    }
    return jar;
  }

  static long countEntries(Path jar) {
    try (ZipFile zf = new ZipFile(jar.toFile())) {
      return zf.stream().filter(e -> !e.isDirectory()).count();
    } catch (Exception e) {
      return -1;
    }
  }

  static void gc() {
    for (int i = 0; i < 3; i++) System.gc();
    try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
  }

  static long usedHeap() {
    MemoryMXBean mx = ManagementFactory.getMemoryMXBean();
    return mx.getHeapMemoryUsage().getUsed();
  }
}
