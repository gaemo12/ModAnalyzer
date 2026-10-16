import com.jaranalyzer.scanners.*;
import com.jaranalyzer.scanners.engine.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Self-test di ArchiveIntegrityAnalyzer (stile progetto, zero dipendenze):
 * zip costruiti a mano, positivi e negativi per controllo.
 * Esecuzione: scripts/run-selftests.bat (o javac + java -cp ... ArchiveIntegritySelfTest).
 */
public class ArchiveIntegritySelfTest {
  static int fails = 0;
  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }
  static Path tmp;

  public static void main(String[] a) throws Exception {
    tmp = Files.createTempDirectory("arc-test");
    ArchiveIntegrityAnalyzer analyzer = new ArchiveIntegrityAnalyzer();

    check("zip-slip ../ rilevato", hasRule(analyzer, zipOf(
        entry("../evil.txt", "x")), "zip-slip-path"));
    check("percorso assoluto rilevato", hasRule(analyzer, zipOf(
        entry("/etc/cron.d/x", "x")), "zip-slip-path"));
    check("dati accodati rilevati", hasRule(analyzer,
        appended(zipOf(entry("a.txt", "ciao")), 100), "zip-trailing-data"));
    check("MZ sotto .txt rilevato", hasRule(analyzer,
        zipOf(rawEntry("data.txt", mz())), "exe-magic-wrong-extension"));
    check("nomi duplicati rilevati", hasRule(analyzer,
        zipStored(List.of(entry("dup.txt", "1"), entry("dup.txt", "2"))), "zip-duplicate-names"));
    check("collisione case rilevata", hasRule(analyzer, zipOf(
        entry("Readme.txt", "1"), entry("README.txt", "2")), "zip-case-collision"));
    check("classe fuori .class rilevata", hasRule(analyzer,
        zipOf(rawEntry("res.dat", cafebabe())), "class-magic-wrong-extension"));
    check("jar pulito: zero finding", analyzer.analyze(
        zipOf(entry("A.txt", "ciao"), entry("lib/util.json", "{}"))).isEmpty());

    System.out.println(fails == 0 ? "ARCHIVE-SELFTEST PASS" : "ARCHIVE-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }

  static boolean hasRule(ArchiveIntegrityAnalyzer an, File jar, String rule) throws Exception {
    for (Finding f : an.analyze(jar)) {
      if (rule.equals(f.getRuleName())) return true;
    }
    System.out.println("  regole viste: " + an.analyze(jar).stream()
        .map(Finding::getRuleName).toList());
    return false;
  }

  record Raw(String name, byte[] data) {}
  static Raw entry(String name, String text) {
    return new Raw(name, text.getBytes(StandardCharsets.UTF_8));
  }
  static Raw rawEntry(String name, byte[] data) {
    return new Raw(name, data);
  }
  static byte[] mz() {
    byte[] b = new byte[64];
    b[0] = 0x4D; b[1] = 0x5A;
    return b;
  }
  static byte[] cafebabe() {
    return new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 52};
  }

  static File zipOf(Raw... entries) throws Exception {
    Path p = Files.createTempFile(tmp, "t", ".jar");
    try (java.util.zip.ZipOutputStream z =
        new java.util.zip.ZipOutputStream(Files.newOutputStream(p))) {
      for (Raw r : entries) {
        z.putNextEntry(new java.util.zip.ZipEntry(r.name()));
        z.write(r.data());
        z.closeEntry();
      }
    }
    return p.toFile();
  }

  static File appended(File zip, int extra) throws Exception {
    Path p = Files.createTempFile(tmp, "t", ".jar");
    byte[] base = Files.readAllBytes(zip.toPath());
    byte[] out = Arrays.copyOf(base, base.length + extra);
    Arrays.fill(out, base.length, out.length, (byte) 0x41);
    Files.write(p, out);
    return p.toFile();
  }

  /** Writer zip minimo (STORED): ZipOutputStream rifiuta i nomi duplicati. */
  static File zipStored(List<Raw> entries) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    List<long[]> index = new ArrayList<>(); // offset locale per entry
    for (Raw r : entries) {
      index.add(new long[] {out.size()});
      byte[] name = r.name().getBytes(StandardCharsets.UTF_8);
      java.util.zip.CRC32 crc = new java.util.zip.CRC32();
      crc.update(r.data());
      le32(out, 0x04034B50);
      le16(out, 20); le16(out, 0); le16(out, 0); le16(out, 0); le16(out, 0);
      le32(out, (int) crc.getValue());
      le32(out, r.data().length); le32(out, r.data().length);
      le16(out, name.length); le16(out, 0);
      out.write(name);
      out.write(r.data());
    }
    long cdOff = out.size();
    for (int i = 0; i < entries.size(); i++) {
      Raw r = entries.get(i);
      byte[] name = r.name().getBytes(StandardCharsets.UTF_8);
      java.util.zip.CRC32 crc = new java.util.zip.CRC32();
      crc.update(r.data());
      le32(out, 0x02014B50);
      le16(out, 20); le16(out, 20); le16(out, 0); le16(out, 0); le16(out, 0); le16(out, 0);
      le32(out, (int) crc.getValue());
      le32(out, r.data().length); le32(out, r.data().length);
      le16(out, name.length); le16(out, 0); le16(out, 0);
      le16(out, 0); le16(out, 0); le32(out, 0);
      le32(out, (int) index.get(i)[0]);
      out.write(name);
    }
    long cdSize = out.size() - cdOff;
    le32(out, 0x06054B50);
    le16(out, 0); le16(out, 0);
    le16(out, entries.size()); le16(out, entries.size());
    le32(out, (int) cdSize); le32(out, (int) cdOff);
    le16(out, 0);
    Path p = Files.createTempFile(tmp, "t", ".jar");
    Files.write(p, out.toByteArray());
    return p.toFile();
  }

  static void le16(ByteArrayOutputStream o, int v) {
    o.write(v & 0xFF);
    o.write((v >>> 8) & 0xFF);
  }

  static void le32(ByteArrayOutputStream o, long v) {
    o.write((int) (v & 0xFF));
    o.write((int) ((v >>> 8) & 0xFF));
    o.write((int) ((v >>> 16) & 0xFF));
    o.write((int) ((v >>> 24) & 0xFF));
  }
}
