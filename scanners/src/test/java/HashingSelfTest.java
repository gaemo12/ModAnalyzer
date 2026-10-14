import com.jaranalyzer.scanners.engine.Hashing;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Hash streaming (Fase 6): confronto esatto con il riferimento one-shot
 * su file vuoti, piccoli, binari e grandi; errori filesystem espliciti.
 * Esecuzione: `java -cp ... HashingSelfTest`.
 */
public class HashingSelfTest {
    static int fails = 0;

    static void check(String n, boolean ok) {
        System.out.println((ok ? "OK   " : "FAIL ") + n);
        if (!ok) fails++;
    }

    static String ref(String alg, byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance(alg).digest(b);
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte x : d) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    public static void main(String[] a) throws Exception {
        Path dir = Files.createTempDirectory("hashing");
        // Vuoto.
        Path empty = Files.write(dir.resolve("empty.bin"), new byte[0]);
        check("sha256 vuoto", Hashing.sha256(empty).equals(ref("SHA-256", new byte[0])));
        check("sha1 vuoto", Hashing.sha1(empty).equals(ref("SHA-1", new byte[0])));
        String[] both = Hashing.sha256AndSha1(empty);
        check("doppio vuoto", both[0].equals(ref("SHA-256", new byte[0])) && both[1].equals(ref("SHA-1", new byte[0])));
        // Piccolo testo con non-ASCII.
        byte[] small = "ciao mondo \u00e0\u00e8\u00e9\u00f2\u00f9".getBytes(StandardCharsets.UTF_8);
        Path smallF = Files.write(dir.resolve("small.txt"), small);
        check("sha256 piccolo", Hashing.sha256(smallF).equals(ref("SHA-256", small)));
        check("sha1 piccolo", Hashing.sha1(smallF).equals(ref("SHA-1", small)));
        // Binario 3 MB + 123 byte (non multiplo del buffer interno 64 KB).
        byte[] bin = new byte[3 * 1024 * 1024 + 123];
        new Random(42).nextBytes(bin);
        Path binF = Files.write(dir.resolve("bin.dat"), bin);
        check("sha256 binario", Hashing.sha256(binF).equals(ref("SHA-256", bin)));
        check("sha1 binario", Hashing.sha1(binF).equals(ref("SHA-1", bin)));
        String[] bothBin = Hashing.sha256AndSha1(binF);
        check("doppio binario in un passaggio", bothBin[0].equals(ref("SHA-256", bin)) && bothBin[1].equals(ref("SHA-1", bin)));
        // Grande 20 MB (streaming: confronto esatto, nessuna copia integrale nel chiamante).
        Path big = dir.resolve("big.dat");
        byte[] blk = new byte[1 << 20];
        MessageDigest ref256 = MessageDigest.getInstance("SHA-256");
        MessageDigest ref1 = MessageDigest.getInstance("SHA-1");
        Random rnd = new Random(7);
        try (java.io.OutputStream out = Files.newOutputStream(big)) {
            for (int i = 0; i < 20; i++) {
                rnd.nextBytes(blk);
                out.write(blk);
                ref256.update(blk);
                ref1.update(blk);
            }
        }
        StringBuilder e256 = new StringBuilder(), e1 = new StringBuilder();
        for (byte x : ref256.digest()) e256.append(String.format("%02x", x & 0xFF));
        for (byte x : ref1.digest()) e1.append(String.format("%02x", x & 0xFF));
        check("sha256 20MB", Hashing.sha256(big).equals(e256.toString()));
        check("sha1 20MB", Hashing.sha1(big).equals(e1.toString()));
        // Formato: 64/40 esadecimali minuscoli.
        check("formato sha256", Hashing.sha256(smallF).matches("[0-9a-f]{64}"));
        check("formato sha1", Hashing.sha1(smallF).matches("[0-9a-f]{40}"));
        // File mancante: errore esplicito, non stringa vuota.
        try {
            Hashing.sha256(dir.resolve("inesistente"));
            check("mancante lancia IOException", false);
        } catch (IOException e) {
            check("mancante lancia IOException", true);
        }
        if (fails > 0) {
            System.out.println("FAILURES=" + fails);
            System.exit(1);
        }
        System.out.println("TUTTO OK");
    }
}
