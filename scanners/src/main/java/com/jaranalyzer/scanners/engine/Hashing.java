package com.jaranalyzer.scanners.engine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hash di file in streaming (mai {@code readAllBytes} sul file intero).
 * Usato da tutti i moduli: un solo passaggio per SHA-256 (+SHA-1 dove serve).
 */
public final class Hashing {
    private static final int BUFFER = 65536;

    private Hashing() {
    }

    public static String sha256(Path file) throws IOException {
        return hex(digest(file, "SHA-256"));
    }

    /** SHA-1 in streaming (Modrinth identifica i file con SHA-1: non sostituire). */
    public static String sha1(Path file) throws IOException {
        return hex(digest(file, "SHA-1"));
    }

    /** @return {sha256, sha1} con un'unica lettura (cartella mods: Modrinth usa SHA-1). */
    public static String[] sha256AndSha1(Path file) throws IOException {
        MessageDigest sha256 = digest("SHA-256");
        MessageDigest sha1 = digest("SHA-1");
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[BUFFER];
            int n;
            while ((n = in.read(buf)) != -1) {
                sha256.update(buf, 0, n);
                sha1.update(buf, 0, n);
            }
        }
        return new String[] { hex(sha256.digest()), hex(sha1.digest()) };
    }

    public static String sha256(byte[] bytes) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] digest(Path file, String algorithm) throws IOException {
        MessageDigest md = digest(algorithm);
        try (InputStream in = Files.newInputStream(file);
                DigestInputStream dis = new DigestInputStream(in, md)) {
            byte[] buf = new byte[BUFFER];
            while (dis.read(buf) != -1) {
            }
        }
        return md.digest();
    }

    private static MessageDigest digest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
