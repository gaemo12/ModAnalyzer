package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import java.io.File;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Integrità dell'archivio (report revisione, sez. 2): quello che
 * Manifest/Structure non coprono. Economico e quasi senza falsi positivi:
 *
 * <ul>
 *   <li>payload accodato dopo l'EOCD, dati prima del primo header;</li>
 *   <li>nomi con {@code ..} o assoluti (zip-slip);</li>
 *   <li>nomi duplicati / collisioni di maiuscole;</li>
 *   <li>conteggio local header vs central directory (parser differential);</li>
 *   <li>magia contro estensione (eseguibile con estensione ingannevole).</li>
 * </ul>
 */
public class ArchiveIntegrityAnalyzer implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(ArchiveIntegrityAnalyzer.class);
    private static final int MAX_EVIDENCE_NAMES = 10;
    /** Oltre questa taglia si saltano le scansioni raw dell'intero file. */
    private static final long MAX_RAW_SCAN_BYTES = 64L * 1024 * 1024;

    @Override
    public String getName() {
        return "Archive Integrity";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        List<Finding> findings = new ArrayList<>();
        log.info("Starting archive integrity analysis on {}", jarFile.getName());
        checkRawLayout(jarFile, findings);
        checkNames(jarFile, findings);
        checkMagic(jarFile, findings);
        log.info("Archive integrity complete - {} finding(s)", findings.size());
        return findings;
    }

    /* ---------- layout raw (EOCD, header) ---------- */

    private void checkRawLayout(File jarFile, List<Finding> findings) {
        long len = jarFile.length();
        if (len < 22 || len > MAX_RAW_SCAN_BYTES) {
            return;
        }
        try (RandomAccessFile f = new RandomAccessFile(jarFile, "r")) {
            int tailLen = (int) Math.min(len, 70000);
            byte[] tail = new byte[tailLen];
            f.seek(len - tailLen);
            f.readFully(tail);
            int eocd = -1;
            for (int i = tailLen - 22; i >= 0; i--) {
                if (tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) {
                return; // non è uno zip leggibile: ci pensa JarFile
            }
            int comment = (tail[eocd + 20] & 0xFF) | ((tail[eocd + 21] & 0xFF) << 8);
            long trailing = (long) tailLen - (eocd + 22 + comment);
            if (trailing > 0) {
                findings.add(new Finding.Builder().ruleName("zip-trailing-data")
                        .title("Dati accodati dopo l'archivio (" + trailing + " byte)")
                        .description("Dopo la fine della directory centrale ci sono byte extra: payload accodato allo zip.")
                        .severity(Severity.HIGH).category(Category.STRUCTURE)
                        .location(jarFile.getName()).evidence("Byte dopo EOCD+commento: " + trailing)
                        .family("archive-integrity").build());
            }
            int centralCount = (tail[eocd + 10] & 0xFF) | ((tail[eocd + 11] & 0xFF) << 8);
            byte[] head = new byte[4];
            f.seek(0);
            f.readFully(head);
            boolean startsWithPk = head[0] == 0x50 && head[1] == 0x4B;
            int localCount = countLocalHeaders(f, len);
            if (localCount >= 0 && centralCount != localCount) {
                findings.add(new Finding.Builder().ruleName("zip-header-count-mismatch")
                        .title("Local header e directory centrale non concordano")
                        .description("Parser diversi vedono contenuti diversi: possibile archivio ambiguo costruito ad arte.")
                        .severity(Severity.MEDIUM).category(Category.STRUCTURE)
                        .location(jarFile.getName())
                        .evidence("Local headers: " + localCount + ", central directory: " + centralCount)
                        .family("archive-integrity").build());
            }
            if (!startsWithPk && localCount > 0) {
                findings.add(new Finding.Builder().ruleName("zip-leading-data")
                        .title("Dati prima del primo header zip")
                        .description("Il file non inizia con un header zip ma contiene voci valide: possibile polyglot.")
                        .severity(Severity.LOW).category(Category.STRUCTURE)
                        .location(jarFile.getName()).evidence("Primi 4 byte non PK, voci locali: " + localCount)
                        .family("archive-integrity").build());
            }
        } catch (Exception e) {
            log.debug("checkRawLayout fallito per {}: {}", jarFile.getName(), e.getMessage());
        }
    }

    /** Conta le firme PK\x03\x04 (con controllo versione minima anti-rumore). */
    private int countLocalHeaders(RandomAccessFile f, long len) {
        try {
            int n = 0;
            byte[] buf = new byte[8192];
            long pos = 0;
            int carry = 0;
            f.seek(0);
            while (pos < len) {
                int r = f.read(buf);
                if (r <= 0) {
                    break;
                }
                for (int i = 0; i < r; i++) {
                    byte b = buf[i];
                    if (carry == 0 && b == 0x50) {
                        carry = 1;
                    } else if (carry == 1 && b == 0x4B) {
                        carry = 2;
                    } else if (carry == 2 && b == 0x03) {
                        carry = 3;
                    } else if (carry == 3 && b == 0x04) {
                        n++;
                        carry = 0;
                    } else {
                        carry = b == 0x50 ? 1 : 0;
                    }
                }
                pos += r;
            }
            return n;
        } catch (Exception e) {
            return -1;
        }
    }

    /* ---------- nomi entry ---------- */

    private void checkNames(File jarFile, List<Finding> findings) {
        List<String> slip = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Map<String, String> folded = new HashMap<>();
        List<String> dups = new ArrayList<>();
        List<String> collisions = new ArrayList<>();
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (e.isDirectory()) {
                    continue;
                }
                String name = e.getName();
                if (isSlip(name) && slip.size() < MAX_EVIDENCE_NAMES) {
                    slip.add(name);
                }
                if (!seen.add(name) && dups.size() < MAX_EVIDENCE_NAMES && !dups.contains(name)) {
                    dups.add(name);
                }
                String key = name.toLowerCase(Locale.ROOT);
                String other = folded.putIfAbsent(key, name);
                if (other != null && !other.equals(name) && collisions.size() < MAX_EVIDENCE_NAMES
                        && !collisions.contains(name + " <> " + other)) {
                    collisions.add(name + " <> " + other);
                }
            }
        } catch (Exception e) {
            log.debug("checkNames fallito per {}: {}", jarFile.getName(), e.getMessage());
            return;
        }
        if (!slip.isEmpty()) {
            findings.add(new Finding.Builder().ruleName("zip-slip-path")
                    .title("Nomi con traversamento (" + slip.size() + ")")
                    .description("Voci con '..' o percorsi assoluti: estrazione non sicura (zip-slip).")
                    .severity(Severity.HIGH).category(Category.STRUCTURE)
                    .location(slip.get(0)).evidence(join(slip)).family("archive-integrity").build());
        }
        if (!dups.isEmpty()) {
            findings.add(new Finding.Builder().ruleName("zip-duplicate-names")
                    .title("Voci duplicate (" + dups.size() + ")")
                    .description("Stesso nome più volte: lettori diversi estraggono contenuti diversi.")
                    .severity(Severity.MEDIUM).category(Category.STRUCTURE)
                    .location(dups.get(0)).evidence(join(dups)).family("archive-integrity").build());
        }
        if (!collisions.isEmpty()) {
            findings.add(new Finding.Builder().ruleName("zip-case-collision")
                    .title("Collisioni maiuscole/minuscole (" + collisions.size() + ")")
                    .description("Nomi uguali a meno del case: su Windows/macOS si sovrascrivono.")
                    .severity(Severity.MEDIUM).category(Category.STRUCTURE)
                    .location(collisions.get(0)).evidence(join(collisions)).family("archive-integrity").build());
        }
    }

    private static boolean isSlip(String name) {
        String n = name.replace('\\', '/');
        if (n.startsWith("/") || n.length() > 2 && Character.isLetter(n.charAt(0)) && n.charAt(1) == ':') {
            return true;
        }
        for (String seg : n.split("/", -1)) {
            if (seg.equals("..")) {
                return true;
            }
        }
        return false;
    }

    /* ---------- magia contro estensione ---------- */

    private void checkMagic(File jarFile, List<Finding> findings) {
        List<String> exeMismatch = new ArrayList<>();
        List<String> zipMismatch = new ArrayList<>();
        List<String> classMismatch = new ArrayList<>();
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (e.isDirectory()) {
                    continue;
                }
                long size = e.getSize();
                if (size < 4 || size > 32L * 1024 * 1024) {
                    continue;
                }
                String lower = e.getName().toLowerCase(Locale.ROOT);
                byte[] head = new byte[8];
                int read;
                try (java.io.InputStream in = jar.getInputStream(e)) {
                    read = in.read(head);
                } catch (Exception ex) {
                    continue;
                }
                if (read < 4) {
                    continue;
                }
                if (head[0] == 0x4D && head[1] == 0x5A) {
                    if (!lower.endsWith(".exe") && !lower.endsWith(".dll") && !lower.endsWith(".sys")
                            && !lower.endsWith(".scr") && !lower.endsWith(".cpl") && !lower.endsWith(".ocx")
                            && exeMismatch.size() < MAX_EVIDENCE_NAMES) {
                        exeMismatch.add(e.getName());
                    }
                } else if (head[0] == 0x7F && head[1] == 0x45 && head[2] == 0x4C && head[3] == 0x46) {
                    if (!lower.endsWith(".so") && !lower.endsWith(".elf") && exeMismatch.size() < MAX_EVIDENCE_NAMES) {
                        exeMismatch.add(e.getName() + " (ELF)");
                    }
                } else if (head[0] == 0x50 && head[1] == 0x4B) {
                    if (!lower.endsWith(".jar") && !lower.endsWith(".zip") && !lower.endsWith(".apk")
                            && !lower.endsWith(".aar") && !lower.endsWith(".whl") && !lower.endsWith(".nupkg")
                            && zipMismatch.size() < MAX_EVIDENCE_NAMES) {
                        zipMismatch.add(e.getName());
                    }
                } else if (head[0] == (byte) 0xCA && head[1] == (byte) 0xFE
                        && head[2] == (byte) 0xBA && head[3] == (byte) 0xBE) {
                    if (!lower.endsWith(".class") && classMismatch.size() < MAX_EVIDENCE_NAMES) {
                        classMismatch.add(e.getName());
                    }
                }
            }
        } catch (Exception e) {
            log.debug("checkMagic fallito per {}: {}", jarFile.getName(), e.getMessage());
            return;
        }
        if (!exeMismatch.isEmpty()) {
            findings.add(new Finding.Builder().ruleName("exe-magic-wrong-extension")
                    .title("Eseguibile con estensione ingannevole (" + exeMismatch.size() + ")")
                    .description("Magia MZ/ELF ma estensione non da eseguibile: binario mascherato.")
                    .severity(Severity.HIGH).category(Category.STRUCTURE)
                    .location(exeMismatch.get(0)).evidence(join(exeMismatch)).family("archive-integrity").build());
        }
        if (!zipMismatch.isEmpty()) {
            findings.add(new Finding.Builder().ruleName("zip-magic-wrong-extension")
                    .title("Archivio con estensione ingannevole (" + zipMismatch.size() + ")")
                    .description("Magia PK ma estensione non da archivio: jar annidato mascherato.")
                    .severity(Severity.MEDIUM).category(Category.STRUCTURE)
                    .location(zipMismatch.get(0)).evidence(join(zipMismatch)).family("archive-integrity").build());
        }
        if (!classMismatch.isEmpty()) {
            findings.add(new Finding.Builder().ruleName("class-magic-wrong-extension")
                    .title("Classe con estensione ingannevole (" + classMismatch.size() + ")")
                    .description("Magia CAFEBABE fuori da un .class: bytecode mascherato da risorsa.")
                    .severity(Severity.HIGH).category(Category.STRUCTURE)
                    .location(classMismatch.get(0)).evidence(join(classMismatch)).family("archive-integrity").build());
        }
    }

    private static String join(List<String> names) {
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            sb.append(n).append('\n');
        }
        return sb.toString().trim();
    }
}
