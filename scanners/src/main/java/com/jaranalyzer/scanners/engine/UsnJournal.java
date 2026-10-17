package com.jaranalyzer.scanners.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lettura del journal USN di NTFS (reimplementazione clean-room del controllo
 * "Modified after Minecraft Launch" di RedLotus Mod Analyzer 2.0). Solo comandi
 * {@code fsutil usn} in sola lettura, nessuna scrittura, nessun handle diretto
 * sul volume:
 * <ul>
 *   <li>{@code queryjournal} funziona senza privilegi (etichette in inglese
 *       anche su Windows localizzati; valori in esadecimale);</li>
 *   <li>{@code readjournal} richiede privilegi di amministratore: qui l'errore
 *       5 viene tradotto in {@link AccessDenied} e il chiamante degrada con
 *       una nota, mai un'eccezione verso la UI.</li>
 * </ul>
 *
 * <p>Ricerca per tempo: il journal è crescente, quindi l'USN di partenza per
 * un istante (l'avvio del gioco) si trova con una ricerca binaria che legge
 * solo il primo record di ogni sonda. Dopo l'avvio del gioco il numero di
 * record è limitato (ore di sessione), quindi la lettura completa finale ha
 * un budget e si interrompe in fretta.</p>
 */
public final class UsnJournal {

    /** Esito di {@code queryjournal}: id del journal e intervallo USN utile. */
    public record Query(long journalId, long firstUsn, long nextUsn) {
    }

    /** Un record del journal relativo a un file. */
    public record Event(long usn, String file, String reason, long timeMillis) {
    }

    /** Eventi letti (best-effort) e flag di troncamento per limite raggiunto. */
    public record Read(List<Event> events, boolean truncated) {
    }

    /** readjournal senza privilegi di amministratore. */
    public static final class AccessDenied extends Exception {
        public AccessDenied(String message) {
            super(message);
        }
    }

    /** Output console di fsutil: code page OEM (italiano = 850). */
    private static final Charset OEM = Charset.forName("IBM850");
    private static final Pattern HEX = Pattern.compile("0x[0-9a-fA-F]+");
    private static final Pattern TS = Pattern.compile("(\\d{4})-(\\d{2})-(\\d{2})[ T](\\d{2}):(\\d{2}):(\\d{2})");

    private UsnJournal() {
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static String fsutil() {
        String root = System.getenv("SystemRoot");
        if (root != null) {
            Path p = Path.of(root, "System32", "fsutil.exe");
            if (Files.isRegularFile(p)) {
                return p.toString();
            }
        }
        return "fsutil";
    }

    /**
     * {@code fsutil usn queryjournal <volume>}: mai eccezioni, null se il
     * volume non ha un journal USN o l'output non è interpretabile.
     */
    public static Query query(String volume) {
        List<String> lines = new ArrayList<>();
        try {
            exec(new String[] { fsutil(), "usn", "queryjournal", volume }, 8_000, l -> {
                lines.add(l);
                return true;
            });
        } catch (AccessDenied e) {
            return null;
        }
        long id = -1;
        long first = -1;
        long next = -1;
        for (String l : lines) {
            String ll = l.toLowerCase(Locale.ROOT).trim();
            Matcher m = HEX.matcher(l);
            if (!m.find()) {
                continue;
            }
            long v = parseHex(m.group());
            if (ll.startsWith("usn journal id")) {
                id = v;
            } else if (ll.startsWith("first usn")) {
                first = v;
            } else if (ll.startsWith("next usn")) {
                next = v;
            }
        }
        if (first < 0 || next < 0 || next <= first) {
            return null;
        }
        return new Query(id, first, next);
    }

    /**
     * Usn da cui iniziare a leggere per coprire {@code targetMillis}: ricerca
     * binaria sul primo record (l'avvio del gioco è di ore prima, i record
     * sono in ordine cronologico).
     */
    public static long usnForTime(String volume, long targetMillis, Query q, long probeBudgetMillis)
            throws AccessDenied {
        long lo = q.firstUsn();
        long hi = q.nextUsn();
        int guard = 0;
        while (lo < hi && guard++ < 64) {
            long mid = lo + (hi - lo) / 2;
            Long t = firstTimeAt(volume, mid, probeBudgetMillis);
            if (t == null) {
                hi = mid; // oltre la fine del journal (o record non leggibile)
            } else if (t < targetMillis) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /**
     * Legge i record dal journal a partire da {@code startUsn}, trattenendo
     * solo i file che passano {@code keep}. Budget di tempo e tetto eventi:
     * in ogni caso si esce senza bloccare la UI.
     */
    public static Read readEvents(String volume, long startUsn, Predicate<String> keep,
            long budgetMillis, int maxEvents) throws AccessDenied {
        List<Event> out = new ArrayList<>();
        boolean[] truncated = { false };
        String[] cur = new String[4]; // usn, file, reason, time
        runRead(volume, startUsn, budgetMillis, line -> {
            String t = line.trim();
            if (t.isEmpty()) {
                clear(cur);
                return true;
            }
            int c = t.indexOf(':');
            if (c < 0) {
                return true;
            }
            String label = t.substring(0, c).trim().toLowerCase(Locale.ROOT);
            String value = t.substring(c + 1).trim();
            if (label.equals("usn")) {
                clear(cur);
                cur[0] = value;
            } else if (label.startsWith("file name")) {
                cur[1] = value;
            } else if (label.startsWith("reason")) {
                cur[2] = value;
            } else if (label.startsWith("time stamp")) {
                cur[3] = value;
                if (cur[1] != null && keep.test(cur[1])) {
                    out.add(new Event(parseLong(cur[0]), cur[1], cur[2] == null ? "" : cur[2], parseTime(value)));
                    if (out.size() >= maxEvents) {
                        truncated[0] = true;
                        return false;
                    }
                }
            }
            return true;
        });
        return new Read(List.copyOf(out), truncated[0]);
    }

    private static void clear(String[] cur) {
        cur[0] = null;
        cur[1] = null;
        cur[2] = null;
        cur[3] = null;
    }

    private static Long firstTimeAt(String volume, long usn, long budgetMillis) throws AccessDenied {
        Long[] found = { null };
        runRead(volume, usn, budgetMillis, line -> {
            String t = line.trim();
            int c = t.indexOf(':');
            if (c > 0 && t.substring(0, c).trim().toLowerCase(Locale.ROOT).startsWith("time stamp")) {
                found[0] = parseTime(t.substring(c + 1).trim());
                return false; // basta il primo record
            }
            return true;
        });
        return found[0];
    }

    /**
     * readjournal con startusn decimale; se il processo fallisce subito senza
     * leggere record (parametro rifiutato), riprova in esadecimale.
     */
    private static void runRead(String volume, long startUsn, long budgetMillis, Predicate<String> onLine)
            throws AccessDenied {
        boolean[] sawRecord = { false };
        Predicate<String> probe = l -> {
            if (l.trim().toLowerCase(Locale.ROOT).startsWith("usn")) {
                sawRecord[0] = true;
            }
            return onLine.test(l);
        };
        int code = exec(new String[] { fsutil(), "usn", "readjournal", volume, "startusn=" + startUsn },
                budgetMillis, probe);
        if (code == 0 || sawRecord[0]) {
            return;
        }
        exec(new String[] { fsutil(), "usn", "readjournal", volume, "startusn=0x" + Long.toHexString(startUsn) },
                budgetMillis, onLine);
    }

    /**
     * Esegue il comando leggendo stdout+stderr riga per riga fino a budget o
     * stop del consumatore. Ritorna il codice di uscita (-1 se non disponibile,
     * -2 se interrotto per budget). Mai eccezioni per accesso negato: quella
     * diventa {@link AccessDenied} (righe "Error 5"/"Access is denied").
     */
    private static int exec(String[] cmd, long budgetMillis, Predicate<String> onLine) throws AccessDenied {
        Process proc = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            proc = pb.start();
            long deadline = System.nanoTime() + budgetMillis * 1_000_000L;
            try (BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream(), OEM))) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (denied(line)) {
                        destroy(proc);
                        throw new AccessDenied(line.trim());
                    }
                    if (!onLine.test(line)) {
                        destroy(proc);
                        return 0;
                    }
                    if (System.nanoTime() > deadline) {
                        destroy(proc);
                        return -2;
                    }
                }
            }
            if (!proc.waitFor(1_500, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                destroy(proc);
                return -2;
            }
            try {
                return proc.exitValue();
            } catch (IllegalThreadStateException e) {
                return -1;
            }
        } catch (IOException e) {
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        } finally {
            if (proc != null && proc.isAlive()) {
                destroy(proc);
            }
        }
    }

    private static void destroy(Process proc) {
        try {
            proc.destroyForcibly();
        } catch (Exception ignored) {
            // niente da fare
        }
    }

    private static boolean denied(String line) {
        String l = line.toLowerCase(Locale.ROOT);
        return l.contains("access is denied") || l.contains("accesso negato");
    }

    static long parseLong(String raw) {
        if (raw == null) {
            return 0L;
        }
        String s = raw.trim();
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return Long.parseLong(s.substring(2), 16);
            }
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static long parseHex(String raw) {
        try {
            return Long.parseLong(raw.substring(2), 16);
        } catch (Exception e) {
            return -1L;
        }
    }

    /** "2026-10-16 22:46:03.1234567" → epoch millis nel fuso locale. */
    static long parseTime(String raw) {
        Matcher m = TS.matcher(raw == null ? "" : raw);
        if (!m.find()) {
            return 0L;
        }
        try {
            LocalDateTime ldt = LocalDateTime.of(
                    Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
                    Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)), Integer.parseInt(m.group(6)));
            return ldt.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        } catch (Exception e) {
            return 0L;
        }
    }
}
