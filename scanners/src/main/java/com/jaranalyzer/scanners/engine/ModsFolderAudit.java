package com.jaranalyzer.scanners.engine;

import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Controlli strutturali sulla cartella mods, complementari alla scansione dei
 * singoli JAR:
 * <ul>
 *   <li><b>id duplicati</b>: due JAR abilitati dichiarano lo stesso id (uno può
 *       sovrascrivere o mascherare l'altro);</li>
 *   <li><b>JAR camuffati</b>: un file con estensione {@code .jar} che in realtà
 *       è un eseguibile, uno script o un altro archivio (firma magica diversa);</li>
 *   <li><b>mod disabilitate</b>: file {@code .jar.disabled/.off/.old/.bak};
 *       vengono aperti solo per cercare indicatori di cheat noti, non per
 *       eseguirli né per leggerne il contenuto personale;</li>
 *   <li><b>nome file vs metadati</b>: un file che richiama una mod molto diffusa
 *       ma dichiara un id/nome diverso (classico rename di un client).</li>
 * </ul>
 *
 * <p>Solo lettura locale, nessuna rete. Gli esiti sono indizi da verificare:
 * una mod può essere rinominata legittimamente, quindi il mismatch resta a
 * bassa severità nel chiamante.
 */
public final class ModsFolderAudit {

    /** Oltre questa soglia non si aprono altre mod disabilitate (si dichiara la nota). */
    private static final int MAX_DISABLED_SCAN = 200;
    /** Tetto voci esaminate in un singolo archivio (archivi ostili con milioni di entry). */
    private static final int MAX_ENTRIES = 50_000;

    private static final Set<String> DISABLED_SUFFIXES = Set.of(
            ".disabled", ".off", ".old", ".bak", ".backup");

    /** Nomi molto diffusi: un rename che non li dichiara nei metadati merita un controllo. */
    private static final Set<String> KNOWN_SLUGS = Set.of(
            "sodium", "lithium", "phosphor", "iris", "indium", "fabricapi", "modmenu",
            "journeymap", "appleskin", "xaero", "starlight", "ferritecore", "modernfix",
            "embeddium", "entityculling", "immediatelyfast");

    /** Dati minimi di un JAR abilitato, già raccolti dalla scansione principale. */
    public record Entry(String fileName, String modId, String modName, String nonJarKind) {
    }

    public record DuplicateId(String id, List<String> files) {
    }

    public record Mismatch(String fileName, String declaredId, String declaredName, String note) {
    }

    /** Mod disabilitata che contiene un indicatore noto o una firma non-JAR. */
    public record DisabledFinding(String fileName, String reason) {
    }

    public record Report(List<String> disabled, List<DisabledFinding> suspiciousDisabled,
            List<String> disguised, List<DuplicateId> duplicateIds, List<Mismatch> mismatches,
            List<String> notes) {

        /** Problemi che meritano attenzione (le sole mod disabilitate non contano). */
        public int issues() {
            return suspiciousDisabled.size() + disguised.size() + duplicateIds.size() + mismatches.size();
        }

        public static Report empty() {
            return new Report(List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        }
    }

    private ModsFolderAudit() {
    }

    /**
     * Esegue i controlli. {@code entries} contiene i soli JAR abilitati con i
     * metadati già letti; {@code quickFlags} è la lista condivisa di indicatori
     * (vuota = salta il controllo degli id delle mod disabilitate).
     */
    public static Report audit(Path dir, List<Entry> entries, Collection<String> quickFlags) {
        List<String> notes = new ArrayList<>();
        List<String> disabled = new ArrayList<>();
        List<DisabledFinding> suspiciousDisabled = new ArrayList<>();
        List<String> disguised = new ArrayList<>();
        List<DuplicateId> duplicateIds = new ArrayList<>();
        List<Mismatch> mismatches = new ArrayList<>();

        List<Entry> safeEntries = entries == null ? List.of() : entries;
        for (Entry e : safeEntries) {
            if (e != null && e.nonJarKind() != null && !e.nonJarKind().isBlank()) {
                disguised.add(e.fileName() + " (" + e.nonJarKind() + ")");
            }
        }

        collectDisabled(dir, quickFlags, disabled, suspiciousDisabled, notes);
        findDuplicateIds(safeEntries, duplicateIds);
        findMismatches(safeEntries, mismatches);

        return new Report(List.copyOf(disabled), List.copyOf(suspiciousDisabled),
                List.copyOf(disguised), List.copyOf(duplicateIds), List.copyOf(mismatches),
                List.copyOf(notes));
    }

    /** true per i nomi che i launcher usano per disattivare una mod. */
    public static boolean isDisabledName(String fileName) {
        String lower = fileName == null ? "" : fileName.toLowerCase(Locale.ROOT);
        if (!lower.contains(".jar")) {
            return false;
        }
        for (String suffix : DISABLED_SUFFIXES) {
            if (lower.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Se il file non inizia come un archivio ZIP/JAR restituisce una descrizione
     * breve della firma (es. "eseguibile Windows (.exe)"), altrimenti null.
     * Non legge altro oltre i primi byte.
     */
    public static String nonJarMagic(Path file) {
        if (file == null) {
            return null;
        }
        byte[] b = new byte[8];
        int n;
        try (InputStream in = Files.newInputStream(file)) {
            n = in.read(b);
        } catch (Exception e) {
            return null; // illeggibile: lo dirà la scansione principale
        }
        if (n <= 0) {
            return "file vuoto";
        }
        if (n >= 2 && b[0] == 'P' && b[1] == 'K') {
            return null; // ZIP/JAR (anche vuoto o con data descriptor)
        }
        if (n >= 2 && b[0] == 'M' && b[1] == 'Z') {
            return "eseguibile Windows (.exe/.dll)";
        }
        if (n >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
            return "eseguibile Linux (ELF)";
        }
        if (n >= 2 && b[0] == '#' && b[1] == '!') {
            return "script eseguibile";
        }
        if (n >= 4 && b[0] == 'R' && b[1] == 'a' && b[2] == 'r' && b[3] == '!') {
            return "archivio RAR";
        }
        if (n >= 6 && b[0] == '7' && b[1] == 'z' && b[2] == (byte) 0xbc && b[3] == (byte) 0xaf) {
            return "archivio 7z";
        }
        if (n >= 2 && b[0] == (byte) 0x1f && b[1] == (byte) 0x8b) {
            return "archivio GZIP";
        }
        if (n >= 3 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h') {
            return "archivio BZIP2";
        }
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(n, 4); i++) {
            hex.append(String.format("%02X", b[i]));
        }
        return "non è un archivio JAR (firma " + hex + ")";
    }

    /**
     * Confronto conservativo di un id di mod con gli indicatori noti: match
     * esatto, ai bordi (caratteri non alfanumerici) oppure come prefisso/suffisso
     * per gli indicatori lunghi. Evita i falsi positivi del semplice
     * {@code contains} su id molto corti.
     */
    public static String flagInId(String id, Collection<String> flags) {
        if (id == null || id.isBlank() || flags == null) {
            return null;
        }
        String lower = id.toLowerCase(Locale.ROOT);
        String compact = lower.replaceAll("[^a-z0-9]", "");
        for (String raw : flags) {
            if (raw == null || raw.isBlank() || raw.indexOf('/') >= 0) {
                continue; // gli indicatori di percorso non hanno senso in un id
            }
            String flag = raw.toLowerCase(Locale.ROOT);
            String fc = flag.replaceAll("[^a-z0-9]", "");
            if (fc.isEmpty()) {
                continue;
            }
            if (lower.equals(flag) || compact.equals(fc)) {
                return raw;
            }
            if (lower.matches(".*(^|[^a-z0-9])" + java.util.regex.Pattern.quote(flag) + "([^a-z0-9]|$).*")) {
                return raw;
            }
            if (fc.length() >= 5 && (compact.startsWith(fc) || compact.endsWith(fc))) {
                return raw;
            }
            if (fc.length() >= 8 && compact.contains(fc)) {
                return raw;
            }
        }
        return null;
    }

    /* ------------------------------------------------------------ interni */

    private static void collectDisabled(Path dir, Collection<String> quickFlags, List<String> disabled,
            List<DisabledFinding> suspiciousDisabled, List<String> notes) {
        if (dir == null || !Files.isDirectory(dir)) {
            notes.add("Cartella mods non leggibile: controllo delle mod disabilitate saltato.");
            return;
        }
        List<Path> paths = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path p : stream) {
                String name = p.getFileName() == null ? "" : p.getFileName().toString();
                if (isDisabledName(name) && Files.isRegularFile(p)) {
                    paths.add(p);
                }
            }
        } catch (Exception e) {
            notes.add("Elenco delle mod disabilitate parziale: " + message(e));
            return;
        }
        paths.sort(Comparator.comparing(p -> p.getFileName().toString(), String.CASE_INSENSITIVE_ORDER));
        int scanned = 0;
        for (Path p : paths) {
            String name = p.getFileName().toString();
            disabled.add(name);
            String magic = nonJarMagic(p);
            if (magic != null) {
                suspiciousDisabled.add(new DisabledFinding(name, magic));
                continue;
            }
            if (quickFlags == null || quickFlags.isEmpty()) {
                continue; // niente indicatori: non si apre il contenuto delle mod disabilitate
            }
            if (scanned++ >= MAX_DISABLED_SCAN) {
                notes.add("Oltre " + MAX_DISABLED_SCAN + " mod disabilitate: le restanti non sono state aperte.");
                break;
            }
            try (ZipFile zip = new ZipFile(p.toFile())) {
                String flag = quickFlagInEntries(zip, quickFlags);
                if (flag == null) {
                    flag = flagInId(ModMetadata.read(zip).id(), quickFlags);
                }
                if (flag != null) {
                    suspiciousDisabled.add(new DisabledFinding(name, "indicatore: " + flag));
                }
            } catch (Exception e) {
                suspiciousDisabled.add(new DisabledFinding(name, "archivio non valido: " + message(e)));
            }
        }
    }

    private static String quickFlagInEntries(ZipFile zip, Collection<String> quickFlags) {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        int n = 0;
        while (entries.hasMoreElements()) {
            if (++n > MAX_ENTRIES) {
                return null;
            }
            String lower = entries.nextElement().getName().toLowerCase(Locale.ROOT);
            for (String flag : quickFlags) {
                if (flag != null && !flag.isEmpty() && lower.contains(flag)) {
                    return flag;
                }
            }
        }
        return null;
    }

    private static void findDuplicateIds(List<Entry> entries, List<DuplicateId> out) {
        Map<String, List<String>> byId = new LinkedHashMap<>();
        Map<String, String> display = new LinkedHashMap<>();
        for (Entry e : entries) {
            if (e == null || e.modId() == null || e.modId().isBlank()) {
                continue;
            }
            String key = e.modId().trim().toLowerCase(Locale.ROOT);
            byId.computeIfAbsent(key, k -> new ArrayList<>()).add(e.fileName());
            display.putIfAbsent(key, e.modId().trim());
        }
        for (Map.Entry<String, List<String>> en : byId.entrySet()) {
            if (en.getValue().size() > 1) {
                out.add(new DuplicateId(display.get(en.getKey()), List.copyOf(en.getValue())));
            }
        }
    }

    private static void findMismatches(List<Entry> entries, List<Mismatch> out) {
        for (Entry e : entries) {
            if (e == null || e.modId() == null || e.modId().isBlank()
                    || e.nonJarKind() != null) {
                continue;
            }
            String file = normalize(e.fileName());
            String declared = normalize(e.modId() + " " + (e.modName() == null ? "" : e.modName()));
            for (String slug : KNOWN_SLUGS) {
                if (file.contains(slug) && !declared.contains(slug)) {
                    out.add(new Mismatch(e.fileName(), e.modId(), e.modName(),
                            "Il nome del file richiama «" + slug + "», ma i metadati dichiarano «"
                                    + (e.modName() == null || e.modName().isBlank() ? e.modId() : e.modName())
                                    + "» (id " + e.modId() + "). Verifica la provenienza."));
                    break;
                }
            }
        }
    }

    private static String normalize(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static String message(Exception e) {
        String m = e.getMessage();
        return m == null ? e.getClass().getSimpleName() : m;
    }
}
