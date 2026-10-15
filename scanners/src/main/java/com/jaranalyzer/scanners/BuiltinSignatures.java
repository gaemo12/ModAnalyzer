package com.jaranalyzer.scanners;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Set di firme incluso (staff / uso locale): codice e dati separati.
 * I dati vivono nel modulo {@code scanner-data-staff} (resources
 * {@code signatures/*.txt} + {@code reputation/*.txt}), dipendenza ESCLUSIVA
 * di app-staff e test: MAI nel Player (che riceve il set via JS1 e lo tiene
 * in memoria). Caricamento tollerante (Fase 6): righe malformate scartate con
 * warn e conteggio, mai set parziali silenziosi; solo un file senza nessuna
 * riga valida (o mancante) lancia eccezione.
 */
public final class BuiltinSignatures {
    private static final Logger log = LoggerFactory.getLogger(BuiltinSignatures.class);

    private BuiltinSignatures() {
    }

    /** Carica i builtin dal classpath indicato (di norma il classloader del modulo). */
    public static SignatureSet fromClasspath(ClassLoader loader) {
        SignatureSets.Builder b = SignatureSets.builder("builtin-1");
        for (String[] row : rows(loader, "signatures/string-signatures.txt", 4)) {
            b.addString(unescape(row[2]), row[0], unescape(row[1]), unescape(row[3]));
        }
        for (String[] row : rows(loader, "signatures/suspicious-apis.txt", 4)) {
            b.addApi(unescape(row[0]), unescape(row[1]), row[2], unescape(row[3]));
        }
        for (String[] row : rows(loader, "signatures/suspicious-paths.txt", 1)) {
            b.addPath(unescape(row[0]));
        }
        Map<String, List<String>> cheats = new LinkedHashMap<>();
        int droppedEmpty = 0;
        for (String[] row : rows(loader, "signatures/cheat-groups.txt", 2)) {
            String pattern = unescape(row[1]);
            if (pattern.isEmpty()) {
                // Il DB originale contiene un pattern vuoto (match-all spurio: "" è
                // contenuto in ogni testo). Scartato qui, non propagato al matching.
                droppedEmpty++;
                continue;
            }
            cheats.computeIfAbsent(row[0], k -> new ArrayList<>()).add(pattern);
        }
        for (Map.Entry<String, List<String>> e : cheats.entrySet()) {
            b.addCheatGroup(e.getKey(), e.getValue());
        }
        for (String[] row : rows(loader, "signatures/quick-flags.txt", 1)) {
            b.addQuickFlag(unescape(row[0]));
        }
        b.maliciousHashes(reputation(loader, "reputation/malicious-hashes.txt"));
        b.knownGoodHashes(reputation(loader, "reputation/known-good-hashes.txt"));
        SignatureSet set = b.build();
        if (droppedEmpty > 0) {
            log.warn("Pattern vuoti scartati dal DB cheat: {}", droppedEmpty);
        }
        log.info("Firme builtin caricate: {} stringhe, {} api, {} cheat, {} quick-flag",
                set.stringSignatures().size(), set.suspiciousApis().size(),
                set.cheatGroups().size(), set.quickFlags().size());
        return set;
    }

    /** Scorciatoia col classloader di questa classe. */
    public static SignatureSet load() {
        return fromClasspath(BuiltinSignatures.class.getClassLoader());
    }

    static List<String[]> rows(ClassLoader loader, String resource, int cols) {
        List<String> lines = readLines(loader, resource);
        List<String[]> out = new ArrayList<>();
        // Tolleranza (Fase 6): una riga corrotta non invalida più l'intero set;
        // viene scartata con warn. Solo un file senza NESSUNA riga valida resta fatale.
        int dropped = 0;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isEmpty()) {
                continue;
            }
            String[] cols2 = line.split("\t", -1);
            if (cols2.length != cols) {
                dropped++;
                log.warn("{}:{}: riga scartata (attese {} colonne, trovate {})",
                        resource, (i + 1), cols, cols2.length);
                continue;
            }
            out.add(cols2);
        }
        if (dropped > 0) {
            log.warn("Righe malformate scartate da {}: {}", resource, dropped);
        }
        if (out.isEmpty()) {
            throw new IllegalStateException(resource + ": nessun dato valido");
        }
        return out;
    }

    /** Formato reputation esistente: {@code <sha256> [etichetta]}, {@code #} commenti. */
    static Map<String, String> reputation(ClassLoader loader, String resource) {
        Map<String, String> out = new LinkedHashMap<>();
        List<String> lines = readLines(loader, resource);
        // Tolleranza (Fase 6): hash malformati scartati con warn, come per rows().
        int dropped = 0;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int sep = line.indexOf(' ');
            String hash = (sep > 0 ? line.substring(0, sep) : line).trim().toLowerCase(Locale.ROOT);
            String label = sep > 0 ? line.substring(sep + 1).trim() : "";
            if (hash.length() != 64) {
                dropped++;
                log.warn("{}: hash scartato: {}", resource, line.length() > 72 ? line.substring(0, 72) + "..." : line);
                continue;
            }
            out.put(hash, label);
        }
        if (dropped > 0) {
            log.warn("Hash malformati scartati da {}: {}", resource, dropped);
        }
        return out;
    }

    static List<String> readLines(ClassLoader loader, String resource) {
        try (InputStream is = loader.getResourceAsStream(resource)) {
            if (is == null) {
                throw new IllegalStateException("risorsa firme mancante: " + resource);
            }
            try (BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                List<String> out = new ArrayList<>();
                String line;
                while ((line = r.readLine()) != null) {
                    out.add(line);
                }
                return out;
            }
        } catch (IOException e) {
            throw new IllegalStateException("lettura firme fallita: " + resource, e);
        }
    }

    /** Inverso dell'escape TSV dell'estrazione (\\ \t \n \r). */
    static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (++i >= s.length()) {
                throw new IllegalStateException("escape troncato in: " + s);
            }
            switch (s.charAt(i)) {
                case '\\': sb.append('\\'); break;
                case 't': sb.append('\t'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                default: throw new IllegalStateException("escape non valido in: " + s);
            }
        }
        return sb.toString();
    }
}
