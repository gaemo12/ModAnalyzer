package com.jaranalyzer.scanners;

import com.jaranalyzer.common.JsonCodec;
import com.jaranalyzer.common.JsonException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fabbriche di {@link SignatureSet}: vuoto, sintetico (test), dal formato JS1 interno.
 * Formato JS1 (documentato in docs/SCANNERS.md, opaco per il backend):
 * {@code {"v":1,"issued":N,"version":"...","signatures":[{pattern,severity,family?,description?}],
 * "suspiciousApis":[{owner,method,severity,description?}],"suspiciousPaths":[],
 * "cheatGroups":{"nome":[patterni]},"quickFlags":[],"maliciousHashes":{},"knownGoodHashes":{}}}.
 * Validazione rigida: versioni diverse, forme errate o limiti superati rifiutano
 * l'intero set (mai degrado silenzioso).
 */
public final class SignatureSets {
    /** Limiti anti-abuso per i set forniti dall'host. */
    public static final int MAX_STRINGS = 100_000;
    public static final int MAX_APIS = 20_000;
    public static final int MAX_PATHS = 10_000;
    public static final int MAX_CHEAT_GROUPS = 500;
    public static final int MAX_CHEAT_PATTERNS = 50_000;
    public static final int MAX_HASHES = 200_000;
    public static final int MAX_QUICK_FLAGS = 20_000;

    private SignatureSets() {
    }

    /** Set vuoto valido: i moduli girano comunque (zero match). */
    public static SignatureSet empty() {
        return new Impl("empty", List.of(), List.of(), List.of(), Map.of(), List.of(), Map.of(), Map.of());
    }

    public static Builder builder(String version) {
        return new Builder(version);
    }

    /** Parsa e valida il payload interno JS1 (l'involucro firmato lo verifica il chiamante). */
    @SuppressWarnings("unchecked")
    public static SignatureSet parse(String json) {
        Map<String, Object> m;
        try {
            m = JsonCodec.parseObject(json);
        } catch (JsonException e) {
            throw new IllegalArgumentException("set firme illeggibile: " + e.getMessage(), e);
        }
        Object v = m.get("v");
        if (!(v instanceof Long) || ((Long) v) != 1L) {
            throw new IllegalArgumentException("versione set firme non supportata");
        }
        Object issued = m.get("issued");
        if (!(issued instanceof Long) || ((Long) issued) <= 0) {
            throw new IllegalArgumentException("issued mancante nel set firme");
        }
        Builder b = builder("js1-" + issued);
        for (Object o : list(m, "signatures")) {
            Map<String, Object> s = obj(o, "signatures");
            b.addString(req(s, "pattern"), req(s, "severity"), opt(s, "family"), opt(s, "description"));
        }
        for (Object o : list(m, "suspiciousApis")) {
            Map<String, Object> s = obj(o, "suspiciousApis");
            b.addApi(req(s, "owner"), req(s, "method"), req(s, "severity"), opt(s, "description"));
        }
        for (Object o : list(m, "suspiciousPaths")) {
            b.addPath(str(o, "suspiciousPaths"));
        }
        Object cg = m.get("cheatGroups");
        if (cg instanceof Map) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) cg).entrySet()) {
                if (!(e.getValue() instanceof List)) {
                    throw new IllegalArgumentException("cheatGroups non valido: " + e.getKey());
                }
                List<String> pats = new ArrayList<>();
                for (Object o : (List<Object>) e.getValue()) {
                    pats.add(str(o, "cheatGroups." + e.getKey()));
                }
                b.addCheatGroup(e.getKey(), pats);
            }
        } else if (cg != null) {
            throw new IllegalArgumentException("cheatGroups non oggetto");
        }
        for (Object o : list(m, "quickFlags")) {
            b.addQuickFlag(str(o, "quickFlags"));
        }
        b.maliciousHashes(hashes(m, "maliciousHashes"));
        b.knownGoodHashes(hashes(m, "knownGoodHashes"));
        return b.build();
    }

    private static List<Object> list(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) {
            return List.of();
        }
        if (!(v instanceof List)) {
            throw new IllegalArgumentException(key + " non lista");
        }
        return (List<Object>) v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o, String key) {
        if (!(o instanceof Map)) {
            throw new IllegalArgumentException(key + ": elemento non oggetto");
        }
        return (Map<String, Object>) o;
    }

    private static String str(Object o, String key) {
        if (!(o instanceof String)) {
            throw new IllegalArgumentException(key + ": elemento non stringa");
        }
        return (String) o;
    }

    private static String req(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (!(v instanceof String) || ((String) v).isEmpty()) {
            throw new IllegalArgumentException("campo assente: " + key);
        }
        return (String) v;
    }

    private static String opt(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) {
            return "";
        }
        if (!(v instanceof String)) {
            throw new IllegalArgumentException("campo non stringa: " + key);
        }
        return (String) v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> hashes(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) {
            return Map.of();
        }
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException(key + " non oggetto");
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
            if (!(e.getValue() instanceof String)) {
                throw new IllegalArgumentException(key + ": valore non stringa per " + e.getKey());
            }
            out.put(e.getKey(), (String) e.getValue());
        }
        return out;
    }

    /** Costruttore validante per set sintetici (test) e loader. */
    public static final class Builder {
        private final String version;
        private final List<SignatureSet.SigPattern> strings = new ArrayList<>();
        private final List<SignatureSet.SuspApi> apis = new ArrayList<>();
        private final List<String> paths = new ArrayList<>();
        private final Map<String, List<String>> cheatGroups = new LinkedHashMap<>();
        private final List<String> quickFlags = new ArrayList<>();
        private final Map<String, String> malicious = new LinkedHashMap<>();
        private final Map<String, String> knownGood = new LinkedHashMap<>();

        Builder(String version) {
            if (version == null || version.isBlank()) {
                throw new IllegalArgumentException("version assente");
            }
            this.version = version;
        }

        public Builder addString(String pattern, String severity, String family, String description) {
            if (strings.size() >= MAX_STRINGS) {
                throw new IllegalArgumentException("troppe firme a stringa");
            }
            checkSeverity(severity);
            strings.add(new SignatureSet.SigPattern(pattern, severity, family, description));
            return this;
        }

        public Builder addApi(String owner, String method, String severity, String description) {
            if (apis.size() >= MAX_APIS) {
                throw new IllegalArgumentException("troppe API sospette");
            }
            checkSeverity(severity);
            apis.add(new SignatureSet.SuspApi(owner, method, severity, description));
            return this;
        }

        private static void checkSeverity(String severity) {
            try {
                Severity.valueOf(severity);
            } catch (IllegalArgumentException | NullPointerException e) {
                throw new IllegalArgumentException("severity non valida: " + severity);
            }
        }

        public Builder addPath(String path) {
            if (paths.size() >= MAX_PATHS) {
                throw new IllegalArgumentException("troppi percorsi sospetti");
            }
            if (path == null || path.isEmpty()) {
                throw new IllegalArgumentException("percorso assente");
            }
            paths.add(path);
            return this;
        }

        public Builder addCheatGroup(String name, List<String> patterns) {
            if (cheatGroups.size() >= MAX_CHEAT_GROUPS) {
                throw new IllegalArgumentException("troppi gruppi cheat");
            }
            if (name == null || name.isBlank() || patterns == null || patterns.isEmpty()) {
                throw new IllegalArgumentException("gruppo cheat non valido: " + name);
            }
            if (patterns.size() > MAX_CHEAT_PATTERNS) {
                throw new IllegalArgumentException("troppi pattern per " + name);
            }
            List<String> clean = new ArrayList<>();
            for (String p : patterns) {
                if (p == null || p.isEmpty()) {
                    throw new IllegalArgumentException("pattern vuoto in " + name);
                }
                clean.add(p);
            }
            if (cheatGroups.putIfAbsent(name, List.copyOf(clean)) != null) {
                throw new IllegalArgumentException("gruppo duplicato: " + name);
            }
            return this;
        }

        public Builder addQuickFlag(String flag) {
            if (quickFlags.size() >= MAX_QUICK_FLAGS) {
                throw new IllegalArgumentException("troppi quick flag");
            }
            if (flag == null || flag.isEmpty()) {
                throw new IllegalArgumentException("quick flag assente");
            }
            quickFlags.add(flag.toLowerCase(java.util.Locale.ROOT));
            return this;
        }

        public Builder maliciousHashes(Map<String, String> hashes) {
            putHashes(malicious, hashes, "maliciousHashes");
            return this;
        }

        public Builder knownGoodHashes(Map<String, String> hashes) {
            putHashes(knownGood, hashes, "knownGoodHashes");
            return this;
        }

        private void putHashes(Map<String, String> target, Map<String, String> hashes, String what) {
            if (hashes == null) {
                return;
            }
            for (Map.Entry<String, String> e : hashes.entrySet()) {
                if (target.size() >= MAX_HASHES) {
                    throw new IllegalArgumentException("troppi hash in " + what);
                }
                String k = e.getKey() == null ? "" : e.getKey().trim().toLowerCase(java.util.Locale.ROOT);
                if (!k.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("hash non valido in " + what + ": " + e.getKey());
                }
                target.put(k, e.getValue() == null ? "" : e.getValue());
            }
        }

        public SignatureSet build() {
            return new Impl(version, List.copyOf(strings), List.copyOf(apis), List.copyOf(paths),
                    Map.copyOf(cheatGroups), List.copyOf(quickFlags), Map.copyOf(malicious), Map.copyOf(knownGood));
        }
    }

    static final class Impl implements SignatureSet {
        private final String version;
        private final List<SigPattern> strings;
        private final List<SuspApi> apis;
        private final List<String> paths;
        private final Map<String, List<String>> cheatGroups;
        private final List<String> quickFlags;
        private final Map<String, String> malicious;
        private final Map<String, String> knownGood;

        Impl(String version, List<SigPattern> strings, List<SuspApi> apis, List<String> paths,
                Map<String, List<String>> cheatGroups, List<String> quickFlags,
                Map<String, String> malicious, Map<String, String> knownGood) {
            this.version = version;
            this.strings = strings;
            this.apis = apis;
            this.paths = paths;
            this.cheatGroups = cheatGroups;
            this.quickFlags = quickFlags;
            this.malicious = malicious;
            this.knownGood = knownGood;
        }

        @Override
        public List<SigPattern> stringSignatures() {
            return strings;
        }

        @Override
        public List<SuspApi> suspiciousApis() {
            return apis;
        }

        @Override
        public List<String> suspiciousPaths() {
            return paths;
        }

        @Override
        public Map<String, List<String>> cheatGroups() {
            return cheatGroups;
        }

        @Override
        public List<String> quickFlags() {
            return quickFlags;
        }

        @Override
        public Map<String, String> maliciousHashes() {
            return malicious;
        }

        @Override
        public Map<String, String> knownGoodHashes() {
            return knownGood;
        }

        @Override
        public String version() {
            return version;
        }
    }
}
