package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.common.JsonCodec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rilevamento account Minecraft da file launcher/log (port senza Jackson del
 * servizio originale: stessa logica, stessi limiti). Legge SOLO username e UUID:
 * mai token, password, cookie o credenziali (i parser estraggono 4 campi e
 * scartano tutto il resto). Le basi (appData/userProfile) arrivano dall'host.
 */
public final class AccountScanner {
    private static final Logger log = LoggerFactory.getLogger(AccountScanner.class);
    /** Stessi limiti del codice originale. */
    public static final long MAX_FILE_BYTES = 0x1400000L;
    public static final int MAX_FILE_LINES = 200000;
    public static final int MAX_LOG_FILES = 500;
    private static final Pattern LOGIN_LOG_PATTERN =
            Pattern.compile("LoginData\\{name='([^']+)',\\s*uuid=([0-9a-fA-F-]{32,36})");

    /** Solo identificativi pubblici: username, UUID, launcher, tipo. Niente segreti. */
    public record Account(String username, String uuid, String launcher, String type) {
    }

    private AccountScanner() {
    }

    public static List<Account> detect(Path appData, Path userProfile) {
        List<Account> out = new ArrayList<>();
        if (appData != null) {
            File mc = appData.resolve(".minecraft").toFile();
            parseOfficialAccounts(new File(mc, "launcher_accounts.json"), out);
            parseOfficialProfiles(new File(mc, "launcher_profiles.json"), out);
            parseFeatherAccounts(new File(appData.resolve(".feather/accounts.json").toString()), out);
            parsePrismAccounts(new File(appData.resolve("PrismLauncher/accounts.json").toString()), out);
            parsePrismAccounts(new File(appData.resolve("PolyMC/accounts.json").toString()), out);
            parsePrismAccounts(new File(appData.resolve("MultiMC/accounts.json").toString()), out);
            AtomicInteger budget = new AtomicInteger(MAX_LOG_FILES);
            scanInstance(mc, "Minecraft (.minecraft)", budget, out);
            File modrinthProfiles = appData.resolve("ModrinthApp/profiles").toFile();
            File[] subs = modrinthProfiles.listFiles(File::isDirectory);
            if (subs != null) {
                for (File s : subs) {
                    scanInstance(s, "Modrinth - " + s.getName(), budget, out);
                }
            }
            File atInstances = appData.resolve("ATLauncher/instances").toFile();
            File[] atSubs = atInstances.listFiles(File::isDirectory);
            if (atSubs != null) {
                for (File s : atSubs) {
                    scanInstance(s, "ATLauncher - " + s.getName(), budget, out);
                }
            }
            File atCfg1 = appData.resolve("ATLauncher/configs/accounts.json").toFile();
            File atCfg2 = appData.resolve("ATLauncher/accounts.json").toFile();
            parseATLauncherAccounts(atCfg1.exists() ? atCfg1 : atCfg2, out);
            for (String dir : new String[] { "PrismLauncher", "PolyMC", "MultiMC" }) {
                File inst = appData.resolve(dir + "/instances").toFile();
                File[] ii = inst.listFiles(File::isDirectory);
                if (ii == null) {
                    continue;
                }
                for (File s : ii) {
                    for (String sub : new String[] { ".minecraft", "minecraft", "root", "" }) {
                        File root = sub.isEmpty() ? s : new File(s, sub);
                        if (root.isDirectory()) {
                            scanInstance(root, dir + " - " + s.getName(), budget, out);
                            break;
                        }
                    }
                }
            }
            parseModrinthAccounts(appData.resolve(".tlauncher/accounts.json").toFile(), out);
            scanInstance(appData.resolve(".tlauncher/minecraft").toFile(), "TLauncher", budget, out);
        }
        if (userProfile != null) {
            parseLunarAccounts(
                    userProfile.resolve(".lunarclient/settings/game/accounts.json").toFile(), out);
        }
        return mergeDuplicateAccounts(out);
    }

    // ---------------------------------------------------------- parsing JSON
    private static Map<String, Object> readJson(File f) {
        if (f == null || !f.isFile()) {
            return null;
        }
        try {
            byte[] bytes = readCappedBytes(f);
            Object v = JsonCodec.parse(new String(bytes, StandardCharsets.UTF_8));
            return v instanceof Map ? (Map<String, Object>) v : null;
        } catch (Exception e) {
            log.debug("JSON illeggibile {}: {}", f.getName(), e.getMessage());
            return null;
        }
    }

    private static List<Object> readJsonArray(File f) {
        if (f == null || !f.isFile()) {
            return null;
        }
        try {
            byte[] bytes = readCappedBytes(f);
            Object v = JsonCodec.parse(new String(bytes, StandardCharsets.UTF_8));
            return v instanceof List ? (List<Object>) v : null;
        } catch (Exception e) {
            log.debug("JSON illeggibile {}: {}", f.getName(), e.getMessage());
            return null;
        }
    }

    private static String str(Map<String, Object> m, String key) {
        if (m == null) {
            return "";
        }
        Object v = m.get(key);
        return v instanceof String ? (String) v : "";
    }

    private static String firstNonEmpty(Map<String, Object> m, String... keys) {
        for (String k : keys) {
            String v = str(m, k);
            if (!v.isBlank()) {
                return v;
            }
        }
        return "";
    }

    @SuppressWarnings("unchecked")
    private static void parseOfficialAccounts(File f, List<Account> out) {
        try {
            Map<String, Object> root = readJson(f);
            if (root == null) {
                return;
            }
            Object accs = root.get("accounts");
            if (!(accs instanceof Map)) {
                return;
            }
            for (Object o : ((Map<String, Object>) accs).values()) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                Object prof = acc.get("minecraftProfile");
                if (!(prof instanceof Map)) {
                    continue;
                }
                String name = str((Map<String, Object>) prof, "name");
                if (name.isEmpty()) {
                    continue;
                }
                out.add(new Account(name, str((Map<String, Object>) prof, "id"),
                        "Official Launcher", str(acc, "type").isEmpty() ? "Unknown" : str(acc, "type")));
            }
        } catch (Exception e) {
            log.debug("parse official accounts fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void parseOfficialProfiles(File f, List<Account> out) {
        try {
            Map<String, Object> root = readJson(f);
            if (root == null) {
                return;
            }
            Object db = root.get("authenticationDatabase");
            if (!(db instanceof Map)) {
                return;
            }
            for (Object o : ((Map<String, Object>) db).values()) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                String name = str(acc, "displayName");
                if (name.isEmpty()) {
                    continue;
                }
                out.add(new Account(name, str(acc, "uuid"), "Official Profiles", "Legacy/Mojang"));
            }
        } catch (Exception e) {
            log.debug("parse official profiles fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void parseFeatherAccounts(File f, List<Account> out) {
        try {
            Map<String, Object> root = readJson(f);
            if (root == null) {
                return;
            }
            for (Object o : asList(root.get("accounts"))) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                Object prof = acc.get("minecraftProfile");
                if (!(prof instanceof Map)) {
                    continue;
                }
                String name = str((Map<String, Object>) prof, "name");
                if (name.isEmpty()) {
                    continue;
                }
                out.add(new Account(name, str((Map<String, Object>) prof, "id"), "Feather Client", "Microsoft"));
            }
        } catch (Exception e) {
            log.debug("parse feather fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void parsePrismAccounts(File f, List<Account> out) {
        try {
            Map<String, Object> root = readJson(f);
            if (root == null) {
                return;
            }
            for (Object o : asList(root.get("accounts"))) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                Object prof = acc.get("profile");
                if (!(prof instanceof Map)) {
                    continue;
                }
                String name = str((Map<String, Object>) prof, "name");
                if (name.isEmpty()) {
                    continue;
                }
                String type = str(acc, "type");
                out.add(new Account(name, str((Map<String, Object>) prof, "id"),
                        "Prism/Poly/Multi Launcher", type.isEmpty() ? "Microsoft" : type));
            }
        } catch (Exception e) {
            log.debug("parse prism fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void parseLunarAccounts(File f, List<Account> out) {
        try {
            Map<String, Object> root = readJson(f);
            if (root == null) {
                return;
            }
            Object accs = root.get("accounts");
            List<Object> list = new ArrayList<>();
            if (accs instanceof Map) {
                list.addAll(((Map<String, Object>) accs).values());
            } else if (accs instanceof List) {
                list.addAll((List<Object>) accs);
            } else {
                return;
            }
            for (Object o : list) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                String name = firstNonEmpty(acc, "username", "name");
                if (name.isEmpty()) {
                    continue;
                }
                out.add(new Account(name, firstNonEmpty(acc, "uuid", "id"), "Lunar Client", "Microsoft"));
            }
        } catch (Exception e) {
            log.debug("parse lunar fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void parseModrinthAccounts(File f, List<Account> out) {
        try {
            List<Object> list = readJsonArray(f);
            if (list == null) {
                Map<String, Object> root = readJson(f);
                if (root == null) {
                    return;
                }
                list = asList(root.get("accounts"));
            }
            for (Object o : list) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                String name = firstNonEmpty(acc, "username", "name", "displayName");
                if (name.isEmpty()) {
                    continue;
                }
                out.add(new Account(name, firstNonEmpty(acc, "uuid", "id"),
                        "Modrinth App / TLauncher", "Microsoft/Offline"));
            }
        } catch (Exception e) {
            log.debug("parse modrinth/tlauncher fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void parseATLauncherAccounts(File f, List<Account> out) {
        try {
            List<Object> list = readJsonArray(f);
            if (list == null) {
                Map<String, Object> root = readJson(f);
                if (root == null) {
                    return;
                }
                list = asList(root.get("accounts"));
            }
            for (Object o : list) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> acc = (Map<String, Object>) o;
                String name = firstNonEmpty(acc, "minecraftUsername", "username", "displayName", "name");
                if (name.isEmpty()) {
                    continue;
                }
                Object ms = acc.get("isMicrosoft");
                String type = str(acc, "type");
                if (type.isEmpty()) {
                    type = Boolean.TRUE.equals(ms) ? "Microsoft" : "Mojang/Offline";
                }
                out.add(new Account(name, firstNonEmpty(acc, "uuid", "id"), "ATLauncher", type));
            }
        } catch (Exception e) {
            log.debug("parse atlauncher fallito: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) {
        if (o instanceof List) {
            return (List<Object>) o;
        }
        if (o instanceof Map) {
            return new ArrayList<>(((Map<String, Object>) o).values());
        }
        return List.of();
    }

    // ------------------------------------------------------ istanze, txt, log
    private static void scanInstance(File instanceRoot, String label, AtomicInteger logBudget, List<Account> out) {
        if (instanceRoot == null || !instanceRoot.isDirectory()) {
            return;
        }
        File logs = new File(instanceRoot, "logs");
        if (logs.isDirectory()) {
            parseMinecraftLogs(logs, label + " - Log", logBudget, out);
        }
        parseAccountSwitcherTxt(new File(instanceRoot, "config/account.txt"), label, out);
    }

    private static void parseAccountSwitcherTxt(File f, String label, List<Account> out) {
        if (!f.isFile()) {
            return;
        }
        try {
            for (String line : readTextLines(f)) {
                if (!line.trim().isEmpty()) {
                    out.add(new Account(line.trim(), "", label + " (Account Switcher - offline)", "Offline"));
                    break;
                }
            }
        } catch (Exception e) {
            log.debug("account.txt illeggibile: {}", e.getMessage());
        }
    }

    private static void parseMinecraftLogs(File logsDir, String label, AtomicInteger budget, List<Account> out) {
        File[] files = logsDir.listFiles((dir, name) -> !name.startsWith("debug")
                && (name.equalsIgnoreCase("latest.log") || name.endsWith(".log") || name.endsWith(".log.gz")));
        if (files == null) {
            return;
        }
        java.util.Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
        for (File f : files) {
            if (budget.getAndDecrement() <= 0) {
                return;
            }
            try {
                for (String line : readTextLines(f)) {
                    if (!line.contains("LoginData{")) {
                        continue;
                    }
                    Matcher m = LOGIN_LOG_PATTERN.matcher(line);
                    if (m.find()) {
                        out.add(new Account(m.group(1), m.group(2), label, "Rilevato da log"));
                    }
                }
            } catch (Exception e) {
                log.debug("log illeggibile {}: {}", f.getName(), e.getMessage());
            }
        }
    }

    static List<String> readTextLines(File f) throws Exception {
        List<String> out = new ArrayList<>();
        try (InputStream raw = new FileInputStream(f);
                InputStream in = f.getName().endsWith(".gz") ? new GZIPInputStream(raw) : raw) {
            Charset utf8 = StandardCharsets.UTF_8;
            BufferedReader r = new BufferedReader(new InputStreamReader(
                    new CappedStream(in, MAX_FILE_BYTES),
                    utf8.newDecoder().onMalformedInput(CodingErrorAction.REPLACE)));
            String line;
            int count = 0;
            while ((line = r.readLine()) != null) {
                if (++count > MAX_FILE_LINES) {
                    break;
                }
                out.add(line);
            }
        }
        return out;
    }

    static byte[] readCappedBytes(File f) throws Exception {
        try (InputStream in = new FileInputStream(f);
                CappedStream capped = new CappedStream(in, MAX_FILE_BYTES);
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = capped.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    static final class CappedStream extends InputStream {
        private final InputStream in;
        private long left;

        CappedStream(InputStream in, long max) {
            this.in = in;
            this.left = max;
        }

        @Override
        public int read() throws java.io.IOException {
            if (left <= 0) {
                return -1;
            }
            int b = in.read();
            if (b != -1) {
                left--;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws java.io.IOException {
            if (left <= 0) {
                return -1;
            }
            int n = in.read(b, off, (int) Math.min(len, left));
            if (n > 0) {
                left -= n;
            }
            return n;
        }

        @Override
        public void close() throws java.io.IOException {
            in.close();
        }
    }

    // ------------------------------------------------------------------ dedup
    static List<Account> mergeDuplicateAccounts(List<Account> in) {
        int n = in.size();
        if (n == 0) {
            return new ArrayList<>();
        }
        int[] parent = new int[n];
        for (int i = 0; i < n; i++) {
            parent[i] = i;
        }
        Map<String, Integer> byUuid = new HashMap<>();
        Map<String, Integer> byName = new HashMap<>();
        for (int i = 0; i < n; i++) {
            String u = normalizeUuid(in.get(i).uuid());
            if (u != null) {
                Integer j = byUuid.putIfAbsent(u, i);
                if (j != null) {
                    union(parent, i, j);
                }
            }
            String name = normalizeName(in.get(i).username());
            if (name != null) {
                Integer j = byName.putIfAbsent(name, i);
                if (j != null) {
                    union(parent, i, j);
                }
            }
        }
        Map<Integer, Account> merged = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            int root = find(parent, i);
            Account acc = in.get(i);
            merged.merge(root, acc, AccountScanner::mergeAccounts);
        }
        return new ArrayList<>(merged.values());
    }

    private static int find(int[] parent, int i) {
        while (parent[i] != i) {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        return i;
    }

    private static void union(int[] parent, int a, int b) {
        parent[find(parent, a)] = find(parent, b);
    }

    private static Account mergeAccounts(Account a, Account b) {
        return new Account(
                preferValue(a.username(), b.username()),
                preferValue(a.uuid(), b.uuid()),
                mergeLabels(a.launcher(), b.launcher()),
                preferValue(a.type(), b.type()));
    }

    private static String preferValue(String a, String b) {
        if (a == null || a.isBlank() || a.equals("Rilevato da log")) {
            return b == null ? "" : b;
        }
        return a;
    }

    private static String mergeLabels(String a, String b) {
        if (a == null || a.isBlank()) {
            return b == null ? "" : b;
        }
        if (b == null || b.isBlank() || a.equals(b) || a.contains(b)) {
            return a;
        }
        if (b.contains(a)) {
            return b;
        }
        return a + " + " + b;
    }

    static String normalizeUuid(String uuid) {
        if (uuid == null) {
            return null;
        }
        String u = uuid.replace("-", "").toLowerCase(java.util.Locale.ROOT);
        return u.length() >= 32 ? u : null;
    }

    static String normalizeName(String name) {
        if (name == null) {
            return null;
        }
        String t = name.trim().toLowerCase(java.util.Locale.ROOT);
        return t.isEmpty() ? null : t;
    }
}
