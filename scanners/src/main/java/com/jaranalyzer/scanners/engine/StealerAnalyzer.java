/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.objectweb.asm.ClassReader
 *  org.objectweb.asm.ClassVisitor
 *  org.objectweb.asm.MethodVisitor
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 */
package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Category;
import com.jaranalyzer.scanners.Finding;
import com.jaranalyzer.scanners.Severity;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StealerAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(StealerAnalyzer.class);
    private static final Set<String> BROWSER_PATHS = Set.of("Google\\Chrome\\User Data\\Default\\Login Data", "Google\\Chrome\\User Data\\Default\\Cookies", "Google\\Chrome\\User Data\\Default\\Web Data", "Google\\Chrome\\User Data\\Local State", "Google\\Chrome\\User Data\\Default\\Bookmarks", "Google\\Chrome\\User Data\\Default\\History", "Chrome\\User Data\\Default\\Login Data", "Chrome\\User Data\\Default\\Local State", "Chrome\\User Data\\Default\\Web Data", "Firefox\\Profiles", "Firefox\\Profiles\\*.default-release\\logins.json", "Firefox\\Profiles\\*.default-release\\cookies.sqlite", "Firefox\\Profiles\\*.default-release\\key4.db", "Firefox\\Profiles\\*.default\\logins.json", "Firefox\\Profiles\\*.default\\cookies.sqlite", "Microsoft\\Edge\\User Data\\Default\\Login Data", "Edge\\User Data\\Default\\Login Data", "Opera Software\\Opera Stable\\Login Data", "BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data");
    private static final Set<String> CRYPTO_WALLET_PATHS = Set.of("\\AppData\\Roaming\\Electrum\\wallets", "\\AppData\\Roaming\\Exodus\\exodus.wallet", "\\AppData\\Roaming\\atomic\\Local Storage", "\\AppData\\Roaming\\Coinomi\\Coinomi", "\\AppData\\Roaming\\Zcash", "\\AppData\\Roaming\\Litecoin", "\\AppData\\Roaming\\Bitcoin", "\\AppData\\Roaming\\Ethereum", "\\AppData\\Roaming\\Monero", "\\AppData\\Roaming\\Cardano", "\\AppData\\Roaming\\dogecoin", "\\AppData\\Roaming\\Jaxx", "\\AppData\\Roaming\\com.liberty.jaxx", ".electrum\\wallets", ".bitcoin\\wallet.dat", ".ethereum\\keystore", ".monero\\wallet", "wallet.dat", "seed.txt", "private.key", "keystore", "UTC--2023", "UTC--2024", "UTC--2025", "UTC--2026");
    private static final Set<String> DISCORD_PATHS = Set.of("Discord\\Local Storage\\leveldb", "discord\\Local Storage\\leveldb", "discord\\Local Storage", "discordptb\\Local Storage\\leveldb", "discordcanary\\Local Storage\\leveldb", "discord\\Local Storage\\leveldb\\log", "discord\\Local Storage\\leveldb\\ldb");
    private static final Set<String> SQLITE_OWNERS = Set.of("org/sqlite/JDBC", "org/sqlite/DB", "java/sql/DriverManager", "java/sql/Connection", "java/sql/Statement", "java/sql/PreparedStatement", "java/sql/ResultSet");
    private static final Set<String> SQLITE_METHODS = Set.of("getConnection", "prepareStatement", "executeQuery", "executeUpdate", "execute", "getString", "getBytes");
    private static final Set<String> STEALER_METHODS = Set.of("getToken", "getTokens", "extractToken", "stealToken", "getPassword", "getPasswords", "extractPassword", "getCookies", "extractCookies", "getWallet", "getWallets", "stealWallet", "getDiscord", "getTelegram", "grabber", "stealer", "Stealer", "collectPasswords", "collectTokens", "sendToServer", "exfiltrate", "readLoginData", "readLocalState", "decryptChromePassword");
    private static final Set<String> TELEGRAM_PATHS = Set.of("tdata\\", "Telegram Desktop\\tdata", "Telegram\\tdata");
    private static final Set<String> STEALER_STRINGS = Set.of("stealer", "Stealer", "STEALER", "grabber", "Grabber", "GRABBER", "token", "Token", "TOKEN", "password", "Password", "PASSWORD", "cookie", "Cookie", "COOKIE", "wallet", "Wallet", "WALLET", "discord", "Discord", "DISCORD", "telegram", "Telegram", "TELEGRAM", "exfiltrate", "Exfiltrate", "Login Data", "Web Data", "Local State", "leveldb", "ldb", "logins.json", "key4.db");

    @Override
    public String getName() {
        return "Stealer Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting stealer analysis on {}", (Object)jarFile.getName());
        final List browserPaths = Collections.synchronizedList(new ArrayList());
        final List walletPaths = Collections.synchronizedList(new ArrayList());
        final List discordPaths = Collections.synchronizedList(new ArrayList());
        final List telegramPaths = Collections.synchronizedList(new ArrayList());
        final List stealerStringLocs = Collections.synchronizedList(new ArrayList());
        final List stealerMethodLocs = Collections.synchronizedList(new ArrayList());
        final List sqliteLocs = Collections.synchronizedList(new ArrayList());
        final LinkedHashMap<String, AtomicInteger> counts = new LinkedHashMap<String, AtomicInteger>();
        counts.put("sqlite", new AtomicInteger());
        counts.put("browser", new AtomicInteger());
        counts.put("wallet", new AtomicInteger());
        counts.put("discord", new AtomicInteger());
        counts.put("telegram", new AtomicInteger());
        counts.put("stealerString", new AtomicInteger());
        counts.put("stealerMethod", new AtomicInteger());
        counts.put("webhook", new AtomicInteger());
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                byte[] bytes;
                JarEntry entry = en.nextElement();
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
                }
                catch (Exception e) {
                    continue;
                }
                if (name.endsWith(".class")) {
                    ClassReader cr;
                    final String classRef = name;
                    try {
                        cr = new ClassReader(bytes);
                    }
                    catch (Exception e) {
                        continue;
                    }
                    cr.accept(new ClassVisitor(589824){

                        public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                            return new MethodVisitor(589824){

                                public void visitMethodInsn(int opc, String owner, String n, String d, boolean itf) {
                                    String loc = classRef + "::" + mName;
                                    if (SQLITE_OWNERS.contains(owner) && SQLITE_METHODS.contains(n)) {
                                        ((AtomicInteger)counts.get("sqlite")).incrementAndGet();
                                        if (sqliteLocs.size() < 5) {
                                            sqliteLocs.add(loc + " -> " + owner + "." + n);
                                        }
                                    }
                                    if ("org/sqlite/JDBC".equals(owner)) {
                                        ((AtomicInteger)counts.get("sqlite")).incrementAndGet();
                                        if (sqliteLocs.size() < 5) {
                                            sqliteLocs.add(loc + " -> SQLite JDBC");
                                        }
                                    }
                                    String key = owner + " " + n;
                                    for (String sm : STEALER_METHODS) {
                                        if (!n.equals(sm) && !key.contains(sm)) continue;
                                        ((AtomicInteger)counts.get("stealerMethod")).incrementAndGet();
                                        if (stealerMethodLocs.size() >= 10) break;
                                        stealerMethodLocs.add(classRef + "::" + mName + " -> " + n);
                                        break;
                                    }
                                    if (!"java/net/URL".equals(owner) || "<init>".equals(n)) {
                                        // empty if block
                                    }
                                    super.visitMethodInsn(opc, owner, n, d, itf);
                                }

                                public void visitLdcInsn(Object value) {
                                    if (value instanceof String) {
                                        String s = (String)value;
                                        String lower = s.toLowerCase(Locale.ROOT);
                                        for (String browserPath : BROWSER_PATHS) {
                                            if (!lower.contains(browserPath.toLowerCase(Locale.ROOT))) continue;
                                            ((AtomicInteger)counts.get("browser")).incrementAndGet();
                                            if (browserPaths.size() >= 10) break;
                                            browserPaths.add(classRef + "::" + mName + " -> " + s.substring(0, Math.min(60, s.length())));
                                            break;
                                        }
                                        for (String walletPath : CRYPTO_WALLET_PATHS) {
                                            if (!lower.contains(walletPath.toLowerCase(Locale.ROOT))) continue;
                                            ((AtomicInteger)counts.get("wallet")).incrementAndGet();
                                            if (walletPaths.size() >= 10) break;
                                            walletPaths.add(classRef + "::" + mName + " -> " + s.substring(0, Math.min(60, s.length())));
                                            break;
                                        }
                                        for (String discordPath : DISCORD_PATHS) {
                                            if (!lower.contains(discordPath.toLowerCase(Locale.ROOT))) continue;
                                            ((AtomicInteger)counts.get("discord")).incrementAndGet();
                                            if (discordPaths.size() >= 5) break;
                                            discordPaths.add(classRef + "::" + mName + " -> " + s.substring(0, Math.min(60, s.length())));
                                            break;
                                        }
                                        for (String tgPath : TELEGRAM_PATHS) {
                                            if (!lower.contains(tgPath.toLowerCase(Locale.ROOT))) continue;
                                            ((AtomicInteger)counts.get("telegram")).incrementAndGet();
                                            if (telegramPaths.size() >= 5) break;
                                            telegramPaths.add(classRef + "::" + mName + " -> " + s.substring(0, Math.min(60, s.length())));
                                            break;
                                        }
                                        if (lower.contains("discord.com/api/webhooks")) {
                                            ((AtomicInteger)counts.get("webhook")).incrementAndGet();
                                        }
                                        for (String stStr : STEALER_STRINGS) {
                                            if (!s.contains(stStr) || stStr.length() <= 3) continue;
                                            ((AtomicInteger)counts.get("stealerString")).incrementAndGet();
                                            if (stealerStringLocs.size() >= 10) break;
                                            stealerStringLocs.add(classRef + "::" + mName + " -> \"" + s.substring(0, Math.min(40, s.length())) + "\"");
                                            break;
                                        }
                                    }
                                    super.visitLdcInsn(value);
                                }
                            };
                        }
                    }, 4);
                    continue;
                }
                try {
                    if (bytes.length <= 0 || bytes.length > 102400) continue;
                    String text = new String(bytes, StandardCharsets.UTF_8);
                    String lower = text.toLowerCase(Locale.ROOT);
                    for (String browserPath : BROWSER_PATHS) {
                        if (!lower.contains(browserPath.toLowerCase(Locale.ROOT))) continue;
                        ((AtomicInteger)counts.get("browser")).incrementAndGet();
                        break;
                    }
                    for (String walletPath : CRYPTO_WALLET_PATHS) {
                        if (!lower.contains(walletPath.toLowerCase(Locale.ROOT))) continue;
                        ((AtomicInteger)counts.get("wallet")).incrementAndGet();
                        break;
                    }
                    if (!lower.contains("discord.com/api/webhooks")) continue;
                    ((AtomicInteger)counts.get("webhook")).incrementAndGet();
                }
                catch (Exception exception) {}
            }
        }
        boolean anyStealer = false;
        if (((AtomicInteger)counts.get("browser")).get() > 0) {
            anyStealer = true;
            findings.add(new Finding.Builder().title("Browser credential theft \u2014 " + ((AtomicInteger)counts.get("browser")).get() + " riferimenti").description("Path di browser per rubare credenziali salvate (Login Data, Cookies, password Chrome/Firefox/Edge).").severity(Severity.CRITICAL).category(Category.FILE_ACCESS).location("Multipli file").evidence("Browser paths:\n" + String.join((CharSequence)"\n", browserPaths)).family("BrowserCredentialStealer").recommendation("Contiene percorso a Login Data di Chrome/Firefox/Edge per estrarre password.").build());
        }
        if (((AtomicInteger)counts.get("wallet")).get() > 0) {
            anyStealer = true;
            findings.add(new Finding.Builder().title("Crypto wallet theft \u2014 " + ((AtomicInteger)counts.get("wallet")).get() + " riferimenti").description("Path di wallet crypto: Bitcoin, Ethereum, Monero, Electrum, Exodus, Atomic, Jaxx, Coinomi.").severity(Severity.CRITICAL).category(Category.FILE_ACCESS).location("Multipli file").evidence("Wallet paths:\n" + String.join((CharSequence)"\n", walletPaths)).family("CryptoWalletStealer").build());
        }
        if (((AtomicInteger)counts.get("discord")).get() > 0 || ((AtomicInteger)counts.get("webhook")).get() > 0) {
            anyStealer = true;
            findings.add(new Finding.Builder().title("Discord token theft \u2014 " + (((AtomicInteger)counts.get("discord")).get() + ((AtomicInteger)counts.get("webhook")).get()) + " riferimenti").description("Path a Discord Local Storage (leveldb) per rubare token di autenticazione Discord e/o webhook per esfiltrazione.").severity(Severity.CRITICAL).category(Category.FILE_ACCESS).location("Multipli file").evidence("Discord paths:\n" + String.join((CharSequence)"\n", discordPaths)).family("DiscordTokenStealer").build());
        }
        if (((AtomicInteger)counts.get("telegram")).get() > 0) {
            anyStealer = true;
            findings.add(new Finding.Builder().title("Telegram session theft \u2014 " + ((AtomicInteger)counts.get("telegram")).get() + " riferimenti").description("Path a tdata di Telegram Desktop per rubare sessioni di autenticazione di Telegram.").severity(Severity.CRITICAL).category(Category.FILE_ACCESS).location("Multipli file").evidence("Telegram paths:\n" + String.join((CharSequence)"\n", telegramPaths)).family("TelegramSessionStealer").build());
        }
        if (((AtomicInteger)counts.get("sqlite")).get() > 0 && ((AtomicInteger)counts.get("browser")).get() > 0) {
            anyStealer = true;
            findings.add(new Finding.Builder().title("COMBO: SQLite + Browser paths \u2014 credenziali estraibili").description("SQLite + percorsi browser = i database delle password (Login Data) sono file SQLite. Il codice legge i file SQLite dei browser per estrarre credenziali.").severity(Severity.CRITICAL).category(Category.FILE_ACCESS).location("Multipli .class").evidence("SQLite usage count: " + ((AtomicInteger)counts.get("sqlite")).get() + "\nBrowser path count: " + ((AtomicInteger)counts.get("browser")).get()).family("BrowserCredentialStealer").build());
        }
        if (((AtomicInteger)counts.get("stealerMethod")).get() > 0) {
            anyStealer = true;
            findings.add(new Finding.Builder().title("Metodi stealer \u2014 " + ((AtomicInteger)counts.get("stealerMethod")).get() + " occorrenze").description("Nomi di metodo tipici di stealer: getToken, extractPassword, getWallet, collectPasswords, sendToServer.").severity(Severity.HIGH).category(Category.MALWARE_SIGNATURE).location("Multipli .class").evidence("Stealer methods:\n" + String.join((CharSequence)"\n", stealerMethodLocs)).family("StealerMethod").build());
        }
        if (!anyStealer && ((AtomicInteger)counts.get("stealerString")).get() > 3) {
            findings.add(new Finding.Builder().title("Stringhe stealer \u2014 " + ((AtomicInteger)counts.get("stealerString")).get() + " occorrenze").description("Il JAR contiene stringhe tipiche di stealer (token, password, wallet, discord, grabber).").severity(Severity.MEDIUM).category(Category.MALWARE_SIGNATURE).location("Multipli .class").evidence("Stealer strings:\n" + String.join((CharSequence)"\n", stealerStringLocs)).family("StealerString").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Stealer analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }
}
