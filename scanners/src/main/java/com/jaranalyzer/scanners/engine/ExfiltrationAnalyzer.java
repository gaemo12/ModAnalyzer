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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExfiltrationAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(ExfiltrationAnalyzer.class);
    private static final Set<String> CLIPBOARD_OWNERS = Set.of("java/awt/datatransfer/Clipboard", "java/awt/Toolkit");
    private static final Set<String> CLIPBOARD_METHODS = Set.of("getSystemClipboard", "setContents", "getContents");
    private static final Map<String, Pattern> WALLET_ADDRESS_PATTERNS = Map.of("BTC", Pattern.compile("(^|[^A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}([^A-Za-z0-9]|$)"), "BTC_BECH32", Pattern.compile("bc1[a-z0-9]{25,90}", 2), "ETH", Pattern.compile("0x[a-fA-F0-9]{40}"), "LTC", Pattern.compile("(^|[^A-Za-z0-9])[LM][a-km-zA-HJ-NP-Z1-9]{26,33}([^A-Za-z0-9]|$)"), "XMR", Pattern.compile("4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"));
    private static final Pattern DISCORD_TOKEN_PATTERN = Pattern.compile("([MN][A-Za-z\\d_-]{23,25}\\.[A-Za-z\\d_-]{6}\\.[A-Za-z\\d_-]{27,38}|mfa\\.[A-Za-z\\d_-]{80,90})");
    private static final Pattern DISCORD_WEBHOOK_URL_PATTERN = Pattern.compile("https?://(?:canary\\.|ptb\\.)?discord(?:app)?\\.com/api/webhooks/\\d{17,20}/[\\w-]{60,90}");
    private static final Set<String> TEXT_LIKE_EXTENSIONS = Set.of(".txt", ".json", ".yml", ".yaml", ".properties", ".xml", ".cfg", ".ini", ".md", ".css", ".js", ".html", ".htm", ".csv", ".lang");
    private static final Set<String> IMAGE_EXTENSIONS = Set.of(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".ttf", ".otf");
    private static final byte[] ZIP_MAGIC = new byte[]{80, 75, 3, 4};
    private static final byte[] CLASS_MAGIC = new byte[]{-54, -2, -70, -66};
    private static final byte[] MZ_MAGIC = new byte[]{77, 90};

    @Override
    public String getName() {
        return "Exfiltration Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting exfiltration analysis on {}", (Object)jarFile.getName());
        AtomicInteger clipperCombo = new AtomicInteger();
        List<String> clipperLocs = Collections.synchronizedList(new ArrayList());
        AtomicInteger discordTokens = new AtomicInteger();
        List<String> discordTokenLocs = Collections.synchronizedList(new ArrayList());
        AtomicInteger discordWebhooks = new AtomicInteger();
        List<String> discordWebhookLocs = Collections.synchronizedList(new ArrayList());
        List<String> polyglotEntries = Collections.synchronizedList(new ArrayList());
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
                this.checkPolyglot(name, bytes, polyglotEntries);
                if (name.endsWith(".class")) {
                    this.analyzeClass(name, bytes, clipperCombo, clipperLocs);
                    continue;
                }
                if (bytes.length <= 0 || bytes.length > 524288) continue;
                this.scanTextForSecrets(name, bytes, discordTokens, discordTokenLocs, discordWebhooks, discordWebhookLocs);
            }
        }
        if (clipperCombo.get() > 0) {
            findings.add(new Finding.Builder().title("Possibile crypto clipper \u2014 regex wallet + accesso clipboard").description("Nello stesso metodo sono presenti sia pattern regex per riconoscere indirizzi di wallet crypto (BTC/ETH/LTC/XMR) sia chiamate alla clipboard di sistema. Questo \u00e8 il pattern tipico di un \"crypto clipper\": il malware monitora la clipboard, riconosce quando l'utente copia un indirizzo wallet e lo sostituisce con uno controllato dall'attaccante.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli .class").evidence(String.join((CharSequence)"\n", clipperLocs)).family("CryptoClipper").recommendation("Verificare manualmente se il metodo confronta/sostituisce il contenuto della clipboard.").build());
        }
        if (discordTokens.get() > 0) {
            findings.add(new Finding.Builder().title("Token Discord hardcoded \u2014 " + discordTokens.get() + " occorrenze").description("Trovato un token Discord (utente o bot) nel formato reale, incorporato direttamente nel JAR. Un token hardcoded indica quasi sempre un account compromesso usato per esfiltrare dati o un bot malevolo pronto all'uso.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence(String.join((CharSequence)"\n", discordTokenLocs)).family("DiscordTokenHardcoded").recommendation("Il token va considerato compromesso: revocarlo/rigenerarlo se appartiene a un account reale.").build());
        }
        if (discordWebhooks.get() > 0) {
            findings.add(new Finding.Builder().title("Webhook Discord embedded \u2014 " + discordWebhooks.get() + " occorrenze").description("URL di webhook Discord completo e funzionante incorporato nel JAR. Tecnica molto comune nei mod/grabber malevoli per inviare dati rubati (token, screenshot, file, informazioni di sistema) senza bisogno di un proprio server C2.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli file").evidence(String.join((CharSequence)"\n", discordWebhookLocs)).family("DiscordWebhookExfiltration").build());
        }
        if (!polyglotEntries.isEmpty()) {
            findings.add(new Finding.Builder().title("File polyglot / payload nascosto \u2014 " + polyglotEntries.size() + " entry sospette").description("Una o pi\u00f9 entry nel JAR hanno un'estensione che dichiara un tipo di file (immagine, testo, config) ma il contenuto reale (magic bytes) \u00e8 quello di un JAR/ZIP, di un file .class o di un eseguibile Windows (MZ). \u00c8 una tecnica comune per nascondere un secondo stage o un payload dentro una risorsa apparentemente innocua.").severity(Severity.HIGH).category(Category.STRUCTURE).location("Multipli file").evidence(String.join((CharSequence)"\n", polyglotEntries)).family("PolyglotPayload").recommendation("Estrarre ed ispezionare manualmente le entry elencate.").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Exfiltration analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private void checkPolyglot(String entryName, byte[] bytes, List<String> polyglotEntries) {
        if (bytes.length < 4) {
            return;
        }
        String lower = entryName.toLowerCase(Locale.ROOT);
        String ext = ExfiltrationAnalyzer.extensionOf(lower);
        if (ext == null) {
            return;
        }
        if (!TEXT_LIKE_EXTENSIONS.contains(ext) && !IMAGE_EXTENSIONS.contains(ext)) {
            return;
        }
        String realType = null;
        if (ExfiltrationAnalyzer.startsWith(bytes, ZIP_MAGIC)) {
            realType = "ZIP/JAR";
        } else if (ExfiltrationAnalyzer.startsWith(bytes, CLASS_MAGIC)) {
            realType = "Java .class";
        } else if (ExfiltrationAnalyzer.startsWith(bytes, MZ_MAGIC)) {
            realType = "Eseguibile Windows (MZ/PE)";
        }
        if (realType != null && polyglotEntries.size() < 20) {
            polyglotEntries.add(entryName + " \u2014 dichiarato \"" + ext + "\" ma contenuto reale: " + realType);
        }
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; ++i) {
            if (data[i] == prefix[i]) continue;
            return false;
        }
        return true;
    }

    private static String extensionOf(String lowerName) {
        int idx = lowerName.lastIndexOf(46);
        if (idx < 0) {
            return null;
        }
        return lowerName.substring(idx);
    }

    private void analyzeClass(final String classRef, byte[] bytes, final AtomicInteger clipperCombo, final List<String> clipperLocs) {
        ClassReader cr;
        try {
            cr = new ClassReader(bytes);
        }
        catch (Exception e) {
            return;
        }
        cr.accept(new ClassVisitor(589824){

            public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                return new MethodVisitor(589824){
                    boolean usesClipboard;
                    boolean usesWalletRegex;
                    {
                        this.usesClipboard = false;
                        this.usesWalletRegex = false;
                    }

                    public void visitMethodInsn(int opc, String owner, String n, String d, boolean itf) {
                        if (CLIPBOARD_OWNERS.contains(owner) && CLIPBOARD_METHODS.contains(n)) {
                            this.usesClipboard = true;
                        }
                        super.visitMethodInsn(opc, owner, n, d, itf);
                    }

                    public void visitLdcInsn(Object value) {
                        if (value instanceof String) {
                            String s = (String)value;
                            if (ExfiltrationAnalyzer.looksLikeWalletRegexLiteral(s)) {
                                this.usesWalletRegex = true;
                            }
                            for (Pattern addrPattern : WALLET_ADDRESS_PATTERNS.values()) {
                                if (!addrPattern.matcher(s).find()) continue;
                                this.usesWalletRegex = true;
                                break;
                            }
                        }
                        super.visitLdcInsn(value);
                    }

                    public void visitEnd() {
                        if (this.usesClipboard && this.usesWalletRegex) {
                            clipperCombo.incrementAndGet();
                            if (clipperLocs.size() < 10) {
                                clipperLocs.add(classRef + "::" + mName + " -> clipboard + wallet-address pattern");
                            }
                        }
                        super.visitEnd();
                    }
                };
            }
        }, 4);
    }

    private static boolean looksLikeWalletRegexLiteral(String s) {
        boolean hasRegexSyntax;
        if (s.length() < 8 || s.length() > 200) {
            return false;
        }
        boolean bl = hasRegexSyntax = s.contains("[") && s.contains("]") && (s.contains("{") || s.contains("+") || s.contains("*"));
        if (!hasRegexSyntax) {
            return false;
        }
        String lower = s.toLowerCase(Locale.ROOT);
        return lower.contains("a-z") || lower.contains("a-f") || lower.contains("0-9") || s.contains("bc1") || s.contains("0x[a-fA-F0-9]");
    }

    private void scanTextForSecrets(String entryName, byte[] bytes, AtomicInteger discordTokens, List<String> discordTokenLocs, AtomicInteger discordWebhooks, List<String> discordWebhookLocs) {
        String text;
        try {
            text = new String(bytes, StandardCharsets.UTF_8);
        }
        catch (Exception e) {
            return;
        }
        Matcher tokenMatcher = DISCORD_TOKEN_PATTERN.matcher(text);
        while (tokenMatcher.find() && discordTokens.get() < 25) {
            discordTokens.incrementAndGet();
            if (discordTokenLocs.size() >= 10) continue;
            String match = tokenMatcher.group();
            discordTokenLocs.add(entryName + " -> " + ExfiltrationAnalyzer.redact(match));
        }
        Matcher webhookMatcher = DISCORD_WEBHOOK_URL_PATTERN.matcher(text);
        while (webhookMatcher.find() && discordWebhooks.get() < 25) {
            discordWebhooks.incrementAndGet();
            if (discordWebhookLocs.size() >= 10) continue;
            discordWebhookLocs.add(entryName + " -> " + ExfiltrationAnalyzer.redact(webhookMatcher.group()));
        }
    }

    private static String redact(String secret) {
        if (secret.length() <= 12) {
            return "***redacted***";
        }
        return secret.substring(0, 6) + "..." + secret.substring(secret.length() - 4) + " (redacted)";
    }
}
