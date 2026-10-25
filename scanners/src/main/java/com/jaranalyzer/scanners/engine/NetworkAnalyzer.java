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
import java.util.Iterator;
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

public class NetworkAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(NetworkAnalyzer.class);
    private static final Pattern IP_PATTERN = Pattern.compile("\\b((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))\\b");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[\\w\\-./:%?=&#@+]+", 2);
    private static final Pattern PORT_PATTERN = Pattern.compile(":(\\d{1,5})(?:[/\"'\\s]|$)");
    private static final List<String> PRIVATE_PREFIXES = List.of("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "0.0.0.0", "255.255.255.255");
    private static final Map<Integer, String> SUSPICIOUS_PORTS = Map.ofEntries(Map.entry(4444, "Metasploit default reverse shell"), Map.entry(1337, "Porta hacker classica \u2014 C2 comune"), Map.entry(31337, "Porta Elite \u2014 backdoor storica"), Map.entry(1234, "Test/debug port \u2014 spesso C2"), Map.entry(8888, "Alternate HTTP \u2014 spesso C2"), Map.entry(9999, "Porta C2 comune"), Map.entry(6666, "Porta IRC/botnet"), Map.entry(6667, "IRC \u2014 botnet C2"), Map.entry(6668, "IRC \u2014 botnet C2"), Map.entry(6669, "IRC \u2014 botnet C2"), Map.entry(1080, "SOCKS proxy \u2014 anonimizzazione"), Map.entry(9050, "Tor SOCKS proxy"), Map.entry(9150, "Tor Browser SOCKS proxy"), Map.entry(4433, "HTTPS alternativo \u2014 evasione firewall"), Map.entry(8443, "HTTPS alternativo \u2014 evasione firewall"), Map.entry(2222, "SSH alternativo"), Map.entry(5555, "ADB Android / C2"), Map.entry(7777, "C2 generico"), Map.entry(3333, "Cryptominer pool porta comune"));
    private static final Set<String> SUSPICIOUS_DOMAIN_PATTERNS = Set.of(".onion", "no-ip.com", "no-ip.org", "no-ip.net", "ddns.net", "duckdns.org", "dynu.com", "zapto.org", "serveo.net", "ngrok.io", "ngrok-free.app", "localtunnel.me", "portmap.io", "pastebin.com", "hastebin.com", "paste.ee", "paste.gg", "rentry.co", "raw.githubusercontent.com", "gist.github.com", "cdn.discordapp.com", "media.discordapp.net");
    private static final Set<String> SSL_BYPASS_OWNERS = Set.of("javax/net/ssl/TrustManager", "javax/net/ssl/X509TrustManager", "javax/net/ssl/SSLContext", "javax/net/ssl/HttpsURLConnection", "javax/net/ssl/SSLSocketFactory");
    private static final Set<String> SSL_BYPASS_METHODS = Set.of("setDefaultSSLSocketFactory", "setDefaultHostnameVerifier", "setSSLSocketFactory", "setHostnameVerifier", "checkClientTrusted", "checkServerTrusted", "getAcceptedIssuers");
    private static final Set<String> SOCKET_OWNERS = Set.of("java/net/Socket", "java/net/ServerSocket", "java/net/DatagramSocket", "java/net/MulticastSocket", "java/nio/channels/SocketChannel", "java/nio/channels/ServerSocketChannel", "java/nio/channels/DatagramChannel");
    private static final Set<String> HTTP_OWNERS = Set.of("java/net/URL", "java/net/HttpURLConnection", "java/net/URLConnection", "sun/net/www/protocol/http/HttpURLConnection", "okhttp3/OkHttpClient", "okhttp3/Request$Builder", "org/apache/http/client/HttpClient", "org/apache/http/impl/client/CloseableHttpClient");
    private static final Set<String> WEBSOCKET_OWNERS = Set.of("javax/websocket/Session", "javax/websocket/WebSocketContainer", "java/net/http/WebSocket", "org/java_websocket/client/WebSocketClient");
    private static final Set<String> DNS_OWNERS = Set.of("java/net/InetAddress", "java/net/InetSocketAddress", "java/net/Inet4Address", "java/net/Inet6Address");
    private static final Set<String> DNS_METHODS = Set.of("getByName", "getAllByName", "getByAddress", "getLocalHost");
    private static final String URL_CLASSLOADER = "java/net/URLClassLoader";
    /** Campione iniziale per le entry oltre il cap (Fase 2). */
    private static final long SAMPLE_HEAD_BYTES = 1L * 1024 * 1024;

    @Override
    public String getName() {
        return "Network Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting network analysis on {}", (Object)jarFile.getName());
        final ArrayList<String> hardcodedIPs = new ArrayList<String>();
        final ArrayList<String> suspiciousURLs = new ArrayList<String>();
        final ArrayList<String> suspiciousDomains = new ArrayList<String>();
        final ArrayList<String> suspiciousPorts = new ArrayList<String>();
        final AtomicInteger sslBypassCount = new AtomicInteger();
        final AtomicInteger socketCount = new AtomicInteger();
        final AtomicInteger httpCount = new AtomicInteger();
        final AtomicInteger websocketCount = new AtomicInteger();
        final AtomicInteger dnsCount = new AtomicInteger();
        final AtomicInteger urlClassloaderCount = new AtomicInteger();
        final List sslBypassLocs = Collections.synchronizedList(new ArrayList());
        final List urlCLLocs = Collections.synchronizedList(new ArrayList());
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                String text;
                byte[] bytes;
                JarEntry entry = en.nextElement();
                if (entry.isDirectory()) continue;
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) {
                        // Oltre il cap: campione iniziale invece di punto cieco (Fase 2).
                        this.scanSample(jar, entry, hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts, skips);
                        continue;
                    }
                }
                catch (Exception e) {
                    continue;
                }
                final String entryName = entry.getName();
                if (entryName.endsWith(".class")) {
                    ClassReader cr;
                    try {
                        cr = new ClassReader(bytes);
                    }
                    catch (Exception e) {
                        continue;
                    }
                    cr.accept(new ClassVisitor(589824){

                        public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                            return new MethodVisitor(589824){
                                /** LDC precedente del metodo per ricomporre gli split (Fase 1). */
                                private final String[] prev = new String[1];

                                public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                                    String loc;
                                    if (SSL_BYPASS_OWNERS.contains(owner) && SSL_BYPASS_METHODS.contains(name)) {
                                        // Override che delega (stesso nome del metodo chiamato, es. un
                                        // TrustManager wrapper): legittimo, non bypass. Il bypass vero
                                        // non delega a nessuno.
                                        if (!name.equals(mName)) {
                                            sslBypassCount.incrementAndGet();
                                            loc = entryName + "::" + mName + " \u2192 " + owner.replace('/', '.') + "." + name;
                                            if (sslBypassLocs.size() < 5) {
                                                sslBypassLocs.add(loc);
                                            }
                                        }
                                    }
                                    if (SOCKET_OWNERS.contains(owner)) {
                                        socketCount.incrementAndGet();
                                    }
                                    if (HTTP_OWNERS.contains(owner)) {
                                        httpCount.incrementAndGet();
                                    }
                                    if (WEBSOCKET_OWNERS.contains(owner)) {
                                        websocketCount.incrementAndGet();
                                    }
                                    if (DNS_OWNERS.contains(owner) && DNS_METHODS.contains(name)) {
                                        dnsCount.incrementAndGet();
                                    }
                                    if (NetworkAnalyzer.URL_CLASSLOADER.equals(owner)) {
                                        urlClassloaderCount.incrementAndGet();
                                        loc = entryName + "::" + mName;
                                        if (urlCLLocs.size() < 5) {
                                            urlCLLocs.add(loc);
                                        }
                                    }
                                    super.visitMethodInsn(opc, owner, name, d, itf);
                                }

                                public void visitLdcInsn(Object value) {
                                    if (value instanceof String) {
                                        String s = (String)value;
                                        NetworkAnalyzer.this.scanStringForNetworkIndicators(s, entryName, hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts);
                                        // Stringhe offuscate: decodifica prudente e ri-scansione (Fase 1).
                                        String b64 = StringNorm.tryBase64(s);
                                        if (b64 != null) {
                                            NetworkAnalyzer.this.scanStringForNetworkIndicators(b64, entryName + " [base64]", hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts);
                                        } else {
                                            String hex = StringNorm.tryHex(s);
                                            if (hex != null) {
                                                NetworkAnalyzer.this.scanStringForNetworkIndicators(hex, entryName + " [hex]", hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts);
                                            }
                                        }
                                        // Split su LDC adiacenti ("ht"+"tp://..."): ricompone a coppie (Fase 1).
                                        if (prev[0] != null) {
                                            String joined = prev[0] + s;
                                            if (joined.length() <= 4096) {
                                                NetworkAnalyzer.this.scanStringForNetworkIndicators(joined, entryName + " [concat]", hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts);
                                            }
                                        }
                                        prev[0] = s.length() > 2048 ? s.substring(0, 2048) : s;
                                    }
                                    super.visitLdcInsn(value);
                                }
                            };
                        }
                    }, 4);
                    continue;
                }
                if (bytes.length > 0x500000) {
                    // Testo oltre 5 MB: campione iniziale invece di salto cieco (Fase 2).
                    this.scanSample(jar, entry, hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts, skips);
                    continue;
                }
                try {
                    text = new String(bytes, StandardCharsets.UTF_8);
                }
                catch (Exception e) {
                    continue;
                }
                if (!this.isMostlyText(text)) continue;
                this.scanStringForNetworkIndicators(text, entryName, hardcodedIPs, suspiciousURLs, suspiciousDomains, suspiciousPorts);
            }
        }        if (!hardcodedIPs.isEmpty()) {
            findings.add(new Finding.Builder().title("IP hardcodati rilevati (" + hardcodedIPs.size() + ")").description("Il JAR contiene indirizzi IP pubblici hardcodati. Nei malware, questi IP sono spesso server C2 (Command & Control) per ricevere comandi o esfiltrare dati.").severity(Severity.HIGH).category(Category.NETWORK).location("Multipli file").evidence("IP trovati:\n" + String.join((CharSequence)"\n", hardcodedIPs.subList(0, Math.min(15, hardcodedIPs.size())))).family("HardcodedIP").recommendation("Verifica ogni IP su servizi di threat intelligence (VirusTotal, Shodan, AbuseIPDB).").build());
        }
        if (!suspiciousURLs.isEmpty()) {
            findings.add(new Finding.Builder().title("URL sospetti hardcodati (" + suspiciousURLs.size() + ")").description("Trovati URL hardcodati che potrebbero essere endpoint C2, server di download payload, o server di esfiltrazione dati.").severity(Severity.HIGH).category(Category.NETWORK).location("Multipli file").evidence("URL trovati:\n" + String.join((CharSequence)"\n", suspiciousURLs.subList(0, Math.min(10, suspiciousURLs.size())))).family("SuspiciousURL").build());
        }
        if (!suspiciousDomains.isEmpty()) {
            findings.add(new Finding.Builder().title("Domini sospetti rilevati (" + suspiciousDomains.size() + ")").description("Il JAR contiene riferimenti a domini sospetti: servizi DDNS (no-ip, duckdns), tunnel (ngrok, serveo), siti paste per C2 (pastebin), o hosting Tor (.onion).").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli file").evidence("Domini:\n" + String.join((CharSequence)"\n", suspiciousDomains)).family("SuspiciousDomain").recommendation("DDNS e servizi tunnel sono comunemente usati da malware per nascondere l'infrastruttura C2 reale.").build());
        }
        if (!suspiciousPorts.isEmpty()) {
            findings.add(new Finding.Builder().title("Porte di rete sospette (" + suspiciousPorts.size() + ")").description("Trovate connessioni su porte tipiche di backdoor, reverse shell e C2 (4444, 1337, 31337, 6666, 9050 Tor, ecc.).").severity(Severity.HIGH).category(Category.NETWORK).location("Multipli file").evidence("Porte:\n" + String.join((CharSequence)"\n", suspiciousPorts)).family("SuspiciousPort").build());
        }
        if (sslBypassCount.get() > 0) {
            findings.add(new Finding.Builder().title("SSL/TLS bypass rilevato (" + sslBypassCount.get() + " metodi)").description("Il JAR implementa TrustManager o HostnameVerifier che accettano qualsiasi certificato senza validazione. Questo bypassa completamente la sicurezza HTTPS e permette attacchi MITM \u2014 tecnica comune in RAT e stealer.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli .class").evidence("SSL bypass calls:\n" + String.join((CharSequence)"\n", sslBypassLocs)).family("SSLBypass").recommendation("checkServerTrusted() vuoto o getAcceptedIssuers() che ritorna array vuoto sono le firme classiche di SSL bypass.").build());
        }
        if (websocketCount.get() > 0) {
            findings.add(new Finding.Builder().title("WebSocket persistente rilevato").description("Il JAR usa WebSocket per connessioni bidirezionali persistenti. I RAT moderni usano WebSocket al posto di socket raw per eludere i firewall e passare come traffico web normale.").severity(Severity.HIGH).category(Category.NETWORK).location("Multipli .class").evidence("WebSocket API calls: " + websocketCount.get()).family("WebSocketC2").build());
        }
        if (urlClassloaderCount.get() > 0) {
            findings.add(new Finding.Builder().title("URLClassLoader \u2014 caricamento classe remota").description("Il JAR usa URLClassLoader per caricare classi da URL. Se l'URL \u00e8 remoto, permette il download e l'esecuzione di codice arbitrario a runtime \u2014 pattern classico di staged loader.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli .class").evidence("URLClassLoader usages:\n" + String.join((CharSequence)"\n", urlCLLocs)).family("RemoteClassLoading").build());
        }
        if (socketCount.get() > 0 && sslBypassCount.get() > 0) {
            findings.add(new Finding.Builder().title("COMBO: Socket + SSL bypass \u2014 pattern RAT/C2").description("Il JAR combina connessioni socket attive con SSL bypass. Questa combinazione \u00e8 il pattern esatto dei RAT (Remote Access Trojan) e dei client C2 che comunicano tramite TLS senza validare il certificato.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli .class").evidence("Socket calls: " + socketCount.get() + "\nSSL bypass calls: " + sslBypassCount.get()).family("RATNetwork").build());
        }
        if (urlClassloaderCount.get() > 0 && httpCount.get() > 0) {
            findings.add(new Finding.Builder().title("COMBO: URLClassLoader + HTTP \u2014 staged downloader").description("Il JAR scarica risorse tramite HTTP e le carica come classi Java. Pattern tipico di dropper/loader multi-stage: scarica il payload reale da un server remoto ed lo esegue direttamente in memoria.").severity(Severity.CRITICAL).category(Category.NETWORK).location("Multipli .class").evidence("HTTP calls: " + httpCount.get() + "\nURLClassLoader calls: " + urlClassloaderCount.get()).family("StagedLoader").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        if (skips.hasSampled()) {
            findings.add(skips.toSampledFinding(jarFile.getName(), SAMPLE_HEAD_BYTES, "NetworkAnalyzer"));
        }
        log.info("Network analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    /** Campione iniziale di un'entry oltre il cap, scansionato come testo (Fase 2). */
    private void scanSample(JarFile jar, JarEntry entry, List<String> ips, List<String> urls,
            List<String> domains, List<String> ports, EntryBytes.SkipLog skips) {
        try {
            byte[] head = EntryBytes.readHead(jar, entry, SAMPLE_HEAD_BYTES);
            if (head == null || head.length == 0) {
                return;
            }
            skips.sampled(entry.getName());
            String text = new String(head, StandardCharsets.UTF_8);
            this.scanStringForNetworkIndicators(text, entry.getName() + " [campione]", ips, urls, domains, ports);
        } catch (Exception e) {
            log.debug("Network sample fallito per {}: {}", (Object)entry.getName(), (Object)e.getMessage());
        }
    }

    private void scanStringForNetworkIndicators(String s, String location, List<String> ips, List<String> urls, List<String> domains, List<String> ports) {
        // MANIFEST = metadati: lì "21.0.12.1" è una versione JDK, non un IPv4
        // (stesso principio delle regole IOC: mai finding dai metadati).
        boolean manifest = location != null
                && location.toUpperCase(Locale.ROOT).startsWith("META-INF/MANIFEST.MF");
        Matcher ipMatcher = IP_PATTERN.matcher(s);
        while (ipMatcher.find()) {
            String entry;
            String ip = ipMatcher.group(1);
            if (manifest || this.isPrivateIP(ip) || ips.size() >= 20 || ips.contains(entry = ip + " (in: " + location + ")")) continue;
            ips.add(entry);
        }
        Matcher urlMatcher = URL_PATTERN.matcher(s);
        while (urlMatcher.find()) {
            Object entry;
            String url = urlMatcher.group();
            if (!this.isSuspiciousURL(url) || urls.size() >= 15 || urls.contains(entry = url + " (in: " + location + ")")) continue;
            urls.add((String)entry);
        }
        String lower = s.toLowerCase(Locale.ROOT);
        for (String domPat : SUSPICIOUS_DOMAIN_PATTERNS) {
            String entry;
            if (!lower.contains(domPat) || domains.size() >= 15 || domains.contains(entry = "[" + domPat + "] in: " + location + " \u2192 " + s.substring(0, Math.min(80, s.length())))) continue;
            domains.add(entry);
        }
        Matcher portMatcher = PORT_PATTERN.matcher(s);
        while (portMatcher.find()) {
            try {
                String entry;
                int port = Integer.parseInt(portMatcher.group(1));
                String desc = SUSPICIOUS_PORTS.get(port);
                if (desc == null || ports.size() >= 10 || ports.contains(entry = ":" + port + " \u2014 " + desc + " (in: " + location + ")")) continue;
                ports.add(entry);
            }
            catch (NumberFormatException numberFormatException) {}
        }
    }

    private boolean isPrivateIP(String ip) {
        for (String prefix : PRIVATE_PREFIXES) {
            if (!ip.startsWith(prefix)) continue;
            return true;
        }
        return false;
    }

    private boolean isSuspiciousURL(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        if (lower.contains("maven.org") || lower.contains("gradle.org") || lower.contains("springframework.org") || lower.contains("apache.org") || lower.contains("github.com/") && !lower.contains("/releases/")) {
            return false;
        }
        if (IP_PATTERN.matcher(url).find()) {
            return true;
        }
        Iterator<Integer> iterator = SUSPICIOUS_PORTS.keySet().iterator();
        while (iterator.hasNext()) {
            int port = iterator.next();
            if (!url.contains(":" + port)) continue;
            return true;
        }
        for (String dom : SUSPICIOUS_DOMAIN_PATTERNS) {
            if (!lower.contains(dom)) continue;
            return true;
        }
        return false;
    }

    private boolean isMostlyText(String content) {
        if (content.isEmpty()) {
            return false;
        }
        int nonPrintable = 0;
        int sample = Math.min(content.length(), 512);
        for (int i = 0; i < sample; ++i) {
            char c = content.charAt(i);
            if (c >= '\t' && (c <= '\r' || c >= ' ')) continue;
            ++nonPrintable;
        }
        return (double)nonPrintable < (double)sample * 0.05;
    }
}
