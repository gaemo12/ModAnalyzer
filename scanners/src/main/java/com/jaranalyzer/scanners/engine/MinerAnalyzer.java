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
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MinerAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(MinerAnalyzer.class);
    private static final Set<String> STRATUM_STRINGS = Set.of("stratum+tcp://", "stratum+ssl://", "stratum+tls://", "stratum://", "mining.subscribe", "mining.authorize", "mining.notify", "mining.set_difficulty", "mining.submit", "eth_submitHashrate", "eth_getWork", "eth_submitWork");
    private static final Set<String> POOL_DOMAINS = Set.of("pool.minexmr.com", "minexmr.com", "moneroocean.stream", "c3pool.com", "xmrpool.eu", "xmrpool.net", "supportxmr.com", "hashvault.pro", "2miners.com", "nanopool.org", "ethermine.org", "flexpool.io", "f2pool.com", "antpool.com", "nicehash.com", "miningpoolhub.com", "unmineable.com", "hiveon.net");
    private static final Set<String> MINER_SOFTWARE = Set.of("xmrig", "XMRig", "XMRIG", "xmr-stak", "XMR-Stak", "cpuminer", "CpuMiner", "ccminer", "cgminer", "bfgminer", "lolminer", "t-rex", "gminer", "nanominer", "srbminer", "teamredminer", "ethminer", "nsfminer", "kawpowminer", "PhoenixMiner");
    private static final Set<String> MINING_API_STRINGS = Set.of("hashrate", "Hashrate", "HASHRATE", "getBlockTemplate", "submitBlock", "getwork", "getWork", "difficulty", "shareFound", "worker_name", "wallet_address", "randomx", "RandomX", "CryptoNight", "cryptonight", "kawpow", "ProgPow", "progpow", "ethash", "Ethash", "autolykos");
    private static final Pattern XMR_WALLET = Pattern.compile("\\b4[0-9A-Za-z]{94,}\\b");
    private static final Pattern BTC_WALLET = Pattern.compile("\\b(?:1|3)[0-9A-HJ-NP-Za-km-z]{25,34}\\b|\\bbc1[0-9a-z]{6,87}\\b");
    private static final Pattern ETH_WALLET = Pattern.compile("\\b0x[0-9a-fA-F]{40}\\b");
    private static final String RUNTIME_OWNER = "java/lang/Runtime";
    private static final String THREAD_OWNER = "java/lang/Thread";

    @Override
    public String getName() {
        return "Miner Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting miner analysis on {}", (Object)jarFile.getName());
        final ArrayList<String> stratumHits = new ArrayList<String>();
        final ArrayList<String> poolHits = new ArrayList<String>();
        final ArrayList<String> softwareHits = new ArrayList<String>();
        final ArrayList<String> apiHits = new ArrayList<String>();
        final ArrayList<String> walletHits = new ArrayList<String>();
        final AtomicInteger availProcsCount = new AtomicInteger();
        final AtomicInteger threadNewCount = new AtomicInteger();
        final List cpuAbuseLocs = Collections.synchronizedList(new ArrayList());
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                String text;
                byte[] bytes;
                JarEntry entry = en.nextElement();
                if (entry.isDirectory()) continue;
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
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

                        public MethodVisitor visitMethod(int access, String mName, String desc, String sig, String[] exc) {
                            final String methodRef = entryName + "::" + mName;
                            return new MethodVisitor(589824){
                                boolean hasAvailProcs;
                                boolean hasThreadNew;
                                {
                                    this.hasAvailProcs = false;
                                    this.hasThreadNew = false;
                                }

                                public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                                    if (MinerAnalyzer.RUNTIME_OWNER.equals(owner) && "availableProcessors".equals(name)) {
                                        this.hasAvailProcs = true;
                                        availProcsCount.incrementAndGet();
                                    }
                                    if (MinerAnalyzer.THREAD_OWNER.equals(owner) && "<init>".equals(name)) {
                                        this.hasThreadNew = true;
                                        threadNewCount.incrementAndGet();
                                    }
                                    super.visitMethodInsn(opc, owner, name, d, itf);
                                }

                                public void visitLdcInsn(Object value) {
                                    if (value instanceof String) {
                                        String s = (String)value;
                                        MinerAnalyzer.this.scanForMinerStrings(s, entryName, stratumHits, poolHits, softwareHits, apiHits, walletHits);
                                    }
                                    super.visitLdcInsn(value);
                                }

                                public void visitEnd() {
                                    if (this.hasAvailProcs && this.hasThreadNew && cpuAbuseLocs.size() < 5) {
                                        cpuAbuseLocs.add(methodRef);
                                    }
                                }
                            };
                        }
                    }, 4);
                    continue;
                }
                if (bytes.length > 0x200000) continue;
                try {
                    text = new String(bytes, StandardCharsets.UTF_8);
                }
                catch (Exception e) {
                    continue;
                }
                this.scanForMinerStrings(text, entryName, stratumHits, poolHits, softwareHits, apiHits, walletHits);
            }
        }
        if (!stratumHits.isEmpty()) {
            findings.add(new Finding.Builder().title("Protocollo Stratum rilevato (" + stratumHits.size() + " hit)").description("Il JAR contiene stringhe del protocollo Stratum usato dal mining pool. mining.subscribe, mining.authorize, stratum+tcp:// sono le chiamate RPC standard per connettersi a un pool e ricevere lavoro da calcolare.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence("Stratum strings:\n" + String.join((CharSequence)"\n", stratumHits)).family("Miner").recommendation("Presenza del protocollo Stratum in un JAR non dichiaratamente un miner \u00e8 un indicatore critico di cryptojacking.").build());
        }
        if (!poolHits.isEmpty()) {
            findings.add(new Finding.Builder().title("Pool di mining noti (" + poolHits.size() + " riferimenti)").description("Il JAR contiene riferimenti a domini di pool di mining noti: minexmr, moneroocean, c3pool, nicehash, ethermine, ecc.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence("Pool domains:\n" + String.join((CharSequence)"\n", poolHits)).family("Miner").build());
        }
        if (!softwareHits.isEmpty()) {
            findings.add(new Finding.Builder().title("Software miner identificato (" + softwareHits.size() + " match)").description("Il JAR contiene riferimenti a software miner noti: XMRig, xmr-stak, cpuminer, ethminer, lolminer, ecc.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence("Miner software:\n" + String.join((CharSequence)"\n", softwareHits)).family("Miner").build());
        }
        if (!walletHits.isEmpty()) {
            findings.add(new Finding.Builder().title("Wallet address crypto hardcodato (" + walletHits.size() + ")").description("Il JAR contiene indirizzi wallet di criptovaluta hardcodati (XMR, BTC, ETH). Nei miner malevoli, \u00e8 l'indirizzo dell'attaccante che riceve i proventi del cryptojacking.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence("Wallet addresses:\n" + String.join((CharSequence)"\n", walletHits)).family("MinerWallet").build());
        }
        if (!apiHits.isEmpty()) {
            findings.add(new Finding.Builder().title("Mining API strings (" + apiHits.size() + " riferimenti)").description("Il JAR contiene stringhe tipiche dell'API di mining: hashrate, getBlockTemplate, difficulty, RandomX, Ethash, ecc.").severity(Severity.HIGH).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence("API strings:\n" + String.join((CharSequence)"\n", apiHits)).family("Miner").build());
        }
        if (!cpuAbuseLocs.isEmpty()) {
            findings.add(new Finding.Builder().title("CPU abuse pattern \u2014 availableProcessors + Thread creation").description("Metodi che chiamano Runtime.availableProcessors() e creano thread: pattern tipico dei miner che saturano tutti i core CPU disponibili per massimizzare l'hashrate.").severity(Severity.HIGH).category(Category.MALWARE_BEHAVIOR).location("Multipli .class").evidence("CPU abuse locations:\n" + String.join((CharSequence)"\n", cpuAbuseLocs)).family("CPUAbuse").build());
        }
        if (!stratumHits.isEmpty() && !walletHits.isEmpty()) {
            findings.add(new Finding.Builder().title("COMBO CRITICO: Stratum + Wallet \u2014 Cryptominer completo").description("Il JAR contiene sia il protocollo Stratum che un wallet hardcodato. Questo \u00e8 un cryptominer completo integrato nel JAR: si connette al pool con le credenziali dell'attaccante e usa le risorse CPU/GPU della vittima per minare criptovaluta.").severity(Severity.CRITICAL).category(Category.MALWARE_BEHAVIOR).location("Multipli file").evidence("Stratum hits: " + stratumHits.size() + "\nWallet hits: " + walletHits.size()).family("Cryptominer").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Miner analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }

    private void scanForMinerStrings(String s, String location, List<String> stratum, List<String> pools, List<String> software, List<String> api, List<String> wallets) {
        String lower = s.toLowerCase(Locale.ROOT);
        String snip = s.substring(0, Math.min(120, s.length()));
        for (String st : STRATUM_STRINGS) {
            if (!lower.contains(st.toLowerCase(Locale.ROOT)) || stratum.size() >= 10) continue;
            this.addUnique(stratum, "[" + st + "] in " + location + " \u2192 " + snip);
        }
        for (String pool : POOL_DOMAINS) {
            if (!lower.contains(pool.toLowerCase(Locale.ROOT)) || pools.size() >= 10) continue;
            this.addUnique(pools, "[" + pool + "] in " + location);
        }
        for (String sw : MINER_SOFTWARE) {
            if (!s.contains(sw) || software.size() >= 10) continue;
            this.addUnique(software, "[" + sw + "] in " + location);
        }
        for (String a : MINING_API_STRINGS) {
            if (!s.contains(a) || api.size() >= 15) continue;
            this.addUnique(api, "[" + a + "] in " + location);
        }
        if (wallets.size() < 10) {
            if (XMR_WALLET.matcher(s).find()) {
                this.addUnique(wallets, "[XMR wallet] in " + location + ": " + snip);
            }
            if (ETH_WALLET.matcher(s).find()) {
                this.addUnique(wallets, "[ETH wallet] in " + location + ": " + snip);
            }
            if (BTC_WALLET.matcher(s).find()) {
                this.addUnique(wallets, "[BTC wallet] in " + location + ": " + snip);
            }
        }
    }

    private void addUnique(List<String> list, String value) {
        if (!list.contains(value)) {
            list.add(value);
        }
    }
}
