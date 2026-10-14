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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InjectionAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(InjectionAnalyzer.class);
    private static final Set<String> INSTR_METHODS = Set.of("redefineClasses", "retransformClasses", "getAllLoadedClasses", "appendToBootstrapClassLoaderSearch", "appendToSystemClassLoaderSearch", "addTransformer", "removeTransformer");
    private static final Set<String> CL_OWNERS = Set.of("java/net/URLClassLoader", "java/lang/ClassLoader", "java/security/SecureClassLoader");
    private static final Set<String> GADGET_CLASSES = Set.of("org/apache/commons/collections/functors/InvokerTransformer", "org/apache/commons/collections/functors/ChainedTransformer", "org/apache/commons/collections4/functors/InvokerTransformer", "org/springframework/context/support/ClassPathXmlApplicationContext", "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl");
    private static final Set<String> JNDI_OWNERS = Set.of("javax/naming/InitialContext", "javax/naming/Context", "javax/naming/directory/InitialDirContext", "java/rmi/registry/LocateRegistry", "java/rmi/Naming");
    private static final Set<String> JNDI_URL_PREFIXES = Set.of("ldap://", "ldaps://", "rmi://", "iiop://", "corbaname:", "dns://", "jndi:");
    private static final Set<String> TEMPLATE_OWNERS = Set.of("org/springframework/expression/spel/standard/SpelExpressionParser", "groovy/lang/GroovyShell", "groovy/lang/GroovyClassLoader", "bsh/Interpreter", "javax/script/ScriptEngine", "freemarker/template/Template", "org/apache/velocity/VelocityContext");
    private static final Set<String> TEMPLATE_METHODS = Set.of("parseExpression", "evaluate", "eval", "execute", "process", "merge");
    private static final Set<String> UNSAFE_OWNERS = Set.of("sun/misc/Unsafe", "jdk/internal/misc/Unsafe");
    private static final Set<String> UNSAFE_METHODS = Set.of("allocateMemory", "reallocateMemory", "freeMemory", "putByte", "putShort", "putInt", "putLong", "putObject", "putBoolean", "getByte", "getShort", "getInt", "getLong", "getObject", "objectFieldOffset", "staticFieldOffset", "defineClass", "defineAnonymousClass", "allocateInstance", "throwException");
    private static final Set<String> ATTACH_OWNERS = Set.of("com/sun/tools/attach/VirtualMachine", "com/sun/tools/attach/VirtualMachineDescriptor");
    private static final String OIS = "java/io/ObjectInputStream";
    private static final String CFT = "java/lang/instrument/ClassFileTransformer";

    @Override
    public String getName() {
        return "Injection Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        Set classesWithRetransform;
        Set classesWithCFT;
        List jndiLoc;
        List gadgetLoc;
        List instrLoc;
        AtomicInteger cftCount;
        AtomicInteger jndiUrlCount;
        AtomicInteger jndiCount;
        AtomicInteger gadgetCount;
        AtomicInteger instrCount;
        ArrayList<Finding> findings;
        final EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        block36: {
            findings = new ArrayList<Finding>();
            log.info("Starting injection analysis on {}", (Object)jarFile.getName());
            instrCount = new AtomicInteger();
            final AtomicInteger clDefCount = new AtomicInteger();
            gadgetCount = new AtomicInteger();
            jndiCount = new AtomicInteger();
            jndiUrlCount = new AtomicInteger();
            final AtomicInteger templCount = new AtomicInteger();
            final AtomicInteger unsafeCount = new AtomicInteger();
            final AtomicInteger attachCount = new AtomicInteger();
            final AtomicInteger deserCount = new AtomicInteger();
            cftCount = new AtomicInteger();
            instrLoc = Collections.synchronizedList(new ArrayList());
            final List clLoc = Collections.synchronizedList(new ArrayList());
            gadgetLoc = Collections.synchronizedList(new ArrayList());
            jndiLoc = Collections.synchronizedList(new ArrayList());
            final List templLoc = Collections.synchronizedList(new ArrayList());
            final List unsafeLoc = Collections.synchronizedList(new ArrayList());
            final List attachLoc = Collections.synchronizedList(new ArrayList());
            final List deserLoc = Collections.synchronizedList(new ArrayList());
            classesWithCFT = Collections.synchronizedSet(new HashSet());
            classesWithRetransform = Collections.synchronizedSet(new HashSet());
            try (JarFile jar = new JarFile(jarFile);){
                Enumeration<JarEntry> en = jar.entries();
                while (en.hasMoreElements()) {
                    byte[] bytes;
                    JarEntry entry = en.nextElement();
                    if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                    try {
                        bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                        if (bytes == null) continue;
                    }
                    catch (Exception e) {
                        continue;
                    }
                    final String classRef = entry.getName();
                    ClassReader cr = new ClassReader(bytes);
                    cr.accept(new ClassVisitor(589824){

                        public void visit(int version, int access, String name, String sig, String superName, String[] interfaces) {
                            if (GADGET_CLASSES.contains(superName)) {
                                gadgetCount.incrementAndGet();
                                if (gadgetLoc.size() < 5) {
                                    gadgetLoc.add(classRef + " extends " + superName);
                                }
                            }
                            if (interfaces != null) {
                                for (String iface : interfaces) {
                                    if (!InjectionAnalyzer.CFT.equals(iface)) continue;
                                    cftCount.incrementAndGet();
                                    classesWithCFT.add(classRef);
                                }
                            }
                            super.visit(version, access, name, sig, superName, interfaces);
                        }

                        public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                            return new MethodVisitor(589824){
                                boolean hasJndiUrl;
                                boolean hasJndiCall;
                                boolean hasDeser;
                                boolean hasUnsafe;
                                boolean hasGadget;
                                boolean hasTemplate;
                                boolean hasCLDefine;
                                boolean hasAttach;
                                boolean hasInstr;
                                boolean hasRetransform;
                                {
                                    this.hasJndiUrl = false;
                                    this.hasJndiCall = false;
                                    this.hasDeser = false;
                                    this.hasUnsafe = false;
                                    this.hasGadget = false;
                                    this.hasTemplate = false;
                                    this.hasCLDefine = false;
                                    this.hasAttach = false;
                                    this.hasInstr = false;
                                    this.hasRetransform = false;
                                }

                                public void visitMethodInsn(int opc, String owner, String name, String d, boolean itf) {
                                    String loc = classRef + "::" + mName;
                                    if ("java/lang/instrument/Instrumentation".equals(owner) && INSTR_METHODS.contains(name)) {
                                        this.hasInstr = true;
                                        instrCount.incrementAndGet();
                                        if (instrLoc.size() < 5) {
                                            instrLoc.add(loc + " \u2192 " + name);
                                        }
                                    }
                                    if ("retransformClasses".equals(name) || "redefineClasses".equals(name)) {
                                        this.hasRetransform = true;
                                        classesWithRetransform.add(classRef);
                                    }
                                    if (CL_OWNERS.contains(owner) && "defineClass".equals(name)) {
                                        this.hasCLDefine = true;
                                        clDefCount.incrementAndGet();
                                        if (clLoc.size() < 5) {
                                            clLoc.add(loc);
                                        }
                                    }
                                    if (JNDI_OWNERS.contains(owner) && "lookup".equals(name)) {
                                        this.hasJndiCall = true;
                                        jndiCount.incrementAndGet();
                                        if (jndiLoc.size() < 5) {
                                            jndiLoc.add(loc + " [lookup]");
                                        }
                                    }
                                    if (TEMPLATE_OWNERS.contains(owner) && TEMPLATE_METHODS.contains(name)) {
                                        this.hasTemplate = true;
                                        templCount.incrementAndGet();
                                        if (templLoc.size() < 5) {
                                            templLoc.add(loc + " \u2192 " + owner + "." + name);
                                        }
                                    }
                                    if (UNSAFE_OWNERS.contains(owner) && UNSAFE_METHODS.contains(name)) {
                                        this.hasUnsafe = true;
                                        unsafeCount.incrementAndGet();
                                        if (unsafeLoc.size() < 5) {
                                            unsafeLoc.add(loc + " \u2192 Unsafe." + name);
                                        }
                                    }
                                    if (ATTACH_OWNERS.contains(owner)) {
                                        this.hasAttach = true;
                                        attachCount.incrementAndGet();
                                        if (attachLoc.size() < 5) {
                                            attachLoc.add(loc + " \u2192 " + owner + "." + name);
                                        }
                                    }
                                    if (InjectionAnalyzer.OIS.equals(owner) && "readObject".equals(name)) {
                                        this.hasDeser = true;
                                        deserCount.incrementAndGet();
                                        if (deserLoc.size() < 5) {
                                            deserLoc.add(loc);
                                        }
                                    }
                                    if (GADGET_CLASSES.contains(owner)) {
                                        this.hasGadget = true;
                                        gadgetCount.incrementAndGet();
                                        if (gadgetLoc.size() < 5) {
                                            gadgetLoc.add(loc + " uses " + owner);
                                        }
                                    }
                                    super.visitMethodInsn(opc, owner, name, d, itf);
                                }

                                public void visitLdcInsn(Object value) {
                                    if (value instanceof String) {
                                        String s = (String)value;
                                        String lower = s.toLowerCase(Locale.ROOT);
                                        for (String prefix : JNDI_URL_PREFIXES) {
                                            if (!lower.contains(prefix)) continue;
                                            this.hasJndiUrl = true;
                                            jndiUrlCount.incrementAndGet();
                                            String loc = classRef + "::" + mName;
                                            if (jndiLoc.size() >= 5) break;
                                            jndiLoc.add(loc + " [URL: " + s.substring(0, Math.min(60, s.length())) + "]");
                                            break;
                                        }
                                    }
                                    super.visitLdcInsn(value);
                                }

                                public void visitEnd() {
                                    String loc = classRef + "::" + mName;
                                    if (this.hasJndiCall && this.hasJndiUrl) {
                                        findings.add(new Finding.Builder().title("JNDI Injection \u2014 Log4Shell style").description("JNDI lookup con URL costruito dinamicamente. Questo \u00e8 il pattern esatto di Log4Shell: carica classi da server LDAP/RMI remoto per RCE.").severity(Severity.CRITICAL).category(Category.CODE_INJECTION).location(loc).evidence("JNDI lookup + JNDI URL in " + loc).family("JNDIInjection").build());
                                    }
                                    if (this.hasCLDefine) {
                                        findings.add(new Finding.Builder().title("ClassLoader.defineClass() \u2014 payload injection").description("defineClass() carica una classe da array di byte a runtime. Se i byte vengono da decrypt/download, \u00e8 payload injection multi-stage.").severity(Severity.CRITICAL).category(Category.CODE_INJECTION).location(loc).evidence("defineClass() in " + loc).family("ClassLoaderInjection").build());
                                    }
                                    if (this.hasUnsafe) {
                                        findings.add(new Finding.Builder().title("sun.misc.Unsafe \u2014 memoria JVM diretta").description("Uso di Unsafe per lettura/scrittura diretta della memoria JVM, bypassando tutti i controlli di sicurezza.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location(loc).family("UnsafeMemory").build());
                                    }
                                    if (this.hasAttach) {
                                        findings.add(new Finding.Builder().title("VirtualMachine.attach() \u2014 process injection").description("Attach API per agganciare un processo JVM gi\u00e0 in esecuzione e iniettare un Java Agent.").severity(Severity.CRITICAL).category(Category.CODE_INJECTION).location(loc).evidence("VirtualMachine.attach() in " + loc).family("AttachAPIInjection").build());
                                    }
                                    if (this.hasTemplate) {
                                        findings.add(new Finding.Builder().title("Template/Expression injection").description("Valutazione di espressioni a runtime (SpEL, Groovy, BeanShell, Velocity, Freemarker). Se la sorgente \u00e8 input utente non sanificato = RCE.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location(loc).family("TemplateInjection").build());
                                    }
                                    if (this.hasDeser) {
                                        findings.add(new Finding.Builder().title("Java Deserialization \u2014 ObjectInputStream.readObject()").description("Deserializzazione oggetti Java. Se i dati provengono da rete/input non fidato, pu\u00f2 essere sfruttata per RCE tramite gadget chain.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location(loc).evidence("readObject() in " + loc).family("JavaDeserialization").build());
                                    }
                                }
                            };
                        }
                    }, 4);
                }
                JarEntry manifestEntry = jar.getJarEntry("META-INF/MANIFEST.MF");
                if (manifestEntry == null) break block36;
                try (InputStream is = jar.getInputStream(manifestEntry);){
                    Manifest manifest = new Manifest(is);
                    Attributes attrs = manifest.getMainAttributes();
                    if (attrs != null) {
                        String agentClass = attrs.getValue("Agent-Class");
                        String premainClass = attrs.getValue("Premain-Class");
                        String bootClassPath = attrs.getValue("Boot-Class-Path");
                        String canRetransform = attrs.getValue("Can-Retransform-Classes");
                        String canRedefine = attrs.getValue("Can-Redefine-Classes");
                        String canSetNativePrefix = attrs.getValue("Can-Set-Native-Method-Prefix");
                        if (agentClass != null) {
                            findings.add(new Finding.Builder().title("Java Agent (Agent-Class) \u2014 " + agentClass).description("MANIFEST.MF dichiara Agent-Class. Il JAR pu\u00f2 essere caricato come Java Agent tramite VirtualMachine.attach() o API di Attach, eseguendo codice con i privilegi del JVM target.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location("META-INF/MANIFEST.MF").evidence("Agent-Class: " + agentClass).family("JavaAgentManifest").build());
                        }
                        if (premainClass != null) {
                            findings.add(new Finding.Builder().title("Java Agent (Premain-Class) \u2014 " + premainClass).description("MANIFEST.MF dichiara Premain-Class. Il JAR pu\u00f2 essere usato come Java Agent a linea di comando (-javaagent), con esecuzione prima del main().").severity(Severity.HIGH).category(Category.CODE_INJECTION).location("META-INF/MANIFEST.MF").evidence("Premain-Class: " + premainClass).family("JavaAgentManifest").build());
                        }
                        if (bootClassPath != null) {
                            findings.add(new Finding.Builder().title("Boot-Class-Path \u2014 " + bootClassPath).description("MANIFEST.MF dichiara Boot-Class-Path: " + bootClassPath + ". Carica classi nel bootstrap classloader, aggirando la maggior parte delle protezioni JVM.").severity(Severity.CRITICAL).category(Category.CODE_INJECTION).location("META-INF/MANIFEST.MF").evidence("Boot-Class-Path: " + bootClassPath).family("JavaAgentManifest").build());
                        }
                        int capabilityCount = 0;
                        if ("true".equalsIgnoreCase(canRetransform)) {
                            ++capabilityCount;
                        }
                        if ("true".equalsIgnoreCase(canRedefine)) {
                            ++capabilityCount;
                        }
                        if ("true".equalsIgnoreCase(canSetNativePrefix)) {
                            ++capabilityCount;
                        }
                        if (capabilityCount > 0) {
                            findings.add(new Finding.Builder().title("Agent Capabilities \u2014 " + capabilityCount + " attive").description("MANIFEST.MF dichiara capacit\u00e0 agent: " + (canRetransform != null ? "retransform " : "") + (canRedefine != null ? "redefine " : "") + (canSetNativePrefix != null ? "native-prefix" : "") + ". Queste permettono al Java Agent di modificare classi gi\u00e0 caricate e/o alterare la risoluzione nativa.").severity(Severity.MEDIUM).category(Category.CODE_INJECTION).location("META-INF/MANIFEST.MF").evidence("Can-Retransform: " + canRetransform + ", Can-Redefine: " + canRedefine + ", Can-Set-Native-Method-Prefix: " + canSetNativePrefix).family("JavaAgentManifest").build());
                        }
                    }
                }
                catch (Exception e) {
                    log.warn("Failed to parse MANIFEST.MF", (Throwable)e);
                }
            }
        }
        HashSet selfMod = new HashSet(classesWithCFT);
        selfMod.retainAll(classesWithRetransform);
        if (!selfMod.isEmpty()) {
            findings.add(new Finding.Builder().title("Self-modifying code \u2014 " + selfMod.size() + " classi").description("Classi che implementano ClassFileTransformer E chiamano retransformClasses(). Pattern di payload che si auto-iniettano o patchano classi gi\u00e0 caricate in memoria.").severity(Severity.CRITICAL).category(Category.CODE_INJECTION).location("Multipli .class").evidence("Classi:\n" + String.join((CharSequence)"\n", selfMod.stream().limit(5L).toList())).family("SelfModifyingCode").build());
        }
        if (cftCount.get() > 0 && selfMod.isEmpty()) {
            findings.add(new Finding.Builder().title("ClassFileTransformer \u2014 " + cftCount.get() + " implementazioni").description(cftCount.get() + " classi implementano ClassFileTransformer: intercettano il bytecode di ogni classe prima dell'esecuzione.").severity(Severity.HIGH).category(Category.CODE_INJECTION).evidence("Count: " + cftCount.get()).family("ClassFileTransformer").build());
        }
        if (instrCount.get() > 0) {
            findings.add(new Finding.Builder().title("Java Instrumentation API \u2014 " + instrCount.get() + " chiamate").description("Chiamate a redefineClasses, retransformClasses, addTransformer, ecc.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location("Multipli .class").evidence("Calls:\n" + String.join((CharSequence)"\n", instrLoc)).family("JavaAgent").build());
        }
        if (gadgetCount.get() > 0) {
            findings.add(new Finding.Builder().title("Serialization gadget chain \u2014 " + gadgetCount.get() + " riferimenti").description("Classi di gadget chain (Commons Collections, Spring, TemplatesImpl) che combinate con readObject() da fonte non fidata permettono RCE.").severity(Severity.CRITICAL).category(Category.CODE_INJECTION).location("Multipli .class").evidence("Gadget locations:\n" + String.join((CharSequence)"\n", gadgetLoc)).family("SerializationGadget").build());
        }
        if (jndiCount.get() > 0 || jndiUrlCount.get() > 0) {
            int tot = jndiCount.get() + jndiUrlCount.get();
            findings.add(new Finding.Builder().title("JNDI / RMI usage \u2014 " + tot + " riferimenti").description("Lookup JNDI, RMI registry o URL ldap://, rmi://, iiop://. Vettori di Log4Shell, Spring4Shell e varianti.").severity(Severity.HIGH).category(Category.CODE_INJECTION).location("Multipli .class").evidence("Locations:\n" + String.join((CharSequence)"\n", jndiLoc)).family("JNDIInjection").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Injection analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }
}
