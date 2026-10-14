/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.objectweb.asm.AnnotationVisitor
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
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CheatAnalyzer
implements JarAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(CheatAnalyzer.class);
    private static final Set<String> MIXIN_ANNOTATIONS = Set.of("Lorg/spongepowered/asm/mixin/Mixin;", "Lorg/spongepowered/asm/mixin/injection/Inject;", "Lorg/spongepowered/asm/mixin/injection/Overwrite;", "Lorg/spongepowered/asm/mixin/injection/Redirect;", "Lorg/spongepowered/asm/mixin/injection/ModifyArg;", "Lorg/spongepowered/asm/mixin/injection/ModifyArgs;", "Lorg/spongepowered/asm/mixin/injection/ModifyConstant;", "Lorg/spongepowered/asm/mixin/injection/ModifyVariable;", "Lorg/spongepowered/asm/mixin/Shadow;", "Lorg/spongepowered/asm/mixin/Overwrite;");
    private static final Set<String> ASM_OWNERS = Set.of("org/objectweb/asm/ClassWriter", "org/objectweb/asm/MethodVisitor", "org/objectweb/asm/ClassVisitor", "org/objectweb/asm/ClassReader", "org/objectweb/asm/tree/ClassNode", "org/objectweb/asm/tree/MethodNode", "javassist/ClassPool", "javassist/CtClass", "javassist/CtMethod");
    private static final Set<String> MOVEMENT_FIELDS = Set.of("motionX", "motionY", "motionZ", "onGround", "isFlying", "noClip", "stepHeight", "jumpMovementFactor", "fallDistance", "field_70159_w", "field_70181_x", "field_70158_ak", "field_70122_o", "field_71158_b");
    private static final Set<String> ROTATION_FIELDS = Set.of("rotationYaw", "rotationPitch", "prevRotationYaw", "prevRotationPitch", "renderYawOffset", "field_70177_z", "field_70125_A", "field_70126_B", "field_70127_C");
    private static final Set<String> COMBAT_METHODS = Set.of("attackEntity", "attackTargetEntityWithCurrentItem", "damageEntity", "onLivingAttack");
    private static final Set<String> GL_OWNERS = Set.of("org/lwjgl/opengl/GL11", "com/mojang/blaze3d/systems/RenderSystem");
    private static final Set<String> GL_ESP_METHODS = Set.of("glDisable", "glDepthMask", "glDepthFunc", "glBegin", "glEnd", "glLineWidth", "glColor4f", "glColor4d", "glVertex3f", "glVertex3d");
    private static final Set<String> ATTACH_OWNERS = Set.of("com/sun/tools/attach/VirtualMachine", "com/sun/tools/attach/VirtualMachineDescriptor");
    private static final Set<String> BYPASS_STRINGS = Set.of("Watchdog", "watchdog", "NoCheat", "nocheat", "AAC", "Vulcan", "vulcan", "Grim", "grim", "Matrix", "matrix", "Spartan", "spartan", "Intave", "intave", "AntiCheat", "anticheat", "fakePacket", "spoofPacket", "packetSpoofing", "timerBypass", "legitMode", "simulateMovement", "sendPacket", "receivePacket", "C04PacketPlayerPosition", "C05PacketPlayerLook", "C06PacketPlayerPosLook");
    private static final Set<String> C2_STRINGS = Set.of("discord.com/api/webhooks", "api.telegram.org", "pastebin.com", "hastebin.com", "githubusercontent.com", "hwid", "HWID", "checkLicense", "verifyKey", "killSwitch", "kill_switch", "authenticate");
    private static final Set<String> CHEAT_PACKAGES = Set.of("me/rigamortis/seppuku", "me/zero/meteor", "com/lambda/client", "net/ccbluex/liquidbounce", "org/rusherhack", "net/wurstclient", "me/lyrizz/outware", "modules/movement", "modules/combat", "modules/render", "hack/", "hacks/", "client/modules");

    @Override
    public String getName() {
        return "Cheat Analyzer";
    }

    @Override
    public List<Finding> analyze(File jarFile) throws Exception {
        final ArrayList<Finding> findings = new ArrayList<Finding>();
        EntryBytes.SkipLog skips = new EntryBytes.SkipLog();
        log.info("Starting cheat analysis on {}", (Object)jarFile.getName());
        final AtomicInteger mixinCount = new AtomicInteger();
        final AtomicInteger asmCount = new AtomicInteger();
        final AtomicInteger moveCount = new AtomicInteger();
        final AtomicInteger rotCount = new AtomicInteger();
        final AtomicInteger combatCount = new AtomicInteger();
        final AtomicInteger espCount = new AtomicInteger();
        final AtomicInteger reflCount = new AtomicInteger();
        final AtomicInteger bypassCount = new AtomicInteger();
        final AtomicInteger c2Count = new AtomicInteger();
        final AtomicInteger attachCount = new AtomicInteger();
        final List mixinLocations = Collections.synchronizedList(new ArrayList());
        final List asmLocations = Collections.synchronizedList(new ArrayList());
        final List moveLocations = Collections.synchronizedList(new ArrayList());
        final List combatLocations = Collections.synchronizedList(new ArrayList());
        final List espLocations = Collections.synchronizedList(new ArrayList());
        final List bypassLocations = Collections.synchronizedList(new ArrayList());
        final List c2Locations = Collections.synchronizedList(new ArrayList());
        final List attachLocations = Collections.synchronizedList(new ArrayList());
        List<String> cheatPkgMatches = Collections.synchronizedList(new ArrayList());
        boolean hasMixinConfig = false;
        boolean hasKnownPkg = false;
        try (JarFile jar = new JarFile(jarFile);){
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                byte[] bytes;
                JarEntry entry = en.nextElement();
                String name = entry.getName();
                if (name.startsWith("mixins.") && name.endsWith(".json")) {
                    hasMixinConfig = true;
                }
                for (String pkg : CHEAT_PACKAGES) {
                    if (!name.toLowerCase(Locale.ROOT).contains(pkg)) continue;
                    hasKnownPkg = true;
                    if (cheatPkgMatches.size() >= 5) break;
                    cheatPkgMatches.add(name);
                    break;
                }
                if (entry.isDirectory() || !name.endsWith(".class")) continue;
                try {
                    bytes = EntryBytes.read(jar, entry, EntryBytes.DEFAULT_MAX_ENTRY_BYTES, skips);
                    if (bytes == null) continue;
                }
                catch (Exception e) {
                    continue;
                }
                ClassReader cr = new ClassReader(bytes);
                final String classRef = name;
                cr.accept(new ClassVisitor(589824){

                    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                        if (MIXIN_ANNOTATIONS.contains(descriptor)) {
                            mixinCount.incrementAndGet();
                            if (mixinLocations.size() < 8) {
                                mixinLocations.add(classRef + " [" + descriptor + "]");
                            }
                        }
                        return super.visitAnnotation(descriptor, visible);
                    }

                    public MethodVisitor visitMethod(int access, final String mName, String desc, String sig, String[] exc) {
                        return new MethodVisitor(589824){
                            boolean hasASM;
                            boolean hasMove;
                            boolean hasRot;
                            boolean hasCombat;
                            boolean hasESP;
                            boolean hasReflAcc;
                            boolean hasBypass;
                            boolean hasC2;
                            boolean hasAttach;
                            {
                                this.hasASM = false;
                                this.hasMove = false;
                                this.hasRot = false;
                                this.hasCombat = false;
                                this.hasESP = false;
                                this.hasReflAcc = false;
                                this.hasBypass = false;
                                this.hasC2 = false;
                                this.hasAttach = false;
                            }

                            public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                                if (MIXIN_ANNOTATIONS.contains(descriptor)) {
                                    mixinCount.incrementAndGet();
                                    if (mixinLocations.size() < 8) {
                                        mixinLocations.add(classRef + "::" + mName);
                                    }
                                }
                                return super.visitAnnotation(descriptor, visible);
                            }

                            public void visitMethodInsn(int opc, String owner, String n, String d, boolean itf) {
                                if (ASM_OWNERS.contains(owner)) {
                                    this.hasASM = true;
                                }
                                if (COMBAT_METHODS.contains(n)) {
                                    this.hasCombat = true;
                                }
                                if (ATTACH_OWNERS.contains(owner)) {
                                    this.hasAttach = true;
                                }
                                if (GL_OWNERS.contains(owner) && GL_ESP_METHODS.contains(n)) {
                                    this.hasESP = true;
                                }
                                if (("java/lang/reflect/Field".equals(owner) || "java/lang/reflect/Method".equals(owner) || "java/lang/Class".equals(owner)) && ("setAccessible".equals(n) || "getDeclaredField".equals(n) || "getDeclaredMethod".equals(n))) {
                                    this.hasReflAcc = true;
                                }
                                super.visitMethodInsn(opc, owner, n, d, itf);
                            }

                            public void visitFieldInsn(int opc, String owner, String n, String d) {
                                boolean isWrite;
                                boolean bl = isWrite = opc == 181 || opc == 179;
                                if (isWrite && MOVEMENT_FIELDS.contains(n)) {
                                    this.hasMove = true;
                                }
                                if (isWrite && ROTATION_FIELDS.contains(n)) {
                                    this.hasRot = true;
                                }
                                super.visitFieldInsn(opc, owner, n, d);
                            }

                            public void visitLdcInsn(Object value) {
                                if (value instanceof String) {
                                    String s = (String)value;
                                    for (String b : BYPASS_STRINGS) {
                                        if (!s.contains(b)) continue;
                                        this.hasBypass = true;
                                        break;
                                    }
                                    for (String c : C2_STRINGS) {
                                        if (!s.contains(c)) continue;
                                        this.hasC2 = true;
                                        break;
                                    }
                                }
                                super.visitLdcInsn(value);
                            }

                            public void visitEnd() {
                                String loc = classRef + "::" + mName;
                                if (this.hasASM) {
                                    asmCount.incrementAndGet();
                                    if (asmLocations.size() < 5) {
                                        asmLocations.add(loc);
                                    }
                                }
                                if (this.hasMove) {
                                    moveCount.incrementAndGet();
                                    if (moveLocations.size() < 5) {
                                        moveLocations.add(loc);
                                    }
                                }
                                if (this.hasRot) {
                                    rotCount.incrementAndGet();
                                }
                                if (this.hasCombat) {
                                    combatCount.incrementAndGet();
                                    if (combatLocations.size() < 5) {
                                        combatLocations.add(loc);
                                    }
                                }
                                if (this.hasESP) {
                                    espCount.incrementAndGet();
                                    if (espLocations.size() < 5) {
                                        espLocations.add(loc);
                                    }
                                }
                                if (this.hasReflAcc) {
                                    reflCount.incrementAndGet();
                                }
                                if (this.hasBypass) {
                                    bypassCount.incrementAndGet();
                                    if (bypassLocations.size() < 5) {
                                        bypassLocations.add(loc);
                                    }
                                }
                                if (this.hasC2) {
                                    c2Count.incrementAndGet();
                                    if (c2Locations.size() < 5) {
                                        c2Locations.add(loc);
                                    }
                                }
                                if (this.hasAttach) {
                                    attachCount.incrementAndGet();
                                    if (attachLocations.size() < 5) {
                                        attachLocations.add(loc);
                                    }
                                }
                                if (this.hasRot && this.hasCombat) {
                                    findings.add(new Finding.Builder().title("Aimbot / Silent Aimbot rilevato").description("Metodo scrive rotationYaw/Pitch programmaticamente e chiama metodi di attacco entit\u00e0. Pattern tipico di aimbot, silent aimbot e triggerbot.").severity(Severity.CRITICAL).category(Category.CHEAT).location(loc).evidence("rotationYaw/Pitch write + attackEntity in " + loc).family("Aimbot").build());
                                }
                                if (this.hasESP) {
                                    findings.add(new Finding.Builder().title("ESP / Wallhack (OpenGL depth bypass)").description("Metodo usa GL11/RenderSystem per disabilitare depth testing o modificare la pipeline di rendering. Pattern tipico di ESP, Wallhack e Tracers.").severity(Severity.HIGH).category(Category.CHEAT).location(loc).evidence("GL depth/color ops in " + loc).family("ESP").build());
                                }
                                if (this.hasASM && mixinCount.get() > 0) {
                                    findings.add(new Finding.Builder().title("ASM + Mixin combo injection").description("Metodo usa ASM ClassWriter/MethodVisitor in una classe con annotazioni Mixin. Combinazione usata da cheat avanzati per iniettare bytecode nelle classi del gioco.").severity(Severity.CRITICAL).category(Category.CHEAT).location(loc).family("BytecodeInjection").build());
                                }
                                if (this.hasAttach) {
                                    findings.add(new Finding.Builder().title("VirtualMachine.attach() \u2014 process injection").description("Utilizzo della Attach API per iniettare un Java Agent in un processo JVM gi\u00e0 in esecuzione. Usato da cheat per agganciarsi al processo del gioco.").severity(Severity.CRITICAL).category(Category.CHEAT).location(loc).evidence("VirtualMachine.attach() in " + loc).family("AttachInjection").build());
                                }
                            }
                        };
                    }
                }, 4);
            }
        }
        if (mixinCount.get() > 0) {
            findings.add(new Finding.Builder().title("Mixin injection \u2014 " + mixinCount.get() + " annotazioni").description(mixinCount.get() + " annotazioni Mixin (@Mixin, @Inject, @Overwrite, @Redirect, ecc.). I Mixin sono usati dai cheat per modificare il bytecode del gioco a runtime." + (hasMixinConfig ? " File mixins.*.json trovato." : "")).severity(mixinCount.get() > 10 ? Severity.CRITICAL : Severity.HIGH).category(Category.CHEAT).location("Multipli .class").evidence("Count: " + mixinCount.get() + "\nLocazioni:\n" + String.join((CharSequence)"\n", mixinLocations)).family("MixinInjection").recommendation("Esamina i target dei Mixin: @Mixin su classi di movimento o rete = cheat.").build());
        }
        if (asmCount.get() > 0) {
            findings.add(new Finding.Builder().title("ASM bytecode manipulation \u2014 " + asmCount.get() + " metodi").description(asmCount.get() + " metodi usano ClassWriter/MethodVisitor di ASM per modificare bytecode a runtime.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Metodi:\n" + String.join((CharSequence)"\n", asmLocations)).family("ASMInjection").build());
        }
        if (moveCount.get() > 0) {
            findings.add(new Finding.Builder().title("Hook movimenti entit\u00e0 \u2014 " + moveCount.get() + " scritture").description(moveCount.get() + " scritture su campi di movimento (motionX/Y/Z, onGround, noClip, stepHeight). Pattern di speed hack, flight, noclip, step hack.").severity(moveCount.get() > 3 ? Severity.CRITICAL : Severity.HIGH).category(Category.CHEAT).location("Multipli .class").evidence("Metodi:\n" + String.join((CharSequence)"\n", moveLocations)).family("MovementCheat").build());
        }
        if (rotCount.get() > 0 && combatCount.get() == 0) {
            findings.add(new Finding.Builder().title("Modifica rotazione entit\u00e0 \u2014 " + rotCount.get() + " scritture").description("Scritture programmatiche su rotationYaw/Pitch fuori dall'input handler normale. Indicatore di aimbot o smooth aimbot.").severity(Severity.HIGH).category(Category.CHEAT).evidence("rotationYaw/Pitch write count: " + rotCount.get()).family("Aimbot").build());
        }
        if (combatCount.get() > 5) {
            findings.add(new Finding.Builder().title("KillAura / MultiAura \u2014 " + combatCount.get() + " hook").description("Alto numero di hook su metodi di attacco. Pattern di KillAura, MultiAura, ForceAura.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Combat hooks:\n" + String.join((CharSequence)"\n", combatLocations)).family("KillAura").build());
        }
        if (reflCount.get() > 5) {
            findings.add(new Finding.Builder().title("Reflection injection massiva \u2014 " + reflCount.get() + " accessi").description(reflCount.get() + " utilizzi di getDeclaredField/Method + setAccessible(true). I cheat usano la reflection per accedere ai campi privati delle classi del gioco.").severity(reflCount.get() > 15 ? Severity.HIGH : Severity.MEDIUM).category(Category.CHEAT).evidence("setAccessible/getDeclared count: " + reflCount.get()).family("ReflectionInjection").build());
        }
        if (bypassCount.get() > 0) {
            findings.add(new Finding.Builder().title("Anti-cheat bypass \u2014 " + bypassCount.get() + " riferimenti").description(bypassCount.get() + " riferimenti a sistemi anti-cheat noti (Watchdog, AAC, Vulcan, Grim, Matrix) o tecniche di bypass. Il JAR contiene logica per eludere il rilevamento.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Bypass locations:\n" + String.join((CharSequence)"\n", bypassLocations)).family("AntiCheatBypass").recommendation("Presenza di riferimenti a specifici anti-cheat = cheat progettato per eluderli.").build());
        }
        if (c2Count.get() > 0) {
            findings.add(new Finding.Builder().title("C2 / License server \u2014 " + c2Count.get() + " indicatori").description("Riferimenti a server C2: webhook Discord, server licenza, HWID check o kill switch.").severity(Severity.HIGH).category(Category.CHEAT).location("Multipli .class").evidence("C2 locations:\n" + String.join((CharSequence)"\n", c2Locations)).family("CheatC2").build());
        }
        if (hasKnownPkg) {
            findings.add(new Finding.Builder().title("Package cheat client noto trovato").description("Il JAR contiene package di cheat client noti: LiquidBounce, Meteor, Lambda, RusherHack, Seppuku, ecc.").severity(Severity.CRITICAL).category(Category.CHEAT).location("Multipli .class").evidence("Package:\n" + String.join((CharSequence)"\n", cheatPkgMatches)).family("KnownCheatClient").build());
        }
        if (hasMixinConfig && mixinCount.get() == 0) {
            findings.add(new Finding.Builder().title("File Mixin config senza annotazioni visibili").description("JAR contiene mixins.*.json ma nessuna annotazione Mixin standard. Possibili annotazioni offuscate o classi Mixin come bytecode puro.").severity(Severity.MEDIUM).category(Category.CHEAT).location("mixins.*.json").family("MixinInjection").build());
        }
        if (!skips.isEmpty()) {
            findings.add(skips.toFinding(jarFile.getName(), EntryBytes.DEFAULT_MAX_ENTRY_BYTES));
        }
        log.info("Cheat analysis complete \u2013 {} finding(s)", (Object)findings.size());
        return findings;
    }
}
