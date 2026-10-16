package com.jaranalyzer.scanners.engine.rules;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.ArrayList;
import java.util.List;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Estrazione stringhe dalle classi senza fidarsi dei soli {@code LDC}
 * (report revisione, sez. 1).
 *
 * <ul>
 *   <li>{@link #ldcStrings}: stringhe d'uso, via {@code visitLdcInsn}.</li>
 *   <li>{@link #utf8Constants}: tutto il constant pool Utf8 (nomi esclusi no:
 *   include anche descrittori, ma per gli IOC va bene), quindi valori di
 *   annotazioni, argomenti dei bootstrap {@code invokedynamic} e
 *   {@code ConstantValue} dei campi.</li>
 * </ul>
 * Mai eccezioni verso il chiamante: classi non leggibili danno liste vuote.
 */
public final class ConstantPool {
    private static final Logger log = LoggerFactory.getLogger(ConstantPool.class);
    /** Stringhe oltre questa lunghezza non sono IOC utili. */
    private static final int MAX_STR_LEN = 8192;
    /** Tetto anti-abuso per classi degeneri. */
    private static final int MAX_STRINGS = 20000;

    private ConstantPool() {
    }

    /** Stringhe caricate con LDC nei metodi (ambito CLASS_CONST). */
    public static List<String> ldcStrings(byte[] cls) {
        List<String> out = new ArrayList<>();
        if (cls == null || cls.length < 8) {
            return out;
        }
        try {
            ClassReader cr = new ClassReader(cls);
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc,
                        String sig, String[] ex) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitLdcInsn(Object value) {
                            if (value instanceof String s && out.size() < MAX_STRINGS
                                    && s.length() <= MAX_STR_LEN && !s.isEmpty()) {
                                out.add(s);
                            }
                            super.visitLdcInsn(value);
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (Throwable t) {
            log.debug("ldcStrings fallito: {}", t.getMessage());
        }
        return out;
    }

    /**
     * Tutte le costanti Utf8 del pool (ambito CLASS_POOL). Il tag sta a
     * {@code off-1}, la lunghezza u2 a {@code off} (layout interno ASM).
     */
    public static List<String> utf8Constants(byte[] cls) {
        List<String> out = new ArrayList<>();
        if (cls == null || cls.length < 8) {
            return out;
        }
        try {
            ClassReader cr = new ClassReader(cls);
            int n = cr.getItemCount();
            for (int i = 1; i < n && out.size() < MAX_STRINGS; i++) {
                int off;
                try {
                    off = cr.getItem(i);
                } catch (Exception e) {
                    continue;
                }
                if (off < 1 || off >= cls.length || (cls[off - 1] & 0xFF) != 1) {
                    continue; // 1 = CONSTANT_Utf8
                }
                int len = cr.readUnsignedShort(off);
                if (len <= 0 || len > MAX_STR_LEN || off + 2 + len > cls.length) {
                    continue;
                }
                try {
                    String s = new DataInputStream(
                            new ByteArrayInputStream(cls, off, len + 2)).readUTF();
                    if (!s.isEmpty()) {
                        out.add(s);
                    }
                } catch (Exception ignored) {
                    // voce non decodificabile: si salta
                }
            }
        } catch (Throwable t) {
            log.debug("utf8Constants fallito: {}", t.getMessage());
        }
        return out;
    }
}
