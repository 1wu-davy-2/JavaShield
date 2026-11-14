package com.javashield.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

class StubGeneratorTest {

    private static final Charset LATIN_1 = Charset.forName("ISO-8859-1");

    @Test
    void stubKeepsMetadataAndDropsBusinessStrings() throws Exception {
        byte[] original = read("/com/javashield/builder/fixture/Target.class");
        byte[] stub = StubGenerator.stub(original);

        assertEquals("com/javashield/builder/fixture/Target", new ClassReader(stub).getClassName());
        assertTrue(stub.length < original.length, "stub should be smaller than the original");

        String raw = new String(stub, LATIN_1);
        assertFalse(raw.contains("business-secret-value"), "string constants must not leak into the stub");
        assertTrue(raw.contains("com/javashield/builder/fixture/Demo"), "annotations must be preserved");
    }

    @Test
    void everyConcreteMethodBecomesAThrow() throws Exception {
        byte[] stub = StubGenerator.stub(read("/com/javashield/builder/fixture/Target.class"));
        final List<String> answerOpcodes = new ArrayList<String>();
        final boolean[] answerAnnotated = {false};

        new ClassReader(stub).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                if (!"answer".equals(name)) {
                    return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        answerOpcodes.add(opcode + ":" + type);
                    }

                    @Override
                    public void visitInsn(int opcode) {
                        answerOpcodes.add(String.valueOf(opcode));
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        answerOpcodes.add("LDC:" + value);
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String method,
                                                String desc, boolean itf) {
                        answerOpcodes.add(opcode + ":" + owner + "." + method);
                    }

                    @Override
                    public void visitLineNumber(int line, Label start) {
                        answerOpcodes.add("LINE");
                    }

                    @Override
                    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                        answerAnnotated[0] = true;
                        return null;
                    }
                };
            }
        }, 0);

        assertEquals(5, answerOpcodes.size(), "stub body should be exactly one throw: " + answerOpcodes);
        assertEquals(Opcodes.NEW + ":java/lang/LinkageError", answerOpcodes.get(0));
        assertEquals(String.valueOf(Opcodes.DUP), answerOpcodes.get(1));
        assertTrue(answerOpcodes.get(2).startsWith("LDC:"));
        assertEquals(Opcodes.INVOKESPECIAL + ":java/lang/LinkageError.<init>", answerOpcodes.get(3));
        assertEquals(String.valueOf(Opcodes.ATHROW), answerOpcodes.get(4));
        assertTrue(answerAnnotated[0], "method annotation must survive");
        assertFalse(answerOpcodes.contains("LINE"), "line numbers belong to the real class only");
    }

    @Test
    void classAnnotationSurvives() throws Exception {
        byte[] stub = StubGenerator.stub(read("/com/javashield/builder/fixture/Target.class"));
        final boolean[] seen = {false};
        new ClassReader(stub).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                if (descriptor.contains("Demo")) {
                    seen[0] = true;
                }
                return null;
            }
        }, 0);
        assertTrue(seen[0]);
    }

    private static byte[] read(String resource) throws Exception {
        InputStream in = StubGeneratorTest.class.getResourceAsStream(resource);
        if (in == null) {
            throw new IllegalStateException("fixture not found: " + resource);
        }
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }
}
