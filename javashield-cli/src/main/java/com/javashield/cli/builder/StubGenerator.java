package com.javashield.cli.builder;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.TypePath;

/**
 * Generates the metadata stub that replaces a protected class.
 *
 * <p>The stub keeps everything a framework scans for - class name, super class,
 * interfaces, field and method signatures, annotations, generics, record
 * components, sealed permits - and replaces every method body with a throw. The
 * real bytecode lives in an encrypted sidecar.
 *
 * <p>This is deliberately different from clearing method bodies in place: the
 * stub is never verified by the JVM because the transformer replaces it before
 * definition, and ASM based scanners (Spring component scan, MyBatis, Swagger)
 * can still read the metadata they need.
 */
public final class StubGenerator {

    private static final String ERROR_TYPE = "java/lang/LinkageError";
    private static final String ERROR_MESSAGE = "JavaShield: class loaded without the protection agent";

    private StubGenerator() {
    }

    public static String internalName(byte[] classBytes) {
        return new ClassReader(classBytes).getClassName();
    }

    public static byte[] stub(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        // Deliberately not ClassWriter(reader, ...): copying the original constant pool
        // would keep every string literal from the method bodies inside the stub.
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visitSource(String source, String debug) {
                // Drop SourceFile and SourceDebugExtension; the real class keeps them.
            }

            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object value) {
                // static final String constants are business data (SQL, keys, URLs).
                Object safeValue = value instanceof String ? null : value;
                return super.visitField(access, name, descriptor, signature, safeValue);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                    return delegate;
                }
                return new StubMethodVisitor(delegate);
            }
        };
        reader.accept(visitor, 0);
        return writer.toByteArray();
    }

    /**
     * Forwards metadata events to the writer and swallows all code events, then
     * emits a single {@code throw new LinkageError(...)} body.
     */
    private static final class StubMethodVisitor extends MethodVisitor {

        private final MethodVisitor delegate;
        private boolean emitted;

        StubMethodVisitor(MethodVisitor delegate) {
            super(Opcodes.ASM9);
            this.delegate = delegate;
        }

        @Override
        public void visitCode() {
            if (emitted) {
                return;
            }
            emitted = true;
            delegate.visitCode();
            delegate.visitTypeInsn(Opcodes.NEW, ERROR_TYPE);
            delegate.visitInsn(Opcodes.DUP);
            delegate.visitLdcInsn(ERROR_MESSAGE);
            delegate.visitMethodInsn(Opcodes.INVOKESPECIAL, ERROR_TYPE, "<init>",
                    "(Ljava/lang/String;)V", false);
            delegate.visitInsn(Opcodes.ATHROW);
        }

        @Override
        public void visitEnd() {
            if (!emitted) {
                visitCode();
            }
            delegate.visitMaxs(0, 0);
            delegate.visitEnd();
        }

        @Override
        public void visitParameter(String name, int access) {
            delegate.visitParameter(name, access);
        }

        @Override
        public AnnotationVisitor visitAnnotationDefault() {
            return delegate.visitAnnotationDefault();
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            return delegate.visitAnnotation(descriptor, visible);
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath,
                                                     String descriptor, boolean visible) {
            return delegate.visitTypeAnnotation(typeRef, typePath, descriptor, visible);
        }

        @Override
        public void visitAnnotableParameterCount(int parameterCount, boolean visible) {
            delegate.visitAnnotableParameterCount(parameterCount, visible);
        }

        @Override
        public AnnotationVisitor visitParameterAnnotation(int parameter, String descriptor, boolean visible) {
            return delegate.visitParameterAnnotation(parameter, descriptor, visible);
        }
    }
}
