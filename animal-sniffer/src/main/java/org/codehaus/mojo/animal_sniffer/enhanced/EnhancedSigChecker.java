package org.codehaus.mojo.animal_sniffer.enhanced;

/*
 * The MIT License
 *
 * Copyright (c) 2008 Kohsuke Kawaguchi and codehaus.org.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

import org.codehaus.mojo.animal_sniffer.ClassFileVisitor;
import org.codehaus.mojo.animal_sniffer.Clazz;
import org.codehaus.mojo.animal_sniffer.RegexUtils;
import org.codehaus.mojo.animal_sniffer.logging.Logger;
import org.codehaus.mojo.animal_sniffer.logging.PrintWriterLogger;
import org.objectweb.asm.*;

import java.io.*;
import java.nio.CharBuffer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * @author elseifer
 * @version $Id: EnhancedSigChecker.java, v 0.1 2020年06月29日 下午4:34 elseifer Exp $
 */
public class EnhancedSigChecker extends ClassFileVisitor {

    private final List<MatchRule> includedPackageRules;

    private final Set<String> includedPackages;

    /**
     * The fully qualified name of the annotation to use to annotate methods/fields/classes that are to be ignored by animal sniffer.
     */
    public static final String ANNOTATION_FQN = "org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement";

    /**
     * Similar to {@link #ANNOTATION_FQN}. Kept for backward compatibility reasons
     */
    public static final String PREVIOUS_ANNOTATION_FQN = "org.jvnet.animal_sniffer.IgnoreJRERequirement";

    private final Map<String, Clazz> classes = new HashMap<String, Clazz>();

    private final Logger logger;

    /**
     * Classes in this packages are considered to be resolved elsewhere and thus not a subject of the error checking when referenced.
     */
    private final List<MatchRule> ignoredPackageRules;

    private final Set<String> ignoredPackages;

    private final Set<String> ignoredOuterClassesOrMethods = new HashSet<String>();

    private boolean hadError = false;

    private List<File> sourcePath;

    private Collection<String> annotationDescriptors;

    public EnhancedSigChecker(InputStream in, Set<String> ignoredPackages, Logger logger)
            throws IOException {

        this(in, ignoredPackages, new HashSet<String>(), logger);

    }

    public EnhancedSigChecker(InputStream in, Set<String> ignoredPackages, Set<String> includedPackages, Logger logger)
            throws IOException {

        this.includedPackages = new HashSet<String>();
        this.includedPackageRules = new LinkedList<MatchRule>();

        for (String wildcard : includedPackages) {
            if (wildcard.indexOf('*') == -1 && wildcard.indexOf('?') == -1) {
                this.includedPackages.add(wildcard.replace('.', '/'));
            } else {
                this.includedPackageRules.add(newMatchRule(wildcard.replace('.', '/')));
            }
        }

        this.ignoredPackages = new HashSet<String>();
        this.ignoredPackageRules = new LinkedList<MatchRule>();
        for (String wildcard : ignoredPackages) {
            if (wildcard.indexOf('*') == -1 && wildcard.indexOf('?') == -1) {
                this.ignoredPackages.add(wildcard.replace('.', '/'));
            } else {
                this.ignoredPackageRules.add(newMatchRule(wildcard.replace('.', '/')));
            }
        }
        this.annotationDescriptors = new HashSet<String>();
        this.annotationDescriptors.add(toAnnotationDescriptor(ANNOTATION_FQN));
        this.annotationDescriptors.add(toAnnotationDescriptor(PREVIOUS_ANNOTATION_FQN));

        this.logger = logger;
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new GZIPInputStream(in));
            while (true) {
                Clazz c = (Clazz) ois.readObject();
                if (c == null) {
                    return; // finished
                }
                classes.put(c.getName(), c);
            }
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        } finally {
            if (ois != null) {
                try {
                    ois.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    private static final Map<String, String> SIG_VERSION = new HashMap<String, String>();

    static {
        SIG_VERSION.put("8", "java18-1.0.signature");
        SIG_VERSION.put("7", "java17-1.0.signature");
        SIG_VERSION.put("6", "java16-1.1.signature");
        SIG_VERSION.put("5", "java15-1.0.signature");
    }

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            System.err.println("Usage: java -jar animal-sniffer.jar [JAR/CLASS FILES] -v [...] -i [...]");
            //System.err.println("-h  : show a human readable Java version number of class file");
            System.err.println("-v [number]: expected and compliant version number of Java，" +
                    "for example，7 represents java7, default is 5, max is 8");
            System.err.println("-i [package]: ignored package");

            System.exit(-1);
        }

        //如何把 ignore 设置成可配置的 ?
        Set<String> ignoredPackages = new HashSet<String>();

        Integer version = 5;

        List<File> files = new ArrayList<File>();
        for (int i = 0; i < args.length; i++) {

            if ("-v".equals(args[i])) {
                try {
                    version = Integer.valueOf(args[++i]);
                    version = version > 8 ? 8 : version;
                    System.out.println("expected and compliant version number of Java is " + version);
                } catch (NumberFormatException nfe) {
                    System.err.println("wrong arg for -v");
                    throw nfe;
                }
                continue;
            }

            if ("-i".equals(args[i])) {
                ignoredPackages.add(args[++i]);
                continue;
            }

            File file = new File(args[i]);

            if (file.exists()) {
                files.add(file);
            } else {
                System.err.println("jar or class file is not exist: " + args[i]);
            }

        }

        if (files.isEmpty()) {
            System.err.println("there is no avaliable jar or class file");
            return;
        }

        String sigFileName = SIG_VERSION.get(version.toString());

        //读取 sigFileName 文件
        InputStream in = EnhancedSigChecker.class.getClassLoader().getResourceAsStream(sigFileName);

        EnhancedSigChecker checker = new EnhancedSigChecker(in, ignoredPackages, new PrintWriterLogger(System.out));

        for (File file : files) {
            System.out.println("\n======= Start to check [" + file + "] =======");
            checker.process(file);
            System.out.println("======= Check [" + file + "] finished =======");
        }
    }

    /**
     * @since 1.9
     */
    public void setSourcePath(List<File> sourcePath) {
        this.sourcePath = sourcePath;
    }

    /**
     * Sets the annotation type(s) that this checker should consider to ignore annotated methods, classes or fields.
     * <p>
     * By default, the {@link #ANNOTATION_FQN} and {@link #PREVIOUS_ANNOTATION_FQN} are used.
     * <p>
     * If you want to <strong>add</strong> an extra annotation types, make sure to add the standard one to the specified lists.
     *
     * @param annotationTypes a list of the fully qualified name of the annotation types to consider for ignoring annotated method, class
     *                        and field
     * @since 1.11
     */
    public void setAnnotationTypes(Collection<String> annotationTypes) {
        this.annotationDescriptors.clear();
        for (String annotationType : annotationTypes) {
            annotationDescriptors.add(toAnnotationDescriptor(annotationType));
        }
    }

    protected void process(final String name, InputStream image)
            throws IOException {
        ClassReader cr = new ClassReader(image);

        try {
            cr.accept(new CheckingVisitor(name), 0);
        } catch (ArrayIndexOutOfBoundsException e) {
            logger.error("Bad class file " + name);
            // MANIMALSNIFFER-9 it is a pity that ASM does not throw a nicer error on encountering a malformed
            // class file.
            throw new IOException("Bad class file " + name, e);
        }
    }

    private interface MatchRule {
        boolean matches(String text);
    }

    private static class PrefixMatchRule implements MatchRule {
        private final String prefix;

        private PrefixMatchRule(String prefix) {
            this.prefix = prefix;
        }

        public boolean matches(String text) {
            return text.startsWith(prefix);
        }
    }

    private static class ExactMatchRule implements MatchRule {
        private final String match;

        private ExactMatchRule(String match) {
            this.match = match;
        }

        public boolean matches(String text) {
            return match.equals(text);
        }
    }

    private static class RegexMatchRule implements MatchRule {
        private final Pattern regex;

        public RegexMatchRule(Pattern regex) {
            this.regex = regex;
        }

        public boolean matches(String text) {
            return regex.matcher(text).matches();
        }
    }

    private MatchRule newMatchRule(String matcher) {
        int i = matcher.indexOf('*');
        if (i == -1) {
            return new ExactMatchRule(matcher);
        }
        if (i == matcher.length() - 1) {
            return new PrefixMatchRule(matcher.substring(0, i));
        }
        return new RegexMatchRule(RegexUtils.compileWildcard(matcher));
    }

    public boolean isSignatureBroken() {
        return hadError;
    }

    private class CheckingVisitor
            extends ClassVisitor {
        private final Set<String> ignoredPackageCache;

        private String packagePrefix;
        private int    line;
        private String name;
        private String internalName;

        private boolean ignoreClass = false;

        //major version of .class file
        private int majorVersion;

        private CheckingVisitor(String name) {
            super(Opcodes.ASM5);
            this.ignoredPackageCache = new HashSet<String>(50 * ignoredPackageRules.size());
            this.name = name;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            internalName = name;
            packagePrefix = name.substring(0, name.lastIndexOf('/') + 1);
            majorVersion = version;
        }

        @Override
        public void visitSource(String source, String debug) {
            //fix npe
            if (sourcePath == null) {
                name = packagePrefix + source;
                return;
            }
            for (File root : sourcePath) {
                File s = new File(root, packagePrefix + source);
                if (s.isFile()) {
                    name = s.getAbsolutePath();
                }
            }
        }

        @Override
        public void visitOuterClass(String owner, String name, String desc) {
            if (ignoredOuterClassesOrMethods.contains(owner) ||
                    (name != null && ignoredOuterClassesOrMethods.contains(owner + "#" + name + desc))) {
                ignoreClass = true;
            }
        }

        private boolean isIgnoreAnnotation(String desc) {
            for (String annoDesc : annotationDescriptors) {
                if (desc.equals(annoDesc)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
            if (isIgnoreAnnotation(desc)) {
                ignoreClass = true;
                ignoredOuterClassesOrMethods.add(internalName);
            }
            return super.visitAnnotation(desc, visible);
        }

        @Override
        public FieldVisitor visitField(int access, String name, final String descriptor, String signature, Object value) {
            return new FieldVisitor(Opcodes.ASM5) {

                @Override
                public void visitEnd() {
                    checkType(Type.getType(descriptor), false);
                }

            };
        }

        @Override
        public MethodVisitor visitMethod(int access, final String name, final String desc, String signature, String[] exceptions) {
            line = 0;
            return new MethodVisitor(Opcodes.ASM5) {
                /**
                 * True if @IgnoreJRERequirement is set.
                 */
                boolean ignoreError = ignoreClass;
                Label label = null;
                Map<Label, Set<String>> exceptions = new HashMap<Label, Set<String>>();

                @Override
                public void visitEnd() {
                    checkType(Type.getReturnType(desc), ignoreError);
                }

                @Override
                public AnnotationVisitor visitAnnotation(String annoDesc, boolean visible) {
                    if (isIgnoreAnnotation(annoDesc)) {
                        ignoreError = true;
                        ignoredOuterClassesOrMethods.add(internalName + "#" + name + desc);
                    }
                    return super.visitAnnotation(annoDesc, visible);
                }

                private static final String LAMBDA_METAFACTORY = "java/lang/invoke/LambdaMetafactory";

                @Override
                public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs) {
                    if (LAMBDA_METAFACTORY.equals(bsm.getOwner())) {
                        if ("metafactory".equals(bsm.getName()) ||
                                "altMetafactory".equals(bsm.getName())) {
                            // check the method reference
                            Handle methodHandle = (Handle) bsmArgs[1];
                            check(methodHandle.getOwner(), methodHandle.getName() + methodHandle.getDesc(), ignoreError);
                            // check the functional interface type
                            checkType(Type.getReturnType(desc), ignoreError);
                        }
                    }
                }

                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                    checkType(Type.getReturnType(desc), ignoreError);
                    check(owner, name + desc, ignoreError);
                }

                @Override
                public void visitTypeInsn(int opcode, String type) {
                    checkType(type, ignoreError);
                }

                @Override
                public void visitFieldInsn(int opcode, String owner, String name, String desc) {
                    check(owner, name + '#' + desc, ignoreError);
                }

                @Override
                public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
                    if (type != null) {
                        Set<String> exceptionTypes = exceptions.get(handler);
                        if (exceptionTypes == null) {
                            exceptionTypes = new HashSet<String>();
                            exceptions.put(handler, exceptionTypes);
                        }
                        // we collect the types for the handler
                        // because we do not have the line number here
                        // and we need a list for a multi catch block
                        exceptionTypes.add(type);
                    }
                }

                @Override
                public void visitFrame(int type, int nLocal, Object[] local, int nStack, Object[] stack) {
                    Set<String> exceptionTypes = exceptions.remove(label);
                    if (exceptionTypes != null) {
                        for (String exceptionType : exceptionTypes) {
                            checkType(exceptionType, ignoreError);
                        }
                        for (int i = 0; i < nStack; i++) {
                            Object obj = stack[i];
                            // on the frame stack we check if we have a type which is not
                            // present in the catch/multi catch statement
                            if (obj instanceof String && !exceptionTypes.contains(obj)) {
                                checkType(obj.toString(), ignoreError);
                            }
                        }
                    }
                }

                @Override
                public void visitLineNumber(int line, Label start) {
                    CheckingVisitor.this.line = line;
                }

                @Override
                public void visitLabel(Label label) {
                    this.label = label;
                }

            };
        }

        private void checkType(Type asmType, boolean ignoreError) {
            if (asmType == null) {
                return;
            }
            if (asmType.getSort() == Type.OBJECT) {
                checkType(asmType.getInternalName(), ignoreError);
            }
            if (asmType.getSort() == Type.ARRAY) {
                // recursive call
                checkType(asmType.getElementType(), ignoreError);
            }
        }

        private void checkType(String type, boolean ignoreError) {
            if (shouldBeIgnored(type, ignoreError)) {
                return;
            }
            if (type.charAt(0) == '[') {
                return; // array
            }
            Clazz sigs = classes.get(type);
            if (sigs == null) {
                error(type, null);
            }
        }

        private void check(String owner, String sig, boolean ignoreError) {
            if (shouldBeIgnored(owner, ignoreError)) {
                return;
            }
            if (find(classes.get(owner), sig, true)) {
                return; // found it
            }
            error(owner, sig);
        }

        private boolean shouldBeIgnored(String type, boolean ignoreError) {
            if (ignoreError) {
                return true;    // warning suppressed in this context
            }
            if (type.charAt(0) == '[') {
                return true; // array
            }

            if (ignoredPackages.contains(type) || ignoredPackageCache.contains(type)) {
                return true;
            }
            for (MatchRule rule : ignoredPackageRules) {
                if (rule.matches(type)) {
                    ignoredPackageCache.add(type);
                    return true;
                }
            }
            return false;
        }

        /**
         * If the given signature is found in the specified class, return true.
         *
         * @param baseFind TODO
         */
        private boolean find(Clazz c, String sig, boolean baseFind) {
            if (c == null) {
                return false;
            }
            if (c.getSignatures().contains(sig)) {
                return true;
            }

            if (sig.startsWith("<"))
            // constructor and static initializer shouldn't go up the inheritance hierarchy
            {
                return false;
            }

            if (find(classes.get(c.getSuperClass()), sig, false)) {
                return true;
            }

            if (c.getSuperInterfaces() != null) {
                for (int i = 0; i < c.getSuperInterfaces().length; i++) {
                    if (find(classes.get(c.getSuperInterfaces()[i]), sig, false)) {
                        return true;
                    }
                }
            }

            // This is a rare case and quite expensive, so moving it to the end of this method and only execute it from
            // first find-call.
            if (baseFind) {
                // MANIMALSNIFFER-49
                Pattern returnTypePattern = Pattern.compile("(.+\\))L(.+);");
                Matcher returnTypeMatcher = returnTypePattern.matcher(sig);
                if (returnTypeMatcher.matches()) {
                    String method = returnTypeMatcher.group(1);
                    String returnType = returnTypeMatcher.group(2);

                    Clazz returnClass = classes.get(returnType);

                    if (returnClass != null && returnClass.getSuperClass() != null) {
                        String oldSignature = method + 'L' + returnClass.getSuperClass() + ';';
                        if (find(c, oldSignature, false)) {
                            logger.info(name + (line > 0 ? ":" + line : "")
                                    + ": Covariant return type change detected: "
                                    + toSourceForm(c.getName(), oldSignature) + " has been changed to "
                                    + toSourceForm(c.getName(), sig));
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private void error(String type, String sig) {
            hadError = true;
            logger.error("major version:" + majorVersion + " in " + name + (line > 0 ? ":" + line : "") + ": Undefined reference: "
                    + toSourceForm(type, sig));
        }
    }

    static String toSourceForm(String type, String sig) {
        String sourceType = toSourceType(type);
        if (sig == null) {
            return sourceType;
        }
        int hash = sig.indexOf('#');
        if (hash != -1) {
            return toSourceType(CharBuffer.wrap(sig, hash + 1, sig.length())) + " " + sourceType + "." + sig.substring(0, hash);
        }
        int lparen = sig.indexOf('(');
        if (lparen != -1) {
            int rparen = sig.indexOf(')');
            if (rparen != -1) {
                StringBuilder b = new StringBuilder();
                String returnType = sig.substring(rparen + 1);
                if (returnType.equals("V")) {
                    b.append("void");
                } else {
                    b.append(toSourceType(CharBuffer.wrap(returnType)));
                }
                b.append(' ');
                b.append(sourceType);
                b.append('.');
                // XXX consider prettifying <init>
                b.append(sig.substring(0, lparen));
                b.append('(');
                boolean first = true;
                CharBuffer args = CharBuffer.wrap(sig, lparen + 1, rparen);
                while (args.hasRemaining()) {
                    if (first) {
                        first = false;
                    } else {
                        b.append(", ");
                    }
                    b.append(toSourceType(args));
                }
                b.append(')');
                return b.toString();
            }
        }
        return "{" + type + ":" + sig + "}"; // ??
    }

    static String toAnnotationDescriptor(String classFqn) {
        return "L" + fromSourceType(classFqn) + ";";
    }

    private static String toSourceType(CharBuffer type) {
        switch (type.get()) {
            case 'L':
                for (int i = type.position(); i < type.limit(); i++) {
                    if (type.get(i) == ';') {
                        String text = type.subSequence(0, i - type.position()).toString();
                        type.position(i + 1);
                        return toSourceType(text);
                    }
                }
                return "{" + type + "}"; // ??
            case '[':
                return toSourceType(type) + "[]";
            case 'B':
                return "byte";
            case 'C':
                return "char";
            case 'D':
                return "double";
            case 'F':
                return "float";
            case 'I':
                return "int";
            case 'J':
                return "long";
            case 'S':
                return "short";
            case 'Z':
                return "boolean";
            default:
                return "{" + type + "}"; // ??
        }
    }

    private static String toSourceType(String text) {
        return text.replaceFirst("^java/lang/([^/]+)$", "$1").replace('/', '.').replace('$', '.');
    }

    private static String fromSourceType(String text) {
        return text.replace('.', '/').replace('.', '$');
    }

}