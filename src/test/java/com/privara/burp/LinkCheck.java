package com.privara.burp;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Does the built extension link against a REAL Burp Suite? Burp ships the Montoya API inside its own
 * jar; this reads every class file of the extension, takes every Montoya class, method and field it
 * references (straight from the constant pool), and resolves each one in the given Burp jar. It also
 * checks that every abstract method of a Montoya interface the extension implements is implemented,
 * so a Burp release that adds one is caught before a customer's Burp throws AbstractMethodError.
 *
 * <pre>  java -cp build/test-classes com.privara.burp.LinkCheck build/classes /path/to/burpsuite.jar</pre>
 *
 * Run by {@code BURP_JAR=/path/to/burpsuite.jar ./build.sh test}. Burp's own code is never run: the
 * classes are only loaded (not initialised) to read their signatures.
 */
public final class LinkCheck {
    private static final String MONTOYA = "burp/api/montoya/";

    public static void main(String[] args) throws Exception {
        Path classes = Paths.get(args[0]);
        URL burp = Paths.get(args[1]).toUri().toURL();
        ClassLoader platform = ClassLoader.getPlatformClassLoader();
        URLClassLoader burpLoader = new URLClassLoader(new URL[] {burp}, platform);
        URLClassLoader ours = new URLClassLoader(new URL[] {classes.toUri().toURL()}, burpLoader);
        TreeSet<String> refs = new TreeSet<>();
        List<String> missing = new ArrayList<>();
        List<String> ourNames = new ArrayList<>();
        try (Stream<Path> s = Files.walk(classes)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class")).sorted()::iterator) {
                String rel = classes.relativize(p).toString().replace('\\', '/');
                ourNames.add(rel.substring(0, rel.length() - 6).replace('/', '.'));
                try (InputStream in = Files.newInputStream(p)) {
                    refs.addAll(montoyaRefs(in));
                }
            }
        }
        for (String r : refs) {
            String[] k = r.split(" ", 4);   // kind owner name descriptor
            try {
                Class<?> c = Class.forName(k[1].replace('/', '.'), false, burpLoader);
                if (k[0].equals("class")) {
                    continue;
                }
                if (k[0].equals("field") ? !hasField(c, k[2]) : !hasMethod(c, k[2], k[3])) {
                    missing.add(r);
                }
            } catch (ClassNotFoundException | LinkageError e) {
                missing.add(r + "  (" + e + ")");
            }
        }
        int impl = 0;
        for (String n : ourNames) {
            Class<?> c;
            List<Class<?>> ifaces;
            try {
                c = Class.forName(n, false, ours);
                if (c.isInterface() || Modifier.isAbstract(c.getModifiers())) {
                    continue;
                }
                ifaces = allInterfaces(c);
            } catch (ClassNotFoundException | LinkageError e) {
                missing.add("cannot load " + n + " against this jar  (" + e + ")");
                continue;
            }
            for (Class<?> i : ifaces) {
                if (!i.getName().startsWith("burp.api.montoya.")) {
                    continue;
                }
                for (Method m : i.getMethods()) {
                    if (!Modifier.isAbstract(m.getModifiers())) {
                        continue;
                    }
                    impl++;
                    if (!implemented(c, m)) {
                        missing.add("unimplemented " + c.getName() + " :: " + i.getName() + "." + m.getName()
                                + descriptor(m));
                    }
                }
            }
        }
        System.out.println("LinkCheck against " + Paths.get(args[1]).getFileName() + ": " + refs.size()
                + " Montoya references, " + impl + " interface methods to implement");
        for (String m : missing) {
            System.out.println("  MISSING  " + m);
        }
        System.out.println(missing.isEmpty() ? "LINK OK" : "LINK FAILED (" + missing.size() + ")");
        System.exit(missing.isEmpty() ? 0 : 1);
    }

    /** "class|method|imethod|field owner name descriptor" for every Montoya constant. */
    static List<String> montoyaRefs(InputStream raw) throws IOException {
        DataInputStream in = new DataInputStream(raw);
        if (in.readInt() != 0xCAFEBABE) {
            throw new IOException("not a class file");
        }
        in.readUnsignedShort();
        in.readUnsignedShort();
        int n = in.readUnsignedShort();
        Object[] cp = new Object[n];
        int[][] refs = new int[n][];
        int[] kind = new int[n];
        for (int i = 1; i < n; i++) {
            int tag = in.readUnsignedByte();
            kind[i] = tag;
            switch (tag) {
                case 1: cp[i] = in.readUTF(); break;
                case 3: case 4: in.readInt(); break;
                case 5: case 6: in.readLong(); i++; break;
                case 7: case 8: case 16: case 19: case 20: refs[i] = new int[] {in.readUnsignedShort()}; break;
                case 9: case 10: case 11: case 12: case 17: case 18:
                    refs[i] = new int[] {in.readUnsignedShort(), in.readUnsignedShort()}; break;
                case 15: in.readUnsignedByte(); refs[i] = new int[] {in.readUnsignedShort()}; break;
                default: throw new IOException("constant tag " + tag);
            }
        }
        List<String> out = new ArrayList<>();
        for (int i = 1; i < n; i++) {
            if (kind[i] == 7) {
                String c = (String) cp[refs[i][0]];
                if (c.startsWith(MONTOYA)) {
                    out.add("class " + c + " - -");
                }
            } else if (kind[i] == 9 || kind[i] == 10 || kind[i] == 11) {
                String owner = (String) cp[refs[refs[i][0]][0]];
                if (!owner.startsWith(MONTOYA)) {
                    continue;
                }
                int[] nt = refs[refs[i][1]];
                out.add((kind[i] == 9 ? "field " : kind[i] == 10 ? "method " : "imethod ") + owner + " "
                        + cp[nt[0]] + " " + cp[nt[1]]);
            }
        }
        return out;
    }

    static boolean hasField(Class<?> c, String name) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            for (Field f : k.getDeclaredFields()) {
                if (f.getName().equals(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean hasMethod(Class<?> c, String name, String desc) {
        List<Class<?>> todo = new ArrayList<>();
        todo.add(c);
        for (int i = 0; i < todo.size(); i++) {
            Class<?> k = todo.get(i);
            for (Method m : k.getDeclaredMethods()) {
                if (m.getName().equals(name) && descriptor(m).equals(desc)) {
                    return true;
                }
            }
            if (k.getSuperclass() != null) {
                todo.add(k.getSuperclass());
            }
            todo.addAll(List.of(k.getInterfaces()));
        }
        return name.equals("<init>");   // constructors of Montoya types are never called by the extension
    }

    static boolean implemented(Class<?> c, Method want) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            for (Method m : k.getDeclaredMethods()) {
                if (m.getName().equals(want.getName()) && !Modifier.isAbstract(m.getModifiers())
                        && java.util.Arrays.equals(m.getParameterTypes(), want.getParameterTypes())) {
                    return true;
                }
            }
        }
        return false;
    }

    static List<Class<?>> allInterfaces(Class<?> c) {
        List<Class<?>> out = new ArrayList<>();
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            for (Class<?> i : k.getInterfaces()) {
                if (!out.contains(i)) {
                    out.add(i);
                }
            }
        }
        for (int i = 0; i < out.size(); i++) {
            for (Class<?> s : out.get(i).getInterfaces()) {
                if (!out.contains(s)) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    static String descriptor(Method m) {
        StringBuilder b = new StringBuilder("(");
        for (Class<?> p : m.getParameterTypes()) {
            b.append(type(p));
        }
        return b.append(')').append(type(m.getReturnType())).toString();
    }

    static String type(Class<?> c) {
        if (c.isArray()) {
            return c.getName().replace('.', '/');
        }
        if (!c.isPrimitive()) {
            return "L" + c.getName().replace('.', '/') + ";";
        }
        if (c == void.class) {
            return "V";
        }
        if (c == boolean.class) {
            return "Z";
        }
        if (c == byte.class) {
            return "B";
        }
        if (c == char.class) {
            return "C";
        }
        if (c == short.class) {
            return "S";
        }
        if (c == int.class) {
            return "I";
        }
        if (c == long.class) {
            return "J";
        }
        if (c == float.class) {
            return "F";
        }
        return "D";
    }
}
