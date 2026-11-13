package com.privara.burp.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader and writer, so the extension needs no third-party jar inside Burp.
 *
 * Objects become {@code Map<String,Object>} (insertion ordered), arrays {@code List<Object>},
 * numbers {@code Long} or {@code Double}, plus String, Boolean and null. Input comes from the
 * Privara API (and, through it, from an analysis of an UNTRUSTED app), so the parser is bounded:
 * nesting depth is capped and every error is an exception, never a partial value.
 */
public final class Json {
    private static final int MAX_DEPTH = 64;

    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    public static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("no JSON");
        }
        Json p = new Json(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != p.s.length()) {
            throw new IllegalArgumentException("trailing data after JSON at " + p.i);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Object o) {
        return o instanceof List ? (List<Object>) o : new ArrayList<>();
    }

    public static String str(Object o) {
        return o == null ? "" : (o instanceof String ? (String) o : String.valueOf(o));
    }

    public static long num(Object o, long dflt) {
        if (o instanceof Number) {
            return ((Number) o).longValue();
        }
        try {
            return Long.parseLong(str(o).trim());
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    public static boolean bool(Object o) {
        return Boolean.TRUE.equals(o);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                break;
            }
        }
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON nested too deeply");
        }
        if (i >= s.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        char c = s.charAt(i);
        switch (c) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"':
                return string();
            case 't':
                lit("true");
                return Boolean.TRUE;
            case 'f':
                lit("false");
                return Boolean.FALSE;
            case 'n':
                lit("null");
                return null;
            default:
                return number();
        }
    }

    private void lit(String w) {
        if (!s.startsWith(w, i)) {
            throw new IllegalArgumentException("bad JSON literal at " + i);
        }
        i += w.length();
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (i < s.length() && s.charAt(i) == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') {
                throw new IllegalArgumentException("expected a key at " + i);
            }
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') {
                throw new IllegalArgumentException("expected ':' at " + i);
            }
            i++;
            ws();
            m.put(k, value(depth + 1));
            ws();
            if (i >= s.length()) {
                throw new IllegalArgumentException("unterminated object");
            }
            char c = s.charAt(i++);
            if (c == '}') {
                return m;
            }
            if (c != ',') {
                throw new IllegalArgumentException("expected ',' or '}' at " + (i - 1));
            }
        }
    }

    private List<Object> array(int depth) {
        List<Object> a = new ArrayList<>();
        i++;
        ws();
        if (i < s.length() && s.charAt(i) == ']') {
            i++;
            return a;
        }
        while (true) {
            ws();
            a.add(value(depth + 1));
            ws();
            if (i >= s.length()) {
                throw new IllegalArgumentException("unterminated array");
            }
            char c = s.charAt(i++);
            if (c == ']') {
                return a;
            }
            if (c != ',') {
                throw new IllegalArgumentException("expected ',' or ']' at " + (i - 1));
            }
        }
    }

    private String string() {
        StringBuilder b = new StringBuilder();
        i++;
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') {
                return b.toString();
            }
            if (c == '\\') {
                if (i >= s.length()) {
                    break;
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) {
                            throw new IllegalArgumentException("bad \\u escape");
                        }
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("bad escape at " + (i - 1));
                }
            } else {
                b.append(c);
            }
        }
        throw new IllegalArgumentException("unterminated string");
    }

    private Object number() {
        int st = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
            i++;
        }
        String t = s.substring(st, i);
        if (t.isEmpty()) {
            throw new IllegalArgumentException("unexpected character at " + st);
        }
        try {
            if (t.contains(".") || t.contains("e") || t.contains("E")) {
                return Double.parseDouble(t);
            }
            return Long.parseLong(t);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad number at " + st);
        }
    }

    // ------------------------------------------------------------------ writer

    public static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String) {
            quote(b, (String) v);
        } else if (v instanceof Number || v instanceof Boolean) {
            b.append(v);
        } else if (v instanceof Map) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                quote(b, e.getKey());
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof List) {
            b.append('[');
            boolean first = true;
            for (Object o : (List<Object>) v) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                write(b, o);
            }
            b.append(']');
        } else {
            quote(b, String.valueOf(v));
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
    }
}
