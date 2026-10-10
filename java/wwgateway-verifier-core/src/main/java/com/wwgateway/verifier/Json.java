package com.wwgateway.verifier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, strict JSON parser (RFC 8259) with no dependencies.
 * Objects become {@code LinkedHashMap<String,Object>}, arrays {@code List<Object>},
 * integers {@link BigInteger}, other numbers {@link Double}, plus String/Boolean/null.
 * Integers stay exact, matching the Python implementation of the canonical form.
 */
public final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    public static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != p.s.length()) throw new IllegalArgumentException("trailing data at " + p.i);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) throw new IllegalArgumentException("expected JSON object");
        return (Map<String, Object>) v;
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++; else break;
        }
    }

    private Object value(int depth) {
        if (depth > 64) throw new IllegalArgumentException("nesting too deep");
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{': return object(depth);
            case '[': return array(depth);
            case '"': return string();
            case 't': literal("true"); return Boolean.TRUE;
            case 'f': literal("false"); return Boolean.FALSE;
            case 'n': literal("null"); return null;
            default: return number();
        }
    }

    private void literal(String word) {
        if (!s.startsWith(word, i)) throw new IllegalArgumentException("invalid literal at " + i);
        i += word.length();
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (peek() == '}') { i++; return m; }
        while (true) {
            ws();
            if (peek() != '"') throw new IllegalArgumentException("expected key at " + i);
            String key = string();
            ws();
            expect(':');
            ws();
            if (m.containsKey(key)) throw new IllegalArgumentException("duplicate key " + key);
            m.put(key, value(depth + 1));
            ws();
            char c = next();
            if (c == '}') return m;
            if (c != ',') throw new IllegalArgumentException("expected , or } at " + (i - 1));
        }
    }

    private List<Object> array(int depth) {
        List<Object> a = new ArrayList<>();
        i++;
        ws();
        if (peek() == ']') { i++; return a; }
        while (true) {
            ws();
            a.add(value(depth + 1));
            ws();
            char c = next();
            if (c == ']') return a;
            if (c != ',') throw new IllegalArgumentException("expected , or ] at " + (i - 1));
        }
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') return b.toString();
            if (c < 0x20) throw new IllegalArgumentException("control character in string");
            if (c != '\\') { b.append(c); continue; }
            char e = next();
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
                    if (i + 4 > s.length()) throw new IllegalArgumentException("bad unicode escape");
                    b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                    break;
                default: throw new IllegalArgumentException("bad escape");
            }
        }
    }

    private Object number() {
        int start = i;
        if (peek() == '-') i++;
        if (peek() == '0') { i++; } else if (Character.isDigit(peek())) { while (i < s.length() && Character.isDigit(s.charAt(i))) i++; } else throw new IllegalArgumentException("invalid number at " + start);
        boolean integer = true;
        if (i < s.length() && s.charAt(i) == '.') {
            integer = false; i++;
            if (!Character.isDigit(peek())) throw new IllegalArgumentException("invalid fraction");
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        }
        if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
            integer = false; i++;
            if (peek() == '+' || peek() == '-') i++;
            if (!Character.isDigit(peek())) throw new IllegalArgumentException("invalid exponent");
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        }
        String lit = s.substring(start, i);
        if (integer) return new BigInteger(lit);
        double d = Double.parseDouble(lit);
        if (Double.isInfinite(d)) throw new IllegalArgumentException("number out of range");
        return d;
    }

    private char peek() { return i < s.length() ? s.charAt(i) : '\0'; }
    private char next() { if (i >= s.length()) throw new IllegalArgumentException("unexpected end"); return s.charAt(i++); }
    private void expect(char c) { if (next() != c) throw new IllegalArgumentException("expected " + c + " at " + (i - 1)); }
}
