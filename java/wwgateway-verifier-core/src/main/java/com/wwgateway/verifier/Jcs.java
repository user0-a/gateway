package com.wwgateway.verifier;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Canonical JSON (RFC 8785 profile shared with the gateway and the Python SDK).
 * Keys sorted by UTF-16 code units, ECMAScript string escaping and number formatting,
 * integers kept exact. Works on Java 17+.
 */
public final class Jcs {
    private Jcs() {}

    public static String canonicalize(Object value) {
        StringBuilder b = new StringBuilder();
        write(value, b);
        return b.toString();
    }

    public static byte[] canonicalBytes(Object value) {
        return canonicalize(value).getBytes(StandardCharsets.UTF_8);
    }

    public static String sha256Hex(Object value) {
        return HexFormat.of().formatHex(sha256(canonicalBytes(value)));
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void write(Object v, StringBuilder b) {
        if (v == null) { b.append("null"); return; }
        if (v instanceof Boolean bool) { b.append(bool ? "true" : "false"); return; }
        if (v instanceof String str) { string(str, b); return; }
        if (v instanceof BigInteger || v instanceof Long || v instanceof Integer || v instanceof Short || v instanceof Byte) { b.append(v.toString()); return; }
        if (v instanceof BigDecimal bd) {
            if (bd.signum() == 0 || bd.stripTrailingZeros().scale() <= 0) { b.append(bd.toBigIntegerExact().toString()); return; }
            b.append(number(bd.doubleValue())); return;
        }
        if (v instanceof Number n) { b.append(number(n.doubleValue())); return; }
        if (v instanceof Map<?, ?> m) {
            List<String> keys = new ArrayList<>();
            for (Object k : m.keySet()) {
                if (!(k instanceof String)) throw new IllegalArgumentException("object keys must be strings");
                keys.add((String) k);
            }
            keys.sort(String::compareTo); // String.compareTo orders by UTF-16 code units
            b.append('{');
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) b.append(',');
                string(keys.get(i), b);
                b.append(':');
                write(m.get(keys.get(i)), b);
            }
            b.append('}');
            return;
        }
        if (v instanceof Collection<?> c) {
            b.append('[');
            int i = 0;
            for (Object item : c) { if (i++ > 0) b.append(','); write(item, b); }
            b.append(']');
            return;
        }
        throw new IllegalArgumentException("unsupported type " + v.getClass());
    }

    private static void string(String s, StringBuilder b) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        b.append('"');
    }

    /** ECMAScript Number::toString for finite doubles. */
    static String number(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("NaN/Infinity not allowed");
        if (d == 0) return "0";
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new BigDecimal(d).toBigInteger().toString();
        String sign = d < 0 ? "-" : "";
        BigDecimal bd = shortest(Math.abs(d));
        String digits = bd.unscaledValue().toString();
        int k = digits.length();
        int n = k - bd.scale();
        String out;
        if (k <= n && n <= 21) out = digits + "0".repeat(n - k);
        else if (0 < n && n <= 21) out = digits.substring(0, n) + "." + digits.substring(n);
        else if (-6 < n && n <= 0) out = "0." + "0".repeat(-n) + digits;
        else {
            int e = n - 1;
            out = digits.charAt(0) + (k > 1 ? "." + digits.substring(1) : "") + "e" + (e > 0 ? "+" : "-") + Math.abs(e);
        }
        return sign + out;
    }

    /**
     * Shortest decimal that round-trips to {@code d}, choosing the closest one when several have the
     * same length (ECMAScript rule). Independent of the JDK's Double.toString, which may emit an
     * extra digit (e.g. 4.9E-324 instead of 5E-324).
     */
    private static BigDecimal shortest(double d) {
        BigDecimal exact = new BigDecimal(d);
        for (int precision = 1; precision <= 17; precision++) {
            BigDecimal candidate = exact.round(new java.math.MathContext(precision, java.math.RoundingMode.HALF_EVEN));
            if (Double.parseDouble(candidate.toString()) == d) return candidate.stripTrailingZeros();
        }
        return exact.stripTrailingZeros();
    }
}
