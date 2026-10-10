package com.wwgateway.verifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Base64url, Ed25519 JWK handling, RFC 7638 thumbprints and EdDSA verification (JDK only). */
public final class Crypto {
    private Crypto() {}

    public static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] unb64url(String s) {
        if (s == null || s.indexOf('+') >= 0 || s.indexOf('/') >= 0 || s.indexOf('=') >= 0) {
            throw new VerificationException("malformed_token", "invalid base64url", 401);
        }
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("malformed_token", "invalid base64url", 401);
        }
    }

    /** Ed25519 public key from a JWK {"kty":"OKP","crv":"Ed25519","x":...}. */
    public static PublicKey ed25519FromJwk(Object jwkObject) {
        if (!(jwkObject instanceof Map<?, ?> jwk) || !"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv")) || !(jwk.get("x") instanceof String x)) {
            throw new VerificationException("bad_key", "unsupported key type", 401);
        }
        byte[] raw = unb64url(x);
        if (raw.length != 32) throw new VerificationException("bad_key", "invalid Ed25519 key", 401);
        try {
            byte[] le = raw.clone();
            boolean xOdd = (le[31] & 0x80) != 0;
            le[31] &= 0x7F;
            byte[] be = new byte[32];
            for (int i = 0; i < 32; i++) be[i] = le[31 - i];
            EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, be));
            return KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
        } catch (Exception e) {
            throw new VerificationException("bad_key", "invalid Ed25519 key", 401);
        }
    }

    public static String jwkThumbprint(Map<?, ?> jwk) {
        Map<String, Object> required = new LinkedHashMap<>();
        required.put("crv", jwk.get("crv"));
        required.put("kty", jwk.get("kty"));
        required.put("x", jwk.get("x"));
        return b64url(Jcs.sha256(Jcs.canonicalBytes(required)));
    }

    public static String sha256B64url(String ascii) {
        return b64url(Jcs.sha256(ascii.getBytes(StandardCharsets.US_ASCII)));
    }

    /** Parsed compact JWS. */
    public record Jws(Map<String, Object> header, Map<String, Object> payload, byte[] signingInput, byte[] signature) {}

    public static Jws decode(String token) {
        if (token == null || token.length() > 16384) throw new VerificationException("malformed_token", "malformed token", 401);
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) throw new VerificationException("malformed_token", "malformed token", 401);
        try {
            Map<String, Object> header = Json.parseObject(new String(unb64url(parts[0]), StandardCharsets.UTF_8));
            Map<String, Object> payload = Json.parseObject(new String(unb64url(parts[1]), StandardCharsets.UTF_8));
            return new Jws(header, payload, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII), unb64url(parts[2]));
        } catch (VerificationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new VerificationException("malformed_token", "malformed token", 401);
        }
    }

    public static void verifyEd25519(PublicKey key, Jws jws) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(key);
            sig.update(jws.signingInput());
            if (!sig.verify(jws.signature())) throw new VerificationException("bad_signature", "signature verification failed", 401);
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("bad_signature", "signature verification failed", 401);
        }
    }
}
