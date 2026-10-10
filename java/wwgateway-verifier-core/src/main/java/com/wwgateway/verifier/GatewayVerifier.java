package com.wwgateway.verifier;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Local verification of WWGateWay action and data-access tokens inside a bank system.
 * Behaviour and error codes are identical to {@code wwg_sdk.GatewayVerifier} (Python).
 *
 * <p>Network access to the gateway is needed only for the JWKS (cached, refreshed on unknown kid)
 * and the signed policy snapshot (revocations + live risk tolerance). If the snapshot cannot be
 * refreshed within {@code snapshotMaxAge}, every request fails closed with {@code policy_unavailable}.
 */
public final class GatewayVerifier {
    public static final String TYP_ACTION = "wwg-action+jwt";
    public static final String TYP_DATA = "wwg-data+jwt";
    public static final String TYP_POLICY = "wwg-policy+jwt";
    public static final String TYP_PROOF = "wwg-proof+jwt";
    private static final Map<String, Integer> RISK = Map.of("low", 1, "medium", 2, "high", 3, "critical", 4);

    private final String gatewayUrl;
    private final String issuer;
    private final String audience;
    private final ReplayStore replay;
    private final boolean requirePop;
    private final long skew;
    private final long proofMaxAge;
    private final long snapshotMaxAge;
    private final Function<String, Map<String, Object>> fetch;
    private final Clock clock;
    private final Object lock = new Object();
    private Map<String, PublicKey> keys = Map.of();
    private double keysFetchedAt;
    private Map<String, Object> snapshot;

    private GatewayVerifier(Builder b) {
        this.gatewayUrl = stripSlash(Objects.requireNonNull(b.gatewayUrl, "gatewayUrl"));
        this.issuer = Objects.requireNonNull(b.issuer, "issuer");
        this.audience = Objects.requireNonNull(b.audience, "audience");
        this.replay = b.replayStore != null ? b.replayStore : new InMemoryReplayStore(b.clock);
        this.requirePop = b.requirePop;
        this.skew = b.clockSkewSeconds;
        this.proofMaxAge = b.proofMaxAgeSeconds;
        this.snapshotMaxAge = b.snapshotMaxAgeSeconds;
        this.clock = b.clock;
        this.fetch = b.fetchJson != null ? b.fetchJson : httpFetcher(b.httpTimeout);
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String gatewayUrl, issuer, audience;
        private ReplayStore replayStore;
        private boolean requirePop = true;
        private long clockSkewSeconds = 5, proofMaxAgeSeconds = 60, snapshotMaxAgeSeconds = 30;
        private Function<String, Map<String, Object>> fetchJson;
        private Clock clock = Clock.systemUTC();
        private Duration httpTimeout = Duration.ofSeconds(3);

        public Builder gatewayUrl(String v) { gatewayUrl = v; return this; }
        public Builder issuer(String v) { issuer = v; return this; }
        public Builder audience(String v) { audience = v; return this; }
        public Builder replayStore(ReplayStore v) { replayStore = v; return this; }
        public Builder requireProofOfPossession(boolean v) { requirePop = v; return this; }
        public Builder clockSkewSeconds(long v) { clockSkewSeconds = v; return this; }
        public Builder proofMaxAgeSeconds(long v) { proofMaxAgeSeconds = v; return this; }
        public Builder snapshotMaxAgeSeconds(long v) { snapshotMaxAgeSeconds = v; return this; }
        public Builder fetchJson(Function<String, Map<String, Object>> v) { fetchJson = v; return this; }
        public Builder clock(Clock v) { clock = v; return this; }
        public Builder httpTimeout(Duration v) { httpTimeout = v; return this; }
        public GatewayVerifier build() { return new GatewayVerifier(this); }
    }

    // ------------------------------------------------------------------ public API

    /** Verifies and CONSUMES an action token for exactly this action and these parameters. */
    public VerifiedClaims verifyAction(String token, String proof, String method, String url, String action, Object params) {
        Map<String, Object> claims = verifyToken(token, TYP_ACTION);
        if (!Objects.equals(claims.get("action"), action)) throw new VerificationException("wrong_action", "token authorizes a different action", 403);
        if (!Objects.equals(claims.get("params_hash"), Jcs.sha256Hex(params))) throw new VerificationException("params_mismatch", "request parameters differ from the authorized ones", 403);
        checkPolicy(claims);
        checkProof(claims, token, proof, method, url);
        long exp = asLong(claims.get("exp"));
        if (!replay.add("tok:" + claims.get("jti"), exp + skew)) throw new VerificationException("token_replay", "token already used", 401);
        if (claims.get("plan_id") instanceof String planId && claims.get("step_id") instanceof String stepId) {
            if (!replay.add("step:" + planId + ":" + stepId, (long) now() + 30L * 86400)) {
                throw new VerificationException("step_already_executed", "this plan step was already executed", 409);
            }
        }
        return new VerifiedClaims(claims);
    }

    /** Verifies a data-access token for reading {@code table}; apply its scope with {@link VerifiedClaims}. */
    public VerifiedClaims verifyDataAccess(String token, String proof, String method, String url, String table) {
        Map<String, Object> claims = verifyToken(token, TYP_DATA);
        Object tables = claims.get("tables");
        if (!(tables instanceof Collection<?> c) || !c.contains(table)) throw new VerificationException("table_not_allowed", "token does not grant access to " + table, 403);
        checkPolicy(claims);
        checkProof(claims, token, proof, method, url);
        return new VerifiedClaims(claims);
    }

    // ------------------------------------------------------------------ token checks

    private Map<String, Object> verifyToken(String token, String typ) {
        Crypto.Jws jws = Crypto.decode(token);
        Map<String, Object> h = jws.header();
        if (!"EdDSA".equals(h.get("alg"))) throw new VerificationException("bad_alg", "only EdDSA tokens are accepted", 401);
        if (!typ.equals(h.get("typ"))) throw new VerificationException("wrong_token_type", "expected " + typ, 401);
        if (h.containsKey("crit")) throw new VerificationException("bad_header", "unsupported critical header", 401);
        Crypto.verifyEd25519(key(h.get("kid")), jws);
        Map<String, Object> p = jws.payload();
        double now = now();
        if (!issuer.equals(p.get("iss"))) throw new VerificationException("wrong_issuer", "token issued by an untrusted issuer", 401);
        if (!audience.equals(p.get("aud"))) throw new VerificationException("wrong_audience", "token is not intended for this system", 403);
        Long exp = optLong(p.get("exp"));
        Long nbf = optLong(p.containsKey("nbf") ? p.get("nbf") : p.get("iat"));
        if (exp == null || now >= exp + skew) throw new VerificationException("expired", "token expired", 401);
        if (nbf == null || now + skew < nbf) throw new VerificationException("not_yet_valid", "token not yet valid", 401);
        if (!(p.get("jti") instanceof String)) throw new VerificationException("malformed_token", "missing jti", 401);
        return p;
    }

    private void checkPolicy(Map<String, Object> claims) {
        Map<String, Object> snap = policy();
        if (listContains(snap.get("revoked_jti"), claims.get("jti"))) throw new VerificationException("revoked", "token revoked", 401);
        if (listContains(snap.get("revoked_agents"), claims.get("sub"))) throw new VerificationException("agent_revoked", "agent suspended", 401);
        if (claims.get("plan_id") != null && listContains(snap.get("revoked_plans"), claims.get("plan_id"))) throw new VerificationException("plan_revoked", "plan cancelled", 401);
        String tol = snap.get("risk_tolerance") instanceof String s ? s : "low";
        if (snap.get("system_risk_tolerances") instanceof Map<?, ?> systems && systems.get(audience) instanceof String sys
                && RISK.containsKey(sys) && RISK.get(sys) < RISK.getOrDefault(tol, 1)) {
            tol = sys;
        }
        Object risk = claims.get("risk_level");
        if (!(risk instanceof String r) || !RISK.containsKey(r) || RISK.get(r) > RISK.getOrDefault(tol, 1)) {
            throw new VerificationException("risk_tolerance", "token risk " + risk + " exceeds current tolerance " + tol, 401);
        }
    }

    private void checkProof(Map<String, Object> claims, String token, String proof, String method, String url) {
        String jkt = claims.get("cnf") instanceof Map<?, ?> cnf && cnf.get("jkt") instanceof String s ? s : null;
        if (jkt == null) {
            if (requirePop) throw new VerificationException("pop_required", "token is not bound to an agent key", 401);
            return;
        }
        if (proof == null || proof.isEmpty()) throw new VerificationException("proof_missing", "proof of possession required", 401);
        Crypto.Jws jws = Crypto.decode(proof);
        if (!"EdDSA".equals(jws.header().get("alg")) || !TYP_PROOF.equals(jws.header().get("typ"))) throw new VerificationException("bad_proof", "invalid proof header", 401);
        Object jwk = jws.header().get("jwk");
        PublicKey key = Crypto.ed25519FromJwk(jwk);
        if (!Crypto.jwkThumbprint((Map<?, ?>) jwk).equals(jkt)) throw new VerificationException("proof_key_mismatch", "proof not signed by the key bound to the token", 401);
        Crypto.verifyEd25519(key, jws);
        Map<String, Object> p = jws.payload();
        if (!method.toUpperCase().equals(p.get("htm"))) throw new VerificationException("proof_method_mismatch", "proof issued for another HTTP method", 401);
        if (!path(String.valueOf(p.getOrDefault("htu", ""))).equals(path(url))) throw new VerificationException("proof_url_mismatch", "proof issued for another URL", 401);
        if (!Crypto.sha256B64url(token).equals(p.get("ath"))) throw new VerificationException("proof_token_mismatch", "proof issued for another token", 401);
        Long iat = optLong(p.get("iat"));
        double now = now();
        if (iat == null || Math.abs(now - iat) > proofMaxAge) throw new VerificationException("proof_stale", "proof is too old or from the future", 401);
        if (!(p.get("jti") instanceof String jti) || !replay.add("proof:" + jkt + ":" + jti, (long) now + proofMaxAge + skew)) {
            throw new VerificationException("proof_replay", "proof already used", 401);
        }
    }

    // ------------------------------------------------------------------ keys and policy

    private PublicKey key(Object kid) {
        synchronized (lock) {
            if (!(kid instanceof String k)) throw new VerificationException("unknown_kid", "missing kid", 401);
            if (!keys.containsKey(k) && now() - keysFetchedAt > 10) {
                try {
                    refreshKeys();
                } catch (VerificationException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw new VerificationException("keys_unavailable", "cannot fetch gateway keys: " + e.getMessage(), 503);
                }
            }
            PublicKey key = keys.get(k);
            if (key == null) throw new VerificationException("unknown_kid", "token signed with an unknown key", 401);
            return key;
        }
    }

    private void refreshKeys() {
        Map<String, Object> jwks = fetch.apply(gatewayUrl + "/.well-known/jwks.json");
        Map<String, PublicKey> fresh = new HashMap<>();
        if (jwks.get("keys") instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof Map<?, ?> jwk && jwk.get("kid") instanceof String kid && "EdDSA".equals(jwk.containsKey("alg") ? jwk.get("alg") : "EdDSA")) {
                    fresh.put(kid, Crypto.ed25519FromJwk(jwk));
                }
            }
        }
        keys = Map.copyOf(fresh);
        keysFetchedAt = now();
    }

    /** Current signed policy snapshot; refreshed when expired; fails closed when stale. */
    public Map<String, Object> policy() {
        synchronized (lock) {
            double now = now();
            Map<String, Object> snap = snapshot;
            if (snap != null && now < asLong(snap.get("exp")) && now - asLong(snap.get("iat")) <= snapshotMaxAge) return snap;
            try {
                Object token = fetch.apply(gatewayUrl + "/v1/policy-snapshot").get("snapshot");
                Crypto.Jws jws = Crypto.decode((String) token);
                if (!"EdDSA".equals(jws.header().get("alg")) || !TYP_POLICY.equals(jws.header().get("typ"))) throw new VerificationException("bad_policy", "unexpected policy snapshot type", 401);
                Crypto.verifyEd25519(key(jws.header().get("kid")), jws);
                Map<String, Object> p = jws.payload();
                if (!issuer.equals(p.get("iss"))) throw new VerificationException("bad_policy", "policy snapshot from wrong issuer", 401);
                if (snap != null && asLong(p.get("iat")) < asLong(snap.get("iat"))) throw new VerificationException("bad_policy", "policy snapshot rollback", 401);
                Long iat = optLong(p.get("iat")), exp = optLong(p.get("exp"));
                if (iat == null || exp == null || now - iat > snapshotMaxAge || iat - now > skew || now >= exp + skew) {
                    throw new VerificationException("policy_unavailable", "policy snapshot is not fresh (replayed or clock skew)", 503);
                }
                snapshot = p;
                return p;
            } catch (VerificationException e) {
                throw e;
            } catch (RuntimeException e) {
                if (snap != null && now - asLong(snap.get("iat")) <= snapshotMaxAge) return snap;
                throw new VerificationException("policy_unavailable", "gateway policy unavailable: " + e.getMessage(), 503);
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private double now() { return clock.millis() / 1000.0; }

    private static boolean listContains(Object list, Object value) {
        return list instanceof Collection<?> c && value != null && c.contains(value);
    }

    private static Long optLong(Object o) {
        if (o instanceof Number n && !(o instanceof Double) && !(o instanceof Float)) return n.longValue();
        return null;
    }

    private static long asLong(Object o) {
        Long v = optLong(o);
        if (v == null) throw new VerificationException("malformed_token", "expected integer", 401);
        return v;
    }

    private static String path(String url) {
        try {
            String p = URI.create(url).getRawPath();
            return p == null ? "" : p;
        } catch (IllegalArgumentException e) {
            return "\u0000invalid";
        }
    }

    private static String stripSlash(String s) { return s.endsWith("/") ? s.substring(0, s.length() - 1) : s; }

    private static Function<String, Map<String, Object>> httpFetcher(Duration timeout) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).build();
        return url -> {
            try {
                HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(url)).timeout(timeout).GET().build(), HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode());
                return Json.parseObject(r.body());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        };
    }
}
