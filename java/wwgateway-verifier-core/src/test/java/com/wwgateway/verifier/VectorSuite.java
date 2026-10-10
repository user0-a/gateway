package com.wwgateway.verifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Cross-language conformance: runs the vectors produced by tools/make_java_vectors.py (Python
 * reference implementation) against the Java verifier. Plain Java so it also runs without JUnit:
 *   java -cp target/classes:target/test-classes com.wwgateway.verifier.VectorSuite path/to/vectors.json
 */
public final class VectorSuite {
    private VectorSuite() {}

    @SuppressWarnings("unchecked")
    public static List<String> run(Path file) throws Exception {
        Map<String, Object> v = Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
        List<String> failures = new ArrayList<>();
        int passed = 0;

        for (Object o : (List<Object>) v.get("canonical")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Object parsed = Json.parse((String) c.get("json"));
            String got = Jcs.canonicalize(parsed);
            if (!got.equals(c.get("canonical"))) failures.add("canonical: " + c.get("json") + " -> " + got + " expected " + c.get("canonical"));
            else if (!Jcs.sha256Hex(parsed).equals(c.get("sha256"))) failures.add("sha256 mismatch for " + c.get("json"));
            else passed++;
        }

        long now = ((Number) v.get("now")).longValue();
        Clock clock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
        Map<String, Object> jwks = (Map<String, Object>) v.get("jwks");
        String snapshot = (String) v.get("snapshot");

        for (Object o : (List<Object>) v.get("cases")) {
            Map<String, Object> testCase = (Map<String, Object>) o;
            GatewayVerifier verifier = GatewayVerifier.builder()
                    .gatewayUrl("https://gateway.example").issuer((String) v.get("issuer")).audience((String) v.get("audience"))
                    .clock(clock).replayStore(new InMemoryReplayStore(clock))
                    .fetchJson(url -> url.endsWith("/.well-known/jwks.json") ? jwks : Map.of("snapshot", snapshot))
                    .build();
            int i = 0;
            for (Object co : (List<Object>) testCase.get("calls")) {
                Map<String, Object> call = (Map<String, Object>) co;
                String label = testCase.get("name") + " #" + (++i);
                String expect = (String) call.get("expect");
                String outcome;
                VerifiedClaims claims = null;
                try {
                    if ("data".equals(call.get("kind"))) {
                        claims = verifier.verifyDataAccess((String) call.get("token"), (String) call.get("proof"), (String) call.get("method"), (String) call.get("url"), (String) call.get("table"));
                    } else {
                        claims = verifier.verifyAction((String) call.get("token"), (String) call.get("proof"), (String) call.get("method"), (String) call.get("url"), (String) call.get("action"), call.get("params"));
                    }
                    outcome = "ok";
                } catch (VerificationException e) {
                    outcome = e.code();
                }
                if (!outcome.equals(expect)) {
                    failures.add(label + ": got " + outcome + ", expected " + expect);
                    continue;
                }
                if (claims != null && call.containsKey("scoped")) {
                    List<Map<String, Object>> rows = (List<Map<String, Object>>) call.get("rows");
                    Object scoped = claims.applyDataScope(rows, (String) call.get("table"));
                    if (!Jcs.canonicalize(scoped).equals(Jcs.canonicalize(call.get("scoped")))) {
                        failures.add(label + ": data scope " + Jcs.canonicalize(scoped));
                        continue;
                    }
                }
                passed++;
            }
        }
        System.out.println("vectors passed: " + passed + ", failed: " + failures.size());
        failures.forEach(f -> System.out.println("  FAIL " + f));
        return failures;
    }

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "src/test/resources/vectors.json");
        System.exit(run(file).isEmpty() ? 0 : 1);
    }
}
