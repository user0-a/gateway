package com.wwgateway.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.wwgateway.verifier.GatewayVerifier;
import com.wwgateway.verifier.InMemoryReplayStore;
import com.wwgateway.verifier.Jcs;
import com.wwgateway.verifier.Json;
import com.wwgateway.verifier.ReplayStore;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The starter inside a real Spring MVC application, driven by the cross-language vectors produced by the
 * Python reference (wwgateway-verifier-core/src/test/resources/vectors.json; regenerate with `make vectors`).
 */
@SpringBootTest(classes = GatewayStarterIT.TestApp.class, properties = {
        "wwgateway.gateway-url=https://gateway.example",
        "wwgateway.max-body-bytes=" + GatewayStarterIT.MAX_BODY_BYTES})
@AutoConfigureMockMvc
class GatewayStarterIT {
    static final int MAX_BODY_BYTES = 4096;
    static final Map<String, Object> VECTORS = loadVectors();
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(((Number) VECTORS.get("now")).longValue()), ZoneOffset.UTC);
    /** Selects the second handler on POST /transfers, annotated with another action (for the "wrong action" vector). */
    static final String ENDPOINT_HEADER = "X-Test-Endpoint";
    /** HTTP status per error code, as in the Python reference (wwg_sdk.VerificationError, default 401). */
    static final Map<String, Integer> STATUS = Map.of(
            "wrong_audience", 403, "wrong_action", 403, "params_mismatch", 403, "table_not_allowed", 403,
            "step_already_executed", 409, "keys_unavailable", 503, "policy_unavailable", 503);

    @Autowired MockMvc mvc;
    @Autowired TestController controller;
    @Autowired ResettableReplayStore replayStore;
    @Autowired List<GatewayVerifier> verifiers;

    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @DynamicPropertySource
    static void gatewayProperties(DynamicPropertyRegistry registry) {
        registry.add("wwgateway.issuer", () -> VECTORS.get("issuer"));
        registry.add("wwgateway.audience", () -> VECTORS.get("audience"));
    }

    @BeforeEach
    void freshState() {
        replayStore.reset();
        controller.reset();
    }

    @Test
    void testVerifierReplacesTheAutoConfiguredOne() {
        assertThat(verifiers).hasSize(1);
    }

    // ------------------------------------------------------------------ vector cases over HTTP

    @TestFactory
    @SuppressWarnings("unchecked")
    Stream<DynamicTest> actionVectorsOverHttp() {
        List<Map<String, Object>> cases = new ArrayList<>();
        for (Object o : (List<Object>) VECTORS.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            if (((List<Map<String, Object>>) c.get("calls")).stream().allMatch(call -> "action".equals(call.get("kind")))) cases.add(c);
        }
        assertThat(cases).hasSize(25);
        return cases.stream().map(c -> DynamicTest.dynamicTest((String) c.get("name"), () -> {
            replayStore.reset();
            controller.reset();
            int i = 0;
            for (Map<String, Object> call : (List<Map<String, Object>>) c.get("calls")) {
                runActionCall(c.get("name") + " #" + (++i), call);
            }
        }));
    }

    private void runActionCall(String label, Map<String, Object> call) throws Exception {
        assertEquals("POST", call.get("method"), label);
        assertEquals("/transfers", URI.create((String) call.get("url")).getPath(), label);
        String expect = (String) call.get("expect");
        int before = controller.calls.get();

        MockHttpServletRequestBuilder request = actionRequest((String) call.get("token"), (String) call.get("proof"), call.get("params"));
        if (!"transfer.create".equals(call.get("action"))) request.header(ENDPOINT_HEADER, call.get("action"));

        if ("ok".equals(expect)) {
            Map<String, Object> claims = payload((String) call.get("token"));
            mvc.perform(request)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.agent").value(claims.get("sub")))
                    .andExpect(jsonPath("$.step").value(claims.get("step_id")));
            assertEquals(before + 1, controller.calls.get(), label + ": controller must run once");
            // the controller still received the exact body the interceptor hashed
            assertEquals(Jcs.canonicalize(call.get("params")), Jcs.canonicalize(controller.lastBody.get()), label);
        } else {
            mvc.perform(request)
                    .andExpect(status().is(STATUS.getOrDefault(expect, 401)))
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.error").value(expect));
            assertEquals(before, controller.calls.get(), label + ": controller must NOT run");
        }
    }

    @Test
    void dataAccessReturnsOnlyTheScopedRowsAndColumns() throws Exception {
        Map<String, Object> call = vectorCall("data access ok");
        mvc.perform(get("/accounts").header("Authorization", "GatewayData " + call.get("token")).header("WWG-Proof", (String) call.get("proof")))
                .andExpect(status().isOk())
                .andExpect(content().json("[{\"id\":1,\"owner\":\"Ala\"}]", true))
                .andExpect(content().json(Jcs.canonicalize(call.get("scoped")), true));
        assertEquals(1, controller.calls.get());
    }

    @Test
    void dataAccessToAnotherTableIsRejected() throws Exception {
        Map<String, Object> call = vectorCall("data table not allowed");
        mvc.perform(get("/ops").header("Authorization", "GatewayData " + call.get("token")).header("WWG-Proof", (String) call.get("proof")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("table_not_allowed"));
        assertEquals(0, controller.calls.get());
    }

    // ------------------------------------------------------------------ fail closed on missing / wrong input

    @Test
    void missingAuthorizationIsRejected() throws Exception {
        mvc.perform(post("/transfers").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(validCall().get("params"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_required"));
        assertEquals(0, controller.calls.get());
    }

    @Test
    void otherAuthorizationSchemesAreRejected() throws Exception {
        Map<String, Object> call = validCall();
        for (String header : List.of("Bearer " + call.get("token"), "GatewayData " + call.get("token"), "GatewayAction", "gatewayaction " + call.get("token"))) {
            mvc.perform(post("/transfers").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(call.get("params")))
                            .header("Authorization", header).header("WWG-Proof", (String) call.get("proof")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("token_required"));
        }
        mvc.perform(get("/accounts").header("Authorization", "GatewayAction " + vectorCall("data access ok").get("token")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_required"));
        assertEquals(0, controller.calls.get());
    }

    @Test
    void bodyLargerThanTheLimitIsRejectedBeforeTheTokenIsConsumed() throws Exception {
        Map<String, Object> call = validCall();
        String padded = "{\"pad\":\"" + "x".repeat(MAX_BODY_BYTES) + "\"}";
        mvc.perform(post("/transfers").contentType(MediaType.APPLICATION_JSON).content(padded)
                        .header("Authorization", "GatewayAction " + call.get("token")).header("WWG-Proof", (String) call.get("proof")))
                .andExpect(status().isPayloadTooLarge());
        assertEquals(0, controller.calls.get());
        // the same token and proof are still unused
        mvc.perform(actionRequest((String) call.get("token"), (String) call.get("proof"), call.get("params"))).andExpect(status().isOk());
        assertEquals(1, controller.calls.get());
    }

    @Test
    void withoutTheBodyCacheProtectedActionsFailClosed() throws Exception {
        // Interceptor without CachedBodyFilter: the body cannot be bound to the token, so nothing may run.
        GatewayVerifier verifier = verifiers.get(0);
        MockMvc noFilter = MockMvcBuilders.standaloneSetup(controller)
                .addInterceptors(new GatewayAuthorizationInterceptor(verifier, new DefaultGatewayParamsExtractor()))
                .setCustomArgumentResolvers(new GatewayPrincipalArgumentResolver())
                .build();
        Map<String, Object> call = validCall();
        noFilter.perform(actionRequest((String) call.get("token"), (String) call.get("proof"), call.get("params")))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("body_not_cached"));
        assertEquals(0, controller.calls.get());
    }

    @Test
    void bodyAtTheLimitIsAccepted() throws Exception {
        String json = "{\"pad\":\"" + "x".repeat(MAX_BODY_BYTES - 10) + "\"}";
        assertEquals(MAX_BODY_BYTES, json.getBytes(StandardCharsets.UTF_8).length);
        mvc.perform(post("/echo").contentType(MediaType.APPLICATION_JSON).content(json)).andExpect(status().isOk());
    }

    @Test
    void endpointsWithoutAnnotationsAreUntouched() throws Exception {
        mvc.perform(get("/health")).andExpect(status().isOk()).andExpect(content().string("ok"));
        mvc.perform(post("/echo").contentType(MediaType.APPLICATION_JSON).content("{\"a\":\"żółć\",\"n\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.a").value("żółć"))
                .andExpect(jsonPath("$.n").value(1));
        // a garbage Authorization header on an unprotected endpoint is ignored, as before
        mvc.perform(get("/health").header("Authorization", "GatewayAction garbage")).andExpect(status().isOk());
    }

    // ------------------------------------------------------------------ auto-configuration conditions

    private static final WebApplicationContextRunner WEB = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(WwGatewayAutoConfiguration.class));

    @Test
    void autoConfigurationDoesNotStartWithoutGatewayUrl() {
        WEB.withPropertyValues("wwgateway.issuer=x", "wwgateway.audience=y").run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).doesNotHaveBean(GatewayVerifier.class);
            assertThat(ctx).doesNotHaveBean(ReplayStore.class);
            assertThat(ctx).doesNotHaveBean("wwgCachedBodyFilter");
            assertThat(ctx).doesNotHaveBean("wwgWebMvcConfigurer");
        });
    }

    @Test
    void autoConfigurationStartsWithGatewayUrl() {
        WEB.withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.issuer=x", "wwgateway.audience=y").run(ctx -> {
            assertThat(ctx).hasSingleBean(GatewayVerifier.class);
            assertThat(ctx).getBean(ReplayStore.class).isInstanceOf(InMemoryReplayStore.class);
            assertThat(ctx).hasBean("wwgCachedBodyFilter");
            assertThat(ctx).hasBean("wwgWebMvcConfigurer");
        });
    }

    @Test
    void autoConfigurationOnlyAppliesToServletApplications() {
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(WwGatewayAutoConfiguration.class))
                .withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.issuer=x", "wwgateway.audience=y")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(GatewayVerifier.class));
    }

    @Test
    void missingIssuerOrAudienceFailsStartup() {
        WEB.withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.audience=y").run(ctx -> assertThat(ctx).hasFailed());
        WEB.withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.issuer=x").run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void jdbcReplayStoreIsSelectedAndEnforcesSingleUse() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class, JdbcTemplateAutoConfiguration.class, WwGatewayAutoConfiguration.class))
                .withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.issuer=x", "wwgateway.audience=y", "wwgateway.replay-store=jdbc",
                        "spring.datasource.url=jdbc:h2:mem:wwg-replay;DB_CLOSE_DELAY=-1")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).getBean(ReplayStore.class).isInstanceOf(JdbcReplayStore.class);
                    JdbcTemplate jdbc = ctx.getBean(JdbcTemplate.class);
                    jdbc.execute("CREATE TABLE wwg_replay (replay_key VARCHAR(512) PRIMARY KEY, expires_at BIGINT NOT NULL)");
                    ReplayStore store = ctx.getBean(ReplayStore.class);
                    long now = System.currentTimeMillis() / 1000;
                    assertThat(store.add("tok:a", now + 60)).isTrue();
                    assertThat(store.add("tok:a", now + 60)).isFalse();
                    assertThat(store.add("tok:old", now - 1)).isTrue();
                    assertThat(store.add("tok:old", now + 60)).as("expired entries may be reused").isTrue();
                });
    }

    @Test
    void jdbcReplayStoreWithoutDataSourceFailsStartupInsteadOfFallingBackToMemory() {
        WEB.withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.issuer=x", "wwgateway.audience=y", "wwgateway.replay-store=jdbc")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    // ------------------------------------------------------------------ helpers

    private MockHttpServletRequestBuilder actionRequest(String token, String proof, Object params) throws Exception {
        MockHttpServletRequestBuilder request = post("/transfers")
                .contentType(MediaType.APPLICATION_JSON)
                // deliberately NOT canonical JSON (indented): the server must hash the parsed value
                .content(mapper.writeValueAsBytes(params))
                .header("Authorization", "GatewayAction " + token);
        if (proof != null) request.header("WWG-Proof", proof);
        return request;
    }

    private static Map<String, Object> validCall() { return vectorCall("valid action token"); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> vectorCall(String name) {
        for (Object o : (List<Object>) VECTORS.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            if (name.equals(c.get("name"))) return ((List<Map<String, Object>>) c.get("calls")).get(0);
        }
        throw new IllegalArgumentException("no vector case " + name);
    }

    private static Map<String, Object> payload(String token) {
        return Json.parseObject(new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    private static Map<String, Object> loadVectors() {
        try {
            return Json.parseObject(Files.readString(Path.of("../wwgateway-verifier-core/src/test/resources/vectors.json"), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("cannot read the shared vectors", e);
        }
    }

    // ------------------------------------------------------------------ test application

    /** Single-use store that the test empties before every vector case. */
    static final class ResettableReplayStore implements ReplayStore {
        private volatile ReplayStore delegate = new InMemoryReplayStore(CLOCK);

        void reset() { delegate = new InMemoryReplayStore(CLOCK); }

        @Override
        public boolean add(String key, long expiresAt) { return delegate.add(key, expiresAt); }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(TestController.class)
    static class TestApp {
        @Bean
        ResettableReplayStore replayStore() { return new ResettableReplayStore(); }

        @Bean
        @SuppressWarnings("unchecked")
        GatewayVerifier gatewayVerifier(ResettableReplayStore replayStore) {
            Map<String, Object> jwks = (Map<String, Object>) VECTORS.get("jwks");
            Map<String, Object> snapshot = Map.of("snapshot", VECTORS.get("snapshot"));
            return GatewayVerifier.builder()
                    .gatewayUrl("https://gateway.example")
                    .issuer((String) VECTORS.get("issuer"))
                    .audience((String) VECTORS.get("audience"))
                    .clock(CLOCK)
                    .replayStore(replayStore)
                    .fetchJson(url -> url.endsWith("/.well-known/jwks.json") ? jwks : snapshot)
                    .build();
        }

        /**
         * Wraps every request after the starter's body cache, as Spring Security and many other filters do.
         * The gateway must still find the cached body underneath the wrapper.
         */
        @Bean
        FilterRegistrationBean<Filter> wrappingFilter() {
            FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>((req, res, chain) ->
                    chain.doFilter(new HttpServletRequestWrapper((HttpServletRequest) req), res));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 100);
            return bean;
        }
    }

    @RestController
    static class TestController {
        final AtomicInteger calls = new AtomicInteger();
        final AtomicReference<Map<String, Object>> lastBody = new AtomicReference<>();

        void reset() {
            calls.set(0);
            lastBody.set(null);
        }

        @PostMapping("/transfers")
        @GatewayAction("transfer.create")
        Map<String, Object> transfer(@RequestBody Map<String, Object> body, GatewayPrincipal p) {
            calls.incrementAndGet();
            lastBody.set(body);
            return Map.of("agent", p.agentId(), "step", p.stepId());
        }

        @PostMapping(path = "/transfers", headers = ENDPOINT_HEADER + "=account.close")
        @GatewayAction("account.close")
        Map<String, Object> closeAccount(@RequestBody Map<String, Object> body, GatewayPrincipal p) {
            calls.incrementAndGet();
            return Map.of("agent", p.agentId());
        }

        @GetMapping("/accounts")
        @GatewayDataAccess(table = "accounts")
        List<Map<String, Object>> accounts(GatewayPrincipal p) {
            calls.incrementAndGet();
            return p.applyDataScope(List.of(
                    Map.of("id", 1, "owner", "Ala", "balance", "1.00"),
                    Map.of("id", 2, "owner", "Ola", "balance", "2.00")), "accounts");
        }

        @GetMapping("/ops")
        @GatewayDataAccess(table = "operations")
        List<Map<String, Object>> operations(GatewayPrincipal p) {
            calls.incrementAndGet();
            return List.of();
        }

        @GetMapping("/health")
        String health() { return "ok"; }

        @PostMapping("/echo")
        Map<String, Object> echo(@RequestBody Map<String, Object> body) { return body; }
    }
}
