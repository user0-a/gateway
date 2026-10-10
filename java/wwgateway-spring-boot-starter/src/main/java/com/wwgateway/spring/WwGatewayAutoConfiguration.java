package com.wwgateway.spring;

import com.wwgateway.verifier.GatewayVerifier;
import com.wwgateway.verifier.InMemoryReplayStore;
import com.wwgateway.verifier.ReplayStore;
import java.util.List;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Enabled when {@code wwgateway.gateway-url} is set in a servlet web application. */
// After JdbcTemplateAutoConfiguration so @ConditionalOnBean(JdbcTemplate) sees its bean; by name, spring-jdbc is optional.
@AutoConfiguration(afterName = "org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "wwgateway", name = "gateway-url")
@EnableConfigurationProperties(WwGatewayProperties.class)
public class WwGatewayAutoConfiguration {
    private static final Log log = LogFactory.getLog(WwGatewayAutoConfiguration.class);

    /** Cluster-safe replay store; selected with wwgateway.replay-store=jdbc. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(JdbcTemplate.class)
    @ConditionalOnProperty(prefix = "wwgateway", name = "replay-store", havingValue = "jdbc")
    static class JdbcReplayStoreConfiguration {
        @Bean
        @ConditionalOnMissingBean(ReplayStore.class)
        @ConditionalOnBean(JdbcTemplate.class)
        ReplayStore wwgJdbcReplayStore(JdbcTemplate jdbc) {
            return new JdbcReplayStore(jdbc);
        }
    }

    @Bean
    @ConditionalOnMissingBean(ReplayStore.class)
    @ConditionalOnProperty(prefix = "wwgateway", name = "replay-store", havingValue = "memory", matchIfMissing = true)
    public ReplayStore wwgReplayStore() {
        log.warn("WWGateWay uses an in-memory replay store: single use is guaranteed per instance only. Use wwgateway.replay-store=jdbc for clusters.");
        return new InMemoryReplayStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public GatewayVerifier wwgGatewayVerifier(WwGatewayProperties props, ReplayStore replayStore) {
        return GatewayVerifier.builder()
                .gatewayUrl(props.getGatewayUrl())
                .issuer(Objects.requireNonNull(props.getIssuer(), "wwgateway.issuer is required"))
                .audience(Objects.requireNonNull(props.getAudience(), "wwgateway.audience is required"))
                .replayStore(replayStore)
                .requireProofOfPossession(props.isRequireProofOfPossession())
                .clockSkewSeconds(props.getClockSkewSeconds())
                .proofMaxAgeSeconds(props.getProofMaxAgeSeconds())
                .snapshotMaxAgeSeconds(props.getSnapshotMaxAgeSeconds())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public GatewayParamsExtractor wwgParamsExtractor() {
        return new DefaultGatewayParamsExtractor();
    }

    @Bean
    public FilterRegistrationBean<CachedBodyFilter> wwgCachedBodyFilter(WwGatewayProperties props) {
        FilterRegistrationBean<CachedBodyFilter> bean = new FilterRegistrationBean<>(new CachedBodyFilter(props.getMaxBodyBytes()));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return bean;
    }

    @Bean
    public WebMvcConfigurer wwgWebMvcConfigurer(GatewayVerifier verifier, GatewayParamsExtractor extractor) {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(new GatewayAuthorizationInterceptor(verifier, extractor)).order(Ordered.HIGHEST_PRECEDENCE);
            }

            @Override
            public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                resolvers.add(new GatewayPrincipalArgumentResolver());
            }
        };
    }
}
