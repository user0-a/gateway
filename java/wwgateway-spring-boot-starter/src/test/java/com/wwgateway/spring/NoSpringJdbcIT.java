package com.wwgateway.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.wwgateway.verifier.GatewayVerifier;
import com.wwgateway.verifier.InMemoryReplayStore;
import com.wwgateway.verifier.ReplayStore;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

/**
 * Runs in a separate failsafe execution with spring-jdbc removed from the classpath (see pom.xml):
 * spring-jdbc is optional, so the auto-configuration must load without it.
 */
class NoSpringJdbcIT {
    private static final WebApplicationContextRunner WEB = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(WwGatewayAutoConfiguration.class))
            .withPropertyValues("wwgateway.gateway-url=https://gw", "wwgateway.issuer=x", "wwgateway.audience=y");

    @Test
    void springJdbcIsReallyAbsent() {
        assertThatThrownBy(() -> Class.forName("org.springframework.jdbc.core.JdbcTemplate"))
                .isInstanceOf(ClassNotFoundException.class);
    }

    @Test
    void autoConfigurationLoadsWithTheInMemoryReplayStore() {
        WEB.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).hasSingleBean(GatewayVerifier.class);
            assertThat(ctx).getBean(ReplayStore.class).isInstanceOf(InMemoryReplayStore.class);
            assertThat(ctx).hasBean("wwgWebMvcConfigurer");
        });
    }

    @Test
    void jdbcReplayStoreRequestedWithoutSpringJdbcFailsStartup() {
        WEB.withPropertyValues("wwgateway.replay-store=jdbc").run(ctx -> assertThat(ctx).hasFailed());
    }
}
