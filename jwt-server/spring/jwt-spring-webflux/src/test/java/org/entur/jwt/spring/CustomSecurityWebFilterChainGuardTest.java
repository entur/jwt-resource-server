package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.actuate.web.reactive.ReactiveManagementWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.reactive.ReactiveOAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.reactive.ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A custom SecurityWebFilterChain bean would shadow the chain of this starter, so startup fails.
 */
public class CustomSecurityWebFilterChainGuardTest {

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebFluxAutoConfiguration.class, JwtWebFluxSecurityAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @org.springframework.boot.test.context.TestConfiguration
    @EnableWebFluxSecurity
    static class SecurityWebFilterChainConfiguration {
        @Bean
        public SecurityWebFilterChain myChain(ServerHttpSecurity http) {
            return http.authorizeExchange(c -> c.anyExchange().permitAll()).build();
        }
    }

    @Test
    public void testFailsWithCustomSecurityWebFilterChain() {
        runner.withUserConfiguration(SecurityWebFilterChainConfiguration.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("myChain");
        });
    }

    @Test
    public void testFailsWithCustomSecurityWebFilterChainWhenOnlyJwtDisabled() {
        runner.withUserConfiguration(SecurityWebFilterChainConfiguration.class)
                .withPropertyValues("entur.jwt.enabled=false")
                .run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("entur.authorization.enabled=false");
        });
    }

    @Test
    public void testFailsWithCustomSecurityWebFilterChainWhenOnlyAuthorizationDisabled() {
        runner.withUserConfiguration(SecurityWebFilterChainConfiguration.class)
                .withPropertyValues("entur.authorization.enabled=false")
                .run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("entur.jwt.enabled=false");
        });
    }

    @Test
    public void testStartsWithCustomSecurityWebFilterChainWhenDisabled() {
        runner.withUserConfiguration(SecurityWebFilterChainConfiguration.class)
                // the CORS configuration requires the JWT or authorization configuration
                .withPropertyValues("entur.jwt.enabled=false", "entur.authorization.enabled=false", "entur.cors.enabled=false")
                .run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).getBeans(SecurityWebFilterChain.class).containsOnlyKeys("myChain");
        });
    }

    @Test
    public void testStartsWithSpringBootSecurityAutoConfigurations() {
        runner.withConfiguration(AutoConfigurations.of(
                        ReactiveWebSecurityAutoConfiguration.class,
                        ReactiveManagementWebSecurityAutoConfiguration.class,
                        ReactiveOAuth2ResourceServerAutoConfiguration.class,
                        ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration.class))
                // so that Spring Boot's resource server auto-configuration would also add a chain
                .withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:1/jwks.json")
                .run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).getBeans(SecurityWebFilterChain.class).containsOnlyKeys("jwtSecurityWebFilterChain");
        });
    }
}
