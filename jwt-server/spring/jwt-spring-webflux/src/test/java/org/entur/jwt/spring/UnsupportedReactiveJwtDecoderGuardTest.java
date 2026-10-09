package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A ReactiveJwtDecoder bean would be ignored by the webflux module, so startup fails.
 */
public class UnsupportedReactiveJwtDecoderGuardTest {

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @Configuration
    static class ReactiveJwtDecoderConfiguration {
        @Bean
        public ReactiveJwtDecoder myReactiveJwtDecoder() {
            return token -> {
                throw new IllegalStateException("Not used");
            };
        }
    }

    @Test
    public void testStartsWithoutReactiveJwtDecoderBean() {
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testStartsWithReactiveJwtDecoderBeanByDefault() {
        runner.withUserConfiguration(ReactiveJwtDecoderConfiguration.class).run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithReactiveJwtDecoderBeanWhenEnabled() {
        runner.withUserConfiguration(ReactiveJwtDecoderConfiguration.class)
                .withPropertyValues("entur.jwt.decode.fail-on-jwt-decoder-bean=true")
                .run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("myReactiveJwtDecoder");
        });
    }
}
