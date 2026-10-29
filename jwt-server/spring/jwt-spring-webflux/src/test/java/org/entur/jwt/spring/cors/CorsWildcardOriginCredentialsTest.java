package org.entur.jwt.spring.cors;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.JwtWebFluxAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Browsers do not accept credentials for any origin (*), so explicitly allowing both fails startup.
 */
public class CorsWildcardOriginCredentialsTest {

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebFluxAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json",
                    "entur.cors.mode=api",
                    "entur.cors.origins[0]=*"
            );

    @Test
    public void testStartsWithAnyOrigin() {
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testStartsWithAnyOriginWithoutCredentials() {
        runner.withPropertyValues("entur.cors.allow-credentials=false").run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithAnyOriginWithCredentials() {
        runner.withPropertyValues("entur.cors.allow-credentials=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("entur.cors.allow-credentials")
                            .hasMessageContaining("entur.cors.origins");
                });
    }
}
