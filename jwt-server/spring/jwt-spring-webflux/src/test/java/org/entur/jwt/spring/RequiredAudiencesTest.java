package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Startup fails if there are tenants but no audiences, as tokens issued for other APIs would then be accepted.
 */
public class RequiredAudiencesTest {

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebFluxAutoConfiguration.class, JwtWebFluxSecurityAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @Test
    public void testFailsWithoutAudiences() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("entur.jwt.claims.audiences");
        });
    }

    @Test
    public void testStartsWithAudiences() {
        runner.withPropertyValues("entur.jwt.claims.audiences=https://my.audience").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("jwtSecurityWebFilterChain");
        });
    }
}
