package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * MDC mappings are not supported by the webflux module, so startup fails if any are configured.
 */
public class UnsupportedMdcMappingsGuardTest {

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebFluxAutoConfiguration.class, JwtWebFluxSecurityAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json",
                    "entur.jwt.claims.audiences=https://my.audience"
            );

    @Test
    public void testStartsWithDefaultMdcProperties() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("jwtSecurityWebFilterChain");
        });
    }

    @Test
    public void testStartsWithMdcMappingsWhenDisabled() {
        runner.withPropertyValues(
                        "entur.jwt.mdc.enabled=false",
                        "entur.jwt.mdc.mappings[0].from=iss",
                        "entur.jwt.mdc.mappings[0].to=issuer")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithMdcMappings() {
        runner.withPropertyValues(
                        "entur.jwt.mdc.mappings[0].from=iss",
                        "entur.jwt.mdc.mappings[0].to=issuer")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("MDC mappings are not supported for WebFlux");
                });
    }
}
