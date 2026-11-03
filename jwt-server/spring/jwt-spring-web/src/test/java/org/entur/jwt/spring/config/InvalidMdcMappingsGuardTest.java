package org.entur.jwt.spring.config;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.JwtWebAutoConfiguration;
import org.entur.jwt.spring.JwtWebSecurityChainAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An MDC mapping without 'from' or 'to' would otherwise fail every authenticated request, so startup fails instead.
 */
public class InvalidMdcMappingsGuardTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebAutoConfiguration.class, JwtWebSecurityChainAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json",
                    "entur.jwt.claims.audiences=https://my.audience"
            );

    @Test
    public void testStartsWithValidMdcMappings() {
        runner.withPropertyValues(
                        "entur.jwt.mdc.mappings[0].from=iss",
                        "entur.jwt.mdc.mappings[0].to=issuer")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("filterChain");
                });
    }

    @Test
    public void testStartsWithInvalidMdcMappingsWhenDisabled() {
        runner.withPropertyValues(
                        "entur.jwt.mdc.enabled=false",
                        "entur.jwt.mdc.mappings[0].from=iss")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithMdcMappingWithoutTo() {
        runner.withPropertyValues("entur.jwt.mdc.mappings[0].from=iss")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("entur.jwt.mdc.mappings[0].to");
                });
    }

    @Test
    public void testFailsWithMdcMappingWithoutFrom() {
        runner.withPropertyValues("entur.jwt.mdc.mappings[0].to=issuer")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("entur.jwt.mdc.mappings[0].from");
                });
    }
}
