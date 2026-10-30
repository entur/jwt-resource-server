package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring Boot's resource server auto-configuration creates a JwtDecoder bean from its own properties;
 * it would be ignored, so startup fails.
 */
public class SpringBootJwtDecoderGuardTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @Test
    public void testStartsWithoutSpringBootResourceServerProperties() {
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testStartsWithSpringBootResourceServerJwtDecoderByDefault() {
        runner.withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:1/jwks.json")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithSpringBootResourceServerJwtDecoderWhenEnabled() {
        runner.withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:1/jwks.json",
                        "entur.jwt.decode.fail-on-jwt-decoder-bean=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("spring.security.oauth2.resourceserver.jwt");
                });
    }
}
