package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Start-up of {@link JwtAutoConfiguration} with various properties.
 */
class JwtAutoConfigurationTest {

    private static final String ISSUER = "https://issuer.a";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.tenants.a.issuer=" + ISSUER,
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @Test
    void testEnabledByDefault() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JwkSourceMap.class);
        });
    }

    @Test
    void testDisabled() {
        runner.withPropertyValues("entur.jwt.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(JwkSourceMap.class);
        });
    }
}
