package org.entur.jwt.spring.cors;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.JwtWebAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CORS is configured even if both JWT authentication and authorization are disabled.
 */
public class CorsWithoutJwtTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=false",
                    "entur.authorization.enabled=false",
                    "entur.cors.mode=api",
                    "entur.cors.origins[0]=https://petstore.swagger.io"
            );

    @Test
    public void testStartsWithJwtAndAuthorizationDisabled() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("corsConfigurationSource");
        });
    }
}
