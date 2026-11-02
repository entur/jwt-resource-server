package org.entur.jwt.spring.properties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The {@code type} of the {@code entur.authorization.permit-all.matcher} properties.
 */
public class CustomHttpMethodTest {

    @Configuration
    @EnableConfigurationProperties(SecurityProperties.class)
    static class PropertiesConfiguration {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(PropertiesConfiguration.class);

    @Test
    public void testFromStringIsCaseInsensitive() {
        assertThat(CustomHttpMethod.fromString("default")).isEqualTo(CustomHttpMethod.DEFAULT);
        assertThat(CustomHttpMethod.fromString("Default")).isEqualTo(CustomHttpMethod.DEFAULT);
        assertThat(CustomHttpMethod.fromString("ant")).isEqualTo(CustomHttpMethod.ANT);
        assertThat(CustomHttpMethod.fromString("ANT")).isEqualTo(CustomHttpMethod.ANT);
    }

    @Test
    public void testFromStringRejectsUnknownType() {
        assertThatThrownBy(() -> CustomHttpMethod.fromString("regex")).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("regex");
    }

    @Test
    public void testDefaultsToDefaultType() {
        runner.run(context -> {
            MatcherConfiguration matcher = context.getBean(SecurityProperties.class).getAuthorization().getPermitAll().getMatcher();

            assertThat(matcher.getType()).isEqualTo(CustomHttpMethod.DEFAULT);
            assertThat(matcher.getMethod().getGet().getType()).isNull();
        });
    }

    @Test
    public void testBindsAntType() {
        runner.withPropertyValues(
                "entur.authorization.permit-all.matcher.type=ant",
                "entur.authorization.permit-all.matcher.method.get.type=ANT"
        ).run(context -> {
            MatcherConfiguration matcher = context.getBean(SecurityProperties.class).getAuthorization().getPermitAll().getMatcher();

            assertThat(matcher.getType()).isEqualTo(CustomHttpMethod.ANT);
            assertThat(matcher.getMethod().getGet().getType()).isEqualTo(CustomHttpMethod.ANT);
        });
    }
}
