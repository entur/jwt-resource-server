package org.entur.jwt.spring.decode;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The shared {@link ClosableJwtDecoders} bean: when it is created, and replacing it.
 */
class ClosableJwtDecodersAutoConfigurationTest {

    private static final String ISSUER = "https://issuer.a";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=" + ISSUER,
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @Configuration
    static class CustomDecodersConfiguration {

        static final JwtDecoder DECODER = token -> {
            throw new IllegalStateException("Not used");
        };

        @Bean
        public ClosableJwtDecoders customClosableJwtDecoders() {
            return new ClosableJwtDecoders(Map.of(ISSUER, DECODER));
        }
    }

    @Test
    void testDecodersAreNotCreatedUnlessUsed() {
        runner.run(context -> assertThat(context.getBeanFactory().containsSingleton("closableJwtDecoders")).isFalse());
    }

    @Test
    void testCustomDecodersReplaceTheDefault() {
        runner.withUserConfiguration(CustomDecodersConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(ClosableJwtDecoders.class);
            assertThat(context.getBean(ClosableJwtDecoders.class).getJwtDecoders().get(ISSUER)).isSameAs(CustomDecodersConfiguration.DECODER);
        });
    }
}
