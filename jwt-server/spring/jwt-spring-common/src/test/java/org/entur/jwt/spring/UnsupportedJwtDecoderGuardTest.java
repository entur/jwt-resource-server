package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

public class UnsupportedJwtDecoderGuardTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=https://issuer.a",
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    @Configuration
    static class JwtDecoderConfiguration {
        @Bean
        public JwtDecoder myJwtDecoder() {
            return token -> {
                throw new IllegalStateException("Not used");
            };
        }
    }

    @Test
    public void testStartsWithoutJwtDecoderBean() {
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithJwtDecoderBean() {
        runner.withUserConfiguration(JwtDecoderConfiguration.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("myJwtDecoder")
                    .hasMessageContaining("ClosableJwtDecoders")
                    .hasMessageContaining("entur.jwt.decode.fail-on-jwt-decoder-bean=false");
        });
    }

    @Test
    public void testStartsWithJwtDecoderBeanWhenDisabled() {
        runner.withUserConfiguration(JwtDecoderConfiguration.class)
                .withPropertyValues("entur.jwt.decode.fail-on-jwt-decoder-bean=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(UnsupportedJwtDecoderGuard.class);
                });
    }
}
