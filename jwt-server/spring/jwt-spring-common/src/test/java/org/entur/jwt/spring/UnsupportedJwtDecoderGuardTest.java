package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.ClassUtils;

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
    public void testStartsWithoutReactor() {
        // this module does not depend on Reactor, i.e. like a servlet application; the guard must not need it
        assertThat(ClassUtils.isPresent("reactor.core.publisher.Mono", getClass().getClassLoader())).isFalse();

        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(UnsupportedJwtDecoderGuard.class);
        });
    }

    @Test
    public void testStartsWithoutJwtDecoderBean() {
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    public void testFailsWithJwtDecoderBeanWhenEnabled() {
        runner.withUserConfiguration(JwtDecoderConfiguration.class)
                .withPropertyValues("entur.jwt.decode.fail-on-jwt-decoder-bean=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("myJwtDecoder")
                            .hasMessageContaining("ClosableJwtDecoders")
                            .hasMessageContaining("entur.jwt.decode.fail-on-jwt-decoder-bean=true");
                });
    }

    @Test
    public void testStartsWithJwtDecoderBeanByDefault() {
        runner.withUserConfiguration(JwtDecoderConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    // the guard is still registered, but does nothing
                    assertThat(context).hasSingleBean(UnsupportedJwtDecoderGuard.class);
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                });
    }
}
