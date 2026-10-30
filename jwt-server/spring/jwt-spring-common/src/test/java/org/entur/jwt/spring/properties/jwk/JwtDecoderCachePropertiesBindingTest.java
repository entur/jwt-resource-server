package org.entur.jwt.spring.properties.jwk;

import org.entur.jwt.spring.properties.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Binding of the {@code entur.jwt.tenants.*.decoder-cache} properties.
 */
public class JwtDecoderCachePropertiesBindingTest {

    @Configuration
    @EnableConfigurationProperties(SecurityProperties.class)
    static class PropertiesConfiguration {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfiguration.class)
            .withPropertyValues("entur.jwt.tenants.a.issuer=https://issuer.a");

    private static JwtDecoderCacheProperties decoderCache(org.springframework.context.ApplicationContext context) {
        return context.getBean(SecurityProperties.class).getJwt().getTenants().get("a").getDecoderCache();
    }

    @Test
    public void testDefaults() {
        runner.run(context -> {
            JwtDecoderCacheProperties properties = decoderCache(context);

            assertThat(properties.isEnabled()).isFalse();
            assertThat(properties.getSize()).isEqualTo(250);
            assertThat(properties.getMode()).isEqualTo(JwtDecoderCacheMode.LRU);
            assertThat(properties.getCleanupInterval()).isEqualTo(60);
        });
    }

    @Test
    public void testBindsAllProperties() {
        runner.withPropertyValues(
                "entur.jwt.tenants.a.decoder-cache.enabled=true",
                "entur.jwt.tenants.a.decoder-cache.size=5",
                "entur.jwt.tenants.a.decoder-cache.mode=fifo", // lower case, as in the documentation
                "entur.jwt.tenants.a.decoder-cache.cleanup-interval=30"
        ).run(context -> {
            JwtDecoderCacheProperties properties = decoderCache(context);

            assertThat(properties.isEnabled()).isTrue();
            assertThat(properties.getSize()).isEqualTo(5);
            assertThat(properties.getMode()).isEqualTo(JwtDecoderCacheMode.FIFO);
            assertThat(properties.getCleanupInterval()).isEqualTo(30);
        });
    }

    @Test
    public void testBindsFixedMode() {
        runner.withPropertyValues("entur.jwt.tenants.a.decoder-cache.mode=fixed")
                .run(context -> assertThat(decoderCache(context).getMode()).isEqualTo(JwtDecoderCacheMode.FIXED));
    }

    @Test
    public void testFailsOnInvalidSize() {
        runner.withPropertyValues("entur.jwt.tenants.a.decoder-cache.size=-2").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("size must be -1 or non-negative");
        });
    }

    @Test
    public void testBindsDisabledCleanupInterval() {
        runner.withPropertyValues("entur.jwt.tenants.a.decoder-cache.cleanup-interval=-1")
                .run(context -> assertThat(decoderCache(context).getCleanupInterval()).isEqualTo(-1));
    }

    @Test
    public void testFailsOnInvalidCleanupInterval() {
        runner.withPropertyValues("entur.jwt.tenants.a.decoder-cache.cleanup-interval=-2").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("cleanupInterval must be -1 or non-negative");
        });
    }

    @Test
    public void testFailsOnUnknownMode() {
        runner.withPropertyValues("entur.jwt.tenants.a.decoder-cache.mode=random").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("decoder-cache.mode");
        });
    }
}
