package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetSourceWrapper;
import com.nimbusds.jose.jwk.source.RateLimitedJWKSetSource;
import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.ArrayList;
import java.util.List;

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

    @Test
    void testHealthIndicatorEnabledByDefault() {
        runner.run(context -> assertThat(context).hasSingleBean(ListJwksHealthIndicator.class));
    }

    @Test
    void testHealthIndicatorDisabled() {
        runner.withPropertyValues("management.health.jwks.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(ListJwksHealthIndicator.class);
            assertThat(context).hasSingleBean(JwkSourceMap.class);
        });
    }

    @Test
    void testCachedAndRateLimitedByDefault() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(getJwkSetSources(context.getBean(JwkSourceMap.class)))
                    .hasAtLeastOneElementOfType(CachingJWKSetSource.class)
                    .hasAtLeastOneElementOfType(RateLimitedJWKSetSource.class);
        });
    }

    @Test
    void testCacheDisabledAlsoDisablesRateLimiting() {
        runner.withPropertyValues("entur.jwt.jwk.cache.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(getJwkSetSources(context.getBean(JwkSourceMap.class))).doesNotHaveAnyElementsOfTypes(CachingJWKSetSource.class, RateLimitedJWKSetSource.class);
        });
    }

    @Test
    void testCacheTimeToLiveMustBeGreaterThanRateLimitInterval() {
        // 100 seconds interval
        runner.withPropertyValues("entur.jwt.jwk.rate-limit.refill-rate=0.01", "entur.jwt.jwk.cache.time-to-live=100").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("entur.jwt.jwk.cache.time-to-live")
                    .hasMessageContaining("entur.jwt.jwk.rate-limit.refill-rate")
                    .hasMessageContaining("entur.jwt.jwk.rate-limit.enabled=false");
        });
    }

    @Test
    void testCacheTimeToLiveGreaterThanRateLimitInterval() {
        runner.withPropertyValues("entur.jwt.jwk.rate-limit.refill-rate=0.01", "entur.jwt.jwk.cache.time-to-live=101").run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void testShortCacheTimeToLiveWithoutRateLimiting() {
        runner.withPropertyValues("entur.jwt.jwk.rate-limit.refill-rate=0.01", "entur.jwt.jwk.cache.time-to-live=100", "entur.jwt.jwk.rate-limit.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(getJwkSetSources(context.getBean(JwkSourceMap.class))).doesNotHaveAnyElementsOfTypes(RateLimitedJWKSetSource.class);
        });
    }

    @Test
    void testFailsOnTenantsWithSameIssuer() {
        runner.withPropertyValues(
                "entur.jwt.tenants.b.issuer=" + ISSUER,
                "entur.jwt.tenants.b.jwk.location=http://localhost:2/jwks.json"
        ).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageStartingWith("Tenants 'a' and 'b' have the same issuer '" + ISSUER + "'.");
        });
    }

    @Test
    void testDisabledTenantWithSameIssuer() {
        runner.withPropertyValues(
                "entur.jwt.tenants.b.enabled=false",
                "entur.jwt.tenants.b.issuer=" + ISSUER,
                "entur.jwt.tenants.b.jwk.location=http://localhost:2/jwks.json"
        ).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(JwkSourceMap.class).getJwkSources()).containsOnlyKeys(ISSUER);
        });
    }

    /**
     * The chain of (wrapped) JWK set sources, outermost first.
     */
    private static List<JWKSetSource<?>> getJwkSetSources(JwkSourceMap<?> jwkSourceMap) {
        JWKSetBasedJWKSource<?> jwkSource = (JWKSetBasedJWKSource<?>) jwkSourceMap.getJwkSources().get(ISSUER);

        List<JWKSetSource<?>> sources = new ArrayList<>();
        JWKSetSource<?> source = jwkSource.getJWKSetSource();
        sources.add(source);
        while (source instanceof JWKSetSourceWrapper<?> wrapper) {
            source = wrapper.getSource();
            sources.add(source);
        }
        return sources;
    }
}
