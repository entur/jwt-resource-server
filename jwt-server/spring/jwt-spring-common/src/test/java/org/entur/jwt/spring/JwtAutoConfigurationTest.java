package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetSourceWrapper;
import com.nimbusds.jose.jwk.source.RateLimitedJWKSetSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Start-up of {@link JwtAutoConfiguration} with various properties.
 */
class JwtAutoConfigurationTest {

    private static final String ISSUER = "https://issuer.a";

    // without the (required) audiences
    private final ApplicationContextRunner runnerWithoutAudiences = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.tenants.a.issuer=" + ISSUER,
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
            );

    private final ApplicationContextRunner runner = runnerWithoutAudiences.withPropertyValues("entur.jwt.claims.audiences=https://my.audience");

    @Configuration
    static class JwkSourceMapConfiguration {

        @Bean
        public JwkSourceMap<SecurityContext> jwkSourceMap() {
            return new JwkSourceMap<>(Map.of(), Map.of());
        }
    }

    @Configuration
    static class EnturJwtValidatorsConfiguration {

        @Bean
        public EnturJwtValidators customEnturJwtValidators() {
            return new EnturJwtValidators(List.of());
        }
    }

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
    void testFailsWithoutAudiences() {
        runnerWithoutAudiences.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("entur.jwt.claims.audiences")
                    .hasMessageContaining("[a]");
        });
    }

    @Test
    void testFailsWithEmptyAudiences() {
        runnerWithoutAudiences.withPropertyValues("entur.jwt.claims.audiences=").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("entur.jwt.claims.audiences");
        });
        runnerWithoutAudiences.withPropertyValues("entur.jwt.claims.audiences[0]=").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("entur.jwt.claims.audiences");
        });
    }

    @Test
    void testStartsWithoutAudiencesWhenDisabled() {
        runnerWithoutAudiences.withPropertyValues("entur.jwt.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(EnturJwtValidators.class);
        });
    }

    @Test
    void testStartsWithoutAudiencesWithoutEnabledTenants() {
        // i.e. with a custom JWK source map, as the default requires enabled tenants
        runnerWithoutAudiences.withUserConfiguration(JwkSourceMapConfiguration.class)
                .withPropertyValues("entur.jwt.tenants.a.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(EnturJwtValidators.class);
                });
    }

    @Test
    void testStartsWithoutAudiencesWithCustomEnturJwtValidators() {
        // the application is responsible for validating the audience
        runnerWithoutAudiences.withUserConfiguration(EnturJwtValidatorsConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(EnturJwtValidators.class).getValidators()).isEmpty();
        });
    }

    @Test
    void testAudienceValidatorWithAudiences() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(EnturJwtValidators.class).getValidators()).hasAtLeastOneElementOfType(AudienceOauth2TokenValidator.class);
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
