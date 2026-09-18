package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultJwksHealthIndicatorTest {

    private static class StubJwkSetSource implements JWKSetSource<SecurityContext> {

        private final JWKSet jwkSet;
        private final KeySourceException exceptionToThrow;

        StubJwkSetSource(JWKSet jwkSet) {
            this.jwkSet = jwkSet;
            this.exceptionToThrow = null;
        }

        StubJwkSetSource(KeySourceException exceptionToThrow) {
            this.jwkSet = null;
            this.exceptionToThrow = exceptionToThrow;
        }

        @Override
        public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context) throws KeySourceException {
            if (exceptionToThrow != null) {
                throw exceptionToThrow;
            }
            return jwkSet;
        }

        @Override
        public void close() {
        }
    }

    @Test
    void isHealthyWhenLatestHealthReportIsHealthy() {
        DefaultJwksHealthIndicator indicator = new DefaultJwksHealthIndicator("my-tenant");
        indicator.notify(new HealthReport<>(new Object(), HealthStatus.HEALTHY, System.currentTimeMillis(), null));

        assertTrue(indicator.isJwksHealtyReport());
        assertTrue(indicator.getJwksHealth().isSuccess());
    }

    @Test
    void isUnhealthyWhenNoHealthReportYet() {
        DefaultJwksHealthIndicator indicator = new DefaultJwksHealthIndicator("my-tenant");

        assertFalse(indicator.isHealthReport());
        assertFalse(indicator.isJwksHealtyReport());
    }

    @Test
    void refreshSucceedsWhenSourceReturnsJwkSet() {
        DefaultJwksHealthIndicator indicator = new DefaultJwksHealthIndicator("my-tenant");
        indicator.setJwkSetSource(new StubJwkSetSource(new JWKSet()));

        assertTrue(indicator.refreshJwksHealth(System.currentTimeMillis()));
        assertTrue(indicator.getJwksHealth().isSuccess());
    }

    @Test
    void refreshFailsWhenSourceThrowsRateLimitException() {
        DefaultJwksHealthIndicator indicator = new DefaultJwksHealthIndicator("my-tenant");
        indicator.setJwkSetSource(new StubJwkSetSource(new RateLimitReachedException()));

        assertFalse(indicator.refreshJwksHealth(System.currentTimeMillis()));
        assertFalse(indicator.getJwksHealth().isSuccess());
    }

    @Test
    void refreshFailsWhenSourceThrowsOtherException() {
        DefaultJwksHealthIndicator indicator = new DefaultJwksHealthIndicator("my-tenant");
        indicator.setJwkSetSource(new StubJwkSetSource(new KeySourceException("boom")));

        assertFalse(indicator.refreshJwksHealth(System.currentTimeMillis()));
    }
}
