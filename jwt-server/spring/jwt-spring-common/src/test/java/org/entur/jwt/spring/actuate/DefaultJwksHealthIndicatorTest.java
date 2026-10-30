package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    // counts the calls, i.e. requests to the JWKs endpoint
    private static class UnreliableJwkSetSource implements JWKSetSource<SecurityContext> {

        private final JWKSet jwkSet = new JWKSet();
        private final AtomicInteger requests = new AtomicInteger();
        private volatile boolean fail;

        void setFail(boolean fail) {
            this.fail = fail;
        }

        int getRequests() {
            return requests.get();
        }

        @Override
        public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context) throws KeySourceException {
            requests.incrementAndGet();
            if (fail) {
                throw new JWKSetUnavailableException("Simulated outage");
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

    @Test
    void refreshFetchesCachedJwkSetAfterFailedRefresh() throws Exception {
        DefaultJwksHealthIndicator indicator = new DefaultJwksHealthIndicator("my-tenant");
        UnreliableJwkSetSource source = new UnreliableJwkSetSource();

        // same order as JwkSourceMapFactory: cache, rate limiting, health reporting
        JWKSetBasedJWKSource<SecurityContext> jwkSource = (JWKSetBasedJWKSource<SecurityContext>) JWKSourceBuilder.create(source)
                .cache(3_600_000, 15_000)
                .refreshAheadCache(false)
                .rateLimited(10_000)
                .healthReporting(indicator)
                .build();
        JWKSetSource<SecurityContext> jwkSetSource = jwkSource.getJWKSetSource();
        indicator.setJwkSetSource(jwkSetSource);

        long time = System.currentTimeMillis();

        JWKSet jwkSet = jwkSetSource.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), time, null);
        assertTrue(indicator.isJwksHealtyReport());

        // refresh for an unknown key id during an outage
        source.setFail(true);
        assertThrows(KeySourceException.class, () -> jwkSetSource.getJWKSet(JWKSetCacheRefreshEvaluator.referenceComparison(jwkSet), time + 1000, null));
        assertFalse(indicator.isJwksHealtyReport());
        assertEquals(2, source.getRequests());

        // rate limit reached, so the JWKs endpoint is not called
        assertFalse(indicator.refreshJwksHealth(time + 2000));
        assertFalse(indicator.isJwksHealtyReport());
        assertEquals(2, source.getRequests());

        // the JWKs endpoint is still down
        assertFalse(indicator.refreshJwksHealth(time + 10_000));
        assertFalse(indicator.isJwksHealtyReport());
        assertEquals(3, source.getRequests());

        source.setFail(false);

        assertTrue(indicator.refreshJwksHealth(time + 11_000));
        assertTrue(indicator.isJwksHealtyReport());
        assertEquals(4, source.getRequests());

        // healthy, so no refresh
        assertTrue(indicator.getJwksHealth().isSuccess());
        assertEquals(4, source.getRequests());
    }
}
