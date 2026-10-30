package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * JWK set source for tests, i.e. the innermost source of a JWK source chain: serves a JWK set,
 * or fails (simulating an outage), optionally blocking until released. Counts the calls which ask for a refresh.
 */
class TestJWKSetSource implements JWKSetSource<SecurityContext> {

    private volatile JWKSet jwkSet;
    private volatile boolean fail;
    private volatile CountDownLatch block;
    private final AtomicInteger refreshes = new AtomicInteger();

    TestJWKSetSource(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    void setJwkSet(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    JWKSet getJwkSet() {
        return jwkSet;
    }

    /**
     * @return number of calls which asked for the JWK set to be refreshed, i.e. for a key which was not found
     */
    int getRefreshes() {
        return refreshes.get();
    }

    void setFail(boolean fail) {
        this.fail = fail;
    }

    /**
     * Block calls until {@link #release()}.
     */
    void block() {
        this.block = new CountDownLatch(1);
    }

    void release() {
        CountDownLatch latch = this.block;
        if (latch != null) {
            latch.countDown();
        }
    }

    @Override
    public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context) throws JWKSetUnavailableException {
        CountDownLatch latch = this.block;
        if (latch != null) {
            try {
                latch.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (refreshEvaluator.requiresRefresh(jwkSet)) {
            refreshes.incrementAndGet();
        }
        if (fail) {
            throw new JWKSetUnavailableException("Simulated outage");
        }
        return jwkSet;
    }

    @Override
    public void close() {
    }
}
