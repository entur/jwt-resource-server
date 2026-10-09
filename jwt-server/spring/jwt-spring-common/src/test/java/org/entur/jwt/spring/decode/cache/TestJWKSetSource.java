package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * JWK set source for tests, i.e. the innermost source of a JWK source chain: serves a JWK set,
 * or fails (simulating an outage), optionally blocking until released.
 */
class TestJWKSetSource implements JWKSetSource<SecurityContext> {

    private volatile JWKSet jwkSet;
    private volatile boolean fail;
    private volatile CountDownLatch block;

    TestJWKSetSource(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    void setJwkSet(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
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
        if (fail) {
            throw new JWKSetUnavailableException("Simulated outage");
        }
        return jwkSet;
    }

    @Override
    public void close() {
    }
}
