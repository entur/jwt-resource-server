package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.EventListener;

/**
 * Fires real JWK source events (no mocks), by running a JWK set (re)load through a {@link CachingJWKSetSource}.
 */
class JwkEvents {

    private JwkEvents() {
    }

    /**
     * Load the JWK set, firing {@link CachingJWKSetSource.RefreshInitiatedEvent} and
     * {@link CachingJWKSetSource.RefreshCompletedEvent} to the listener.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    static void refresh(EventListener listener, JWKSet jwkSet) {
        CachingJWKSetSource<SecurityContext> source = new CachingJWKSetSource<>(new TestJWKSetSource(jwkSet), 60_000, 1_000, listener);
        try {
            source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), null);
        } catch (KeySourceException e) {
            throw new IllegalStateException(e);
        }
    }
}
