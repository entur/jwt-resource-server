package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;

import java.util.HashSet;
import java.util.Set;

/**
 * Per-issuer context that acts directly as a JWK-set {@link EventListener} and tracks the
 * most-recently-seen {@link JWKSet} for its issuer.
 *
 * <p>When a JWK-set refresh event arrives:
 * <ol>
 *   <li>The new {@link JWKSet} is stored in {@link #getCurrentJwkSet()}.</li>
 *   <li>If the set of key IDs has changed, the {@code onUpdate} callback supplied at
 *       construction time is invoked so that the {@link JwtKidIssuerCache} can be
 *       recomputed.</li>
 * </ol>
 *
 * <p>Instances are created by {@link JwtKidIssuerCacheFactory#createContext(String)}.
 * Register the instance itself as an event listener via
 * {@link org.entur.jwt.spring.actuate.ListEventListener#addEventListener}.
 */
public class IssuerJwkContext implements EventListener {

    private final String issuer;
    private final Runnable onUpdate;
    private volatile JWKSet currentJwkSet;
    private volatile Set<String> lastKids = Set.of();

    IssuerJwkContext(String issuer, Runnable onUpdate) {
        this.issuer = issuer;
        this.onUpdate = onUpdate;
    }

    /** Returns the issuer URL this context belongs to. */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Returns the most-recently-received {@link JWKSet}, or {@code null} if no refresh
     * event has been received yet.
     */
    public JWKSet getCurrentJwkSet() {
        return currentJwkSet;
    }

    @Override
    public void notify(Event event) {
        if (event instanceof CachingJWKSetSource.RefreshCompletedEvent<?> e) {
            onJwkSetReceived(e.getJWKSet());
        } else if (event instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent<?> e) {
            onJwkSetReceived(e.getJWKSet());
        }
    }

    private void onJwkSetReceived(JWKSet jwkSet) {
        Set<String> newKids = extractKids(jwkSet);
        if (newKids.equals(lastKids)) {
            return;
        }
        currentJwkSet = jwkSet;
        lastKids = newKids;
        onUpdate.run();
    }

    static Set<String> extractKids(JWKSet jwkSet) {
        Set<String> kids = new HashSet<>();
        for (JWK key : jwkSet.getKeys()) {
            String kid = key.getKeyID();
            if (kid != null && !kid.isBlank()) {
                kids.add(kid);
            }
        }
        return kids;
    }
}
