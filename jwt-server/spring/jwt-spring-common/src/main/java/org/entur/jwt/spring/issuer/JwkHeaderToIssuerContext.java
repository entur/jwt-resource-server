package org.entur.jwt.spring.issuer;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Per-issuer context that acts directly as a JWK-set {@link EventListener} and tracks the
 * most-recently-seen {@link JWKSet} for its issuer.
 *
 */
public class JwkHeaderToIssuerContext implements EventListener {

    public static Set<String> extractKids(JWKSet jwkSet) {
        Set<String> kids = new HashSet<>();
        for (JWK key : jwkSet.getKeys()) {
            String kid = key.getKeyID();
            if (kid != null && !kid.isBlank()) {
                kids.add(kid);
            }
        }
        return kids;
    }

    protected final String issuer;
    protected final JwkHeaderToIssuerContexts contexts;
    protected volatile Set<String> lastKids = Collections.emptySet();

    public JwkHeaderToIssuerContext(String issuer, JwkHeaderToIssuerContexts contexts) {
        this.issuer = issuer;
        this.contexts  = contexts;
    }

    /** Returns the issuer URL this context belongs to. */
    public String getIssuer() {
        return issuer;
    }

    public Set<String> getKids() {
        return lastKids;
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
        lastKids = newKids;
        contexts.setIssuerJwkKids(issuer, newKids);
    }

}