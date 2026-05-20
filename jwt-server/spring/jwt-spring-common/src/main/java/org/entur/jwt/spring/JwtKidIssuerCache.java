package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Maintains a live mapping from JWT {@code kid} header values to issuer URLs.
 *
 * <p>For each configured issuer a {@link EventListener} (obtained via {@link #listenerFor(String)})
 * must be registered with that issuer's {@link com.nimbusds.jose.jwk.source.JWKSource} event bus.
 * Whenever any issuer's JWK set is (re-)loaded the cache recomputes the {@code kid} → issuer
 * mapping.  The fast path is only active once every issuer has reported at least one JWK set
 * <em>and</em> no {@code kid} value is shared between issuers; otherwise {@link #lookupIssuer}
 * returns {@code null} so callers fall back to the regular body-parsing approach.
 */
public class JwtKidIssuerCache {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtKidIssuerCache.class);

    private final Set<String> issuers;

    /** Most-recently-seen JWK set per issuer; populated lazily as refresh events arrive. */
    private final ConcurrentHashMap<String, JWKSet> jwkSetByIssuer = new ConcurrentHashMap<>();

    /**
     * Atomic snapshot of the current kid → issuer map.
     * {@code null} means the fast path is not yet available (not all issuers loaded, or
     * duplicate kids detected).
     */
    private final AtomicReference<Map<String, String>> kidToIssuer = new AtomicReference<>(null);

    public JwtKidIssuerCache(Set<String> issuers) {
        this.issuers = Set.copyOf(issuers);
    }

    /**
     * Returns an {@link EventListener} that forwards JWK-set refresh events for the given issuer
     * into this cache.  Register the returned listener with the issuer's
     * {@link org.entur.jwt.spring.actuate.ListEventListener}.
     */
    public EventListener listenerFor(String issuer) {
        return new IssuerRefreshListener(issuer);
    }

    /**
     * Look up the issuer for a given JWT {@code kid} value.
     *
     * @return the issuer URL, or {@code null} if the fast-path cache is not yet available or the
     *         kid is unknown.
     */
    public String lookupIssuer(String kid) {
        Map<String, String> snapshot = kidToIssuer.get();
        if (snapshot == null) {
            return null;
        }
        return snapshot.get(kid);
    }

    // ---- internal ----------------------------------------------------------

    private void onJwkSetUpdated(String issuer, JWKSet jwkSet) {
        jwkSetByIssuer.put(issuer, jwkSet);
        recompute();
    }

    private void recompute() {
        if (!jwkSetByIssuer.keySet().containsAll(issuers)) {
            // Not all issuers have loaded yet; keep the cache inactive.
            return;
        }

        Map<String, String> newMap = new HashMap<>();
        for (Map.Entry<String, JWKSet> entry : jwkSetByIssuer.entrySet()) {
            String issuer = entry.getKey();
            for (JWK key : entry.getValue().getKeys()) {
                String kid = key.getKeyID();
                if (kid == null || kid.isBlank()) {
                    continue;
                }
                String existing = newMap.putIfAbsent(kid, issuer);
                if (existing != null && !existing.equals(issuer)) {
                    // Duplicate kid across issuers – disable the fast path.
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("kid '{}' is shared between issuers '{}' and '{}'; disabling kid-based issuer lookup", kid, existing, issuer);
                    }
                    kidToIssuer.set(null);
                    return;
                }
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("kid-to-issuer cache updated with {} entries", newMap.size());
        }
        kidToIssuer.set(Map.copyOf(newMap));
    }

    private final class IssuerRefreshListener implements EventListener {

        private final String issuer;

        IssuerRefreshListener(String issuer) {
            this.issuer = issuer;
        }

        @Override
        public void notify(Event event) {
            if (event instanceof CachingJWKSetSource.RefreshCompletedEvent<?> refreshEvent) {
                onJwkSetUpdated(issuer, refreshEvent.getJWKSet());
            } else if (event instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent<?> scheduledEvent) {
                onJwkSetUpdated(issuer, scheduledEvent.getJWKSet());
            }
        }
    }
}
