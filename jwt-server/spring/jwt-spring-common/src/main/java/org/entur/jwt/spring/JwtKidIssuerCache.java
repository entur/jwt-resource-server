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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Maintains a live mapping from JWT {@code kid} header values to issuer URLs.
 *
 * <p>For each configured issuer a {@link EventListener} (obtained via {@link #listenerFor(String)})
 * must be registered with that issuer's JWK event bus. Whenever any issuer's JWK set is
 * (re-)loaded the cache recomputes the {@code kid} → issuer mapping.
 *
 * <p>If two issuers share a {@code kid}, that specific kid is excluded from the cache so that
 * lookups for it fall back to full JWT parsing.  Unaffected kids (unique to a single issuer)
 * remain in the cache.
 */
public class JwtKidIssuerCache {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtKidIssuerCache.class);

    private final Set<String> issuers;

    /** Most-recently-seen JWK set per issuer; populated lazily as refresh events arrive. */
    private final ConcurrentHashMap<String, JWKSet> jwkSetByIssuer = new ConcurrentHashMap<>();

    /**
     * Atomic snapshot of the current kid → issuer map.  Contains only kids that are unique to a
     * single issuer.  Kids shared by two or more issuers are absent so callers fall back to full
     * JWT claim parsing.  Empty map until all issuers have reported at least one JWK set.
     */
    private final AtomicReference<Map<String, String>> kidToIssuer = new AtomicReference<>(Map.of());

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
     * @return the issuer URL if the kid is uniquely owned by one issuer, or {@code null} if the
     *         kid is unknown, shared between issuers, or not all issuers have loaded yet.
     */
    public String lookupIssuer(String kid) {
        return kidToIssuer.get().get(kid);
    }

    // ---- internal ----------------------------------------------------------

    private void onJwkSetUpdated(String issuer, JWKSet jwkSet) {
        jwkSetByIssuer.put(issuer, jwkSet);
        recompute();
    }

    private void recompute() {
        if (!jwkSetByIssuer.keySet().containsAll(issuers)) {
            // Not all issuers have loaded yet; keep the cache empty.
            kidToIssuer.set(Map.of());
            return;
        }

        Map<String, String> newMap = new HashMap<>();
        Set<String> conflictingKids = new HashSet<>();

        for (Map.Entry<String, JWKSet> entry : jwkSetByIssuer.entrySet()) {
            String issuer = entry.getKey();
            for (JWK key : entry.getValue().getKeys()) {
                String kid = key.getKeyID();
                if (kid == null || kid.isBlank() || conflictingKids.contains(kid)) {
                    continue;
                }
                String existing = newMap.put(kid, issuer);
                if (existing != null && !existing.equals(issuer)) {
                    // Conflict: remove this kid so both issuers fall back to claim parsing.
                    newMap.remove(kid);
                    conflictingKids.add(kid);
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("kid '{}' is shared between issuers '{}' and '{}'; disabling kid-based lookup for this kid", kid, existing, issuer);
                    }
                }
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("kid-to-issuer cache updated with {} entries ({} conflicting kids excluded)", newMap.size(), conflictingKids.size());
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
