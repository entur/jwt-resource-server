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
 * <p>If two issuers share a {@code kid}, caching is disabled for <em>both</em> of those issuers:
 * none of their kids appear in the cache and lookups for them fall back to full JWT claims
 * parsing.  Unaffected issuers (whose kids are all unique) remain fully cached.
 *
 * <p>Recomputation is skipped when an updated JWK set contains the same set of key IDs as
 * the previously recorded set for that issuer.
 */
public class JwtKidIssuerCache {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtKidIssuerCache.class);

    private final Set<String> issuers;

    /** Most-recently-seen JWK set per issuer; populated lazily as refresh events arrive. */
    private final ConcurrentHashMap<String, JWKSet> jwkSetByIssuer = new ConcurrentHashMap<>();

    /**
     * Atomic snapshot of the current kid → issuer map.  Contains only kids belonging to
     * issuers that have no kid conflicts with any other issuer.  Empty map until all issuers
     * have reported at least one JWK set.
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
     * @return the issuer URL if the kid is uniquely owned by one issuer (and that issuer has no
     *         other conflicting kids), or {@code null} if the kid is unknown, its issuer shares
     *         any kid with another issuer, or not all issuers have loaded yet.
     */
    public String lookupIssuer(String kid) {
        return kidToIssuer.get().get(kid);
    }

    // ---- internal ----------------------------------------------------------

    private void onJwkSetUpdated(String issuer, JWKSet jwkSet) {
        Set<String> newKids = extractKids(jwkSet);

        // Skip recompute if the set of kids for this issuer has not changed.
        JWKSet previous = jwkSetByIssuer.get(issuer);
        if (previous != null && extractKids(previous).equals(newKids)) {
            return;
        }

        jwkSetByIssuer.put(issuer, jwkSet);
        recompute();
    }

    private void recompute() {
        if (!jwkSetByIssuer.keySet().containsAll(issuers)) {
            // Not all issuers have loaded yet; keep the cache empty.
            kidToIssuer.set(Map.of());
            return;
        }

        // Build kid → set-of-issuers index.
        Map<String, Set<String>> kidToIssuers = new HashMap<>();
        for (Map.Entry<String, JWKSet> entry : jwkSetByIssuer.entrySet()) {
            for (String kid : extractKids(entry.getValue())) {
                kidToIssuers.computeIfAbsent(kid, k -> new HashSet<>()).add(entry.getKey());
            }
        }

        // Issuers that share at least one kid with another issuer are fully disabled.
        Set<String> disabledIssuers = new HashSet<>();
        for (Map.Entry<String, Set<String>> entry : kidToIssuers.entrySet()) {
            if (entry.getValue().size() > 1) {
                disabledIssuers.addAll(entry.getValue());
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("kid '{}' is shared between issuers {}; disabling kid-based lookup for all of them",
                            entry.getKey(), entry.getValue());
                }
            }
        }

        // Build the final map, excluding every kid from disabled issuers.
        Map<String, String> newMap = new HashMap<>();
        for (Map.Entry<String, JWKSet> entry : jwkSetByIssuer.entrySet()) {
            String issuer = entry.getKey();
            if (disabledIssuers.contains(issuer)) {
                continue;
            }
            for (String kid : extractKids(entry.getValue())) {
                newMap.put(kid, issuer);
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("kid-to-issuer cache updated with {} entries ({} issuers disabled due to shared kids)",
                    newMap.size(), disabledIssuers.size());
        }
        kidToIssuer.set(Map.copyOf(newMap));
    }

    private static Set<String> extractKids(JWKSet jwkSet) {
        Set<String> kids = new HashSet<>();
        for (JWK key : jwkSet.getKeys()) {
            String kid = key.getKeyID();
            if (kid != null && !kid.isBlank()) {
                kids.add(kid);
            }
        }
        return kids;
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
