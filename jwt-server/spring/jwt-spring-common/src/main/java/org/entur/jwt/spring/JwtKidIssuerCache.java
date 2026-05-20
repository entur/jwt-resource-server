package org.entur.jwt.spring;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
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
 * Maintains a two-tier mapping that routes a JWT token to the correct issuer without a full
 * JWT parse on the hot path.
 *
 * <p><strong>Tier 1 – raw header string → issuer</strong>: the base64url-encoded first segment
 * of the JWT (everything before the first {@code .}) is used as a plain string key.  This map
 * is populated lazily as traffic arrives; a hit requires zero parsing.
 *
 * <p><strong>Tier 2 – kid → issuer</strong>: built from the JWK sets of all configured issuers.
 * When tier 1 misses, the raw header is decoded and the {@code kid} field is extracted (a
 * header-only Nimbus parse, much cheaper than a full JWT parse). If the kid is found the result
 * is promoted to tier 1 for subsequent requests.
 *
 * <p>For each configured issuer an {@link EventListener} (obtained via {@link #listenerFor(String)})
 * must be registered with that issuer's JWK event bus.  Whenever any issuer's JWK set is
 * (re-)loaded the tier-2 map is recomputed and the tier-1 map is cleared.
 *
 * <p>If two issuers share a {@code kid}, caching is disabled for <em>both</em> of those issuers:
 * none of their kids appear in either cache tier and lookups for them fall back to full JWT
 * claims parsing.  Unaffected issuers (whose kids are all unique) remain fully cached.
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
     * Atomic snapshot of the current kid → issuer map (tier 2).  Contains only kids belonging
     * to issuers that have no kid conflicts with any other issuer.  Empty map until all issuers
     * have reported at least one JWK set.
     */
    private final AtomicReference<Map<String, String>> kidToIssuer = new AtomicReference<>(Map.of());

    /**
     * Lazy per-request cache of raw base64url JWT header string → issuer (tier 1).
     * Populated on demand from the kid map; cleared whenever the kid map is recomputed.
     */
    private final ConcurrentHashMap<String, String> rawHeaderToIssuer = new ConcurrentHashMap<>();

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
     * Look up the issuer for the raw base64url-encoded JWT header segment (everything before
     * the first {@code .} in the token string).
     *
     * <p>On the first call for a given header the header is decoded and the {@code kid} value
     * is extracted (tier-2 lookup).  Subsequent calls for the same raw header string return
     * the cached result without any parsing (tier-1 lookup).
     *
     * @return the issuer URL, or {@code null} if the header is unknown, has no {@code kid}, or
     *         all issuers have not yet loaded their JWK sets.
     */
    public String lookupIssuerByRawHeader(String rawHeader) {
        // Tier 1: direct raw header string lookup – no parsing at all.
        String issuer = rawHeaderToIssuer.get(rawHeader);
        if (issuer != null) {
            return issuer;
        }

        // Tier 2: parse header only to extract kid, then look up in the kid map.
        String kid = extractKidFromRawHeader(rawHeader);
        if (kid != null) {
            issuer = kidToIssuer.get().get(kid);
            if (issuer != null) {
                rawHeaderToIssuer.put(rawHeader, issuer);
                return issuer;
            }
        }
        return null;
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
            rawHeaderToIssuer.clear();
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
        // Clear the raw-header tier so stale header→issuer entries are not served after rotation.
        rawHeaderToIssuer.clear();
    }

    private static String extractKidFromRawHeader(String rawHeader) {
        try {
            return JWSHeader.parse(new Base64URL(rawHeader)).getKeyID();
        } catch (Exception e) {
            return null;
        }
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
