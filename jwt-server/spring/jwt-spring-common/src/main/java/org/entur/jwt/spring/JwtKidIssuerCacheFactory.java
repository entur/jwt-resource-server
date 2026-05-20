package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.events.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Creates and maintains a {@link JwtKidIssuerCache}.
 *
 * <p>For each configured issuer register the listener returned by {@link #listenerFor(String)}
 * with that issuer's JWK event bus.  The factory will then keep the cache up to date as JWK
 * sets are loaded or refreshed.
 *
 * <p>If two issuers share a {@code kid}, caching is disabled for <em>both</em> of those issuers:
 * none of their kids appear in the cache and lookups for them fall back to full JWT claims
 * parsing.  Unaffected issuers remain fully cached.
 *
 * <p>Recomputation is skipped when an updated JWK set contains the same set of key IDs as
 * the previously recorded set for that issuer.
 */
public class JwtKidIssuerCacheFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtKidIssuerCacheFactory.class);

    private final Set<String> issuers;

    /** Most-recently-seen JWK set per issuer; populated lazily as refresh events arrive. */
    private final ConcurrentHashMap<String, JWKSet> jwkSetByIssuer = new ConcurrentHashMap<>();

    private final JwtKidIssuerCache cache = new JwtKidIssuerCache();

    public JwtKidIssuerCacheFactory(Set<String> issuers) {
        this.issuers = Set.copyOf(issuers);
    }

    /**
     * Returns the {@link JwtKidIssuerCache} maintained by this factory.
     */
    public JwtKidIssuerCache getCache() {
        return cache;
    }

    /**
     * Returns an {@link EventListener} that forwards JWK-set refresh events for the given issuer
     * into this factory, keeping the cache up to date.
     */
    public EventListener listenerFor(String issuer) {
        return new IssuerRefreshListener(issuer, this::onJwkSetUpdated);
    }

    // ---- internal ----------------------------------------------------------

    public void onJwkSetUpdated(String issuer, JWKSet jwkSet) {
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
            cache.update(Map.of());
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
        cache.update(newMap);
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

}
