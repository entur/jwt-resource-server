package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Builds and maintains a {@link JwtKidIssuerCache} from a collection of
 * {@link IssuerJwkContext} objects.
 *
 * <p>Call {@link #createContext(String)} once per issuer during startup and register
 * the returned context as an event listener with that issuer's JWK event bus.  The
 * factory itself holds no JWK-set state; all per-issuer JWK-set state lives in the
 * contexts.  Whenever a context receives a JWK-set refresh event it calls back into
 * {@link #recompute()}, which reads the current JWK sets from all contexts and updates
 * the cache.
 *
 * <p>If two issuers share a {@code kid}, caching is disabled for <em>both</em> of those
 * issuers: none of their kids appear in the cache and lookups for them fall back to full
 * JWT claims parsing.  Unaffected issuers remain fully cached.
 */
public class JwtKidIssuerCacheFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtKidIssuerCacheFactory.class);

    /** Ordered map of issuer → context; populated during startup via {@link #createContext}. */
    private final Map<String, IssuerJwkContext> contexts = new LinkedHashMap<>();

    private final JwtKidIssuerCache cache = new JwtKidIssuerCache();

    /**
     * Creates and registers a new {@link IssuerJwkContext} for the given issuer.
     * If a context for this issuer already exists the existing instance is returned.
     *
     * <p>Register the returned context as an event listener with the issuer's JWK event bus.
     */
    public IssuerJwkContext createContext(String issuer) {
        return contexts.computeIfAbsent(issuer, i -> new IssuerJwkContext(i, this::recompute));
    }

    /**
     * Returns the {@link JwtKidIssuerCache} maintained by this factory.
     */
    public JwtKidIssuerCache getCache() {
        return cache;
    }

    // ---- internal ----------------------------------------------------------

    void recompute() {
        Collection<IssuerJwkContext> all = contexts.values();

        // Wait until every issuer has delivered its first JWK set.
        for (IssuerJwkContext ctx : all) {
            if (ctx.getCurrentJwkSet() == null) {
                cache.update(Map.of());
                return;
            }
        }

        // Build kid → set-of-issuers index.
        Map<String, Set<String>> kidToIssuers = new HashMap<>();
        for (IssuerJwkContext ctx : all) {
            for (String kid : IssuerJwkContext.extractKids(ctx.getCurrentJwkSet())) {
                kidToIssuers.computeIfAbsent(kid, k -> new HashSet<>()).add(ctx.getIssuer());
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
        for (IssuerJwkContext ctx : all) {
            if (disabledIssuers.contains(ctx.getIssuer())) {
                continue;
            }
            for (String kid : IssuerJwkContext.extractKids(ctx.getCurrentJwkSet())) {
                newMap.put(kid, ctx.getIssuer());
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("kid-to-issuer cache updated with {} entries ({} issuers disabled due to shared kids)",
                    newMap.size(), disabledIssuers.size());
        }
        cache.update(newMap);
    }
}
