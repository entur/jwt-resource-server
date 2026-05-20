package org.entur.jwt.spring;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Lookup cache that maps JWT tokens to issuers using a two-tier strategy.
 *
 * <p><strong>Tier 1 – raw header string → issuer</strong>: the base64url-encoded first segment
 * of the JWT (everything before the first {@code .}) is used as a plain string key.  This map
 * is populated lazily as traffic arrives; a hit requires zero parsing.
 *
 * <p><strong>Tier 2 – kid → issuer</strong>: on a tier-1 miss the raw header is decoded and the
 * {@code kid} field is extracted (a header-only Nimbus parse, much cheaper than a full JWT parse).
 * If the kid is found the result is promoted to tier 1 for subsequent requests.
 *
 * <p>Instances are created and updated by {@link JwtKidIssuerCacheFactory}.
 */
public class JwtKidIssuerCache {

    /**
     * Atomic snapshot of the current kid → issuer map (tier 2).  Contains only kids belonging
     * to issuers that have no kid conflicts with any other issuer.  Empty map until all issuers
     * have reported at least one JWK set.
     */
    private final AtomicReference<Map<String, String>> kidToIssuer = new AtomicReference<>(Map.of());

    /**
     * Lazy per-request cache of raw base64url JWT header string → issuer (tier 1).
     * Populated on demand from the kid map; cleared whenever the kid map is updated.
     */
    private final ConcurrentHashMap<String, String> rawHeaderToIssuer = new ConcurrentHashMap<>();

    /**
     * Package-private: instances are created by {@link JwtKidIssuerCacheFactory}.
     */
    JwtKidIssuerCache() {
    }

    /**
     * Look up the issuer for the given JWT token.
     *
     * <p>Extracts the raw base64url header segment (everything before the first {@code .})
     * and performs a tier-1 lookup (no parsing at all).  On miss, decodes the header and
     * extracts the {@code kid} for a tier-2 lookup; a hit also promotes the result to tier 1.
     *
     * @param jwtToken the raw JWT token string
     * @return the issuer URL, or {@code null} if not cached (unknown kid, no kid in header,
     *         or not all issuers have loaded yet)
     */
    public String lookupIssuer(String jwtToken) {
        int firstDot = jwtToken.indexOf('.');
        if (firstDot <= 0) {
            return null;
        }
        String rawHeader = jwtToken.substring(0, firstDot);

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
     * Replaces the tier-2 kid → issuer map and clears the tier-1 raw-header cache.
     * Called by {@link JwtKidIssuerCacheFactory} whenever the JWK sets change.
     */
    void update(Map<String, String> newKidToIssuer) {
        kidToIssuer.set(Map.copyOf(newKidToIssuer));
        rawHeaderToIssuer.clear();
    }

    private static String extractKidFromRawHeader(String rawHeader) {
        try {
            return JWSHeader.parse(new Base64URL(rawHeader)).getKeyID();
        } catch (Exception e) {
            return null;
        }
    }
}
