package org.entur.jwt.spring.decode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lookup cache that maps JWT token headers to issuers.
 *
 * <p>Issuers which share a signing key and key id (for example two domains of the same tenant) produce identical
 * headers. A header which is seen with more than one issuer does not identify the issuer, so it is no longer
 * mapped (and never mapped again).
 */
public class JwtHeaderToIssuerMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtHeaderToIssuerMapper.class);

    protected final ConcurrentHashMap<String, String> headerToIssuer = new ConcurrentHashMap<>();

    // headers seen with more than one issuer; these are not mapped
    protected final Set<String> sharedHeaders = ConcurrentHashMap.newKeySet();

    /**
     * Look up the issuer for the given JWT token.
     *
     * <p>Extracts the raw base64url header segment (everything before the first {@code .})
     * and performs a lookup.
     *
     * @param jwtToken the raw JWT token string
     * @return the issuer URL, or {@code null} if not cached
     */
    public String get(String jwtToken) {
        int firstDot = jwtToken.indexOf('.');
        if (firstDot <= 0) {
            return null;
        }
        String rawHeader = jwtToken.substring(0, firstDot);

        return headerToIssuer.get(rawHeader);
    }

    /**
     * Map the header of the given token to the given issuer. If the header is already mapped to another issuer,
     * the header is no longer mapped.
     *
     * @param issuer the issuer the token was verified for
     * @param jwtToken the raw JWT token string
     */
    public void add(String issuer, String jwtToken) {
        int firstDot = jwtToken.indexOf('.');
        if(firstDot == -1) {
            throw new IllegalArgumentException("Expected JWT token on the form a.b.c");
        }
        String rawHeader = jwtToken.substring(0, firstDot);

        if (sharedHeaders.contains(rawHeader)) {
            return;
        }
        // putIfAbsent avoids duplicate log entries under concurrent access (race condition)
        String previousIssuer = headerToIssuer.putIfAbsent(rawHeader, issuer);
        if (previousIssuer == null) {
            if (sharedHeaders.contains(rawHeader)) {
                // seen with another issuer while adding
                headerToIssuer.remove(rawHeader, issuer);
            } else {
                int size = headerToIssuer.size();
                LOGGER.info("New JWT header detected for issuer {}; cache size={}", issuer, size);
            }
        } else if (!previousIssuer.equals(issuer)) {
            // i.e. the issuers share signing key and key id.
            // note: add to the shared headers before removing, so that concurrent adds do not map the header again
            if (sharedHeaders.add(rawHeader)) {
                LOGGER.info("JWT header detected for more than one issuer ({} and {}); no longer mapping this header to an issuer", previousIssuer, issuer);
            }
            headerToIssuer.remove(rawHeader);
        }
    }

    public void clear() {
        headerToIssuer.clear();
        sharedHeaders.clear();
    }

    public Map<String, String> getHeaderToIssuer() {
        return headerToIssuer;
    }

    /**
     * @return headers which have been seen with more than one issuer, i.e. which are not mapped
     */
    public Set<String> getSharedHeaders() {
        return sharedHeaders;
    }

}
