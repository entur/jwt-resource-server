package org.entur.jwt.spring.decode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lookup cache that maps JWT token headers to issuers.
 */
public class JwtHeaderToIssuerMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtHeaderToIssuerMapper.class);

    protected final ConcurrentHashMap<String, String> headerToIssuer = new ConcurrentHashMap<>();

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

    public void add(String issuer, String jwtToken) {
        int firstDot = jwtToken.indexOf('.');
        if(firstDot == -1) {
            throw new IllegalArgumentException("Expected JWT token on the form a.b.c");
        }
        String rawHeader = jwtToken.substring(0, firstDot);

        // containsKey check avoids duplicate log entries under concurrent access (race condition)
        if (!headerToIssuer.containsKey(rawHeader)) {
            headerToIssuer.put(rawHeader, issuer);
            int size = headerToIssuer.size();
            LOGGER.info("New JWT header detected for issuer {}; header='{}' cache size={}", issuer, rawHeader, size);
        }
    }

    public void clear() {
        headerToIssuer.clear();
    }

    public Map<String, String> getHeaderToIssuer() {
        return headerToIssuer;
    }

}
