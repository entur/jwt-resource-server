package org.entur.jwt.spring.decode;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lookup cache that maps JWT tokens to issuers.
 *
 */
public class JwtHeaderToIssuerMapper {

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

        String issuer = headerToIssuer.get(rawHeader);
        if (issuer != null) {
            return issuer;
        }
        return null;
    }

    public void add(String issuer, String jwtToken) {
        int firstDot = jwtToken.indexOf('.');
        String rawHeader = jwtToken.substring(0, firstDot);

        headerToIssuer.put(rawHeader, issuer);
    }

    public void clear() {
        headerToIssuer.clear();
    }

    public Map<String, String> getHeaderToIssuer() {
        return headerToIssuer;
    }

}
