package org.entur.jwt.spring.issuer;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lookup cache that maps JWT tokens to issuers.
 *
 */
public class JwtHeaderToIssuerMapper {

    protected final ConcurrentHashMap<String, String> headerToIssuer = new ConcurrentHashMap<>();
    protected Set<String> issuers = Collections.emptySet();

    public boolean isEnabled() {
        return !issuers.isEmpty();
    }

    public void setIssuers(Set<String> issuers) {
        this.issuers = issuers;

        // clean up
        // if some old kid for some reason is added while this call is made
        // it is not important.
        headerToIssuer.entrySet().removeIf(entry -> !issuers.contains(entry.getValue()));
    }

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

    public boolean isEnabled(String issuer) {
        return issuers.contains(issuer);
    }

    public void add(String issuer, String jwtToken) {
        int firstDot = jwtToken.indexOf('.');
        String rawHeader = jwtToken.substring(0, firstDot);

        headerToIssuer.put(rawHeader, issuer);
    }

    public void clearIssuer(String issuer) {
        headerToIssuer.entrySet().removeIf(entry -> issuer.equals(entry.getValue()));
    }

}