package org.entur.jwt.spring.decode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lookup cache that maps JWT token headers to issuers.
 *
 * <p>When the number of distinct headers exceeds {@code maxSize} (and {@code maxSize} is
 * not {@code -1}) the optimization is disabled entirely (both {@link #get} and
 * {@link #add} become no-ops) to guard against unexpected entropy in JWT headers.
 */
public class JwtHeaderToIssuerMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtHeaderToIssuerMapper.class);

    protected final ConcurrentHashMap<String, String> headerToIssuer = new ConcurrentHashMap<>();
    protected final int maxSize;
    private boolean disabled = false;

    public JwtHeaderToIssuerMapper() {
        this(100);
    }

    public JwtHeaderToIssuerMapper(int maxSize) {
        this.maxSize = maxSize;
    }

    /**
     * Look up the issuer for the given JWT token.
     *
     * <p>Extracts the raw base64url header segment (everything before the first {@code .})
     * and performs a lookup.
     *
     * @param jwtToken the raw JWT token string
     * @return the issuer URL, or {@code null} if not cached or the optimization is disabled
     */
    public String get(String jwtToken) {
        if (disabled) {
            return null;
        }
        int firstDot = jwtToken.indexOf('.');
        if (firstDot <= 0) {
            return null;
        }
        String rawHeader = jwtToken.substring(0, firstDot);

        return headerToIssuer.get(rawHeader);
    }

    public void add(String issuer, String jwtToken) {
        if (disabled) {
            return;
        }
        int firstDot = jwtToken.indexOf('.');
        if(firstDot == -1) {
            throw new IllegalArgumentException("Expected JWT token on the form a.b.c");
        }
        String rawHeader = jwtToken.substring(0, firstDot);

        if (!headerToIssuer.containsKey(rawHeader)) {
            headerToIssuer.put(rawHeader, issuer);
            int size = headerToIssuer.size();
            LOGGER.info("New JWT header detected for issuer {}; header='{}' cache size={}", issuer, rawHeader, size);
            if (maxSize != -1 && size > maxSize) {
                setDisabled(true);
                LOGGER.warn("JWT header-to-issuer cache exceeded max size of {}; disabling header-to-issuer optimization", maxSize);
            }
        }
    }

    public void clear() {
        headerToIssuer.clear();
    }

    public Map<String, String> getHeaderToIssuer() {
        return headerToIssuer;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

}
