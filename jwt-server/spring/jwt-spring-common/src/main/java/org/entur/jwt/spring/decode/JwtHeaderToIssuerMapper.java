package org.entur.jwt.spring.decode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lookup cache that maps JWT token headers to issuers.
 *
 * <p>If the number of distinct headers exceeds {@code maxSize}, the cache is cleared and
 * the optimization is permanently disabled for the lifetime of this instance.
 */
public class JwtHeaderToIssuerMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtHeaderToIssuerMapper.class);

    protected final ConcurrentHashMap<String, String> headerToIssuer = new ConcurrentHashMap<>();
    protected final int maxSize;
    protected final AtomicBoolean disabled = new AtomicBoolean(false);

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
     * @return the issuer URL, or {@code null} if not cached or optimization is disabled
     */
    public String get(String jwtToken) {
        if (disabled.get()) {
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
        if (disabled.get()) {
            return;
        }
        int firstDot = jwtToken.indexOf('.');
        if(firstDot == -1) {
            throw new IllegalArgumentException("Expected JWT token on the form a.b.c");
        }
        String rawHeader = jwtToken.substring(0, firstDot);

        headerToIssuer.put(rawHeader, issuer);

        int size = headerToIssuer.size();
        if (size > maxSize) {
            LOGGER.warn("JWT header-to-issuer cache exceeded max size of {}; disabling optimization to avoid unbounded memory growth", maxSize);
            headerToIssuer.clear();
            disabled.set(true);
        } else {
            LOGGER.debug("Detected new JWT header (cache size={}, header={})", size, rawHeader);
        }
    }

    public void clear() {
        headerToIssuer.clear();
    }

    public Map<String, String> getHeaderToIssuer() {
        return headerToIssuer;
    }

    public boolean isDisabled() {
        return disabled.get();
    }

}
