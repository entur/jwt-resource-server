package org.entur.jwt.spring.properties;

/**
 * Optimization for multi-tenant setups. Avoids parsing the whole JWT to extract the issuer.
 *
 * Most effective if JWT headers are semi-static and unique per issuer. Issuers which share a signing key and key id
 * produce identical headers; such headers are no longer mapped once seen with more than one issuer, so tokens with
 * these headers are resolved by their issuer claim (as without this setting).
 *
 * If only one issuer, this setting has no effect.
 */

public class JwtHeaderDecodeMapHeaderToIssuerProperties {

    private boolean enabled;

    /**
     * Maximum number of distinct JWT headers to cache. If this limit is exceeded, the
     * header-to-issuer optimization is disabled entirely to guard against unexpected
     * entropy in the header (e.g. random/dynamic values). Use {@code -1} to disable the
     * limit.
     */
    private int maxSize = 100;

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getMaxSize() {
        return maxSize;
    }

    public void setMaxSize(int maxSize) {
        this.maxSize = maxSize;
    }
}
