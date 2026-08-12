package org.entur.jwt.spring.properties;

/**
 * Optimization for multi-tenant setups. Avoids parsing the whole JWT to extract the issuer.
 *
 * Enable if JWT headers are known to be unique and semi-static per issuer.
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
