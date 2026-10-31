package org.entur.jwt.client.properties;

/** Failed HTTP token-request backoff, independent of the cache configuration. */
public class JwtRetryAfter {

    private long fallbackDelay = 15;

    /** Create backoff configuration with a 15-second fallback. */
    public JwtRetryAfter() {
    }

    /**
     * Read the delay used without a usable Retry-After header.
     * @return fallback delay in seconds
     */
    public long getFallbackDelay() {
        return fallbackDelay;
    }

    /**
     * Configure the delay used without a usable Retry-After header.
     * @param fallbackDelay fallback delay in seconds; zero leaves failures without a usable header ordinary
     */
    public void setFallbackDelay(long fallbackDelay) {
        this.fallbackDelay = fallbackDelay;
    }
}
