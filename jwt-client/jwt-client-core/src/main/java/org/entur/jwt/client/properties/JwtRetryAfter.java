package org.entur.jwt.client.properties;

/** Failed HTTP token-request backoff, independent of the cache configuration. */
public class JwtRetryAfter {

    private boolean enabled = true;
    private long fallbackDelay = 15;

    /** Create enabled backoff configuration with a 15-second fallback. */
    public JwtRetryAfter() {
    }

    /**
     * Read the backoff enforcement setting.
     * @return whether server directives and fallback backoff are enforced
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Configure backoff enforcement.
     * @param enabled whether server directives and fallback backoff are enforced
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
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
     * @param fallbackDelay fallback delay in seconds; zero disables only this fallback
     */
    public void setFallbackDelay(long fallbackDelay) {
        this.fallbackDelay = fallbackDelay;
    }
}
