package org.entur.jwt.spring.properties.jwk;

public class JwtDecoderCacheProperties {

    private boolean enabled = false;

    // -1 to disable
    private int maxSize = 250;

    /**
     * In seconds, how often to clean up the cache. Default is 60 seconds. Set to -1 to disable cleanup.
     */
    private int cleanupInterval = 60;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getMaxSize() {
        return maxSize;
    }

    public void setMaxSize(int maxSize) {
        this.maxSize = maxSize;
    }

    public int getCleanupInterval() {
        return cleanupInterval;
    }

    public void setCleanupInterval(int cleanupIntervalSeconds) {
        this.cleanupInterval = cleanupIntervalSeconds;
    }
}
