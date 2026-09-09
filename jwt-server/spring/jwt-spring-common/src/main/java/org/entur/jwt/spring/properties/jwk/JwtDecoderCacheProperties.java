package org.entur.jwt.spring.properties.jwk;

public class JwtDecoderCacheProperties {

    private boolean enabled = false;

    // -1 for unlimited size (no cap on the number of cached tokens); use enabled=false to disable caching entirely
    private int maxSize = 250;

    /**
     * In seconds, how often to clean up the cache. Default is 60 seconds. Set to -1 to disable cleanup.
     */
    private int cleanupInterval = 60;

    private JwtDecoderCacheOutageProperties outageCache = new JwtDecoderCacheOutageProperties();

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
        if (maxSize < -1) {
            throw new IllegalArgumentException("maxSize must be -1 or non-negative");
        }
        this.maxSize = maxSize;
    }

    public int getCleanupInterval() {
        return cleanupInterval;
    }

    public void setCleanupInterval(int cleanupIntervalSeconds) {
        this.cleanupInterval = cleanupIntervalSeconds;
    }

    public JwtDecoderCacheOutageProperties getOutageCache() {
        return outageCache;
    }

    public void setOutageCache(JwtDecoderCacheOutageProperties outageCache) {
        this.outageCache = outageCache;
    }
}
