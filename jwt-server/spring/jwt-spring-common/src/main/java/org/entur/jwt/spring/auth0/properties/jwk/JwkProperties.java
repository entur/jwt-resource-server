package org.entur.jwt.spring.auth0.properties.jwk;

/**
 * Configuration of (remote) Json Web Keys client. <br>
 * <br>
 * 
 * note: properties should be using dashes, not camelCase. So healthIndicator
 * field is property 'health-indicator'
 */

public class JwkProperties {

    protected JwkCacheProperties cache = new JwkCacheProperties();

    protected JwkRetryProperties retry = new JwkRetryProperties();

    protected JwkOutageCacheProperties outageCache = new JwkOutageCacheProperties();

    protected JwkRateLimitProperties rateLimit = new JwkRateLimitProperties();

    protected JwkHealthIndicator healthIndicator = new JwkHealthIndicator();

    /** HTTP connect timeout, in seconds */
    protected long connectTimeout = 15; // seconds
    
    /** HTTP read timeout, in seconds */
    protected long readTimeout = 15; // seconds

    public long getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(long connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public long getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(long readTimeout) {
        this.readTimeout = readTimeout;
    }

    public JwkCacheProperties getCache() {
        return cache;
    }

    public void setCache(JwkCacheProperties cache) {
        this.cache = cache;
    }

    public JwkOutageCacheProperties getOutageCache() {
        return outageCache;
    }

    public void setOutageCache(JwkOutageCacheProperties outageCache) {
        this.outageCache = outageCache;
    }

    public JwkRateLimitProperties getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(JwkRateLimitProperties rateLimiting) {
        this.rateLimit = rateLimiting;
    }

    public JwkRetryProperties getRetry() {
        return retry;
    }

    public void setRetry(JwkRetryProperties retrying) {
        this.retry = retrying;
    }

    public JwkHealthIndicator getHealthIndicator() {
        return healthIndicator;
    }

    public void setHealthIndicator(JwkHealthIndicator healthIndicator) {
        this.healthIndicator = healthIndicator;
    }

}
