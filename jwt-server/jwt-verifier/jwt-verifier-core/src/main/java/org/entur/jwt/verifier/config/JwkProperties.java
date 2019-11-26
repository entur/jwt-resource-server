package org.entur.jwt.verifier.config;

/** 
 * Configuration of (remote) Json Web Keys client. <br><br>
 * 
 * note: properties should be using dashes, not camelCase. So healthIndicator field is property 'health-indicator' */

public class JwkProperties {

	protected JwkCacheProperties cache = new JwkCacheProperties();

	protected JwkRetryProperties retry = new JwkRetryProperties();

	protected JwkOutageCacheProperties outageCache = new JwkOutageCacheProperties();

	protected JwkRateLimitProperties rateLimit = new JwkRateLimitProperties();

	protected JwkHealthIndicator healthIndicator = new JwkHealthIndicator();

	protected Integer connectTimeout;
	protected Integer readTimeout;

	public Integer getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(Integer connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public Integer getReadTimeout() {
		return readTimeout;
	}

	public void setReadTimeout(Integer readTimeout) {
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
