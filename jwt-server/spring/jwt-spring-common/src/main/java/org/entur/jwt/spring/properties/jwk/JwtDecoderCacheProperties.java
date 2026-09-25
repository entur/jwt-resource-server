package org.entur.jwt.spring.properties.jwk;

/**
 * Configuration for the opt-in, per-issuer decoded JWT cache, which avoids redundant
 * signature verification on hot paths.
 * <p>
 * Intended for services:
 * <ul>
 *     <li>with a relatively limited set of clients,</li>
 *     <li>with a reasonably long JWT time-to-live, and</li>
 *     <li>using CPU-intensive signatures / PKI.</li>
 * </ul>
 * Services outside this profile - e.g. many distinct, short-lived clients/tokens, or
 * already-cheap signature verification such as HMAC - are unlikely to see a meaningful
 * performance benefit from enabling this cache, while still paying for its memory
 * overhead and the added complexity of staying coherent with JWK rotation.
 */
public class JwtDecoderCacheProperties {

    /**
     * Whether the decoded JWT cache is enabled for this tenant. Opt-in, defaults to {@code false}.
     * <p>
     * Turning this on only has effect if all of the following prerequisites are also met
     * at the (shared, not per-tenant) JWK set cache level:
     * <ul>
     *     <li>{@code entur.jwt.jwk.cache.enabled=true}</li>
     *     <li>{@code entur.jwt.jwk.cache.preemptive.enabled=true}</li>
     *     <li>{@code entur.jwt.jwk.cache.preemptive.eager.enabled=true} - defaults to
     *     {@code false} and must be explicitly enabled</li>
     * </ul>
     * Eager preemptive JWK refresh is required because this cache relies entirely on JWKS
     * refresh events to detect key rotation/revocation and evict affected entries; it never
     * re-checks key liveness on its own. Without background refresh, the JWK set (and by
     * extension this cache) would only refresh on demand, i.e. on a JWK cache miss - so a
     * key rotation could go undetected for as long as traffic keeps hitting the JWK cache,
     * defeating cache coherence.
     * <p>
     * If any prerequisite above is not met, this flag is silently a no-op and no decoded JWT
     * cache is created for the tenant.
     *
     * @see JwkCacheProperties#isEnabled()
     * @see JwkPreemptiveCacheProperties#isEnabled()
     * @see JwtEagerRefresh#isEnabled()
     * @see org.entur.jwt.spring.decode.cache.DecodedJwtCacheConfigurationReader#getActiveJwtDecoderCacheProperties(org.entur.jwt.spring.properties.JwtProperties)
     */
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
