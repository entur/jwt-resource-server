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
 * overhead.
 */
public class JwtDecoderCacheProperties {

    /**
     * Whether the decoded JWT cache is enabled for this tenant. Opt-in, defaults to {@code false}.
     * <p>
     * Requires the (shared, not per-tenant) JWK set cache, i.e. {@code entur.jwt.jwk.cache.enabled=true} (the default):
     * on every cache hit, the keys the JWT was verified with are looked up in the JWK set, so a cached JWT is only
     * used while the JWK set still holds its keys (i.e. key rotation and revocation are detected as soon as the
     * JWK set is refreshed). Without the JWK set cache, this flag is a no-op (a warning is logged).
     *
     * @see JwkCacheProperties#isEnabled()
     * @see org.entur.jwt.spring.decode.cache.DecodedJwtCacheConfigurationReader#getActiveJwtDecoderCacheProperties(org.entur.jwt.spring.properties.JwtProperties)
     */
    private boolean enabled = false;

    /**
     * Target size, i.e. the number of JWTs the cache normally holds at most. With {@code LRU} / {@code FIFO} mode, the
     * cache temporarily exceeds the target size until background eviction has run, and in extreme cases (eviction does
     * not keep up) holds up to double the target size. With {@code FIXED} mode, the cache does not
     * grow beyond the target size (approximately, concurrent additions might overshoot by a few JWTs).
     * -1 for unlimited size (no cap on the number of cached tokens); 0 (like enabled=false) disables the cache.
     */
    private int size = 250;

    /**
     * What to do with new JWTs once the cache holds {@code size} JWTs: evict the least recently used ({@code LRU}, default)
     * or the oldest ({@code FIFO}) JWTs, or stop caching new JWTs until cached JWTs are no longer valid ({@code FIXED}).
     */
    private JwtDecoderCacheMode mode = JwtDecoderCacheMode.LRU;

    /**
     * In seconds, how often to remove expired JWTs from the cache. Default is 60 seconds. Set to -1 to disable cleanup (0 is not allowed).
     */
    private int cleanupInterval = 60;


    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        if (size < -1) {
            throw new IllegalArgumentException("size must be -1 or non-negative");
        }
        this.size = size;
    }

    public JwtDecoderCacheMode getMode() {
        return mode;
    }

    public void setMode(JwtDecoderCacheMode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("mode must not be null");
        }
        this.mode = mode;
    }

    public int getCleanupInterval() {
        return cleanupInterval;
    }

    public void setCleanupInterval(int cleanupIntervalSeconds) {
        if (cleanupIntervalSeconds == 0 || cleanupIntervalSeconds < -1) {
            throw new IllegalArgumentException("cleanupInterval must be -1 (disabled) or positive");
        }
        this.cleanupInterval = cleanupIntervalSeconds;
    }

}
