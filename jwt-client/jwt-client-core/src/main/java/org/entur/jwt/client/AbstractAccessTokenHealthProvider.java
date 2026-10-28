package org.entur.jwt.client;

import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractAccessTokenHealthProvider extends BaseAccessTokenProvider {

    /**
     * The latest health, which is either the outcome of the latest invocation of the below
     * provider or the outcome of a later refresh via the top level provider.
     * A new invocation of the below provider supersedes any previously refreshed status.
     */
    private final AtomicReference<AccessTokenHealth> health = new AtomicReference<>();

    /** Expiry time of the latest access-token returned by the below provider */
    private volatile long accessTokenExpires;

    /** The minimum time to live of the cache above this provider (in milliseconds), or negative if there is no cache */
    protected volatile long cacheMinimumTimeToLive = -1;

    /**
     * Provider to invoke when refreshing state. This should be the top level
     * provider, so that caches are actually populated and so on.
     */

    protected AccessTokenProvider refreshProvider;

    public AbstractAccessTokenHealthProvider(AccessTokenProvider provider) {
        super(provider);
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        long time = System.currentTimeMillis();

        AccessToken accessToken = null;
        try {
            accessToken = provider.getAccessToken(forceRefresh);
        } finally {
            if (accessToken != null) {
                // note: set before the health, so that readers of good health see this expiry
                this.accessTokenExpires = accessToken.getExpires();
            }
            this.health.set(new AccessTokenHealth(time, accessToken != null));
        }

        return accessToken;
    }

    @Override
    public AccessTokenHealth getHealth(boolean refresh) {
        if(!refresh) {
            // not allowed to refresh, use whatever is available
            AccessTokenHealth current = health.get();
            if(current != null && !current.isSuccess()) {
                // the latest call failed (typically a preemptive refresh),
                // but the cache might still hold an access-token which it will return
                long time = System.currentTimeMillis();
                if(hasCachedAccessToken(time)) {
                    return new AccessTokenHealth(time, true);
                }
            }
            return current;
        }

        return getRefreshHealth();
    }

    protected abstract AccessTokenHealth getRefreshHealth();

    private boolean hasCachedAccessToken(long time) {
        long minimumTimeToLive = this.cacheMinimumTimeToLive;
        // a cache serves the latest access-token until minimum time to live is reached
        return minimumTimeToLive >= 0 && time <= accessTokenExpires - minimumTimeToLive;
    }

    /**
     * Set the minimum time to live of the cache above this provider. If set, a failure
     * to refresh does not result in bad health while the cache still holds a valid access-token.
     *
     * @param minimumTimeToLive minimum time to live in milliseconds
     */

    public void setCacheMinimumTimeToLive(long minimumTimeToLive) {
        this.cacheMinimumTimeToLive = minimumTimeToLive;
    }

    /**
     * Get the current health. Read this before invoking the top-level provider.
     *
     * @return current health, to be passed to {@linkplain #publishHealth(AccessTokenHealth, AccessTokenHealth)}
     */

    protected AccessTokenHealth getCurrentHealth() {
        return health.get();
    }

    /**
     * Publish a calculated health, unless the underlying provider has been invoked
     * since the given health was read, i.e. the calculated health might be outdated.
     *
     * @param newHealth calculated health
     * @param previous  health read before the new health was calculated
     */

    protected void publishHealth(AccessTokenHealth newHealth, AccessTokenHealth previous) {
        health.compareAndSet(previous, newHealth);
    }

    public void setRefreshProvider(AccessTokenProvider top) {
        this.refreshProvider = top;
    }
    
    @Override
    public boolean supportsHealth() {
        return true;
    }
}
