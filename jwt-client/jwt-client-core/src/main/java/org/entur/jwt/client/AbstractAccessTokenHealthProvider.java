package org.entur.jwt.client;

public abstract class AbstractAccessTokenHealthProvider extends BaseAccessTokenProvider {

    /**
     * The outcome of the latest invocation of the below provider. Refreshing the health via
     * the top level provider only changes this if the below provider is invoked.
     */
    private volatile AccessTokenHealth health;

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
            boolean success = false;
            if (accessToken != null) {
                // note: set before the health, so that readers of good health see this expiry
                this.accessTokenExpires = accessToken.getExpires();

                // the cache rejects an access-token with less than its minimum time to live,
                // in which case the top level provider fails although the below provider did not
                long minimumTimeToLive = this.cacheMinimumTimeToLive;
                success = minimumTimeToLive < 0 || time <= accessToken.getExpires() - minimumTimeToLive;
            }
            this.health = new AccessTokenHealth(time, success);
        }

        return accessToken;
    }

    @Override
    public AccessTokenHealth getHealth(boolean refresh) {
        if(!refresh) {
            // not allowed to refresh, use whatever is available
            AccessTokenHealth current = this.health; // defensive copy
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
     * Set the minimum time to live of the cache above this provider. If set, an access-token
     * which the cache does not accept results in bad health, and a failure to refresh does not
     * result in bad health while the cache still holds a valid access-token.
     *
     * @param minimumTimeToLive minimum time to live in milliseconds
     */

    public void setCacheMinimumTimeToLive(long minimumTimeToLive) {
        this.cacheMinimumTimeToLive = minimumTimeToLive;
    }

    /**
     * Get the outcome of the latest invocation of the below provider.
     *
     * @return current health, or null if the below provider has not been invoked
     */

    protected AccessTokenHealth getCurrentHealth() {
        return health;
    }

    public void setRefreshProvider(AccessTokenProvider top) {
        this.refreshProvider = top;
    }
    
    @Override
    public boolean supportsHealth() {
        return true;
    }
}
