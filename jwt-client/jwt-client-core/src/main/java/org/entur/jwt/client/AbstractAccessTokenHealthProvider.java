package org.entur.jwt.client;

public abstract class AbstractAccessTokenHealthProvider extends BaseAccessTokenProvider {

    /** The state of the below provider */
    protected volatile AccessTokenHealth providerStatus;
    
    /** The state of the top level provider */
    protected volatile AccessTokenHealth status;

    /** Incremented on every invocation of the underlying provider, guarded by {@linkplain #stateLock} on write */
    private volatile long providerVersion;

    /** Expiry time of the latest access-token returned by the underlying provider */
    protected volatile long lastAccessTokenExpires;

    /** The minimum time to live of the cache above this provider (in milliseconds), or negative if there is no cache */
    protected volatile long cacheMinimumTimeToLive = -1;

    private final Object stateLock = new Object();

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
            AccessTokenHealth health = new AccessTokenHealth(time, accessToken != null);
            synchronized (stateLock) {
                this.providerStatus = health;
                // the latest invocation of the underlying provider supersedes
                // any previously calculated top-level status
                this.status = null;
                this.providerVersion++;
                if (accessToken != null) {
                    this.lastAccessTokenExpires = accessToken.getExpires();
                }
            }
        }

        return accessToken;
    }

    @Override
    public AccessTokenHealth getHealth(boolean refresh) {
        if(!refresh) {
            AccessTokenHealth threadSafeStatus = this.status; // defensive copy
            if(threadSafeStatus != null) {
                return threadSafeStatus;
            }
            // not allowed to refresh
            // use the latest underlying provider status, if available
            AccessTokenHealth threadSafeProviderStatus = this.providerStatus;
            if(threadSafeProviderStatus != null && !threadSafeProviderStatus.isSuccess()) {
                // the latest call to the underlying provider failed (typically a preemptive refresh),
                // but the cache still holds an access-token which it will return
                long time = System.currentTimeMillis();
                if(hasCachedAccessToken(time)) {
                    return new AccessTokenHealth(time, true);
                }
            }
            return threadSafeProviderStatus;
        }

        return getRefreshHealth();
    }

    protected abstract AccessTokenHealth getRefreshHealth();

    private boolean hasCachedAccessToken(long time) {
        long minimumTimeToLive = this.cacheMinimumTimeToLive;
        // a cache serves the latest access-token until minimum time to live is reached
        return minimumTimeToLive >= 0 && time <= lastAccessTokenExpires - minimumTimeToLive;
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
     * Get the current version of the underlying provider state. Read this before
     * inspecting {@linkplain #providerStatus} or invoking the top-level provider.
     *
     * @return version, to be passed to {@linkplain #publishStatus(AccessTokenHealth, long)}
     */

    protected long getProviderVersion() {
        return providerVersion;
    }

    /**
     * Publish a calculated top-level status, unless the underlying provider has been invoked
     * since the given version was read, i.e. the calculated status might be outdated.
     *
     * @param newStatus calculated status
     * @param version   version read before the status was calculated
     */

    protected void publishStatus(AccessTokenHealth newStatus, long version) {
        synchronized (stateLock) {
            if (version == providerVersion) {
                this.status = newStatus;
            }
        }
    }

    public void setRefreshProvider(AccessTokenProvider top) {
        this.refreshProvider = top;
    }
    
    @Override
    public boolean supportsHealth() {
        return true;
    }
}
