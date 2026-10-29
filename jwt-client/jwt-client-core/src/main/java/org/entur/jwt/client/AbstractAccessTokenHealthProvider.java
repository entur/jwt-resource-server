package org.entur.jwt.client;

import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractAccessTokenHealthProvider extends BaseAccessTokenProvider {

    /**
     * The latest health, which is either the outcome of the latest invocation of the below
     * provider or the outcome of a later refresh via the top level provider.
     * A new invocation of the below provider supersedes any previously refreshed status.
     */
    private final AtomicReference<AccessTokenHealth> health = new AtomicReference<>();

    private final ThreadLocal<RefreshInvocation> refreshInvocation = new ThreadLocal<>();

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
            AccessTokenHealth invocationHealth = new AccessTokenHealth(time, accessToken != null);
            this.health.set(invocationHealth);
            RefreshInvocation currentRefresh = refreshInvocation.get();
            if (currentRefresh != null) {
                currentRefresh.health = invocationHealth;
            }
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
     * @return current health, to be passed to {@linkplain #publishRefreshedHealth(AccessTokenHealth, AccessTokenHealth)}
     */

    protected AccessTokenHealth getCurrentHealth() {
        return health.get();
    }

    /**
     * Publish the outcome of a refresh via the top-level provider.
     * <br><br>
     * If the underlying provider was not invoked by the refresh (typically the cache served an access-token),
     * the underlying outcome stands. Whether the cached access-token is still usable is determined when
     * the health is read, so that a cache-derived status cannot outlive the access-token.
     * <br><br>
     * If the underlying provider was invoked, its outcome is already the current health. Only a failed refresh
     * is published, i.e. when the top-level provider did not accept what the underlying provider returned.
     * It is published only if the underlying outcome is still current, so that it does not overwrite a newer outcome.
     *
     * @param refreshed outcome of the refresh
     * @param invocationHealth health produced by the refresh's underlying invocation
     */

    protected void publishRefreshedHealth(AccessTokenHealth refreshed, AccessTokenHealth invocationHealth) {
        if (invocationHealth != null && !refreshed.isSuccess()) {
            health.compareAndSet(invocationHealth, refreshed);
        }
    }

    protected RefreshInvocation beginRefreshInvocation() {
        RefreshInvocation invocation = new RefreshInvocation(refreshInvocation.get());
        refreshInvocation.set(invocation);
        return invocation;
    }

    protected AccessTokenHealth endRefreshInvocation(RefreshInvocation invocation) {
        if (refreshInvocation.get() == invocation) {
            if (invocation.parent == null) {
                refreshInvocation.remove();
            } else {
                refreshInvocation.set(invocation.parent);
            }
        }
        return invocation.health;
    }

    protected static class RefreshInvocation {
        private final RefreshInvocation parent;
        private AccessTokenHealth health;

        private RefreshInvocation(RefreshInvocation parent) {
            this.parent = parent;
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
