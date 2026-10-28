package org.entur.jwt.client;

import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractAccessTokenHealthProvider extends BaseAccessTokenProvider {

    /**
     * Immutable snapshot of the health state. All state is replaced atomically,
     * so readers never see a partial update.
     *
     * @param providerStatus      state of the below provider
     * @param status              state of the top level provider, calculated by a refresh. Null if
     *                            superseded by a newer invocation of the below provider.
     * @param accessTokenExpires  expiry time of the latest access-token returned by the below provider
     */
    protected record State(AccessTokenHealth providerStatus, AccessTokenHealth status, long accessTokenExpires) {
    }

    private final AtomicReference<State> state = new AtomicReference<>(new State(null, null, 0));

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
            AccessTokenHealth health = new AccessTokenHealth(time, accessToken != null);
            AccessToken latest = accessToken;
            // the latest invocation of the underlying provider supersedes
            // any previously calculated top-level status
            state.updateAndGet(previous -> new State(health, null, latest != null ? latest.getExpires() : previous.accessTokenExpires()));
        }

        return accessToken;
    }

    @Override
    public AccessTokenHealth getHealth(boolean refresh) {
        if(!refresh) {
            State snapshot = state.get();
            if(snapshot.status() != null) {
                return snapshot.status();
            }
            // not allowed to refresh
            // use the latest underlying provider status, if available
            AccessTokenHealth providerStatus = snapshot.providerStatus();
            if(providerStatus != null && !providerStatus.isSuccess()) {
                // the latest call to the underlying provider failed (typically a preemptive refresh),
                // but the cache still holds an access-token which it will return
                long time = System.currentTimeMillis();
                if(hasCachedAccessToken(snapshot, time)) {
                    return new AccessTokenHealth(time, true);
                }
            }
            return providerStatus;
        }

        return getRefreshHealth();
    }

    protected abstract AccessTokenHealth getRefreshHealth();

    private boolean hasCachedAccessToken(State snapshot, long time) {
        long minimumTimeToLive = this.cacheMinimumTimeToLive;
        // a cache serves the latest access-token until minimum time to live is reached
        return minimumTimeToLive >= 0 && time <= snapshot.accessTokenExpires() - minimumTimeToLive;
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
     * Get the current state. Read this before inspecting the state or invoking the top-level provider.
     *
     * @return snapshot, to be passed to {@linkplain #publishStatus(AccessTokenHealth, State)}
     */

    protected State getState() {
        return state.get();
    }

    /**
     * Publish a calculated top-level status, unless the underlying provider has been invoked
     * since the given snapshot was read, i.e. the calculated status might be outdated.
     *
     * @param newStatus calculated status
     * @param snapshot  state read before the status was calculated
     */

    protected void publishStatus(AccessTokenHealth newStatus, State snapshot) {
        state.compareAndSet(snapshot, new State(snapshot.providerStatus(), newStatus, snapshot.accessTokenExpires()));
    }

    public void setRefreshProvider(AccessTokenProvider top) {
        this.refreshProvider = top;
    }
    
    @Override
    public boolean supportsHealth() {
        return true;
    }
}
