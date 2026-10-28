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
            return providerStatus;
        }

        return getRefreshHealth();
    }

    protected abstract AccessTokenHealth getRefreshHealth();

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
