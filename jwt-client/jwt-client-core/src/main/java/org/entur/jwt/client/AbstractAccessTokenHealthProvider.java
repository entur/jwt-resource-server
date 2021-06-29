package org.entur.jwt.client;

public abstract class AbstractAccessTokenHealthProvider extends BaseAccessTokenProvider {

    /** The state of the below provider */
    protected volatile AccessTokenHealth providerStatus;
    
    /** The state of the top level provider */
    protected volatile AccessTokenHealth status;

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
            this.providerStatus = new AccessTokenHealth(time, accessToken != null);
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

    public void setRefreshProvider(AccessTokenProvider top) {
        this.refreshProvider = top;
    }
    
    @Override
    public boolean supportsHealth() {
        return true;
    }
}
