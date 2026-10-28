package org.entur.jwt.client;

/**
 * 
 * Eager implementation of health provider. <br>
 * <br>
 * Calls to this health indicator can trigger a (remote) refresh even if the last call to the
 * underlying provider was successful. 
 *  
 */

public class EagerAccessTokenHealthProvider extends AbstractAccessTokenHealthProvider {

    // implementation note: This is a more robust approach than the default implementation uses
    // because we are allowed to refresh the token always.
    
    public EagerAccessTokenHealthProvider(AccessTokenProvider provider) {
        super(provider);
    }

    @Override
    public AccessTokenHealth getHealth(boolean refresh) {
        if (!refresh && this.status == null) {
            // the latest call to the underlying provider failed (typically a scheduled
            // refresh), but as long as the latest access-token is still valid, a
            // valid access-token is available from the cache.
            AccessTokenHealth last = this.providerStatus;
            long time = System.currentTimeMillis();
            if (last != null && !last.isSuccess() && lastAccessTokenExpires > time) {
                return new AccessTokenHealth(time, true);
            }
        }
        return super.getHealth(refresh);
    }

    @Override
    protected AccessTokenHealth getRefreshHealth() {
        long version = getProviderVersion();

        AccessToken accessToken = null;
        try {
            accessToken = refreshProvider.getAccessToken(false);
        } catch (Exception e) {
            // ignore
            logger.warn("Exception refreshing health status.", e);
        }
        // as long as an access-token was returned, health is good
        AccessTokenHealth status = new AccessTokenHealth(System.currentTimeMillis(), accessToken != null);
        publishStatus(status, version);
        return status;
    }

}
