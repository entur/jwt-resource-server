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
    protected AccessTokenHealth getRefreshHealth() {
        long version = getProviderVersion();
        AccessTokenHealth last = this.providerStatus;
        // if the last underlying call failed, a cache hit proves nothing:
        // force a real fetch so that recovery requires an actual success
        boolean force = last != null && !last.isSuccess();

        AccessToken accessToken = null;
        try {
            accessToken = refreshProvider.getAccessToken(force);
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
