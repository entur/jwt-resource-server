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
        AccessToken accessToken = null;
        RefreshInvocation invocation = beginRefreshInvocation();
        AccessTokenHealth invocationHealth;
        try {
            accessToken = refreshProvider.getAccessToken(false);
        } catch (Exception e) {
            // ignore
            logger.warn("Exception refreshing health status.", e);
        } finally {
            invocationHealth = endRefreshInvocation(invocation);
        }
        // as long as an access-token was returned, health is good
        AccessTokenHealth status = new AccessTokenHealth(System.currentTimeMillis(), accessToken != null);
        publishRefreshedHealth(status, invocationHealth);
        return status;
    }

}
