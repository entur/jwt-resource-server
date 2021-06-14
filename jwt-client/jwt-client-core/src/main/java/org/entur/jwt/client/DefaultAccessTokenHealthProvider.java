package org.entur.jwt.client;

/**
 * 
 * Lazy implementation of health provider. <br>
 * <br>
 * Returns bad health if<br>
 * - a previous invocation has failed, and a new invocation (by the indicator, from the top level) fails as well. <br>
 * <br>
 * Returns good health if<br>
 * - a previous invocation was successful, or<br>
 * - a previous invocation has failed, but a new invocation (by the the indicator, from the top level) is successful.<br>
 * <br>
 * Calls to this health indicator does not trigger a (remote) refresh if the last call to the
 * underlying provider was successful. 
 */

public class DefaultAccessTokenHealthProvider extends AbstractAccessTokenHealthProvider {

    public DefaultAccessTokenHealthProvider(AccessTokenProvider provider) {
        super(provider);
    }

    @Override
    protected AccessTokenHealth getRefreshHealth() {
        // assuming a successful call to the underlying provider always results
        // in a healthy top-level provider. 
        //
        // If the last call to the underlying provider is not successful
        // get the access-token from the top level provider,
        // so that the cache is refreshed if necessary.
        // 
        // Thus an unhealthy status can turn to a healthy status just by checking the health

        AccessTokenHealth threadSafeStatus = this.providerStatus; // defensive copy
        if (threadSafeStatus == null || !threadSafeStatus.isSuccess()) {
            // get a fresh status
            AccessToken accessToken = null;
            try {
                accessToken = refreshProvider.getAccessToken(false);
            } catch (Exception e) {
                // ignore
                logger.warn("Exception refreshing health status.", e);
            } finally {
                // as long as an access-token was returned, health is good
                threadSafeStatus = new AccessTokenHealth(System.currentTimeMillis(), accessToken != null);
            }
        } else {
            // promote the latest underlying status as the current top-level status
        }
        this.status = threadSafeStatus;
        return threadSafeStatus;
    }
}
