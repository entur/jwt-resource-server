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

        AccessTokenHealth threadSafeStatus = getCurrentHealth();
        if (threadSafeStatus == null || !threadSafeStatus.isSuccess()) {
            // get a fresh status
            // note: if the underlying provider is invoked, it records its outcome as the current health
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
        }
        return threadSafeStatus;
    }
}
