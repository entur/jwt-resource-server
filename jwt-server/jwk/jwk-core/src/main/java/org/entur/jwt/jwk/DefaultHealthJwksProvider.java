package org.entur.jwt.jwk;

import java.util.List;

/**
 * 
 * Default 'lazy' implementation of health provider. <br>
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

public class DefaultHealthJwksProvider<T> extends BaseJwksProvider<T> {

	/** The state of the below provider */
    private volatile JwksHealth providerStatus;
    
	/** The state of the top level provider */
    private volatile JwksHealth status;

    /**
     * Provider to invoke when refreshing state. This should be the top level
     * provider, so that caches are actually populated and so on.
     */
    private JwksProvider<T> refreshProvider;

    public DefaultHealthJwksProvider(JwksProvider<T> provider) {
        super(provider);
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        long time = System.currentTimeMillis();

        List<T> list = null;
        try {
            list = provider.getJwks(forceUpdate);
        } finally {
            setStatus(new JwksHealth(time, list != null));
        }

        return list;
    }

    protected void setStatus(JwksHealth status) {
        this.providerStatus = status;
    }

    @Override
    public JwksHealth getHealth(boolean refresh) {
    	if(!refresh) {
    		JwksHealth threadSafeStatus = this.status; // defensive copy
            if(threadSafeStatus != null) {
            	return threadSafeStatus;
            }
            // not allowed to refresh
            // use the latest underlying provider status, if available
    		return providerStatus;
    	}

    	// assuming a successful call to the underlying provider always results
    	// in a healthy top-level provider. 
    	//
    	// If the last call to the underlying provider is not successful
    	// get the JWKs from the top level provider (without forcing a refresh)
    	// so that the cache is refreshed if necessary, so an unhealthy status
    	// can turn to a healthy status just by checking the health

    	JwksHealth threadSafeStatus = this.providerStatus; // defensive copy
        if (threadSafeStatus == null || !threadSafeStatus.isSuccess()) {
            // get a fresh status
        	List<T> accessToken = null;
            try {
                accessToken = refreshProvider.getJwks(false);
            } catch (Exception e) {
                // ignore
                logger.info("Exception refreshing health status.", e);
            } finally {
            	// as long as the JWK list was returned, health is good
                threadSafeStatus = new JwksHealth(System.currentTimeMillis(), accessToken != null);
            }
        } else {
        	// promote the latest underlying status as the current top-level status
        }
        this.status = threadSafeStatus;
        return threadSafeStatus;
    }

    public void setRefreshProvider(JwksProvider<T> top) {
        this.refreshProvider = top;
    }
}
