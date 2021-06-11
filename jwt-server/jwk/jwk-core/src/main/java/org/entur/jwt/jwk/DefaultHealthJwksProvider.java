package org.entur.jwt.jwk;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Default implementation of health provider. <br>
 * <br>
 * Returns bad health if<br>
 * - a previous invocation has failed, and<br>
 * - a new invocation fails as well. <br>
 * <br>
 * Returns good health if<br>
 * - a previous invocation was successful, or<br>
 * - a previous invocation has failed, but a new invocation is successful.<br>
 * 
 */

public class DefaultHealthJwksProvider<T> extends BaseJwksProvider<T> {

    private static final Logger logger = LoggerFactory.getLogger(DefaultHealthJwksProvider.class);

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
        this.status = status;
    }

    @Override
    public JwksHealth getHealth(boolean refresh) {
        JwksHealth threadSafeStatus = this.status; // defensive copy
        if (refresh && (threadSafeStatus == null || !threadSafeStatus.isSuccess())) {
            // get a fresh status
            try {
                refreshProvider.getJwks(false);
            } catch (Exception e) {
                // ignore
                logger.warn("Exception refreshing health status.", e);
            } finally {
                // so was this provider actually invoked?
                // check whether we got a new status
                if (this.status != threadSafeStatus) {
                	// status was updates, keep it
                    threadSafeStatus = this.status;
                } else {
                	// status was not updated. 
                	// 
                    // assume a provider above this instance
                    // was able to compensate somehow, i.e. by using a fallback cache
                    threadSafeStatus = new JwksHealth(System.currentTimeMillis(), true);
                }
            }
        }
        return threadSafeStatus;
    }

    public void setRefreshProvider(JwksProvider<T> top) {
        this.refreshProvider = top;
    }
}
