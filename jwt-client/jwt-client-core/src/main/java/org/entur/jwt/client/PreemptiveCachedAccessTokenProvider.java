package org.entur.jwt.client;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Caching {@linkplain AccessTokenProvider} which preemptively attempts to
 * update the cache in the background. The preemptive updates themselves run on
 * a separate, dedicated thread. Updates are is not continuously scheduled, but
 * (lazily) triggered by incoming requests for access-tokens. <br>
 * <br>
 * 
 * This class is intended for uninterrupted operation in high-load scenarios, as
 * it will avoid a (potentially) large number of threads blocking when the cache
 * expires (and must be refreshed).<br>
 * <br>
 * 
 */

public class PreemptiveCachedAccessTokenProvider extends DefaultCachedAccessTokenProvider {

    protected static final Logger logger = LoggerFactory.getLogger(PreemptiveCachedAccessTokenProvider.class);

    // preemptive update should execute when
    // expire - preemptiveRefresh < current time < expire.
    private final long preemptiveRefresh; // milliseconds

    private final ReentrantLock lazyLock = new ReentrantLock();

    private final ExecutorService executorService;

    private final ScheduledExecutorService scheduledExecutorService;
    private ScheduledFuture<?> eagerScheduledFuture;

    // cache expire time is used as its fingerprint
    private volatile long cacheExpires;
    
    /**
     * Construct new instance.
     * 
     * @param provider               Access-token provider
     * @param minimumTimeToLiveUnits minimum time to live (left when returned by
     *                               {@linkplain #getAccessToken(boolean)}).
     * @param minimumTimeToLiveUnit  minimum time to live unit
     * @param refreshTimeoutUnits    cache refresh timeout
     * @param refreshTimeoutUnit     cache refresh timeout unit
     * @param preemptiveTimeoutUnits preemptive timeout. This parameter is relative
     *                               to time to live, i.e. "15 seconds before
     *                               timeout, refresh time cached value".
     * @param preemptiveTimeoutUnit  preemptive timeout unit
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLiveUnits, TimeUnit minimumTimeToLiveUnit, long refreshTimeoutUnits, TimeUnit refreshTimeoutUnit, long preemptiveTimeoutUnits,
            TimeUnit preemptiveTimeoutUnit, boolean eager) {
        this(provider, minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits), refreshTimeoutUnit.toMillis(refreshTimeoutUnits), preemptiveTimeoutUnit.toMillis(preemptiveTimeoutUnits), eager, Executors.newSingleThreadExecutor());
    }

    /**
     * Construct new instance.
     * 
     * @param provider          Access-token provider
     * @param minimumTimeToLive minimum time to live (left when returned by
     *                          {@linkplain #getAccessToken(boolean)}).
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive refresh limit (in milliseconds). This
     *                          parameter is relative to time to live, i.e. "15000
     *                          milliseconds before token is invalid, refresh cached
     *                          value".
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, boolean eager) {
        this(provider, minimumTimeToLive, refreshTimeout, preemptiveRefresh, eager, Executors.newSingleThreadExecutor());
    }

    /**
     * Construct new instance, use a custom executor service.
     * 
     * @param provider          Access-token provider
     * @param minimumTimeToLive minimum time to live (left when returned by
     *                          {@linkplain #getAccessToken(boolean)}).
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
     *                          is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     * @param executorService   executor service
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, boolean eager, ExecutorService executorService) {
        super(provider, minimumTimeToLive, refreshTimeout);

        if (preemptiveRefresh < minimumTimeToLive) {
            throw new IllegalArgumentException("Minimum time to live must be less than preemptive refresh limit");
        }

        this.preemptiveRefresh = preemptiveRefresh;
        this.executorService = executorService;
        
        if(eager) {
            scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        } else {
            scheduledExecutorService = null;
        }        
    }

    @Override
    public AccessToken getAccessToken(long time, boolean forceUpdate) throws AccessTokenException {
        AccessTokenCacheItem cache = this.cache;
        if (forceUpdate || cache == null || !cache.isValid(time)) {
            return super.getAccessTokenBlocking(time, cache).getValue();
        }

        preemptiveRefresh(time, cache, false);

        return cache.getValue();
    }

    protected void schedulePreemptiveRefresh(long time, AccessTokenCacheItem cache) {
        if(eagerScheduledFuture != null) {
            eagerScheduledFuture.cancel(false);
        }
        
        // so we want to keep other threads from triggering preemptive refreshing
        // subtracting the refresh timeout should be enough
        
        // note: minimum time to live is already burnt into the expires
        long delay = cache.getExpires() - time - preemptiveRefresh - refreshTimeout + minimumTimeToLive;
        if(delay > 0) {
            this.eagerScheduledFuture = scheduledExecutorService.schedule(() -> {
                try {
                    // so will only refresh if this specific cache entry still is the current one
                    preemptiveRefresh(System.currentTimeMillis(), cache, true);
                } catch (Exception e) {
                    logger.warn("Scheduled eager token refresh failed", e);
                }
            }, delay, TimeUnit.MILLISECONDS);
            
            if(logger.isDebugEnabled()) logger.debug("Scheduled next eager token refresh in " + getTime(delay));
        } else {
            logger.warn("Not Scheduling eager token refresh");
        }
    }    
    
    @Override
    protected AccessTokenCacheItem loadAccessTokenFromProvider(long time) throws AccessTokenException {
        AccessTokenCacheItem item = super.loadAccessTokenFromProvider(time);
        if(scheduledExecutorService != null) {
            schedulePreemptiveRefresh(time, item);
        }
        
        return item;
    }
    
    /**
     * Preemptive update.
     * 
     * @param time  current time
     * @param cache current cache (non-null)
     */

    protected void preemptiveRefresh(final long time, final AccessTokenCacheItem cache, boolean forceRefresh) {
        if (!cache.isValid(time + preemptiveRefresh) || forceRefresh) {
            // cache will expires soon,
            // preemptively update it

            // check if an update is already in progress
            if (cacheExpires < cache.getExpires()) {
                // seems no update is in progress, see if we can get the lock
                if (lazyLock.tryLock()) {
                    try {
                        // check again now that this thread holds the lock
                        if (cacheExpires < cache.getExpires()) {

                            // still no update is in progress
                            cacheExpires = cache.getExpires();

                            // run update in the background
                            executorService.execute(() -> {
                                try {
                                    PreemptiveCachedAccessTokenProvider.super.getAccessTokenBlocking(time, cache);
                                    
                                    // so next time this method is invoked, it'll be with the updated cache item expiry time
                                } catch (AccessTokenException e) {
                                    // update failed, but another thread can retry
                                    cacheExpires = -1L;
                                    // ignore, unable to update
                                    // another thread will attempt the same
                                    logger.warn("Preemptive cache refresh failed", e);
                                }
                            });
                        }
                    } finally {
                        lazyLock.unlock();
                    }
                }
            }
        }
    }

    /**
     * Return the executor service which services the background refresh.
     * 
     * @return executor service
     */

    public ExecutorService getExecutorService() {
        return executorService;
    }

    ReentrantLock getLazyLock() {
        return lazyLock;
    }
    
    protected String getTime(long update) {
        return Duration.ofMillis(update).toString();
    }    

    protected ScheduledFuture<?> getEagerScheduledFuture() {
        return eagerScheduledFuture;
    }
    
    @Override
    public void close() throws IOException {
        ScheduledFuture<?> eagerJwkListCacheItem = this.eagerScheduledFuture; // defensive copy
        if(eagerJwkListCacheItem != null) {
            eagerJwkListCacheItem.cancel(true);
            logger.info("Cancelled scheduled refresh");
        }
        provider.close();
    }    
}
