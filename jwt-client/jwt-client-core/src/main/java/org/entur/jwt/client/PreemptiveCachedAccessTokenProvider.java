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
    private final boolean shutdownExecutorOnClose;
    
    private final ScheduledExecutorService scheduledExecutorService;
    
    /** do not preemptively refresh before this percentage of a token's lifetime has passed */
    private final int refreshConstraintInPercent;
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
     * @param refreshConstraintInPercent constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLiveUnits, TimeUnit minimumTimeToLiveUnit, long refreshTimeoutUnits, TimeUnit refreshTimeoutUnit, long preemptiveTimeoutUnits,
            TimeUnit preemptiveTimeoutUnit, int refreshConstraintInPercent, boolean eager) {
        this(provider, minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits), refreshTimeoutUnit.toMillis(refreshTimeoutUnits), preemptiveTimeoutUnit.toMillis(preemptiveTimeoutUnits), refreshConstraintInPercent, eager, Executors.newSingleThreadExecutor(), true);
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
     * @param refreshConstraintInPercent constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, int refreshConstraintInPercent, boolean eager) {
        this(provider, minimumTimeToLive, refreshTimeout, preemptiveRefresh, refreshConstraintInPercent, eager, Executors.newSingleThreadExecutor(), true);
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
     * @param refreshConstraintInPercent constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     * @param executorService   executor service
     * @param shutdownExecutorOnClose Whether to shutdown the executor service on calls to close(..).
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, int refreshConstraintInPercent, boolean eager, ExecutorService executorService, boolean shutdownExecutorOnClose) {
        super(provider, minimumTimeToLive, refreshTimeout);

        if (preemptiveRefresh < minimumTimeToLive) {
            throw new IllegalArgumentException("Minimum time to live must be less than preemptive refresh limit");
        }

        this.preemptiveRefresh = preemptiveRefresh;
        this.executorService = executorService;
        this.shutdownExecutorOnClose = shutdownExecutorOnClose;
        this.refreshConstraintInPercent = refreshConstraintInPercent;
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
        
        long delay = cache.getRefreshable() - refreshTimeout - time;
        if(delay > 0) {
            this.eagerScheduledFuture = scheduledExecutorService.schedule(() -> {
                try {
                    // so will only refresh if this specific cache entry still is the current one
                    preemptiveRefresh(System.currentTimeMillis(), cache, true);
                } catch (Exception e) {
                    logger.warn("Scheduled eager access-token refresh failed", e);
                }
            }, delay, TimeUnit.MILLISECONDS);
            
            logger.info("Scheduled next eager access-token refresh in " + getTime(delay));
        } else {
            logger.warn("Not scheduling eager access-token refresh");
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
     * @param forceRefresh force refresh
     */

    protected void preemptiveRefresh(final long time, final AccessTokenCacheItem cache, boolean forceRefresh) {
        if (cache.isRefreshable(time) || forceRefresh) {
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
                                    logger.warn("Preemptive access-token refresh failed", e);
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
    
    @Override
    protected AccessTokenCacheItem createCacheItem(long time, AccessToken accessToken) {
        long timeToLive = accessToken.getExpires() - time;
        
        // limit the configured preemptive refresh to a a percent of the actual time to live on the token
        long earliestRefresh = time + ((timeToLive * refreshConstraintInPercent) / 100);
        
        long refreshable = accessToken.getExpires() - preemptiveRefresh;
        if(refreshable < earliestRefresh) { // i.e. too early
            logger.warn("Token time-to-live of " + (timeToLive/1000) + "s (at " + refreshConstraintInPercent + "%) does not support desired preemptive refresh of " + (preemptiveRefresh/1000) + "s");
            refreshable = earliestRefresh;
        }
        
        long expires = accessToken.getExpires() - minimumTimeToLive;
        
        if(refreshable > expires) { // i.e. too late
            refreshable = expires;
        }
        return new AccessTokenCacheItem(accessToken, expires, refreshable);
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
            logger.info("Cancelled scheduled access-token refresh");
        }
        super.close();
        
        if(shutdownExecutorOnClose) {
        	executorService.shutdownNow();
			try {
				executorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				logger.info("Interrupted while waiting for executor shutdown", e);
			}
        }
        if(scheduledExecutorService != null) {
        	scheduledExecutorService.shutdownNow();
			try {
				scheduledExecutorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				logger.info("Interrupted while waiting for scheduled executor shutdown", e);
			}
        }
        
    }
    
    long getRefreshable(long time) {
        AccessTokenCacheItem cache = this.cache;
        if (cache == null) {
            return -1L;
        }
        return cache.getRefreshable() + time;
    }    
}
