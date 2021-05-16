package org.entur.jwt.jwk;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
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
 * Caching {@linkplain JwksProvider} which preemptively attempts to update the
 * cache in the background. The preemptive updates themselves run on a separate,
 * dedicated thread. Updates are is not continuously scheduled, but (lazily)
 * triggered by incoming requests for JWKs. <br>
 * <br>
 * 
 * This class is intended for uninterrupted operation in high-load scenarios, as
 * it will avoid a (potentially) large number of threads blocking when the cache
 * expires (and must be refreshed).<br>
 * <br>
 * 
 * @param <T> Jwk type
 */

public class PreemptiveCachedJwksProvider<T> extends DefaultCachedJwksProvider<T> {

    private static final Logger logger = LoggerFactory.getLogger(PreemptiveCachedJwksProvider.class);

    // preemptive update should execute when
    // expire - preemptiveRefresh < current time < expire.
    private final long preemptiveRefresh; // milliseconds

    private final ReentrantLock lazyLock = new ReentrantLock();

    private final ExecutorService executorService;
    private final boolean shutdownExecutorOnClose;

    private final ScheduledExecutorService scheduledExecutorService;
    
    // cache expire time is used as its fingerprint
    private volatile long cacheExpires;
    
    private ScheduledFuture<?> eagerScheduledFuture;
    
    /**
     * Construct new instance.
     * 
     * @param provider          Jwk provider
     * @param timeToLive        cache hold time (in milliseconds)
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds), i.e. before giving up
     * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
     *                          is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     */

    public PreemptiveCachedJwksProvider(JwksProvider<T> provider, Duration timeToLive, Duration refreshTimeout, Duration preemptiveRefresh, boolean eager) {
        this(provider, timeToLive.toMillis(), refreshTimeout.toMillis(), preemptiveRefresh.toMillis(), eager, Executors.newSingleThreadExecutor(), true);
    }

    /**
     * Construct new instance.
     * 
     * @param provider          Jwk provider
     * @param timeToLive        cache hold time (in milliseconds)
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds), i.e. before giving up
     * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
     *                          is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     */

    public PreemptiveCachedJwksProvider(JwksProvider<T> provider, long timeToLive, long refreshTimeout, long preemptiveRefresh, boolean eager) {
        this(provider, timeToLive, refreshTimeout, preemptiveRefresh, eager, Executors.newSingleThreadExecutor(), true);
    }

    /**
     * Construct new instance, use a custom executor service.
     * 
     * @param provider          Jwk provider
     * @param timeToLive        cache hold time (in milliseconds)
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds), i.e. before giving up
     * @param preemptiveRefresh preemptive refresh limit (in milliseconds). This
     *                          parameter is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     * @param executorService   executor service
     * @param shutdownExecutorOnClose Whether to shutdown the executor service on calls to close(..).
     */

    public PreemptiveCachedJwksProvider(JwksProvider<T> provider, long timeToLive, long refreshTimeout, long preemptiveRefresh, boolean eager, ExecutorService executorService, boolean shutdownExecutorOnClose) {
        super(provider, timeToLive, refreshTimeout);

        if (preemptiveRefresh + refreshTimeout > timeToLive) {
            throw new IllegalArgumentException("Time to live (" + timeToLive/1000 + "s) must exceed preemptive refresh limit (" + preemptiveRefresh/1000 + "s) + the refresh timeout (" + refreshTimeout/1000 + "s) (as in the max duration of the refresh operation itself)");
        }

        this.preemptiveRefresh = preemptiveRefresh;
        this.executorService = executorService;
        this.shutdownExecutorOnClose = shutdownExecutorOnClose;

        if(eager) {
            scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        } else {
            scheduledExecutorService = null;
        }
    }

    @Override
    public List<T> getJwks(long time, boolean forceUpdate) throws JwksException {
        JwkListCacheItem<T> cache = this.cache;
        if (forceUpdate || cache == null || !cache.isValid(time)) {
            return super.getJwksBlocking(time, cache).getValue();
        }
        preemptiveRefresh(time, cache, false);

        return cache.getValue();
    }

    @Override
    protected JwkListCacheItem<T> loadJwksFromProvider(long time) throws JwksException {
        // note: never run by two threads at the same time
        JwkListCacheItem<T> cache = super.loadJwksFromProvider(time);
        
        if(scheduledExecutorService != null) {
            schedulePreemptiveRefresh(time, cache);
        }
        
        return cache;
    }
    
    protected void schedulePreemptiveRefresh(long time, JwkListCacheItem<T> cache) {
        if(eagerScheduledFuture != null) {
            eagerScheduledFuture.cancel(false);
        }
        
        // so we want to keep other threads from triggering preemptive refreshing
        // subtracting the refresh timeout should be enough
        long delay = cache.getExpires() - time - preemptiveRefresh - refreshTimeout;
        if(delay > 0) {
            this.eagerScheduledFuture = scheduledExecutorService.schedule(() -> {
                try {
                    // so will only refresh if this specific cache entry still is the current one
                    preemptiveRefresh(System.currentTimeMillis(), cache, true);
                } catch (Exception e) {
                    logger.warn("Scheduled eager JWKs refresh failed", e);
                }
            }, delay, TimeUnit.MILLISECONDS);
            
            logger.info("Scheduled next eager JWKs refresh in " + getTime(delay));
        } else {
            logger.warn("Not scheduling eager JWKs refresh");
        }
    }

    protected String getTime(long update) {
        return Duration.ofMillis(update).toString();
    }

    /**
     * Preemptive update, on a background thread.
     * 
     * @param time  current time
     * @param cache current cache (non-null)
     */

    protected void preemptiveRefresh(final long time, final JwkListCacheItem<T> cache, boolean forceRefresh) {
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
                                    logger.info("Perform preemptive JWKs refresh");
                                    PreemptiveCachedJwksProvider.this.getJwksBlocking(time, cache);
                                    
                                    // so next time this method is invoked, it'll be with the updated cache item expiry time
                                } catch (Throwable e) {
                                    // update failed, but another thread can retry
                                    cacheExpires = -1L;
                                    // ignore, unable to update
                                    // another thread will attempt the same
                                    logger.warn("Preemptive JWKs refresh failed", e);
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
    
    ScheduledFuture<?> getEagerScheduledFuture() {
        return eagerScheduledFuture;
    }

    @Override
    public void close() throws IOException {
        ScheduledFuture<?> eagerJwkListCacheItem = this.eagerScheduledFuture; // defensive copy
        if(eagerJwkListCacheItem != null) {
            eagerJwkListCacheItem.cancel(true);
            logger.info("Cancelled scheduled JWKs refresh");
        }
        
        super.close();
        
        if(shutdownExecutorOnClose) {
        	executorService.shutdownNow();
			try {
				executorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				logger.info("Interrupted while waiting for executor shutdown", e);
				Thread.currentThread().interrupt();
			}
        }
        if(scheduledExecutorService != null) {
        	scheduledExecutorService.shutdownNow();
			try {
				scheduledExecutorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				logger.info("Interrupted while waiting for scheduled executor shutdown", e);
				Thread.currentThread().interrupt();
			}
        }        
    }
}
