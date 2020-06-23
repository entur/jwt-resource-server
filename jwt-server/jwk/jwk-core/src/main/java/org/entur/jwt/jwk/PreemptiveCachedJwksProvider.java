package org.entur.jwt.jwk;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

    protected static final Logger logger = LoggerFactory.getLogger(PreemptiveCachedJwksProvider.class);

    // preemptive update should execute when
    // expire - preemptiveRefresh < current time < expire.
    private final long preemptiveRefresh; // milliseconds

    private final ReentrantLock lazyLock = new ReentrantLock();

    private final ExecutorService executorService;

    // cache expire time is used as its fingerprint
    private volatile long cacheExpires;

    /**
     * Construct new instance.
     * 
     * @param provider          Jwk provider
     * @param timeToLive        cache hold time (in milliseconds)
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
     *                          is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     */

    public PreemptiveCachedJwksProvider(JwksProvider<T> provider, Duration timeToLive, Duration refreshTimeout, Duration preemptiveRefresh) {
        this(provider, timeToLive.toMillis(), refreshTimeout.toMillis(), preemptiveRefresh.toMillis(), Executors.newSingleThreadExecutor());
    }

    /**
     * Construct new instance.
     * 
     * @param provider          Jwk provider
     * @param timeToLive        cache hold time (in milliseconds)
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
     *                          is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     */

    public PreemptiveCachedJwksProvider(JwksProvider<T> provider, long timeToLive, long refreshTimeout, long preemptiveRefresh) {
        this(provider, timeToLive, refreshTimeout, preemptiveRefresh, Executors.newSingleThreadExecutor());
    }

    /**
     * Construct new instance, use a custom executor service.
     * 
     * @param provider          Jwk provider
     * @param timeToLive        cache hold time (in milliseconds)
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive refresh limit (in milliseconds). This
     *                          parameter is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     * @param executorService   executor service
     */

    public PreemptiveCachedJwksProvider(JwksProvider<T> provider, long timeToLive, long refreshTimeout, long preemptiveRefresh, ExecutorService executorService) {
        super(provider, timeToLive, refreshTimeout);

        if (preemptiveRefresh > timeToLive) {
            throw new IllegalArgumentException("Time to live must exceed preemptive refresh timeout");
        }

        this.preemptiveRefresh = preemptiveRefresh;
        this.executorService = executorService;
    }

    @Override
    public List<T> getJwks(long time, boolean forceUpdate) throws JwksException {
        JwkListCacheItem<T> cache = this.cache;
        if (forceUpdate || cache == null || !cache.isValid(time)) {
            return super.getJwksBlocking(time, cache);
        }

        preemptiveUpdate(time, cache);

        return cache.getValue();
    }

    /**
     * Preemptive update.
     * 
     * @param time  current time
     * @param cache current cache (non-null)
     */

    protected void preemptiveUpdate(final long time, final JwkListCacheItem<T> cache) {
        if (!cache.isValid(time + preemptiveRefresh)) {
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
                                    logger.info("Perform preemptive cache refresh");
                                    PreemptiveCachedJwksProvider.super.getJwksBlocking(time, cache);
                                } catch (Throwable e) {
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
}
