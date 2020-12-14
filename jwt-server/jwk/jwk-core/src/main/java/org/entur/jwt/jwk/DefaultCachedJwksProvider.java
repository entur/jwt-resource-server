package org.entur.jwt.jwk;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Caching {@linkplain JwksProvider}. Blocks when the cache is updated.
 */

public class DefaultCachedJwksProvider<T> extends AbstractCachedJwksProvider<T> {

    protected final ReentrantLock lock = new ReentrantLock();

    protected final long refreshTimeout;

    /**
     * Construct new instance.
     * 
     * @param provider            Jwk provider
     * @param timeToLive          cache hold time
     * @param refreshTimeout      cache refresh timeout
     */

    public DefaultCachedJwksProvider(JwksProvider<T> provider, Duration timeToLive, Duration refreshTimeout) {
        this(provider, timeToLive.toMillis(), refreshTimeout.toMillis());
    }

    /**
     * Construct new instance.
     * 
     * @param provider       Jwk provider
     * @param timeToLive     cache hold time (in milliseconds)
     * @param refreshTimeout cache refresh timeout unit
     */

    public DefaultCachedJwksProvider(JwksProvider<T> provider, long timeToLive, long refreshTimeout) {
        super(provider, timeToLive);

        this.refreshTimeout = refreshTimeout;
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        return getJwks(System.currentTimeMillis(), forceUpdate);
    }

    protected List<T> getJwks(long time, boolean forceUpdate) throws JwksException {
        JwkListCacheItem<T> cache = this.cache;
        if (forceUpdate || cache == null || !cache.isValid(time)) {
            cache = getJwksBlocking(time, cache);
        }

        return cache.getValue();
    }

    protected JwkListCacheItem<T> getJwksBlocking(long time, JwkListCacheItem<T> cache) throws JwksException {
        // Synchronize so that the first thread to acquire the lock
        // exclusively gets to call the underlying provider.
        // Other (later) threads must wait until the result is ready.
        //
        // If the first to get the lock fails within the waiting interval,
        // subsequent threads will attempt to update the cache themselves.
        //
        // This approach potentially blocks a number of threads,
        // but requesting the same data downstream is not better, so
        // this is a necessary evil.

        try {
            if(lock.tryLock()) {
                try {
                    // see if anyone already refreshed the cache while we were
                    // hold getting the lock
                    if (cache == this.cache) {
                        // Seems cache was not updated.
                        // We hold the lock, so safe to update it now
                        logger.info("Perform JWK cache refresh..");
                        
                        cache = loadJwksFromProvider(time);
                        
                        logger.info("JWK cache refreshed (with {} waiting) ", lock.getQueueLength());
                    } else {
                        // load updated value
                        cache = this.cache;
                        
                        logger.info("JWK cache was previously refreshed");
                    }
                } finally {
                    lock.unlock();
                }
            } else {
                logger.info("Wait for up to {}ms for the JWK cache to be refreshed (with {} already waiting)", refreshTimeout, lock.getQueueLength());
                
                if(lock.tryLock(refreshTimeout, TimeUnit.MILLISECONDS)) {
                    try {
                        // see if anyone already refreshed the cache while we were
                        // hold getting the lock
                        if (cache == this.cache) {
                            // Seems cache was not updated.
                            // We hold the lock, so safe to update it now
                            logger.warn("JWK cache was NOT successfully refreshed while waiting, retry now (with {} waiting)..", lock.getQueueLength());
                                
                            cache = loadJwksFromProvider(time);
                            
                            logger.info("JWK cache refreshed (with {} waiting) ", lock.getQueueLength());
                        } else {
                            // load updated value
                            logger.info("JWK cache was successfully refreshed while waiting");
                            
                            cache = this.cache;
                        }
                    } finally {
                        lock.unlock();
                    }
                } else {
                    throw new JwksUnavailableException("Timeout while waiting for refreshed cache (limit of " + refreshTimeout + "ms exceed).");
                }
            }

            if (cache != null && cache.isValid(time)) {
                return cache;
            }

            throw new JwksUnavailableException("Unable to refresh cache");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore interrupted state to make sonar happy

            throw new JwksUnavailableException("Interrupted while waiting for refreshed cache", e);
        }
    }
    
    /**
     * 
     * Load Jwks from wrapped provider. Guaranteed to only run for one thread at a time.
     * 
     * @param time current time
     * @return
     * @throws JwksException if loading could not be performed
     */

    protected JwkListCacheItem<T> loadJwksFromProvider(long time) throws JwksException {
        List<T> all = provider.getJwks(false);

        // save to cache
        return this.cache = new JwkListCacheItem<>(all, getExpires(time));
    }

    ReentrantLock getLock() {
        return lock;
    }
}
