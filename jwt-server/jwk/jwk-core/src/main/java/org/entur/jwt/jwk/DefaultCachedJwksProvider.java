package org.entur.jwt.jwk;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
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
     * @param provider Jwk provider
     * @param timeToLiveUnits cache hold time 
     * @param timeToLiveUnit cache hold time unit
     * @param refreshTimeoutUnits cache refresh timeout
     * @param refreshTimeoutUnit cache refresh timeout unit
     */
    
    public DefaultCachedJwksProvider(JwksProvider<T> provider, long timeToLiveUnits, TimeUnit timeToLiveUnit, long refreshTimeoutUnits, TimeUnit refreshTimeoutUnit) {
        this(provider, timeToLiveUnit.toMillis(timeToLiveUnits), refreshTimeoutUnit.toMillis(refreshTimeoutUnits));
    }

    /**
     * Construct new instance.
     * 
     * @param provider Jwk provider
     * @param timeToLive cache hold time (in milliseconds)
     * @param refreshTimeout cache refresh timeout unit
     */

    public DefaultCachedJwksProvider(JwksProvider<T> provider, long timeToLive, long refreshTimeout) {
        super(provider, timeToLive);
        
        this.refreshTimeout = refreshTimeout;
    }

    public List<T> getJwks(boolean forceUpdate) throws JwksException {
    	return getJwks(System.currentTimeMillis(), forceUpdate);
    }
    
    protected List<T> getJwks(long time, boolean forceUpdate) throws JwksException {
        JwkListCacheItem<T> cache = this.cache;
        if(forceUpdate || cache == null || !cache.isValid(time)) {
            return getJwksBlocking(time, cache);
        }
        
        return cache.getValue();
    }

    protected List<T> getJwksBlocking(long time, JwkListCacheItem<T> cache) throws JwksException, JwksUnavailableException {
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
            if(lock.tryLock(refreshTimeout, TimeUnit.MILLISECONDS)) {
                // see if anyone already refreshed the cache while we were 
                // hold getting the lock
                if(cache == this.cache) {
                    // Seems cache was not updated. 
                    // We hold the lock, so safe to update it now
                    try {
                        List<T> all = provider.getJwks(false);
    
                        // save to cache
                        this.cache = cache = new JwkListCacheItem<T>(all, getExpires(time));
                    } finally {
                        lock.unlock();
                    }
                } else {
                    // load updated value
                    cache = this.cache;
                }
            } else {
                throw new JwksUnavailableException("Timeout while waiting for refreshed cache (limit of " + refreshTimeout + "ms exceed).");
            }
            
            if(cache != null && cache.isValid(time)) {
                return cache.getValue();
            }
            
            throw new JwksUnavailableException("Unable to refresh cache");
        } catch (InterruptedException e) {
            throw new JwksUnavailableException("Interrupted while waiting for refreshed cache", e);
        }
    }

    ReentrantLock getLock() {
        return lock;
    }

	@Override
	public CompletionStage<List<T>> getFutureJwks(boolean forceUpdate) {
		return getFutureJwks(forceUpdate, System.currentTimeMillis());
	}

	public CompletionStage<List<T>> getFutureJwks(boolean forceUpdate, long time) {
        JwkListCacheItem<T> cache = this.cache;
        if(forceUpdate || cache == null || !cache.isValid(time)) {
        	// make async execution here TODO
        	
        	// queue jobs, which all check whether updating is still necessary
        	// and if so whether we're still within the deadline.
        	// possible solution: have as many threads as cores, so that then the lock is resolved,
        	// it is full parallel effort to complete the waiting work.
        	
        	CompletionStage<List<T>> stage = provider.getFutureJwks(forceUpdate);

        	return stage.whenComplete((l, ex) -> {
        		if(l != null) {
        			DefaultCachedJwksProvider.this.cache = new JwkListCacheItem<T>(l, getExpires(time));
        		}
        	});
        }
        return CompletableFuture.completedStage(cache.getValue());
	}
}
