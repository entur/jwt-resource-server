package org.entur.jwt.client;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Caching {@linkplain AccessTokenProvider}. Blocks when the cache is updated.
 */

public class DefaultCachedAccessTokenProvider extends AbstractCachedAccessTokenProvider {

    protected final ReentrantLock lock = new ReentrantLock();
    
    protected final long minimumTimeToLive;
    protected final long refreshTimeout;

    /**
     * Construct new instance.
     * 
     * @param provider Access-token provider
     * @param minimumTimeToLiveUnits minimum time to live (left when returned by {@linkplain #getAccessToken(boolean)}).
     * @param minimumTimeToLiveUnit minimum time to live unit
     * @param refreshTimeoutUnits cache refresh timeout
     * @param refreshTimeoutUnit cache refresh timeout unit
     */
    
    public DefaultCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLiveUnits, TimeUnit minimumTimeToLiveUnit, long refreshTimeoutUnits, TimeUnit refreshTimeoutUnit) {
        this(provider, minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits), refreshTimeoutUnit.toMillis(refreshTimeoutUnits));
    }

    /**
     * Construct new instance.
     * 
     * @param provider Access-token provider
     * @param minimumTimeToLive minimum time to live left when returned by {@linkplain #getAccessToken(boolean)}.
     * @param refreshTimeout cache refresh timeout unit
     */

    public DefaultCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout) {
        super(provider);
        
        this.minimumTimeToLive = minimumTimeToLive;
        this.refreshTimeout = refreshTimeout;
    }

    /**
     * Get cached token. 
     * 
     * @return token, null if cache is not populated
     */

    public AccessToken getCachedAccessToken() {
    	return getCachedAccessToken(System.currentTimeMillis());
    }

    protected AccessToken getAccessToken(long time, boolean forceUpdate) throws AccessTokenException{
    	AccessTokenCacheItem cache = this.cache;
        if(forceUpdate || cache == null || !cache.isValid(time)) {
            return getAccessTokenBlocking(time, cache);
        }
        
        return cache.getValue();
    }

    protected AccessToken getAccessTokenBlocking(long time, AccessTokenCacheItem cache) throws AccessTokenException {
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
                        // get and save to cache
                    	AccessToken accessToken = provider.getAccessToken(false);
                    	
                    	// reduce cache expiry according to the minimum time to live
                    	this.cache = cache = new AccessTokenCacheItem(accessToken, accessToken.getExpires() - minimumTimeToLive);
                    } finally {
                        lock.unlock();
                    }
                } else {
                    // load updated value
                    cache = this.cache;
                    
                }
            } else {
                throw new AccessTokenUnavailableException("Timeout while waiting for refreshed cache (limit of " + refreshTimeout + "ms exceed).");
            }
            
            if(cache != null && cache.isValid(time)) {
                return cache.getValue();
            }
            
            throw new AccessTokenUnavailableException("Unable to refresh cache");
        } catch (InterruptedException e) {
            throw new AccessTokenUnavailableException("Interrupted while waiting for refreshed cache", e);
        }
    }

    ReentrantLock getLock() {
        return lock;
    }

	@Override
	public void close() throws IOException {
		provider.close();
	}

    long getExpires(long time) {
    	AccessTokenCacheItem cache = this.cache; 
    	if(cache == null) {
    		return -1L;
    	}
        return cache.getExpires() + time;
    }
    
    public long getMinimumTimeToLive() {
		return minimumTimeToLive;
	}
    
    public long getRefreshTimeout() {
		return refreshTimeout;
	}
}
