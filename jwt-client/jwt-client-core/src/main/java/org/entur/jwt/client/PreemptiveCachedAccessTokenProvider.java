package org.entur.jwt.client;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Caching {@linkplain AccessTokenProvider} which preemptively attempts to update the cache in the background. 
 * The preemptive updates themselves run on a separate, dedicated thread. Updates 
 * are is not continuously scheduled, but (lazily) triggered by incoming requests for access-tokens. <br><br>
 * 
 * This class is intended for uninterrupted operation in high-load scenarios, as it will avoid
 * a (potentially) large number of threads blocking when the cache expires (and must be refreshed).<br><br>
 * 
 */

public class PreemptiveCachedAccessTokenProvider extends DefaultCachedAccessTokenProvider {

	protected static final Logger logger = LoggerFactory.getLogger(PreemptiveCachedAccessTokenProvider.class);

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
	 * @param provider Access-token provider
	 * @param minimumTimeToLiveUnits minimum time to live (left when returned by {@linkplain #getAccessToken(boolean)}).
	 * @param minimumTimeToLiveUnit minimum time to live unit
	 * @param refreshTimeoutUnits cache refresh timeout
	 * @param refreshTimeoutUnit cache refresh timeout unit
	 * @param preemptiveTimeoutUnits preemptive timeout. This parameter is relative to time to live, i.e. "15 seconds before timeout, refresh time cached value".  
	 * @param preemptiveTimeoutUnit preemptive timeout unit 
	 */

	public PreemptiveCachedAccessTokenProvider(
			AccessTokenProvider provider,
			long minimumTimeToLiveUnits, 
			TimeUnit minimumTimeToLiveUnit, 
			long refreshTimeoutUnits, 
			TimeUnit refreshTimeoutUnit, 
			long preemptiveTimeoutUnits, 
			TimeUnit preemptiveTimeoutUnit) {
		this(
				provider, 
				minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits),
				refreshTimeoutUnit.toMillis(refreshTimeoutUnits), 
				preemptiveTimeoutUnit.toMillis(preemptiveTimeoutUnits),
				Executors.newSingleThreadExecutor()                
				);
	}

	/**
	 * Construct new instance.
	 * 
	 * @param provider Access-token provider
	 * @param minimumTimeToLive minimum time to live (left when returned by {@linkplain #getAccessToken(boolean)}).
	 * @param refreshTimeout cache refresh timeout unit (in milliseconds)
	 * @param preemptiveRefresh preemptive refresh limit (in milliseconds). This parameter is relative to time to live, i.e. "15000 milliseconds before token is invalid, refresh cached value". 
	 */


	public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh) {
		this(provider, minimumTimeToLive, refreshTimeout, preemptiveRefresh, Executors.newSingleThreadExecutor());
	}

	/**
	 * Construct new instance, use a custom executor service.
	 * 
	 * @param provider Access-token provider
	 * @param minimumTimeToLive minimum time to live (left when returned by {@linkplain #getAccessToken(boolean)}).
	 * @param refreshTimeout cache refresh timeout unit (in milliseconds)
	 * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter is relative to time to live, i.e. "15000 milliseconds before timeout, refresh time cached value".
	 * @param executorService executor service 
	 */

	public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, ExecutorService executorService) {
		super(provider, minimumTimeToLive, refreshTimeout);

		if(preemptiveRefresh < minimumTimeToLive) {
			throw new IllegalArgumentException("Minimum time to live must be less than preemptive refresh limit");
		}

		this.preemptiveRefresh = preemptiveRefresh;
		this.executorService = executorService;
	}

	@Override
	public AccessToken getAccessToken(long time, boolean forceUpdate) throws AccessTokenException {
		AccessTokenCacheItem cache = this.cache;
		if(forceUpdate || cache == null || !cache.isValid(time)) {
			return super.getAccessTokenBlocking(time, cache);
		}

		preemptiveUpdate(time, cache);

		return cache.getValue();
	}

	/**
	 * Preemptive update. 
	 * 
	 * @param time current time
	 * @param cache current cache (non-null)
	 */

	protected void preemptiveUpdate(final long time, final AccessTokenCacheItem cache) {
		if(!cache.isValid(time + preemptiveRefresh)) {
			// cache will expires soon, 
			// preemptively update it

			// check if an update is already in progress
			if(cacheExpires < cache.getExpires()) {
				// seems no update is in progress, see if we can get the lock
				if(lazyLock.tryLock()) {
					try {
						// check again now that this thread holds the lock
						if(cacheExpires < cache.getExpires()) {

							// still no update is in progress
							cacheExpires = cache.getExpires();

							// run update in the background
							executorService.execute(() ->  {
								try {
									PreemptiveCachedAccessTokenProvider.super.getAccessTokenBlocking(time, cache);
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

}
