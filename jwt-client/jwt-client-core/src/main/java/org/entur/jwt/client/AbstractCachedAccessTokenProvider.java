package org.entur.jwt.client;

/**
 * Access-token provider that caches previously obtained access-tokens in memory.
 */

public abstract class AbstractCachedAccessTokenProvider extends BaseAccessTokenProvider {

	protected static class AccessTokenCacheItem {

		// must be final so that initialization is safe
		// https://shipilev.net/blog/2014/safe-public-construction/
		private final AccessToken value;
		private final long expires;

		public AccessTokenCacheItem(AccessToken value, long expires) {
			this.value = value;
			this.expires = expires;
		}

		public boolean isValid(long time) {
			return time <= expires;
		}

		public AccessToken getValue() {
			return value;
		}

		public long getExpires() {
			return expires;
		}
	}  

	protected volatile AccessTokenCacheItem cache; 

	public AbstractCachedAccessTokenProvider(AccessTokenProvider provider) {
		super(provider);
	}

	@Override
	public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
		return getAccessToken(System.currentTimeMillis(), forceRefresh);
	}

	abstract AccessToken getAccessToken(long time, boolean forceUpdate) throws AccessTokenException;

	protected AccessToken getCachedAccessToken(long time) {
		AccessTokenCacheItem threadSafeCache = this.cache; // defensive copy
		if(threadSafeCache != null && threadSafeCache.isValid(time)) {
			return threadSafeCache.getValue();
		}
		return null;
	}

	protected AccessTokenCacheItem getCache() {
		return cache;
	}

}
