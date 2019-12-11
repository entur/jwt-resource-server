package org.entur.jwt.jwk;

import java.util.List;

/**
 * Jwk provider that caches previously obtained list of Jwk in memory.
 */

public abstract class AbstractCachedJwksProvider<T> extends BaseJwksProvider<T> {

    protected static class JwkListCacheItem<T> {

        // must be final so that initialization is safe
        // https://shipilev.net/blog/2014/safe-public-construction/
        private final List<T> value;
        private final long expires;

        public JwkListCacheItem(List<T> value, long expires) {
            this.value = value;
            this.expires = expires;
        }

        public boolean isValid(long time) {
            return time <= expires;
        }

        public List<T> getValue() {
            return value;
        }

        public long getExpires() {
            return expires;
        }

    }

    protected volatile JwkListCacheItem<T> cache;
    protected final long timeToLive; // milliseconds

    public AbstractCachedJwksProvider(JwksProvider<T> provider, long timeToLive) {
        super(provider);
        this.timeToLive = timeToLive;
    }

    abstract List<T> getJwks(long time, boolean forceUpdate) throws JwksException;

    long getExpires(long time) {
        return time + timeToLive;
    }

    long getTimeToLive() {
        return timeToLive;
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        return getJwks(System.currentTimeMillis(), forceUpdate);
    }

    protected JwkListCacheItem<T> getCache(long time) {
        JwkListCacheItem<T> threadSafeCache = this.cache; // defensive copy
        if (threadSafeCache != null && threadSafeCache.isValid(time)) {
            return threadSafeCache;
        }
        return null;
    }
}
