package org.entur.jwt.jwk;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;

/**
 * JwkProvider builder
 * 
 * @see <a href=
 *      "https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a>
 */

public abstract class AbstractJwksProviderBuilder<T, B extends AbstractJwksProviderBuilder<T, B>> {

    // root provider
    protected final JwksProvider<T> jwksProvider;

    // cache
    protected boolean cached = true;
    protected Duration cacheDuration = Duration.ofHours(1);
    protected Duration cacheRefreshTimeoutDuration = Duration.ofSeconds(15);

    protected boolean preemptiveRefresh = true;
    protected Duration preemptiveRefreshDuration = Duration.ofSeconds(30);

    // rate limiting
    protected boolean rateLimited = true;
    protected long bucketSize = 10;
    protected long refillSize = 1;
    protected Duration refillDuration = Duration.ofMinutes(1);

    // retrying
    protected boolean retrying = false;

    // outage
    protected boolean outageCached = false;
    protected Duration outageCachedDuration = Duration.ofSeconds(cacheDuration.get(ChronoUnit.SECONDS) * 10);

    // health indicator support
    protected boolean health = true;

    /**
     * Wrap a specific {@linkplain JwksProvider}. Access to this instance will be
     * cached and/or rate-limited according to the configuration of this builder.
     *
     * @param jwksProvider root JwksProvider
     */

    public AbstractJwksProviderBuilder(JwksProvider<T> jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    /**
     * Toggle the cache of Jwk. By default the provider will use cache.
     *
     * @param cached if the provider should cache jwks
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B cached(boolean cached) {
        this.cached = cached;
        this.preemptiveRefresh = false;
        return (B) this;
    }

    /**
     * Enable the cache specifying size, expire time and maximum wait time for cache
     * refresh.
     * 
     * @param expires            cache hold time
     * @param refreshExpires     cache refresh timeout
     * @return the builder
     */
    
    @SuppressWarnings("unchecked")
    public B cached(Duration expires, Duration refreshExpires) {
        this.cached = true;
        this.cacheDuration = expires;
        this.cacheRefreshTimeoutDuration = refreshExpires;
        return (B) this;
    }
    
    /**
     * Enable the preemptive cache. This also enables caching.
     *
     * @param duration Preemptive limit, relative to cache time to live, i.e. "15
     *              seconds before timeout, refresh time cached value".
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B preemptiveCacheRefresh(Duration duration) {
        this.cached = true;
        this.preemptiveRefresh = true;
        this.preemptiveRefreshDuration = duration;
        return (B) this;
    }

    /**
     * Enable the preemptive cache. This also enables caching.
     *
     * @param preemptive if true, preemptive caching is active
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B preemptiveCacheRefresh(boolean preemptive) {
        if (preemptive) {
            this.cached = true;
        }
        this.preemptiveRefresh = preemptive;
        return (B) this;
    }

    /**
     * Toggle the rate limit of Jwk. By default the Provider will use rate limit.
     *
     * @param rateLimited if the provider should rate limit jwks
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B rateLimited(boolean rateLimited) {
        this.rateLimited = rateLimited;
        return (B) this;
    }

    /**
     * Enable the cache ratelimiting. Rate-limiting is important to protect
     * downstream authorization servers because unknown keys will cause the list to
     * be reloaded; making it a vector for stressing this and the authorization
     * service.
     * 
     * @param bucketSize max number of jwks to deliver in the given rate.
     * @param refillSize number of jwks to refill
     * @param refillDuration duration between refills 
     * @return the builder
     */

    @SuppressWarnings("unchecked")
    public B rateLimited(long bucketSize, long refillSize, Duration refillDuration) {
        this.rateLimited = true;
        this.bucketSize = bucketSize;
        this.refillSize = refillSize;
        this.refillDuration = refillDuration;
        return (B) this;
    }

    protected JwksProvider<T> build(JwksProvider<T> provider) {
        if (!cached && rateLimited) {
            throw new IllegalStateException("Ratelimiting configured without caching");
        } else if (!cached && preemptiveRefresh) {
            throw new IllegalStateException("Premptive cache refresh configured without caching");
        }

        if (retrying) {
            provider = new RetryingJwksProvider<>(provider);
        }
        if (outageCached) {
            provider = new OutageCachedJwksProvider<>(provider, outageCachedDuration);
        }

        DefaultHealthJwksProvider<T> healthProvider = null;
        if (health) {
            provider = healthProvider = new DefaultHealthJwksProvider<>(provider);
        }

        if (rateLimited) {
            provider = getRateLimitedProvider(provider);
        }
        if (preemptiveRefresh) {
            provider = new PreemptiveCachedJwksProvider<>(provider, cacheDuration, cacheRefreshTimeoutDuration, preemptiveRefreshDuration);
        } else if (cached) {
            provider = new DefaultCachedJwksProvider<>(provider, cacheDuration, cacheRefreshTimeoutDuration);
        }
        if (health) {
            // set the top level on the health provider, for refreshing from the top.
            healthProvider.setRefreshProvider(provider);
        }
        return provider;
    }

    protected JwksProvider<T> getRateLimitedProvider(JwksProvider<T> provider) {
        Refill refill = Refill.greedy(refillSize, refillDuration);

        Bandwidth limit = Bandwidth.classic(bucketSize, refill);

        return new RateLimitedJwksProvider<>(provider, Bucket4j.builder().addLimit(limit).build());
    }

    @SuppressWarnings("unchecked")
    public B retrying(boolean retrying) {
        this.retrying = retrying;

        return (B) this;
    }

    /**
     * Toggle the health status. By default this option is enabled.
     *
     * @param enabled true if the health status provider should be enabled
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B health(boolean enabled) {
        this.health = enabled;
        return (B) this;
    }

    /**
     * Toggle the outage cache. By default the Provider will not use an outage
     * cache.
     *
     * @param outageCached if the outage cache is enabled
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B outageCached(boolean outageCached) {
        this.outageCached = outageCached;
        return (B) this;
    }

    /**
     * Enable the shadow cache specifying size and expire time.
     *
     * @param duration amount of time the jwk will be cached
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B outageCached(Duration duration) {
        this.outageCached = true;
        this.outageCachedDuration = duration;
        return (B) this;
    }

}
