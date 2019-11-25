package org.entur.jwt.jwk;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;

/**
 * JwkProvider builder
 * 
 * @see <a href="https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a> 
 */


public class AbstractJwksProviderBuilder<T, B extends AbstractJwksProviderBuilder<T, B>> {

    // root provider
    protected final JwksProvider<T> jwksProvider;

    // cache
    protected boolean cached = true;
    protected TimeUnit expiresUnit = TimeUnit.HOURS;
    protected long expiresIn = 10;
    
    protected TimeUnit refreshExpiresUnit = TimeUnit.SECONDS;
    protected long refreshExpiresIn = 15;
    
    protected boolean preemptiveRefresh = true;
    protected TimeUnit preemptiveRefreshTimeUnit = TimeUnit.SECONDS;
    protected long preemptiveRefreshTimeUnits = 30;
    
    // rate limiting
    protected boolean rateLimited = true;
    protected long bucketSize = 10;
    protected long refillRate = 1;
    protected TimeUnit refilllUnit = TimeUnit.MINUTES;
    
    // retrying
    protected boolean retrying = false;

    // outage
    protected boolean outageCached = false;
    protected long outageCachedExpiresIn = this.expiresIn * 10;
    protected TimeUnit outageCachedExpiresUnit = this.expiresUnit;

    // health indicator support
    protected boolean health = true;

    /**
     * Wrap a specific {@linkplain JwksProvider}. Access to this 
     * instance will be cached and/or rate-limited according to
     * the configuration of this builder.
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
     * Enable the cache specifying size, expire time and maximum wait time for cache refresh.
     * 
     * @param expiresIn cache hold time 
     * @param expiresInUnit cache hold time unit
     * @param refreshExpiresIn cache refresh timeout
     * @param refreshExpiresInUnit cache refresh timeout unit
     * @return the builder
     */    
    
	@SuppressWarnings("unchecked")
    public B cached(long expiresIn, TimeUnit expiresInUnit, long refreshExpiresIn, TimeUnit refreshExpiresInUnit) {
        this.cached = true;
        this.expiresIn = expiresIn;
        this.expiresUnit = expiresInUnit;
        this.refreshExpiresIn = refreshExpiresIn;
        this.refreshExpiresUnit = refreshExpiresInUnit;
        return (B) this;
    }
    
    /**
     * Enable the preemptive cache. This also enables caching.
     *
     * @param units Preemptive limit, relative to cache time to live, i.e. "15 seconds before timeout, refresh time cached value".  
     * @param unit      unit of preemptive limit
     * @return the builder
     */
	@SuppressWarnings("unchecked")
    public B preemptiveCacheRefresh(long units, TimeUnit unit) {
		this.cached = true;
        this.preemptiveRefresh = true;
        this.preemptiveRefreshTimeUnits = units;
        this.preemptiveRefreshTimeUnit = unit;
        return (B) this;
    }    
    
    /**
     * Enable the preemptive cache. This also enables caching.
     *
     * @param preemptive      if true, preemptive caching is active
     * @return the builder
     */
	@SuppressWarnings("unchecked")
    public B preemptiveCacheRefresh(boolean preemptive) {
    	if(preemptive) {
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
    	if(rateLimited) {
    		return rateLimited(10, 1, TimeUnit.MINUTES);
    	} else {
    		this.rateLimited = false;
    	}
    	return (B) this;
    }

    /**
     * Enable the cache ratelimiting. Rate-limiting is important to protect downstream 
     * authorization servers because unknown keys will cause the list to be reloaded; 
     * making it a vector for stressing this and the authorization service.
     * 
     * @param bucketSize max number of jwks to deliver in the given rate.
     * @param refillRate amount of time to wait before a jwk can the jwk will be cached
     * @param unit       unit of time for the expire of jwk
     * @return the builder
     */
    
	@SuppressWarnings("unchecked")
    public B rateLimited(long bucketSize, long refillRate, TimeUnit unit) {
        this.rateLimited = true;
        this.bucketSize = bucketSize;
        this.refillRate = refillRate;
        this.refilllUnit = unit;
    	return (B) this;
    }

	protected JwksProvider<T> build(JwksProvider<T> provider) {
        if(!cached && rateLimited) {
            throw new IllegalStateException("Ratelimiting configured without caching");
        } else if(!cached && preemptiveRefresh) {
            throw new IllegalStateException("Premptive cache refresh configured without caching");
        }
        
		if (retrying) {
            provider = new RetryingJwksProvider<T>(provider);
        }
        if (outageCached) {
            provider = new OutageCachedJwksProvider<T>(provider, outageCachedExpiresIn, outageCachedExpiresUnit);
        }
        
        DefaultHealthJwksProvider<T> healthProvider = null;
        if(health) {
        	provider = healthProvider = new DefaultHealthJwksProvider<>(provider);        	
        }
        
        if (rateLimited) {
            Refill refill = Refill.greedy(refillRate, Duration.ofMillis(refilllUnit.toMillis(refillRate)));
            
            Bandwidth limit = Bandwidth.classic(bucketSize, refill);
        	
            provider = new RateLimitedJwksProvider<T>(provider, Bucket4j.builder().addLimit(limit).build());
        }
        if(preemptiveRefresh) {
            provider = new PreemptiveCachedJwksProvider<T>(provider, expiresIn, expiresUnit, refreshExpiresIn, refreshExpiresUnit, preemptiveRefreshTimeUnits, preemptiveRefreshTimeUnit);
        } else if (cached) {
            provider = new DefaultCachedJwksProvider<T>(provider, expiresIn, expiresUnit, refreshExpiresIn, refreshExpiresUnit);
        }
        if(health) {
        	// set the top level on the health provider, for refreshing from the top.
        	healthProvider.setRefreshProvider(provider);
        }
        return provider;
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
     * Toggle the outage cache. By default the Provider will not use an outage cache.
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
     * @param expiresIn amount of time the jwk will be cached
     * @param unit      unit of time for the expire of jwk
     * @return the builder
     */
	@SuppressWarnings("unchecked")
    public B outageCached(long expiresIn, TimeUnit unit) {
        this.outageCached = true;
        this.outageCachedExpiresIn = expiresIn;
        this.outageCachedExpiresUnit = unit;
        return (B) this;
    }
    
}
