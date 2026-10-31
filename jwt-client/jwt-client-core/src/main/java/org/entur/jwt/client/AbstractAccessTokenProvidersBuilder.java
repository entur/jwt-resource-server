package org.entur.jwt.client;

import java.util.concurrent.TimeUnit;

/**
 * {@linkplain AccessTokenProvider} builder scaffold.
 * 
 * @see <a href=
 *      "https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a>
 */

public abstract class AbstractAccessTokenProvidersBuilder<B extends AbstractAccessTokenProvidersBuilder<B>> {

    // root provider
    protected final AccessTokenProvider accessTokenProvider;

    // cache
    protected boolean cached = true;
    /** minimum time to live, when returned from the cache */
    protected TimeUnit minimumTimeToLiveUnit = TimeUnit.SECONDS;
    protected long minimumTimeToLiveUnits = 15;

    protected TimeUnit refreshExpiresUnit = TimeUnit.SECONDS;
    protected long refreshExpiresIn = 15;

    protected boolean preemptiveRefresh = true;
    protected TimeUnit preemptiveRefreshTimeUnit = TimeUnit.SECONDS;
    protected long preemptiveRefreshTimeUnits = 30;
    protected boolean preemptiveRefreshEager = false;
    protected int preemptiveRefreshConstraint = 25;
    protected long preemptiveErrorCooldown = 15;
    protected TimeUnit preemptiveErrorCooldownUnit = TimeUnit.SECONDS;
    protected long eagerErrorCooldown = 60;
    protected TimeUnit eagerErrorCooldownUnit = TimeUnit.SECONDS;

    // health indicator support
    protected boolean health = true;

    // retrying
    protected boolean retrying = true;

    /** Optional fallback delay in milliseconds. */
    protected Long retryAfterFallbackMillis;

    /**
     * Wrap a specific {@linkplain AccessTokenProvider}. Access to this instance
     * will be cached according to the configuration of this builder.
     *
     * @param accessTokenProvider root accessTokenProvider
     */

    public AbstractAccessTokenProvidersBuilder(AccessTokenProvider accessTokenProvider) {
        this.accessTokenProvider = accessTokenProvider;
    }

    /**
     * Toggle the cache of {@linkplain AccessToken}. By default the provider will
     * use cache.
     *
     * @param cached if the provider should cache access-tokens
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B cached(boolean cached) {
        this.cached = cached;
        if (!cached) {
            this.preemptiveRefresh = false;
        }
        return (B) this;
    }

    /**
     * Toggle the health status of {@linkplain AccessToken}. By default this option
     * is enabled.
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
     * Enable the cache specifying how much time should left on the token when
     * returned (minimal time to live) by the cache and maximum wait (blocking) time
     * for cache refresh.
     * 
     * @param minimumTimeToLiveLeft     minimum time to live units
     * @param minimumTimeToLiveLeftUnit minimum time to live units
     * @param refreshExpiresIn          cache refresh timeout
     * @param refreshExpiresInUnit      cache refresh timeout unit
     * @return the builder
     */

    @SuppressWarnings("unchecked")
    public B cached(long minimumTimeToLiveLeft, TimeUnit minimumTimeToLiveLeftUnit, long refreshExpiresIn, TimeUnit refreshExpiresInUnit) {
        this.cached = true;
        this.minimumTimeToLiveUnits = minimumTimeToLiveLeft;
        this.minimumTimeToLiveUnit = minimumTimeToLiveLeftUnit;
        this.refreshExpiresIn = refreshExpiresIn;
        this.refreshExpiresUnit = refreshExpiresInUnit;
        return (B) this;
    }

    /**
     * Enable the preemptive cache refresh. This also enables caching.
     *
     * @param timeout Preemptive timeout, relative to cache time to live, i.e. "15
     *                seconds before timeout, refresh time cached value".
     * @param unit    unit of preemptive timeout
     * @param constraint constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager   preemptive refresh even if no traffic (schedule update)                         
     * 
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B preemptiveCacheRefresh(long timeout, TimeUnit unit, int constraint, boolean eager) {
        this.cached = true;
        this.preemptiveRefresh = true;
        this.preemptiveRefreshTimeUnits = timeout;
        this.preemptiveRefreshTimeUnit = unit;
        this.preemptiveRefreshEager = eager;
        this.preemptiveRefreshConstraint = constraint;
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
     * Configure the traffic-triggered cooldown after a failed preemptive refresh. Does not delay blocking cache reloads.
     *
     * @param cooldown cooldown duration; zero disables it
     * @param unit cooldown unit
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B preemptiveErrorCooldown(long cooldown, TimeUnit unit) {
        this.preemptiveErrorCooldown = cooldown;
        this.preemptiveErrorCooldownUnit = unit;
        return (B) this;
    }

    /**
     * Configure the eager cooldown after a failed preemptive refresh. Does not delay blocking cache reloads.
     *
     * @param cooldown cooldown duration; scheduled retries wait at least one second
     * @param unit cooldown unit
     * @return the builder
     */
    @SuppressWarnings("unchecked")
    public B eagerErrorCooldown(long cooldown, TimeUnit unit) {
        this.eagerErrorCooldown = cooldown;
        this.eagerErrorCooldownUnit = unit;
        return (B) this;
    }

    /**
     * Configure failed-request backoff for a built-in HTTP provider.
     *
     * @param fallback delay after failure without a usable header; zero leaves such failures ordinary
     * @param unit fallback delay unit
     * @return this builder
     */
    @SuppressWarnings("unchecked")
    public B retryAfter(long fallback, TimeUnit unit) {
        if (fallback < 0) {
            throw new IllegalArgumentException("Retry-After fallback must not be negative");
        }
        this.retryAfterFallbackMillis = unit.toMillis(fallback);
        return (B) this;
    }

    public AccessTokenProvider build() {
        return build(this.accessTokenProvider);
    }

    protected AccessTokenProvider build(AccessTokenProvider provider) {
        if (!cached && preemptiveRefresh) {
            throw new AccessTokenProviderBuilderException("Premptive cache refresh configured without caching");
        }

        AccessTokenProvider root = provider;
        if (retryAfterFallbackMillis != null) {
            if (!(root instanceof AbstractUrlAccessTokenProvider httpProvider)) {
                throw new AccessTokenProviderBuilderException("Retry-After configuration requires a built-in HTTP provider");
            }
            httpProvider.setRetryAfterFallbackMillis(retryAfterFallbackMillis);
        }

        if (root instanceof AbstractUrlAccessTokenProvider) {
            provider = new ExclusiveAccessTokenProvider(provider);
        }
        if (retrying) {
            provider = new RetryingAccessTokenProvider(provider);
        }
        AbstractAccessTokenHealthProvider healthProvider = null;
        if (health) {
            if(preemptiveRefresh && preemptiveRefreshEager) {
                // used simplified health indicator
                provider = healthProvider = new EagerAccessTokenHealthProvider(provider);
            } else {
                provider = healthProvider = new DefaultAccessTokenHealthProvider(provider);
            }
        }
        if (preemptiveRefresh) {
            PreemptiveCachedAccessTokenProvider preemptive = new PreemptiveCachedAccessTokenProvider(provider,
                    minimumTimeToLiveUnits, minimumTimeToLiveUnit, refreshExpiresIn, refreshExpiresUnit, preemptiveRefreshTimeUnits, preemptiveRefreshTimeUnit,
                    preemptiveErrorCooldown, preemptiveErrorCooldownUnit, eagerErrorCooldown, eagerErrorCooldownUnit, preemptiveRefreshConstraint, preemptiveRefreshEager);
            if (root instanceof AbstractUrlAccessTokenProvider httpProvider) {
                preemptive.setRetryAfterDeadline(httpProvider::getRetryAfterDeadlineNanos);
            }
            provider = preemptive;
        } else if (cached) {
            provider = new DefaultCachedAccessTokenProvider(provider, minimumTimeToLiveUnits, minimumTimeToLiveUnit, refreshExpiresIn, refreshExpiresUnit);
        }
        if (healthProvider != null) {
            healthProvider.setRefreshProvider(provider);
            if (cached) {
                healthProvider.setCacheMinimumTimeToLive(minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits));
            }
        }
        return provider;
    }

    @SuppressWarnings("unchecked")
    public B retrying(boolean retrying) {
        this.retrying = retrying;

        return (B) this;
    }

}
