package org.entur.jwt.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 
 * Caching {@linkplain AccessTokenProvider} which preemptively attempts to
 * update the cache in the background. The preemptive updates themselves run on
 * a separate, dedicated thread. Updates are is not continuously scheduled, but
 * (lazily) triggered by incoming requests for access-tokens. <br>
 * <br>
 * 
 * This class is intended for uninterrupted operation in high-load scenarios, as
 * it will avoid a (potentially) large number of threads blocking when the cache
 * expires (and must be refreshed).<br>
 * <br>
 * 
 */

public class PreemptiveCachedAccessTokenProvider extends DefaultCachedAccessTokenProvider {

    protected static final Logger LOGGER = LoggerFactory.getLogger(PreemptiveCachedAccessTokenProvider.class);

    private static final long DEFAULT_PREEMPTIVE_ERROR_COOLDOWN = 15_000L;
    private static final long DEFAULT_EAGER_ERROR_COOLDOWN = 60_000L;

    // preemptive update should execute when
    // expire - preemptiveRefresh < current time < expire.
    private final long preemptiveRefresh; // milliseconds
    private final long preemptiveErrorCooldown; // milliseconds
    private final long eagerErrorCooldown; // milliseconds
    private volatile Long lastPreemptiveFailureNanos;

    private final ReentrantLock lazyLock = new ReentrantLock();

    private final ExecutorService executorService;
    private final boolean shutdownExecutorOnClose;
    
    private final ScheduledExecutorService scheduledExecutorService;
    
    /** do not preemptively refresh before this percentage of a token's lifetime has passed */
    private final int refreshConstraintInPercent;
    private ScheduledFuture<?> eagerScheduledFuture;
    private volatile boolean closed;
    

    private final AtomicReference<AccessTokenCacheItem> refreshingCache = new AtomicReference<>();
    
    /**
     * Construct new instance.
     * 
     * @param provider               Access-token provider
     * @param minimumTimeToLiveUnits minimum time to live (left when returned by
     *                               {@linkplain #getAccessToken(boolean)}).
     * @param minimumTimeToLiveUnit  minimum time to live unit
     * @param refreshTimeoutUnits    cache refresh timeout
     * @param refreshTimeoutUnit     cache refresh timeout unit
     * @param preemptiveTimeoutUnits preemptive timeout. This parameter is relative
     *                               to time to live, i.e. "15 seconds before
     *                               timeout, refresh time cached value".
     * @param preemptiveTimeoutUnit  preemptive timeout unit
     * @param refreshConstraintInPercent constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLiveUnits, TimeUnit minimumTimeToLiveUnit, long refreshTimeoutUnits, TimeUnit refreshTimeoutUnit, long preemptiveTimeoutUnits,
            TimeUnit preemptiveTimeoutUnit, int refreshConstraintInPercent, boolean eager) {
        this(provider, minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits), refreshTimeoutUnit.toMillis(refreshTimeoutUnits), preemptiveTimeoutUnit.toMillis(preemptiveTimeoutUnits), refreshConstraintInPercent, eager, Executors.newSingleThreadExecutor(), true);
    }

    /**
     * Construct with independent traffic-triggered and eager error cooldowns.
     *
     * @param provider                     access-token provider
     * @param minimumTimeToLiveUnits       minimum remaining token lifetime
     * @param minimumTimeToLiveUnit        minimum lifetime unit
     * @param refreshTimeoutUnits          cache refresh timeout
     * @param refreshTimeoutUnit           cache refresh timeout unit
     * @param preemptiveTimeoutUnits       time before expiry to refresh
     * @param preemptiveTimeoutUnit        preemptive refresh unit
     * @param preemptiveErrorCooldownUnits traffic-triggered cooldown after failure;
     *                                     zero disables it
     * @param preemptiveErrorCooldownUnit  traffic-triggered cooldown unit
     * @param eagerErrorCooldownUnits      eager cooldown after failure; retries
     *                                     still wait at least one second
     * @param eagerErrorCooldownUnit       eager cooldown unit
     * @param refreshConstraintInPercent   earliest refresh as a percentage of token
     *                                     lifetime
     * @param eager                        refresh without incoming traffic
     */
    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLiveUnits, TimeUnit minimumTimeToLiveUnit, long refreshTimeoutUnits, TimeUnit refreshTimeoutUnit, long preemptiveTimeoutUnits,
            TimeUnit preemptiveTimeoutUnit, long preemptiveErrorCooldownUnits, TimeUnit preemptiveErrorCooldownUnit, long eagerErrorCooldownUnits, TimeUnit eagerErrorCooldownUnit, int refreshConstraintInPercent, boolean eager) {
        this(provider, minimumTimeToLiveUnit.toMillis(minimumTimeToLiveUnits), refreshTimeoutUnit.toMillis(refreshTimeoutUnits), preemptiveTimeoutUnit.toMillis(preemptiveTimeoutUnits),
                preemptiveErrorCooldownUnit.toMillis(preemptiveErrorCooldownUnits), eagerErrorCooldownUnit.toMillis(eagerErrorCooldownUnits), refreshConstraintInPercent, eager);
    }

    /**
     * Construct new instance.
     * 
     * @param provider          Access-token provider
     * @param minimumTimeToLive minimum time to live (left when returned by
     *                          {@linkplain #getAccessToken(boolean)}).
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive refresh limit (in milliseconds). This
     *                          parameter is relative to time to live, i.e. "15000
     *                          milliseconds before token is invalid, refresh cached
     *                          value".
     * @param refreshConstraintInPercent constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, int refreshConstraintInPercent, boolean eager) {
        this(provider, minimumTimeToLive, refreshTimeout, preemptiveRefresh, refreshConstraintInPercent, eager, Executors.newSingleThreadExecutor(), true);
    }

    /**
     * Construct with independent traffic-triggered and eager error cooldowns.
     *
     * @param provider                   access-token provider
     * @param minimumTimeToLive          minimum remaining token lifetime in
     *                                   milliseconds
     * @param refreshTimeout             cache refresh timeout in milliseconds
     * @param preemptiveRefresh          time before expiry to refresh, in
     *                                   milliseconds
     * @param preemptiveErrorCooldown    traffic-triggered cooldown after failure
     *                                   in milliseconds; zero disables it
     * @param eagerErrorCooldown         eager cooldown after failure in
     *                                   milliseconds; retries wait at least one second
     * @param refreshConstraintInPercent earliest refresh as a percentage of token
     *                                   lifetime
     * @param eager                      refresh without incoming traffic
     */
    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, long preemptiveErrorCooldown, long eagerErrorCooldown, int refreshConstraintInPercent, boolean eager) {
        this(provider, minimumTimeToLive, refreshTimeout, preemptiveRefresh, preemptiveErrorCooldown, eagerErrorCooldown, refreshConstraintInPercent, eager, Executors.newSingleThreadExecutor(), true);
    }

    /**
     * Construct new instance, use a custom executor service.
     * 
     * @param provider          Access-token provider
     * @param minimumTimeToLive minimum time to live (left when returned by
     *                          {@linkplain #getAccessToken(boolean)}).
     * @param refreshTimeout    cache refresh timeout unit (in milliseconds)
     * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
     *                          is relative to time to live, i.e. "15000
     *                          milliseconds before timeout, refresh time cached
     *                          value".
     * @param refreshConstraintInPercent constraint in percent, of a token's lifetime, before any preemptive refresh happens
     * @param eager             preemptive refresh even if no traffic (schedule update)                         
     * @param executorService   executor service
     * @param shutdownExecutorOnClose Whether to shutdown the executor service on calls to close(..).
     */

    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, int refreshConstraintInPercent, boolean eager, ExecutorService executorService, boolean shutdownExecutorOnClose) {
        this(provider, minimumTimeToLive, refreshTimeout, preemptiveRefresh, DEFAULT_PREEMPTIVE_ERROR_COOLDOWN, DEFAULT_EAGER_ERROR_COOLDOWN, refreshConstraintInPercent, eager, executorService, shutdownExecutorOnClose);
    }

    /**
     * Construct with a custom executor and independent traffic-triggered and eager
     * error cooldowns.
     *
     * @param provider                   access-token provider
     * @param minimumTimeToLive          minimum remaining token lifetime in
     *                                   milliseconds
     * @param refreshTimeout             cache refresh timeout in milliseconds
     * @param preemptiveRefresh          time before expiry to refresh, in
     *                                   milliseconds
     * @param preemptiveErrorCooldown    traffic-triggered cooldown after failure
     *                                   in milliseconds; zero disables it
     * @param eagerErrorCooldown         eager cooldown after failure in
     *                                   milliseconds; retries wait at least one second
     * @param refreshConstraintInPercent earliest refresh as a percentage of token
     *                                   lifetime
     * @param eager                      refresh without incoming traffic
     * @param executorService            background refresh executor
     * @param shutdownExecutorOnClose    whether to shut down the executor on close
     */
    public PreemptiveCachedAccessTokenProvider(AccessTokenProvider provider, long minimumTimeToLive, long refreshTimeout, long preemptiveRefresh, long preemptiveErrorCooldown, long eagerErrorCooldown, int refreshConstraintInPercent, boolean eager,
            ExecutorService executorService, boolean shutdownExecutorOnClose) {
        super(provider, minimumTimeToLive, refreshTimeout);

        if (preemptiveRefresh < minimumTimeToLive) {
            throw new IllegalArgumentException("Minimum time to live must be less than preemptive refresh limit");
        }
        if (preemptiveErrorCooldown < 0) {
            throw new IllegalArgumentException("Preemptive error cooldown must not be negative");
        }
        if (eagerErrorCooldown < 0) {
            throw new IllegalArgumentException("Eager error cooldown must not be negative");
        }

        this.preemptiveRefresh = preemptiveRefresh;
        this.preemptiveErrorCooldown = preemptiveErrorCooldown;
        this.eagerErrorCooldown = eagerErrorCooldown;
        this.executorService = executorService;
        this.shutdownExecutorOnClose = shutdownExecutorOnClose;
        this.refreshConstraintInPercent = refreshConstraintInPercent;
        if(eager) {
            scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        } else {
            scheduledExecutorService = null;
        }        
    }

    @Override
    public AccessToken getAccessToken(long time, boolean forceUpdate) throws AccessTokenException {
        AccessTokenCacheItem cache = this.cache;
        if (forceUpdate || cache == null || !cache.isValid(time)) {
            return super.getAccessTokenBlocking(time, cache).getValue();
        }

        preemptiveRefresh(time, cache, false);

        return cache.getValue();
    }

    protected void schedulePreemptiveRefresh(long time, AccessTokenCacheItem cache) {
        if (!cache.isValid(time)) {
            schedulePreemptiveRefresh(cache, Math.max(eagerErrorCooldown, 1000L));
            return;
        }
        // Start before the refresh window to avoid competing with request-triggered
        // refreshes.
        long delay = cache.getRefreshable() - refreshTimeout - time;
        if (delay <= 0) {
            // Retry before cache expiry when possible, without a tight loop.
            delay = Math.max(1000L, (cache.getExpires() - time) / 2);
        }
        schedulePreemptiveRefresh(cache, delay);
    }

    private synchronized void schedulePreemptiveRefresh(AccessTokenCacheItem cache, long delay) {
        if (closed || this.cache != cache) {
            return;
        }
        if(eagerScheduledFuture != null) {
            eagerScheduledFuture.cancel(false);
        }
        
        this.eagerScheduledFuture = scheduleEagerRefresh(() -> {
            try {
                // so will only refresh if this specific cache entry still is the current one
                preemptiveRefresh(currentTimeMillis(), cache, true);
            } catch (Exception e) {
                LOGGER.warn("Scheduled eager access-token refresh failed", e);
            }
        }, delay);

        if(LOGGER.isDebugEnabled()) LOGGER.debug("Scheduled next eager access-token refresh in " + getTime(delay));
    }    

    protected ScheduledFuture<?> scheduleEagerRefresh(Runnable refresh, long delay) {
        return scheduledExecutorService.schedule(refresh, delay, TimeUnit.MILLISECONDS);
    }
    
    @Override
    protected AccessTokenCacheItem loadAccessTokenFromProvider(long time) throws AccessTokenException {
        AccessTokenCacheItem item = super.loadAccessTokenFromProvider(time);
        if(scheduledExecutorService != null) {
            schedulePreemptiveRefresh(currentTimeMillis(), item);
        }
        
        return item;
    }
    
    /**
     * Preemptive update.
     * 
     * @param time  current time
     * @param cache current cache (non-null)
     * @param forceRefresh force refresh
     */

    protected void preemptiveRefresh(final long time, final AccessTokenCacheItem cache, boolean forceRefresh) {
        if (closed) {
            return;
        }
        if(!cache.isRefreshable(time) && !forceRefresh){
            // cache will not expire soon,
            // no need to preemptively update.
            return;
        }
        if (this.cache != cache || refreshingCache.get() == cache) {
            // Ignore obsolete entries and duplicate refreshes of the current entry.
            return;
        }
        if (deferDuringErrorCooldown(cache, forceRefresh)) {
            return;
        }
        // Try to aquire a lock to update the cache.
        if (lazyLock.tryLock()) {
            try {
                // check again now that this thread holds the lock
                if (this.cache != cache || refreshingCache.get() == cache) {
                    return;
                }
                if (deferDuringErrorCooldown(cache, forceRefresh)) {
                    return;
                }
                 // still no update is in progress, so we start one.
                 refreshingCache.set(cache);

                 // run update in the background
                 executorService.execute(() -> {
                     try {
                         PreemptiveCachedAccessTokenProvider.super.getAccessTokenBlocking(time, cache);
                     } catch (Exception e) {
                         boolean deferred = e instanceof AccessTokenRetryAfterException retryAfter && !retryAfter.isRequestAttempted();
                         if (!deferred) {
                             lastPreemptiveFailureNanos = nanoTime();
                         }
                         refreshingCache.compareAndSet(cache, null);
                         if (deferred) {
                             LOGGER.debug("Preemptive access-token refresh deferred until the retry deadline", e);
                         } else {
                             LOGGER.warn("Preemptive access-token refresh failed", e);
                         }
                         if (scheduledExecutorService != null) {
                             // A rejected replacement may already have overwritten the old cache.
                             AccessTokenCacheItem current = this.cache;
                             if (current == cache || !current.isValid(currentTimeMillis())) {
                                 long remaining = remainingCooldownNanos(true);
                                 if (e instanceof AccessTokenRetryAfterException retryAfter) {
                                     remaining = Math.max(remaining, retryAfter.getRetryAfterDeadlineNanos() - nanoTime());
                                 }
                                 schedulePreemptiveRefresh(current, Math.max(1000L, remaining <= 0 ? 0 : TimeUnit.NANOSECONDS.toMillis(remaining - 1) + 1));
                             }
                         }
                     }
                 });
            } finally {
                lazyLock.unlock();
            }
        }
    }

    private boolean deferDuringErrorCooldown(AccessTokenCacheItem cache, boolean scheduledRefresh) {
        long remaining = remainingCooldownNanos(scheduledRefresh);
        if (remaining <= 0) {
            return false;
        }
        if (scheduledRefresh && scheduledExecutorService != null) {
            // Round up so an early timer does not consume the only scheduled retry.
            schedulePreemptiveRefresh(cache, TimeUnit.NANOSECONDS.toMillis(remaining - 1) + 1);
        }
        return true;
    }

    private long remainingCooldownNanos(boolean scheduledRefresh) {
        long now = nanoTime();
        long remaining = 0;
        Long failureNanos = lastPreemptiveFailureNanos;
        if (failureNanos != null) {
            long cooldown = scheduledRefresh ? eagerErrorCooldown : preemptiveErrorCooldown;
            remaining = TimeUnit.MILLISECONDS.toNanos(cooldown) - (now - failureNanos);
        }
        Long deadline = provider.getRetryAfterDeadlineNanos();
        if (deadline != null) {
            remaining = Math.max(remaining, deadline - now);
        }
        return remaining;
    }

    protected long nanoTime() {
        return System.nanoTime();
    }

    protected long currentTimeMillis() {
        return System.currentTimeMillis();
    }

    /**
     * @return traffic-triggered cooldown after a failed preemptive refresh, in milliseconds
     */
    public long getPreemptiveErrorCooldown() {
        return preemptiveErrorCooldown;
    }

    /**
     * @return eager cooldown after a failed preemptive refresh, in milliseconds
     */
    public long getEagerErrorCooldown() {
        return eagerErrorCooldown;
    }
    
    @Override
    protected AccessTokenCacheItem createCacheItem(long time, AccessToken accessToken) {
        long timeToLive = accessToken.getExpires() - time;
        
        // limit the configured preemptive refresh to a a percent of the actual time to live on the token
        long earliestRefresh = time + ((timeToLive * refreshConstraintInPercent) / 100);
        
        long refreshable = accessToken.getExpires() - preemptiveRefresh;
        if(refreshable < earliestRefresh) { // i.e. too early
            LOGGER.warn("Token time-to-live of " + (timeToLive/1000) + "s (at " + refreshConstraintInPercent + "%) does not support desired preemptive refresh of " + (preemptiveRefresh/1000) + "s");
            refreshable = earliestRefresh;
        }
        
        long expires = accessToken.getExpires() - minimumTimeToLive;
        
        if(refreshable > expires) { // i.e. too late
            refreshable = expires;
        }
        return new AccessTokenCacheItem(accessToken, expires, refreshable);
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
    
    protected String getTime(long update) {
        return Duration.ofMillis(update).toString();
    }    

    protected ScheduledFuture<?> getEagerScheduledFuture() {
        return eagerScheduledFuture;
    }
    
    @Override
    public void close() throws IOException {
        synchronized (this) {
            closed = true;
            if (eagerScheduledFuture != null) {
                eagerScheduledFuture.cancel(true);
                if(LOGGER.isDebugEnabled()) LOGGER.debug("Cancelled scheduled access-token refresh");
            }
        }
        super.close();
        
        if(shutdownExecutorOnClose) {
        	executorService.shutdownNow();
			try {
				executorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				if(LOGGER.isDebugEnabled()) LOGGER.debug("Interrupted while waiting for executor shutdown", e);
				Thread.currentThread().interrupt();
			}
        }
        if(scheduledExecutorService != null) {
        	scheduledExecutorService.shutdownNow();
			try {
				scheduledExecutorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				if(LOGGER.isDebugEnabled()) LOGGER.debug("Interrupted while waiting for scheduled executor shutdown", e);
				Thread.currentThread().interrupt();
			}
        }
        
    }
    
    long getRefreshable(long time) {
        AccessTokenCacheItem cache = this.cache;
        if (cache == null) {
            return -1L;
        }
        return cache.getRefreshable() + time;
    }    
}
