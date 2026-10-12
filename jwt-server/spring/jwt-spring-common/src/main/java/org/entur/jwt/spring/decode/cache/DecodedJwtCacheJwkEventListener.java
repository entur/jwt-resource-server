package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Keeps a {@link DecodedJwtCacheJwtDecoder} in sync with a JWK source built by {@code JWKSourceBuilder}:
 * <ul>
 *     <li>JWK set (re)loaded: update the decoder's keys, evicting JWTs whose key changed.</li>
 *     <li>JWK set refreshed: the JWK set is trusted, (continue to) use the cache.</li>
 *     <li>JWK set served from the JWK outage cache ({@link OutageTolerantJWKSetSource.OutageEvent}): cached JWTs
 *     are trusted for as long as the JWK outage cache is, so stop using the cache when the JWK outage cache expires.
 *     Note that such a refresh still completes ({@link CachingJWKSetSource.RefreshCompletedEvent}),
 *     but with the previous JWK set.</li>
 *     <li>JWK set could not be refreshed, and no outage cache was used (disabled or expired): stop using the cache now.</li>
 * </ul>
 * While not using the cache, JWTs are decoded as if no JWT was cached, until the JWK set is refreshed. In other words,
 * the decoded JWT cache follows the JWK outage cache configuration.
 * <br><br>
 * As a safety net which does not depend on events, cached JWTs are trusted for at most the JWK set's own time to live
 * since the last successful refresh. Not every failure fires an event: if an on-demand refresh (i.e. triggered by a JWT
 * with an unknown key id, or after the JWK set expired) fails without the outage cache, the exception propagates out of
 * {@link CachingJWKSetSource} without any event. Normally the scheduled refresh-ahead fails first (which fires an event),
 * but if no refresh-ahead was scheduled ({@link RefreshAheadCachingJWKSetSource.RefreshNotScheduledEvent}), or it did not
 * run, the cache would otherwise keep serving cached JWTs indefinitely.
 * <br><br>
 * Refreshes are serialized by {@link CachingJWKSetSource}, so the events of a single refresh arrive in order:
 * {@link CachingJWKSetSource.RefreshInitiatedEvent}, (retrial and outage events), {@link CachingJWKSetSource.RefreshCompletedEvent}.
 */
public class DecodedJwtCacheJwkEventListener implements EventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecodedJwtCacheJwkEventListener.class);

    protected final DecodedJwtCacheJwtDecoder decoder;

    // whether the JWK set was served from the JWK outage cache during the current refresh
    protected volatile boolean outageDuringRefresh = false;

    // when the current refresh started, i.e. the JWK set's time to live counts from (approximately) this time
    protected volatile long refreshInitiatedAt = Long.MIN_VALUE;

    // whether the 50% / 75% of JWK outage cache time to live warnings have been logged for the current outage
    protected volatile boolean outageHalfTimeWarningLogged = false;
    protected volatile boolean outageThreeQuarterTimeWarningLogged = false;

    public DecodedJwtCacheJwkEventListener(DecodedJwtCacheJwtDecoder decoder) {
        this.decoder = decoder;
    }

    /**
     * Never throws: the events are fired from within the JWK source's refresh (holding its refresh lock, or on the
     * request thread which triggered the refresh), so an exception here would fail the JWK refresh and that request.
     * Instead, a failure to keep the cache in sync means the cache can no longer be trusted, so it is suspended until
     * the next successful refresh.
     */
    @Override
    public void notify(Event event) {
        try {
            handle(event);
        } catch (RuntimeException e) {
            LOGGER.error("Problem handling JWK event {}, stop using decoded JWT cache until the JWK set is refreshed", event.getClass().getSimpleName(), e);
            decoder.suspendAt(System.currentTimeMillis());
        }
    }

    protected void handle(Event event) {
        if(event instanceof CachingJWKSetSource.RefreshInitiatedEvent<?>) {
            outageDuringRefresh = false;
            refreshInitiatedAt = System.currentTimeMillis();
        } else if(event instanceof OutageTolerantJWKSetSource.OutageEvent<?> outageEvent) {
            outageDuringRefresh = true;
            if (LOGGER.isDebugEnabled()) LOGGER.debug("JWK set served from outage cache, stop using decoded JWT cache in {} ms unless the JWK set is refreshed", outageEvent.getRemainingTime());
            decoder.suspendAt(System.currentTimeMillis() + outageEvent.getRemainingTime());
            warnIfOutageIsLasting(outageEvent.getSource().getTimeToLive(), outageEvent.getRemainingTime());
        } else if(event instanceof CachingJWKSetSource.RefreshCompletedEvent<?> refreshCompletedEvent) {
            // fired AFTER the JWK source has been updated with the new JWK set
            decoder.updateKeys(refreshCompletedEvent.getJWKSet());
            if(!outageDuringRefresh) {
                // trust cached JWTs for as long as the JWK set itself is; a successful refresh (i.e. ahead of expiration) extends this
                decoder.suspendAt(getTrustedUntil(refreshCompletedEvent.getSource().getTimeToLive()));
                outageHalfTimeWarningLogged = false;
                outageThreeQuarterTimeWarningLogged = false;
            }
        } else if(event instanceof RefreshAheadCachingJWKSetSource.RefreshNotScheduledEvent<?>) {
            // the refresh-ahead time plus refresh timeout is (within the current refresh) not below the time to live; the JWK set
            // is only refreshed on demand, so key rotation is detected late, and the cache is suspended when the JWK set expires
            LOGGER.warn("No JWK set refresh-ahead was scheduled; the decoded JWT cache is not used from when the JWK set expires until it is refreshed on demand. Check the JWK cache time to live, refresh timeout and preemptive time to expires.");
        } else if(event instanceof CachingJWKSetSource.UnableToRefreshEvent<?>
                || event instanceof RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent<?>
                || event instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshFailed<?>) {
            // failure not covered by the JWK outage cache
            decoder.suspendAt(System.currentTimeMillis());
        }
        // RefreshTimedOutEvent: a thread gave up waiting for another thread's refresh, which
        // itself ends with one of the above events
    }

    /**
     * @param timeToLive JWK set time to live (millis)
     * @return time (epoch millis) until which cached JWTs are trusted, i.e. when the JWK set loaded by the current refresh expires
     */
    protected long getTrustedUntil(long timeToLive) {
        long initiatedAt = refreshInitiatedAt;
        if (initiatedAt == Long.MIN_VALUE) {
            // completed event without initiated event, i.e. not a CachingJWKSetSource; count from now
            initiatedAt = System.currentTimeMillis();
        }
        if (timeToLive <= 0 || timeToLive > Long.MAX_VALUE - initiatedAt) {
            return DecodedJwtCacheJwtDecoder.NEVER;
        }
        return initiatedAt + timeToLive;
    }

    protected void warnIfOutageIsLasting(long timeToLive, long remainingTime) {
        if (timeToLive <= 0) {
            return;
        }
        long elapsed = timeToLive - remainingTime;
        if (elapsed >= timeToLive / 2 && !outageHalfTimeWarningLogged) {
            outageHalfTimeWarningLogged = true;
            LOGGER.warn("JWK set refresh outage has lasted for 50% of the JWK outage cache time to live ({} ms); {} ms left before the decoded JWT cache is no longer used", timeToLive, remainingTime);
        }
        if (elapsed >= (timeToLive * 3) / 4 && !outageThreeQuarterTimeWarningLogged) {
            outageThreeQuarterTimeWarningLogged = true;
            LOGGER.error("JWK set refresh outage has lasted for 75% of the JWK outage cache time to live ({} ms); {} ms left before the decoded JWT cache is no longer used", timeToLive, remainingTime);
        }
    }

    public DecodedJwtCacheJwtDecoder getDecoder() {
        return decoder;
    }
}
