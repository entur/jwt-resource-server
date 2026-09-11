package org.entur.jwt.spring.properties.jwk;

import java.util.concurrent.TimeUnit;

/**
 * Configures how the decoded JWT cache ({@code DecodedJwtCacheJwtDecoder}) behaves while
 * the underlying JWK set is failing to refresh (an "outage"), i.e. when a
 * {@code CachingJWKSetSource.UnableToRefreshEvent} or a
 * {@code CachingJWKSetSource.RefreshTimedOutEvent} is observed.
 */
public class JwtDecoderCacheOutageProperties {

    // whether to keep serving previously cached/validated JWTs while the JWK set fails
    // to refresh, instead of flushing the cache immediately
    protected boolean enabled = true;

    // in seconds; once a refresh outage has lasted this long (continuously, i.e. no
    // successful refresh in between), the decoded JWT cache is flushed so that JWTs are
    // re-verified rather than trusted indefinitely against an increasingly stale local
    // cache. Set to -1 to tolerate outages indefinitely (never auto-flush due to outage).
    protected long timeToLive = TimeUnit.HOURS.toSeconds(10);

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

}
