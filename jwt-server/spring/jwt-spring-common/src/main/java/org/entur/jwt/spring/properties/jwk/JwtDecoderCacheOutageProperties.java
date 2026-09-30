package org.entur.jwt.spring.properties.jwk;

import java.util.concurrent.TimeUnit;

/**
 * Configures how the decoded JWT cache ({@code DecodedJwtCacheJwtDecoder}) behaves while
 * the underlying JWK set is failing to refresh (an "outage"). An outage is detected when the JWK set
 * is served from the JWK outage cache ({@code OutageTolerantJWKSetSource.OutageEvent}), when a
 * (scheduled) refresh-ahead fails, or when a refresh fails or times out.
 * <p>
 * The outage duration is measured from the last successful refresh, and checked both when failure
 * events are observed and on every cache cleanup run (see {@link JwtDecoderCacheProperties#getCleanupInterval()}).
 * Once the cache is flushed, new JWTs are not cached until the JWK set is successfully refreshed.
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
        if (timeToLive < -1) {
            throw new IllegalArgumentException("timeToLive must be -1 or non-negative");
        }
        this.timeToLive = timeToLive;
    }

}
