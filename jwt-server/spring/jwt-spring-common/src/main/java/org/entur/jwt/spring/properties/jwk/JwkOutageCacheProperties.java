package org.entur.jwt.spring.properties.jwk;

import java.util.concurrent.TimeUnit;

public class JwkOutageCacheProperties {

    protected boolean enabled = true;
    /** Time to live, in seconds */
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
