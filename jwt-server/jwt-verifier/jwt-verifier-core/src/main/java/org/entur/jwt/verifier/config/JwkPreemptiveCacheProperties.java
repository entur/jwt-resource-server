package org.entur.jwt.verifier.config;

public class JwkPreemptiveCacheProperties {

    protected boolean enabled = true;
    /** time to expires, in seconds */
    protected long timeToExpires = 30;

    /** should the cache be refresh even if there is no traffic? */
    protected JwtEagerRefresh eager = new JwtEagerRefresh();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public long getTimeToExpires() {
        return timeToExpires;
    }

    public void setTimeToExpires(long timeToExpires) {
        this.timeToExpires = timeToExpires;
    }

    public void setEager(JwtEagerRefresh eager) {
        this.eager = eager;
    }
    
    public JwtEagerRefresh getEager() {
        return eager;
    }
}
