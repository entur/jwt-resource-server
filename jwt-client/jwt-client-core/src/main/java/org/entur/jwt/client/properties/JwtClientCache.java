package org.entur.jwt.client.properties;

public class JwtClientCache {

    private boolean enabled = true;

    /** Minimum number of seconds left before the returned (cached) token expires */
    private long minimumTimeToLive = 15; // in seconds

    /** Number of seconds to wait for a token, if it must be refreshed */
    private long refreshTimeout = 15; // cache refresh timeout in seconds

    private JwtPreemptiveRefresh preemptiveRefresh = new JwtPreemptiveRefresh();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public long getMinimumTimeToLive() {
        return minimumTimeToLive;
    }

    public void setMinimumTimeToLive(long minimumTimeToLive) {
        this.minimumTimeToLive = minimumTimeToLive;
    }

    public JwtPreemptiveRefresh getPreemptiveRefresh() {
        return preemptiveRefresh;
    }

    public void setPreemptiveRefresh(JwtPreemptiveRefresh preemptiveRefresh) {
        this.preemptiveRefresh = preemptiveRefresh;
    }

    public long getRefreshTimeout() {
        return refreshTimeout;
    }

    public void setRefreshTimeout(long refreshTimeout) {
        this.refreshTimeout = refreshTimeout;
    }
}
