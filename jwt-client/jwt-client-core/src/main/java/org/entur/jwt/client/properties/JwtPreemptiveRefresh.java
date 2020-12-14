package org.entur.jwt.client.properties;

public class JwtPreemptiveRefresh {

    private boolean enabled = true;
    /** Preemptively refresh the cache this number of seconds before it expires */
    private int timeToExpires = 30; // in seconds

    protected JwtEagerRefresh eager = new JwtEagerRefresh();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getTimeToExpires() {
        return timeToExpires;
    }

    public void setTimeToExpires(int time) {
        this.timeToExpires = time;
    }

    public void setEager(JwtEagerRefresh eager) {
        this.eager = eager;
    }

    public JwtEagerRefresh getEager() {
        return eager;
    }
}
