package org.entur.jwt.client.properties;

public class PreemptiveRefresh {

    private boolean enabled = true;
    /** Preemptively refresh the cache this number of seconds before it expires */
    private int time = 30; // in seconds

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getTime() {
        return time;
    }

    public void setTime(int time) {
        this.time = time;
    }

}
