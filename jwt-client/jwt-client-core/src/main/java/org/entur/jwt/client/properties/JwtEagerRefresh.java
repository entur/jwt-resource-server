package org.entur.jwt.client.properties;

public class JwtEagerRefresh {
    private boolean enabled = false;
    /** Eager cooldown after a failed preemptive refresh, in seconds; retries wait at least one second. */
    private long errorCooldown = 60;
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }

    public long getErrorCooldown() {
        return errorCooldown;
    }

    public void setErrorCooldown(long errorCooldown) {
        this.errorCooldown = errorCooldown;
    }
}
