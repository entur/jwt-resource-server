package org.entur.jwt.client.properties;

public class JwtPreemptiveRefresh {

    private boolean enabled = true;
    /** Preemptively refresh the cache this number of seconds before it expires */
    private int timeToExpires = 30; // in seconds
    /** 
     * Never refresh the token before a certain percent of its lifetime has elapsed. 
     * <br>
     * This parameter acts as a safeguard for systems which refresh their tokens long before they expire,
     * but where there is a mismatch between the configured expire time (configured in app) 
     * and the token time to live (dynamically configured on the authorization server).
     *  <br>
     */
    private int expiresConstraint = 25; // in percent of a token's lifetime

    /** should the cache be refresh even if there is no traffic? */
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
    
    public void setExpiresConstraint(int expireConstraint) {
        this.expiresConstraint = expireConstraint;
    }
    
    public int getExpiresConstraint() {
        return expiresConstraint;
    }
}
